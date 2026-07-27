#include "scanner_core.h"
#include "embedded_driver.h"
#include "resource.h"

namespace {

constexpr const char* kXvDriverSha256 =
    "440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c";
constexpr const wchar_t* kXvDevicePath = L"\\\\.\\PROCEXP152";

bool IsProcessElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation = {};
    DWORD returned = 0;
    const bool elevated = GetTokenInformation(token, TokenElevation, &elevation,
                                               sizeof(elevation), &returned) &&
                          elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

std::wstring MakeTempDriverPath(const wchar_t* fileStem, unsigned attempt) {
    wchar_t tempDir[MAX_PATH + 2] = {};
    DWORD length = GetTempPathW(static_cast<DWORD>(std::size(tempDir)), tempDir);
    if (length == 0 || length >= std::size(tempDir))
        return {};

    wchar_t name[192] = {};
    swprintf_s(name, L"rxv-%s-%lu-%llu-%u.sys", fileStem,
               GetCurrentProcessId(),
               static_cast<unsigned long long>(GetTickCount64()), attempt);
    return std::wstring(tempDir) + name;
}

HANDLE OpenXvDevice() {
    return CreateFileW(kXvDevicePath, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

}

bool ExtractEmbeddedDriverResource(WORD resourceId,
                                   const char* expectedSha256,
                                   const wchar_t* fileStem,
                                   std::wstring& outPath,
                                   std::string& status) {
    outPath.clear();
    HMODULE module = GetModuleHandleW(nullptr);
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!resource) {
        status = "embedded driver resource not found";
        return false;
    }

    HGLOBAL loaded = LoadResource(module, resource);
    DWORD size = SizeofResource(module, resource);
    const BYTE* bytes = loaded ? static_cast<const BYTE*>(LockResource(loaded)) : nullptr;
    if (!bytes || size == 0 || size > 4 * 1024 * 1024) {
        status = "embedded driver resource is invalid";
        return false;
    }

    const std::string resourceHash = DetectionFilter::ComputeBufferSha256(bytes, size);
    if (resourceHash.empty() || resourceHash != expectedSha256) {
        status = "embedded driver SHA-256 mismatch";
        return false;
    }

    HANDLE file = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 8 && file == INVALID_HANDLE_VALUE; ++attempt) {
        outPath = MakeTempDriverPath(fileStem, attempt);
        if (outPath.empty())
            break;
        file = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    }
    if (file == INVALID_HANDLE_VALUE) {
        outPath.clear();
        status = "could not create temporary driver image";
        return false;
    }

    DWORD written = 0;
    bool writeOk = WriteFile(file, bytes, size, &written, nullptr) && written == size;
    if (writeOk)
        writeOk = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);

    if (!writeOk || DetectionFilter::ComputeFileSha256(outPath) != expectedSha256 ||
        !IsAuthenticodeSigned(outPath)) {
        DeleteEmbeddedDriverFile(outPath);
        status = "temporary driver failed integrity or signature verification";
        return false;
    }

    status = "embedded driver extracted and verified";
    return true;
}

bool DeleteEmbeddedDriverFile(std::wstring& path) {
    if (path.empty())
        return true;

    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND) {
            path.clear();
            return true;
        }
        Sleep(40);
    }



    MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    path.clear();
    return false;
}

XvKernelDriver::~XvKernelDriver() {
    Unload();
}

bool XvKernelDriver::Load() {
    if (IsLoaded())
        return true;
    Unload();

    device_ = OpenXvDevice();
    if (device_ != INVALID_HANDLE_VALUE) {
        status_ = "PROCEXP152 device already available; existing owner preserved";
        return true;
    }

    if (!IsProcessElevated()) {
        status_ = "administrator elevation required for xvscreen kernel backend";
        return false;
    }

    if (!ExtractEmbeddedDriverResource(IDR_DRIVER_XVSCREEN, kXvDriverSha256,
                                       L"xvscreen", tempPath_, status_))
        return false;

    scm_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm_) {
        status_ = "could not open Service Control Manager for xvscreen driver";
        Unload();
        return false;
    }

    serviceName_ = L"RXVScanXv_" + std::to_wstring(GetCurrentProcessId());
    service_ = CreateServiceW(scm_, serviceName_.c_str(), serviceName_.c_str(),
                              SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
                              SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                              SERVICE_ERROR_IGNORE, tempPath_.c_str(), nullptr, nullptr,
                              nullptr, nullptr, nullptr);
    if (!service_) {
        status_ = "could not create temporary xvscreen driver service";
        Unload();
        return false;
    }
    serviceCreated_ = true;

    if (!StartServiceW(service_, 0, nullptr) &&
        GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        status_ = "Windows blocked or failed to start xvscreen driver";
        Unload();
        return false;
    }

    for (int attempt = 0; attempt < 20; ++attempt) {
        device_ = OpenXvDevice();
        if (device_ != INVALID_HANDLE_VALUE)
            break;
        Sleep(50);
    }
    if (device_ == INVALID_HANDLE_VALUE) {
        status_ = "xvscreen driver started but PROCEXP152 device is unavailable";
        Unload();
        return false;
    }

    status_ = "xvscreen/PROCEXP152 driver loaded from verified temporary image";
    return true;
}

bool XvKernelDriver::Unload() {
    if (device_ && device_ != INVALID_HANDLE_VALUE) {
        CloseHandle(device_);
        device_ = INVALID_HANDLE_VALUE;
    }

    if (service_) {
        if (serviceCreated_) {
            SERVICE_STATUS status = {};
            ControlService(service_, SERVICE_CONTROL_STOP, &status);
            for (int attempt = 0; attempt < 20; ++attempt) {
                SERVICE_STATUS_PROCESS current = {};
                DWORD needed = 0;
                if (!QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
                                          reinterpret_cast<BYTE*>(&current),
                                          sizeof(current), &needed) ||
                    current.dwCurrentState == SERVICE_STOPPED)
                    break;
                Sleep(50);
            }
            DeleteService(service_);
        }
        CloseServiceHandle(service_);
        service_ = nullptr;
    }
    if (scm_) {
        CloseServiceHandle(scm_);
        scm_ = nullptr;
    }

    serviceCreated_ = false;
    serviceName_.clear();
    const bool deleted = DeleteEmbeddedDriverFile(tempPath_);
    if (deleted && !status_.empty())
        status_ += " | temporary image removed";
    return deleted;
}
