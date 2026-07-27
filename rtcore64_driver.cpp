#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "rtcore64_driver.h"
#include "embedded_driver.h"
#include "resource.h"
#include <winioctl.h>
#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

#define RTCORE_IOCTL_READ_PHYSICAL  0x80002000
#define RTCORE_IOCTL_READ_KERNEL    0x80002048
#define RTCORE_IOCTL_GET_RANGES     0x80002030

static const wchar_t* kRTCoreServiceName = L"RTCoreScanner";
static constexpr const char* kRTCoreSha256 =
    "a4f44e267698d47f6a905e96b356582b4ee9cf4049e8c792ffda1b7356e68d35";

#pragma pack(push, 1)
struct RTCoreMemReadInput {
    ULONG Unknown;
    ULONG Size;
    ULONGLONG PhysicalAddress;
};

struct RTCoreKernelReadRequest {
    ULONGLONG Reserved0;
    ULONGLONG Address;
    ULONGLONG Offset;
    ULONG ReadSize;
    ULONG Value;
    ULONGLONG Reserved1;
    ULONGLONG Reserved2;
};

struct RTCoreEprocessOffsets {
    DWORD pid;
    DWORD activeProcessLinks;
    DWORD imageFileName;
};
#pragma pack(pop)

static const RTCoreEprocessOffsets kEprocessOffsets = {
    0x2E0, 0x2E8, 0x2A0
};

RTCoreDriver::~RTCoreDriver() {
    Unload();
}

static std::wstring GetSystem32Dir() {
    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return sysDir;
}

static std::wstring GetExecutableDirectory() {
    wchar_t path[MAX_PATH * 4] = {};
    if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path))))
        return {};
    std::wstring directory = path;
    size_t slash = directory.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring{} : directory.substr(0, slash + 1);
}

static bool IsCompatibleRTCoreImage(const std::wstring& path) {
    if (!FileExistsW(path))
        return false;
    auto signer = DetectionFilter::GetVerifiedSignerIdentityCached(path);
    if (!signer.trusted || signer.cnUpper.find(L"MICRO-STAR") == std::wstring::npos)
        return false;

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD size = GetFileSize(file, nullptr);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 4 * 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    std::vector<BYTE> bytes(size);
    DWORD read = 0;
    bool ok = ReadFile(file, bytes.data(), size, &read, nullptr) && read == size;
    CloseHandle(file);
    if (!ok)
        return false;

    static const wchar_t marker[] = L"\\Device\\RTCore64";
    const BYTE* markerBytes = reinterpret_cast<const BYTE*>(marker);
    const size_t markerSize = (std::size(marker) - 1) * sizeof(wchar_t);
    return std::search(bytes.begin(), bytes.end(), markerBytes, markerBytes + markerSize) != bytes.end();
}

static std::wstring FindBundledRTCoreImage() {
    std::wstring directory = GetExecutableDirectory();
    if (directory.empty())
        return {};
    std::wstring standard = directory + L"RTCore64.sys";
    if (IsCompatibleRTCoreImage(standard))
        return standard;

    WIN32_FIND_DATAW data = {};
    HANDLE search = FindFirstFileW((directory + L"*.sys").c_str(), &data);
    if (search == INVALID_HANDLE_VALUE)
        return {};
    std::wstring result;
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            std::wstring candidate = directory + data.cFileName;
            if (IsCompatibleRTCoreImage(candidate)) {
                result = std::move(candidate);
                break;
            }
        }
    } while (FindNextFileW(search, &data));
    FindClose(search);
    return result;
}

bool RTCoreDriver::Load(const std::wstring& driverPath) {
    if (IsLoaded()) return true;
    Unload();

    hDevice = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                          0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDevice != INVALID_HANDLE_VALUE)
        return true;

    std::wstring srcPath = driverPath.empty() ? FindBundledRTCoreImage() : driverPath;
    if (!IsCompatibleRTCoreImage(srcPath) && driverPath.empty()) {
        std::string status;
        if (!ExtractEmbeddedDriverResource(IDR_DRIVER_RTCORE64, kRTCoreSha256,
                                           L"RTCore64", stagedDriverPath, status))
            return false;
        srcPath = stagedDriverPath;
    }
    if (!IsCompatibleRTCoreImage(srcPath)) {
        DeleteEmbeddedDriverFile(stagedDriverPath);
        return false;
    }

    scmHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scmHandle) return false;


    SC_HANDLE oldSvc = OpenServiceW(scmHandle, kRTCoreServiceName, SERVICE_STOP | DELETE);
    if (oldSvc) {
        SERVICE_STATUS ss = {};
        ControlService(oldSvc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(oldSvc);
        CloseServiceHandle(oldSvc);
    }

    svcHandle = CreateServiceW(scmHandle, kRTCoreServiceName, kRTCoreServiceName,
                               SERVICE_START | SERVICE_STOP | DELETE,
                               SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                               SERVICE_ERROR_IGNORE, srcPath.c_str(),
                               nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svcHandle) {
        CloseServiceHandle(scmHandle);
        scmHandle = nullptr;
        DeleteEmbeddedDriverFile(stagedDriverPath);
        return false;
    }
    serviceCreated = true;

    if (!StartServiceW(svcHandle, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            DeleteService(svcHandle); serviceCreated = false;
            CloseServiceHandle(svcHandle); svcHandle = nullptr;
            CloseServiceHandle(scmHandle); scmHandle = nullptr;
            DeleteEmbeddedDriverFile(stagedDriverPath);
            return false;
        }
    }

    hDevice = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                          0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        SERVICE_STATUS ss = {};
        ControlService(svcHandle, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svcHandle); serviceCreated = false;
        CloseServiceHandle(svcHandle); svcHandle = nullptr;
        CloseServiceHandle(scmHandle); scmHandle = nullptr;
        DeleteEmbeddedDriverFile(stagedDriverPath);
        return false;
    }

    return true;
}

void RTCoreDriver::Unload() {
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        hDevice = INVALID_HANDLE_VALUE;
    }
    if (svcHandle) {
        SERVICE_STATUS ss = {};
        ControlService(svcHandle, SERVICE_CONTROL_STOP, &ss);
        if (serviceCreated) DeleteService(svcHandle);
        CloseServiceHandle(svcHandle);
        svcHandle = nullptr;
    }
    if (scmHandle) {
        CloseServiceHandle(scmHandle);
        scmHandle = nullptr;
    }
    serviceCreated = false;
    DeleteEmbeddedDriverFile(stagedDriverPath);
}

bool RTCoreDriver::ReadKernelMemory(uint64_t address, void* buffer, DWORD size) {
    if (!IsLoaded() || !buffer || size == 0 || address < 0xFFFF800000000000ULL)
        return false;

    BYTE* output = static_cast<BYTE*>(buffer);
    DWORD offset = 0;
    while (offset < size) {
        DWORD chunk = (size - offset >= 4) ? 4 : (size - offset >= 2 ? 2 : 1);
        RTCoreKernelReadRequest request = {};
        request.Address = address + offset;
        request.ReadSize = chunk;
        DWORD returned = 0;
        if (!DeviceIoControl(hDevice, RTCORE_IOCTL_READ_KERNEL,
                             &request, sizeof(request), &request, sizeof(request),
                             &returned, nullptr) || returned < sizeof(request))
            return false;
        memcpy(output + offset, &request.Value, chunk);
        offset += chunk;
    }
    return true;
}

bool RTCoreDriver::ReadPhysicalMemory(uint64_t physAddr, void* buffer, DWORD size) {
    if (!IsLoaded() || !buffer || size == 0) return false;

    RTCoreMemReadInput input = {};
    input.Unknown = 0;
    input.Size = size;
    input.PhysicalAddress = physAddr;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, RTCORE_IOCTL_READ_PHYSICAL,
                           &input, sizeof(input),
                           buffer, size, &bytesReturned, nullptr) &&
           bytesReturned == size;
}


struct RTCorePhysRange {
    LONGLONG BaseAddress;
    LONGLONG NumberOfBytes;
};

bool RTCoreDriver::GetPhysicalMemoryRanges(std::vector<RTCoreMemRange>& ranges) {
    if (!IsLoaded()) return false;

    uint8_t buffer[4096] = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice, RTCORE_IOCTL_GET_RANGES,
                         nullptr, 0, buffer, sizeof(buffer), &bytesReturned, nullptr)) {
        return false;
    }

    DWORD count = bytesReturned / sizeof(RTCorePhysRange);
    auto* rawRanges = reinterpret_cast<RTCorePhysRange*>(buffer);
    ranges.clear();
    for (DWORD i = 0; i < count && i < 512; ++i) {
        if (rawRanges[i].NumberOfBytes > 0) {
            ranges.push_back({ (uint64_t)rawRanges[i].BaseAddress, (uint64_t)rawRanges[i].NumberOfBytes });
        }
    }
    return !ranges.empty();
}

static bool IsKernelPointer(uint64_t addr) {
    return addr >= 0xFFFF800000000000ULL;
}

static DWORD ReadKernelExportRva(const std::wstring& kernelPath, const char* exportName) {
    HANDLE hFile = CreateFileW(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < 0x1000) { CloseHandle(hFile); return 0; }

    std::vector<uint8_t> buf(fileSize);
    DWORD nRead = 0;
    if (!ReadFile(hFile, buf.data(), fileSize, &nRead, nullptr) || nRead < 0x1000) {
        CloseHandle(hFile); return 0;
    }
    CloseHandle(hFile);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0 || exportDir.VirtualAddress == 0) return 0;

    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(buf.data() + exportDir.VirtualAddress);
    DWORD* names = reinterpret_cast<DWORD*>(buf.data() + exp->AddressOfNames);
    WORD* ordinals = reinterpret_cast<WORD*>(buf.data() + exp->AddressOfNameOrdinals);
    DWORD* functions = reinterpret_cast<DWORD*>(buf.data() + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(buf.data() + names[i]);
        if (_stricmp(name, exportName) == 0) {
            WORD ordinal = ordinals[i];
            if (ordinal < exp->NumberOfFunctions) {
                return functions[ordinal];
            }
        }
    }
    return 0;
}

static std::wstring FindNtkrnlPath() {
    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring path = std::wstring(sysDir) + L"\\ntoskrnl.exe";
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return path;
    std::vector<std::wstring> candidates = {
        std::wstring(sysDir) + L"\\ntkrnlmp.exe",
        std::wstring(sysDir) + L"\\ntkrnlpa.exe",
        std::wstring(sysDir) + L"\\ntoskrnl.exe",
    };
    for (const auto& c : candidates) {
        if (GetFileAttributesW(c.c_str()) != INVALID_FILE_ATTRIBUTES) return c;
    }
    return path;
}

bool RTCoreDriver::GetKernelPhysicalBase(uint64_t& kernelPhysBase) {
    kernelPhysBase = 0;

    DWORD needed = 0;
    EnumDeviceDrivers(nullptr, 0, &needed);
    if (!needed) return false;
    std::vector<LPVOID> bases(needed / sizeof(LPVOID) + 32);
    if (!EnumDeviceDrivers(bases.data(), (DWORD)(bases.size() * sizeof(LPVOID)), &needed)) return false;
    bases.resize(needed / sizeof(LPVOID));

    uint64_t kernelVirtBase = 0;
    std::wstring kernelPath;
    for (auto* ptr : bases) {
        wchar_t p[MAX_PATH * 2] = {};
        if (GetDeviceDriverFileNameW(ptr, p, (DWORD)std::size(p))) {
            std::wstring path = p;
            size_t s = path.rfind(L'\\');
            std::wstring name = (s != std::wstring::npos) ? path.substr(s + 1) : path;
            std::wstring up = ToUpperInvariant(name);
            if (up.find(L"NTOSKRNL") != std::wstring::npos ||
                up.find(L"NTKRNLMP") != std::wstring::npos) {
                kernelVirtBase = (uint64_t)ptr;
                kernelPath = FindNtkrnlPath();
                break;
            }
        }
    }
    if (!kernelVirtBase || kernelPath.empty()) return false;


    HANDLE hFile = CreateFileW(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    uint8_t hdrBuf[0x1000] = {};
    DWORD nRead = 0;
    ReadFile(hFile, hdrBuf, sizeof(hdrBuf), &nRead, nullptr);
    CloseHandle(hFile);
    if (nRead < 0x400) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hdrBuf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(hdrBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;


    std::vector<RTCoreMemRange> ranges;
    if (!GetPhysicalMemoryRanges(ranges)) {
        ranges.push_back({ 0x1000, 0x4000000 });
    }



    uint8_t chunkBuf[0x100000];
    for (const auto& range : ranges) {
        if (range.base > 0x80000000ULL) continue;
        uint64_t end = range.base + range.size;
        if (end > 0x80000000ULL) end = 0x80000000ULL;
        for (uint64_t pa = range.base; pa < end; pa += sizeof(chunkBuf)) {
            DWORD readSize = (DWORD)((std::min<uint64_t>)(sizeof(chunkBuf), end - pa));
            if (!ReadPhysicalMemory(pa, chunkBuf, readSize)) continue;
            DWORD pagesInChunk = readSize / 0x1000;
            for (DWORD pi = 0; pi < pagesInChunk; ++pi) {
                uint8_t* scanBuf = chunkBuf + (pi * 0x1000);
                auto* mz = reinterpret_cast<IMAGE_DOS_HEADER*>(scanBuf);
                if (mz->e_magic != IMAGE_DOS_SIGNATURE) continue;
                if (mz->e_lfanew <= 0 || (DWORD)mz->e_lfanew > 0x1000 - 4) continue;

                auto* ntCheck = reinterpret_cast<IMAGE_NT_HEADERS64*>(scanBuf + mz->e_lfanew);
                if (ntCheck->Signature != IMAGE_NT_SIGNATURE) continue;
                if (ntCheck->OptionalHeader.SizeOfImage != sizeOfImage) continue;
                if (ntCheck->OptionalHeader.SizeOfHeaders != sizeOfHeaders) continue;
                if (ntCheck->FileHeader.NumberOfSections != nt->FileHeader.NumberOfSections) continue;

                kernelPhysBase = pa + (pi * 0x1000);
                return true;
            }
        }
    }

    return false;
}

static std::vector<DWORD> GetKnownPids() {
    std::unordered_set<DWORD> pidSet;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do { pidSet.insert(pe.th32ProcessID); }
            while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }


    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySysInfo = ntdll
        ? reinterpret_cast<LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG)>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"))
        : nullptr;
    if (NtQuerySysInfo) {
        ULONG needed = 0;
        NtQuerySysInfo(5, nullptr, 0, &needed);
        if (needed < 64) needed = 2 * 1024 * 1024;
        std::vector<uint8_t> buf(needed + 4096);
        LONG st = NtQuerySysInfo(5, buf.data(), (ULONG)buf.size(), &needed);
        if (st >= 0) {
            size_t off = 0;
            while (off + 8 <= buf.size()) {
                ULONG next = *reinterpret_cast<const ULONG*>(buf.data() + off);
                size_t pidOff = off + (sizeof(void*) == 8 ? 0x50 : 0x44);
                if (pidOff + sizeof(ULONG_PTR) <= buf.size()) {
                    DWORD pid = (DWORD)*reinterpret_cast<const ULONG_PTR*>(buf.data() + pidOff);
                    if (pid != 0) pidSet.insert(pid);
                }
                if (!next) break;
                off += next;
                if (off >= buf.size()) break;
            }
        }
    }

    std::vector<DWORD> pids(pidSet.begin(), pidSet.end());
    return pids;
}

std::vector<HiddenEprocessFinding> RTCoreDriver::FindHiddenProcesses() {
    std::vector<HiddenEprocessFinding> findings;
    if (!IsLoaded()) return findings;

    std::vector<RTCoreMemRange> ranges;
    if (!GetPhysicalMemoryRanges(ranges)) {
        ranges.push_back({ 0x1000, 0xFFFFFFFF });
    }

    std::vector<DWORD> knownPids = GetKnownPids();
    std::unordered_set<DWORD> knownSet(knownPids.begin(), knownPids.end());

    uint8_t page[0x1000];
    DWORD selfPid = GetCurrentProcessId();
    DWORD maxPid = 65535;

    for (const auto& range : ranges) {
        uint64_t end = range.base + range.size;
        for (uint64_t pa = range.base; pa < end; pa += 0x1000) {
            if (!ReadPhysicalMemory(pa, page, sizeof(page))) continue;





            uint64_t flink = *reinterpret_cast<uint64_t*>(page + kEprocessOffsets.activeProcessLinks);
            uint64_t blink = *reinterpret_cast<uint64_t*>(page + kEprocessOffsets.activeProcessLinks + 8);
            DWORD pid = *reinterpret_cast<DWORD*>(page + kEprocessOffsets.pid);

            if (IsKernelPointer(flink) && IsKernelPointer(blink) && pid > 0 && pid < maxPid && pid != selfPid) {
                char imageName[16] = {};
                memcpy(imageName, page + kEprocessOffsets.imageFileName, 15);
                imageName[15] = '\0';

                bool printable = true;
                for (int i = 0; imageName[i]; ++i) {
                    if (imageName[i] < 32 || imageName[i] > 126) { printable = false; break; }
                }

                if (printable && strlen(imageName) > 0 && knownSet.find(pid) == knownSet.end()) {
                    HiddenEprocessFinding f;
                    f.pid = pid;
                    f.imageFileName = imageName;
                    f.eprocessPhysical = pa;
                    f.eprocessVirtual = flink - kEprocessOffsets.activeProcessLinks;
                    f.reason = "process visible in physical memory but hidden from user-mode APIs (DKOM)";
                    findings.push_back(f);
                }
            }
        }
    }

    return findings;
}

static bool IsKernelHookPrologue(const BYTE* code, size_t size) {
    if (!code || size < 6)
        return false;
    if (code[0] == 0xE9 || (code[0] == 0xFF && code[1] == 0x25) ||
        (code[0] == 0x68 && code[5] == 0xC3))
        return true;
    return size >= 12 && code[0] == 0x48 && code[1] == 0xB8 &&
           code[10] == 0xFF && code[11] == 0xE0;
}

std::vector<ScannerUI::KernelAnomalyFinding> RTCoreDriver::VerifyKernelVirtualIntegrity() {
    std::vector<ScannerUI::KernelAnomalyFinding> findings;
    if (!IsLoaded())
        return findings;

    DWORD needed = 0;
    if (!EnumDeviceDrivers(nullptr, 0, &needed) || needed < sizeof(LPVOID))
        return findings;
    std::vector<LPVOID> drivers(needed / sizeof(LPVOID) + 8);
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed) ||
        needed < sizeof(LPVOID))
        return findings;
    const uint64_t kernelBase = reinterpret_cast<uint64_t>(drivers.front());
    if (!IsKernelPointer(kernelBase))
        return findings;

    BYTE signature[2] = {};
    if (!ReadKernelMemory(kernelBase, signature, sizeof(signature)) ||
        signature[0] != 'M' || signature[1] != 'Z')
        return findings;

    std::wstring kernelPath = FindNtkrnlPath();
    HMODULE diskImage = LoadLibraryExW(kernelPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!diskImage)
        return findings;

    static const char* criticalExports[] = {
        "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtQuerySystemInformation", "NtQueryInformationProcess", "NtDuplicateObject"
    };

    std::vector<std::string> hooked;
    for (const char* exportName : criticalExports) {
        FARPROC expectedAddress = GetProcAddress(diskImage, exportName);
        if (!expectedAddress)
            continue;
        const uint64_t rva = reinterpret_cast<uint64_t>(expectedAddress) -
                             reinterpret_cast<uint64_t>(diskImage);
        if (rva > 0x10000000ULL)
            continue;

        BYTE actual[16] = {};
        BYTE expected[16] = {};
        memcpy(expected, reinterpret_cast<const void*>(expectedAddress), sizeof(expected));
        if (!ReadKernelMemory(kernelBase + rva, actual, sizeof(actual)))
            continue;
        if (memcmp(actual, expected, sizeof(actual)) != 0 &&
            IsKernelHookPrologue(actual, sizeof(actual)))
            hooked.emplace_back(exportName);
    }
    FreeLibrary(diskImage);

    if (hooked.empty())
        return findings;

    std::string names;
    for (const auto& name : hooked) {
        if (!names.empty()) names += ", ";
        names += name;
    }
    ScannerUI::KernelAnomalyFinding finding;
    finding.severity = "HIGH";
    finding.type = "KERNEL_HOOK";
    finding.driverName = "ntoskrnl.exe";
    finding.path = WideToUtf8(kernelPath);
    finding.reason = "kernel export prologue redirected in live memory";
    finding.detail = "backend=RTCore64 read-only | exports=" + names;
    finding.suspicious = true;
    findings.push_back(std::move(finding));
    return findings;
}

std::vector<ScannerUI::KernelAnomalyFinding> RTCoreDriver::VerifyKernelIntegrity() {
    std::vector<ScannerUI::KernelAnomalyFinding> findings;
    if (!IsLoaded()) return findings;

    uint64_t kernelPhysBase = 0;
    if (!GetKernelPhysicalBase(kernelPhysBase)) return findings;

    std::wstring kernelPath = FindNtkrnlPath();


    HANDLE hFile = CreateFileW(kernelPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return findings;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < 0x1000) { CloseHandle(hFile); return findings; }

    std::vector<uint8_t> diskImage(fileSize);
    DWORD nRead = 0;
    if (!ReadFile(hFile, diskImage.data(), fileSize, &nRead, nullptr) || nRead < 0x1000) {
        CloseHandle(hFile); return findings;
    }
    CloseHandle(hFile);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(diskImage.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return findings;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(diskImage.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return findings;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    IMAGE_SECTION_HEADER* textSection = nullptr;
    for (WORD i = 0; i < numSections; ++i) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textSection = &sections[i];
            break;
        }
    }
    if (!textSection) return findings;

    DWORD textVirtualAddr = textSection->VirtualAddress;
    DWORD textSize = textSection->SizeOfRawData;
    if (textSize == 0) textSize = textSection->Misc.VirtualSize;
    if (textSize == 0 || textSize > 0x400000) return findings;


    uint64_t textPhysBase = kernelPhysBase + textVirtualAddr;
    std::vector<uint8_t> physText(textSize);

    DWORD offset = 0;
    while (offset < textSize) {
        DWORD chunkSize = (std::min<DWORD>)(4096, textSize - offset);
        if (!ReadPhysicalMemory(textPhysBase + offset, physText.data() + offset, chunkSize)) {
            break;
        }
        offset += chunkSize;
    }

    if (offset < textSize) return findings;


    DWORD diskTextRva = textSection->PointerToRawData;
    DWORD diskTextSize = textSection->SizeOfRawData;
    if (diskTextSize == 0 || diskTextSize > textSize) diskTextSize = textSize;
    DWORD compareSize = (std::min<DWORD>)(textSize, diskTextSize);

    std::vector<std::pair<DWORD, DWORD>> patchRanges;
    bool inPatch = false;
    DWORD patchStart = 0;

    for (DWORD i = 0; i < compareSize; ++i) {
        uint8_t diskByte = diskImage[diskTextRva + i];
        uint8_t physByte = physText[i];
        if (diskByte != physByte) {
            if (!inPatch) {
                patchStart = i;
                inPatch = true;
            }
        } else {
            if (inPatch) {
                patchRanges.push_back({ patchStart, i - patchStart });
                inPatch = false;
            }
        }
    }
    if (inPatch) {
        patchRanges.push_back({ patchStart, compareSize - patchStart });
    }

    if (patchRanges.empty()) return findings;

    char detail[512] = {};
    int pos = 0;
    for (size_t i = 0; i < patchRanges.size() && pos < 400; ++i) {
        pos += snprintf(detail + pos, sizeof(detail) - pos,
                       "[0x%X+%u] ", patchRanges[i].first, patchRanges[i].second);
    }

    ScannerUI::KernelAnomalyFinding f;
    f.severity = "HIGH";
    f.type = "HOLLOWING";
    f.driverName = "ntoskrnl.exe";
    f.path = WideToUtf8(kernelPath);
    f.reason = "kernel .text section modified in physical memory (inline hooks or rootkit)";
    f.detail = std::string(detail);
    f.suspicious = true;


    struct CriticalFunc {
        const char* name;
        int minPrologueLen;
    };
    CriticalFunc criticalFuncs[] = {
        { "NtOpenProcess", 4 },
        { "NtReadVirtualMemory", 4 },
        { "NtWriteVirtualMemory", 4 },
        { "NtCreateThreadEx", 4 },
        { "NtOpenProcessToken", 4 },
        { "NtSuspendProcess", 4 },
        { "NtResumeProcess", 4 },
        { "NtProtectVirtualMemory", 4 },
        { "NtAllocateVirtualMemory", 4 },
        { "NtQuerySystemInformation", 4 },
        { "NtQueryInformationProcess", 4 },
        { "NtDuplicateObject", 4 },
        { "NtSetInformationProcess", 4 },
        { "NtClose", 4 },
        { "NtCreateUserProcess", 4 },
        { "NtOpenProcessTokenEx", 4 },
        { "NtAdjustPrivilegesToken", 4 },
        { "NtQueryDirectoryFile", 4 },
    };


    char hookedList[512] = {};
    int hpos = 0;
    for (const auto& cf : criticalFuncs) {
        DWORD rva = ReadKernelExportRva(kernelPath, cf.name);
        if (!rva) continue;


        DWORD diskFuncRva = rva;


        DWORD fileOffset = 0;
        for (WORD i = 0; i < numSections; ++i) {
            DWORD start = sections[i].VirtualAddress;
            DWORD end = start + sections[i].SizeOfRawData;
            if (diskFuncRva >= start && diskFuncRva < end) {
                fileOffset = sections[i].PointerToRawData + (diskFuncRva - start);
                break;
            }
        }
        if (!fileOffset) continue;

        uint8_t expectedPrologue[8] = {};
        if (fileOffset + 8 > diskImage.size()) continue;
        memcpy(expectedPrologue, diskImage.data() + fileOffset, 8);


        uint8_t physPrologue[8] = {};
        uint64_t funcPhys = kernelPhysBase + rva;
        if (!ReadPhysicalMemory(funcPhys, physPrologue, sizeof(physPrologue))) continue;

        if (memcmp(expectedPrologue, physPrologue, 8) != 0) {
            if (hpos > 0) hpos += snprintf(hookedList + hpos, sizeof(hookedList) - hpos, ", ");
            hpos += snprintf(hookedList + hpos, sizeof(hookedList) - hpos, "%s", cf.name);
        }
    }

    if (hpos > 0) {
        f.reason = std::string("kernel functions modified: ") + hookedList;
        f.detail = std::string(detail);
    }

    findings.push_back(f);
    return findings;
}

std::vector<ScannerUI::StreamModFinding> RTCoreDriver::FindStreamModAnomalies() {
    std::vector<ScannerUI::StreamModFinding> findings;
    if (!IsLoaded()) return findings;


    struct EnumCtx { std::unordered_set<HWND> visible; };
    EnumCtx ctx;
    EnumWindows([](HWND hwnd, LPARAM lparam) -> BOOL {
        auto* c = reinterpret_cast<EnumCtx*>(lparam);
        c->visible.insert(hwnd);
        return TRUE;
    }, (LPARAM)&ctx);

    std::vector<RTCoreMemRange> memRanges;
    if (!GetPhysicalMemoryRanges(memRanges)) return findings;

    std::vector<std::string> hookDetails;
    bool foundHiddenOverlays = false;
    int hiddenOverlayCount = 0;
    uint8_t chunk[0x100000];


    for (const auto& range : memRanges) {
        if (range.base > 0x40000000ULL) continue;
        uint64_t end = range.base + range.size;
        if (end > 0x40000000ULL) end = 0x40000000ULL;
        for (uint64_t pa = range.base; pa < end; pa += sizeof(chunk)) {
            DWORD readSize = (DWORD)((std::min<uint64_t>)(sizeof(chunk), end - pa));
            if (!ReadPhysicalMemory(pa, chunk, readSize)) continue;
            DWORD pages = readSize / 0x1000;

            for (DWORD pi = 0; pi < pages; ++pi) {
                uint8_t* page = chunk + (pi * 0x1000);



                for (size_t off = 0; off < 0x1000 - 5; ++off) {
                    if (page[off] == 0xE9) {
                        int32_t jmpOff = *reinterpret_cast<int32_t*>(page + off + 1);
                        uint64_t dest = (pa + (pi * 0x1000) + off + 5) + jmpOff;
                        if (dest < 0xFFFF800000000000ULL) {
                            char buf[128];
                            snprintf(buf, sizeof(buf), "E9 hook at phys=0x%llX -> 0x%llX",
                                     (unsigned long long)(pa + (pi * 0x1000) + off), (unsigned long long)dest);
                            hookDetails.push_back(buf);
                            break;
                        }
                    }

                    if (off + 14 <= 0x1000 &&
                        page[off] == 0x48 && page[off+1] == 0xB8 &&
                        page[off+12] == 0xFF && page[off+13] == 0xE0) {
                        uint64_t* target = reinterpret_cast<uint64_t*>(page + off + 2);
                        if (*target < 0xFFFF800000000000ULL) {
                            char buf[128];
                            snprintf(buf, sizeof(buf), "MOV RAX hook at phys=0x%llX -> 0x%llX",
                                     (unsigned long long)(pa + (pi * 0x1000) + off), (unsigned long long)*target);
                            hookDetails.push_back(buf);
                            break;
                        }
                    }

                    if (off + 6 <= 0x1000 && page[off] == 0x68 && page[off+5] == 0xC3) {
                        uint32_t target32 = *reinterpret_cast<uint32_t*>(page + off + 1);
                        if (target32 > 0x10000 && target32 < 0x7FFFFFFF) {
                            char buf[128];
                            snprintf(buf, sizeof(buf), "PUSH/RET hook at phys=0x%llX -> 0x%llX",
                                     (unsigned long long)(pa + (pi * 0x1000) + off), (unsigned long long)target32);
                            hookDetails.push_back(buf);
                            break;
                        }
                    }
                }




                if (!foundHiddenOverlays) {
                    for (size_t off = 0; off < 0x1000 - 16; off += 8) {
                        uint32_t exStyle = *reinterpret_cast<uint32_t*>(page + off);
                        if ((exStyle & 0x80028) == 0x80028 && (exStyle & 0xFF000000) == 0) {
                            uint64_t hwndVal = *reinterpret_cast<uint64_t*>(page + off + 8);
                            if (hwndVal >= 0xFFFF && hwndVal <= 0xFFFFFFFFFFFFULL) {
                                HWND hwnd = (HWND)(ULONG_PTR)hwndVal;
                                if (ctx.visible.find(hwnd) == ctx.visible.end() && IsWindow(hwnd)) {
                                    foundHiddenOverlays = true;
                                    hiddenOverlayCount++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (!hookDetails.empty()) {
        std::string detail;
        size_t maxReport = hookDetails.size() > 8 ? 8 : hookDetails.size();
        for (size_t i = 0; i < maxReport; ++i) {
            if (!detail.empty()) detail += "; ";
            detail += hookDetails[i];
        }
        ScannerUI::StreamModFinding f;
        f.type = "DWM_HOOK";
        f.process = "physical memory scan";
        f.target = "inline hook trampoline";
        f.detail = detail + (hookDetails.size() > 8 ? " (...)" : "");
        f.severity = hookDetails.size() > 2 ? "HIGH" : "MEDIUM";
        findings.push_back(f);
    }

    if (foundHiddenOverlays) {
        ScannerUI::StreamModFinding f;
        f.type = "OVERLAY";
        f.process = "desktop";
        f.target = "hidden layered overlay window";
        char buf[128];
        snprintf(buf, sizeof(buf), "%d hidden overlay window(s) detected in physical memory (bypassing EnumWindows)",
                 hiddenOverlayCount);
        f.detail = buf;
        f.severity = "HIGH";
        findings.push_back(f);
    }

    return findings;
}


std::vector<ScannerUI::EmulatorFinding> RTCoreDriver::ScanHdPlayerPhysicalMemory() {
    std::vector<ScannerUI::EmulatorFinding> findings;
    if (!IsLoaded()) return findings;

    DWORD hdPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring up = ToUpperInvariant(pe.szExeFile);
                if (up.find(L"HD-PLAYER") != std::wstring::npos ||
                    up.find(L"HD_PLAYER") != std::wstring::npos) {
                    hdPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (!hdPid) {
        ScannerUI::EmulatorFinding f;
        f.process = "HD-Player"; f.type = "NOT_FOUND";
        f.address = "-"; f.detail = "HD-Player process not running";
        f.severity = "FLAG";
        findings.push_back(f);
        return findings;
    }

    HANDLE hHd = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, hdPid);
    if (!hHd) return findings;

    const uint64_t kScanStart = 0xF;
    const uint64_t kScanEnd = 0xFFFAC;


    std::vector<std::pair<uint64_t, uint64_t>> committedRegions;
    uint8_t* addr = (uint8_t*)kScanStart;
    while ((uint64_t)addr < kScanEnd) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hHd, addr, &mbi, sizeof(mbi)) == 0) break;
        if ((uint64_t)mbi.BaseAddress >= kScanEnd) break;
        if (mbi.State == MEM_COMMIT)
            committedRegions.push_back({ (uint64_t)mbi.BaseAddress, mbi.RegionSize });
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }

    if (committedRegions.empty()) {
        CloseHandle(hHd);
        ScannerUI::EmulatorFinding f;
        f.process = "HD-Player [" + std::to_string(hdPid) + "]";
        f.type = "MEMORY"; f.address = "0xF-0xFFFAC";
        f.detail = "no committed memory regions found in target range (expected low range unused)";
        f.severity = "OK";
        findings.push_back(f);
        return findings;
    }


    size_t totalBytes = 0;
    size_t suspiciousCount = 0;
    for (const auto& region : committedRegions) {
        uint64_t start = region.first;
        uint64_t size = region.second;
        if (size > 0x100000) size = 0x100000;

        std::vector<uint8_t> buf((size_t)size);
        SIZE_T nRead = 0;
        if (!ReadProcessMemory(hHd, (LPCVOID)start, buf.data(), size, &nRead) || nRead == 0)
            continue;
        totalBytes += nRead;


        if (nRead >= 2 && buf[0] == 'M' && buf[1] == 'Z') {
            auto* dosH = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
            if (dosH->e_lfanew > 0 && dosH->e_lfanew < (int)nRead - 4) {
                auto* ntH = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dosH->e_lfanew);
                if ((uintptr_t)ntH + sizeof(DWORD) <= (uintptr_t)buf.data() + nRead &&
                    ntH->Signature == IMAGE_NT_SIGNATURE) {
                    char det[256];
                    snprintf(det, sizeof(det), "PE image mapped at 0x%llX - manual mapping / injected DLL",
                             (unsigned long long)start);
                    ScannerUI::EmulatorFinding f;
                    f.process = "HD-Player [" + std::to_string(hdPid) + "]";
                    f.type = "MEMORY INJECT";
                    char a[32]; snprintf(a, sizeof(a), "0x%llX", (unsigned long long)start);
                    f.address = a; f.detail = det; f.severity = "HIGH";
                    findings.push_back(f);
                    suspiciousCount++;
                }
            }
        }


        bool hasRdtsc = false, hasPebWalk = false;
        for (DWORD i = 0; i + 4 < nRead && !(hasRdtsc && hasPebWalk); ++i) {
            if (buf[i] == 0x0F && buf[i+1] == 0x31) hasRdtsc = true;
            if (i + 9 < nRead &&
                buf[i]==0x65 && buf[i+1]==0x48 && buf[i+2]==0x8B &&
                buf[i+3]==0x04 && buf[i+4]==0x25 && buf[i+5]==0x60 &&
                buf[i+6]==0x00 && buf[i+7]==0x00 && buf[i+8]==0x00)
                hasPebWalk = true;
        }
        if (hasRdtsc || hasPebWalk) {
            char det[256];
            snprintf(det, sizeof(det), "shellcode pattern at 0x%llX: %s",
                     (unsigned long long)start,
                     hasRdtsc ? (hasPebWalk ? "RDTSC + PEB walk" : "RDTSC") : "PEB walk");
            ScannerUI::EmulatorFinding f;
            f.process = "HD-Player [" + std::to_string(hdPid) + "]";
            f.type = "MEMORY INJECT";
            char a[32]; snprintf(a, sizeof(a), "0x%llX", (unsigned long long)start);
            f.address = a; f.detail = det; f.severity = "HIGH";
            findings.push_back(f);
            suspiciousCount++;
        }
    }


    {
        auto& snapshot = GetSystemHandleSnapshot();
        if (snapshot.ok) {
            auto* info = snapshot.Info();
            DWORD64 totalHandles = (DWORD64)info->NumberOfHandles;
            DWORD64 hdHandles = 0;
            DWORD64 hdInherited = 0;
            for (DWORD64 i = 0; i < totalHandles; ++i) {
                auto& h = info->Handles[i];
                if ((DWORD64)(ULONG_PTR)h.UniqueProcessId == (DWORD64)hdPid) {
                    hdHandles++;
                    if (h.HandleAttributes & HANDLE_FLAG_INHERIT)
                        hdInherited++;
                }
            }
            char det[256];
            if (hdHandles > 1000) {
                snprintf(det, sizeof(det),
                         "HD-Player has %llu handles (%llu inheritable) - potential handle abuse or leak",
                         (unsigned long long)hdHandles, (unsigned long long)hdInherited);
                ScannerUI::EmulatorFinding f;
                f.process = "HD-Player [" + std::to_string(hdPid) + "]";
                f.type = "HANDLE";
                f.address = "handle table";
                f.detail = det;
                f.severity = hdHandles > 2000 ? "HIGH" : "MEDIUM";
                findings.push_back(f);
            }
        }
    }

    char summary[256];
    snprintf(summary, sizeof(summary),
             "HD-Player memory scan [0xF-0xFFFAC]: %llu bytes committed, %llu suspicious regions",
             (unsigned long long)totalBytes, (unsigned long long)suspiciousCount);
    ScannerUI::EmulatorFinding f;
    f.process = "HD-Player [" + std::to_string(hdPid) + "]";
    f.type = "MEMORY"; f.address = "0xF-0xFFFAC";
    f.detail = summary;
    f.severity = suspiciousCount > 0 ? "HIGH" : "OK";
    findings.push_back(f);

    CloseHandle(hHd);
    return findings;
}
