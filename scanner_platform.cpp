#include "scanner_core.h"

std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), out.data(), len, nullptr, nullptr);
    return out;
}

bool HasExecutableExtension(const std::wstring& path) {
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return ext == L".exe" || ext == L".com" || ext == L".scr";
}

std::wstring ToUpperInvariant(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) { return (wchar_t)towupper(c); });
    return text;
}

static uint16_t ReadBe16(const BYTE* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t ReadBe32(const BYTE* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void WriteBe32(BYTE* p, uint32_t value) {
    p[0] = (BYTE)(value >> 24);
    p[1] = (BYTE)(value >> 16);
    p[2] = (BYTE)(value >> 8);
    p[3] = (BYTE)value;
}

static void AppendBe16(std::vector<BYTE>& out, uint16_t value) {
    out.push_back((BYTE)(value >> 8));
    out.push_back((BYTE)value);
}

static void AppendBe32(std::vector<BYTE>& out, uint32_t value) {
    out.push_back((BYTE)(value >> 24));
    out.push_back((BYTE)(value >> 16));
    out.push_back((BYTE)(value >> 8));
    out.push_back((BYTE)value);
}

static std::string BytesToHex(const BYTE* data, size_t size) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

static bool Sha256Hex(const BYTE* data, size_t size, std::string& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD cbData = 0;
    std::vector<BYTE> object;
    std::array<BYTE, 32> digest = {};

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;

    bool ok = false;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                          sizeof(objectSize), &cbData, 0) == 0) {
        object.resize(objectSize);
        if (BCryptCreateHash(alg, &hash, object.data(), objectSize, nullptr, 0, 0) == 0) {
            if (BCryptHashData(hash, const_cast<PUCHAR>(data), (ULONG)size, 0) == 0 &&
                BCryptFinishHash(hash, digest.data(), (ULONG)digest.size(), 0) == 0) {
                out = BytesToHex(digest.data(), digest.size());
                ok = true;
            }
        }
    }

    if (hash)
        BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

std::string TrimAscii(std::string text) {
    auto isSpace = [](unsigned char c) { return c == ' ' || c == '\r' || c == '\n' || c == '\t'; };
    while (!text.empty() && isSpace((unsigned char)text.front()))
        text.erase(text.begin());
    while (!text.empty() && isSpace((unsigned char)text.back()))
        text.pop_back();
    return text;
}

static bool IsSha256Hex(const std::string& text) {
    if (text.size() != 64)
        return false;
    return std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

static bool GetTpmEndorsementPublicKeyHashFromPowerShell(std::string& hashHex) {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
        return false;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    std::wstring command =
        L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        L"-Command \"$v=(Get-TpmEndorsementKeyInfo -HashAlgorithm SHA256).PublicKeyHash; "
        L"if($v){[Console]::Out.Write($v)}\"";

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    BOOL created = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);

    if (!created) {
        CloseHandle(readPipe);
        return false;
    }

    // Kill PowerShell after 5 s so the pipe closes and ReadFile unblocks.
    // DuplicateHandle gives the thread its own handle so it stays valid after
    // CloseHandle(pi.hProcess) below.
    HANDLE hKiller = nullptr;
    DuplicateHandle(GetCurrentProcess(), pi.hProcess, GetCurrentProcess(),
                    &hKiller, PROCESS_TERMINATE | SYNCHRONIZE, FALSE, 0);
    std::thread([hKiller]() {
        if (hKiller) {
            if (WaitForSingleObject(hKiller, 5000) == WAIT_TIMEOUT)
                TerminateProcess(hKiller, 1);
            CloseHandle(hKiller);
        }
    }).detach();

    std::string output;
    char buffer[256] = {};
    DWORD read = 0;
    while (ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) && read > 0)
        output.append(buffer, buffer + read);

    WaitForSingleObject(pi.hProcess, 500);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);

    output = TrimAscii(output);
    std::transform(output.begin(), output.end(), output.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });

    if (exitCode != 0 || !IsSha256Hex(output))
        return false;

    hashHex = output;
    return true;
}

static bool ReadTpm2PublicArea(TBS_HCONTEXT context, uint32_t handle, std::vector<BYTE>& publicArea) {
    BYTE command[14] = {
        0x80, 0x01,
        0x00, 0x00, 0x00, 0x0E,
        0x00, 0x00, 0x01, 0x73,
        0x00, 0x00, 0x00, 0x00
    };
    WriteBe32(command + 10, handle);

    std::vector<BYTE> response(4096);
    UINT32 responseSize = (UINT32)response.size();
    TBS_RESULT result = Tbsip_Submit_Command(context,
                                             TBS_COMMAND_LOCALITY_ZERO,
                                             TBS_COMMAND_PRIORITY_NORMAL,
                                             command,
                                             (UINT32)sizeof(command),
                                             response.data(),
                                             &responseSize);
    if (result != TBS_SUCCESS || responseSize < 12)
        return false;

    const uint32_t responseCode = ReadBe32(response.data() + 6);
    if (responseCode != 0)
        return false;

    const uint16_t publicSize = ReadBe16(response.data() + 10);
    if (publicSize == 0 || 12u + publicSize > responseSize)
        return false;

    publicArea.assign(response.begin() + 12, response.begin() + 12 + publicSize);
    return true;
}

static bool GetTpmPlatformProviderPublicHash(std::string& hashHex) {
    NCRYPT_PROV_HANDLE provider = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
        return false;

    const wchar_t* properties[] = {
        NCRYPT_PCP_EKPUB_PROPERTY,
        NCRYPT_PCP_RSA_EKPUB_PROPERTY,
        NCRYPT_PCP_ECC_EKPUB_PROPERTY,
        NCRYPT_PCP_SRKPUB_PROPERTY
    };

    bool ok = false;
    for (const wchar_t* property : properties) {
        DWORD size = 0;
        status = NCryptGetProperty(provider, property, nullptr, 0, &size, 0);
        if (status != ERROR_SUCCESS || size == 0)
            continue;

        std::vector<BYTE> blob(size);
        status = NCryptGetProperty(provider, property, blob.data(), (DWORD)blob.size(), &size, 0);
        if (status == ERROR_SUCCESS && size > 0 && Sha256Hex(blob.data(), size, hashHex)) {
            ok = true;
            break;
        }
    }

    NCryptFreeObject(provider);
    return ok;
}

static std::vector<BYTE> BuildTpm2RsaStoragePublicTemplate() {
    std::vector<BYTE> publicBody;
    AppendBe16(publicBody, 0x0001);
    AppendBe16(publicBody, 0x000B);
    AppendBe32(publicBody, 0x00030472);
    AppendBe16(publicBody, 0);
    AppendBe16(publicBody, 0x0006);
    AppendBe16(publicBody, 128);
    AppendBe16(publicBody, 0x0043);
    AppendBe16(publicBody, 0x0010);
    AppendBe16(publicBody, 2048);
    AppendBe32(publicBody, 0);
    AppendBe16(publicBody, 0);

    std::vector<BYTE> publicTemplate;
    AppendBe16(publicTemplate, (uint16_t)publicBody.size());
    publicTemplate.insert(publicTemplate.end(), publicBody.begin(), publicBody.end());
    return publicTemplate;
}

static bool CreateTpm2PrimaryPublicArea(TBS_HCONTEXT context, uint32_t hierarchy,
                                        const std::vector<BYTE>& publicTemplate,
                                        std::vector<BYTE>& publicArea) {
    std::vector<BYTE> command;
    AppendBe16(command, 0x8002);
    AppendBe32(command, 0);
    AppendBe32(command, 0x00000131);
    AppendBe32(command, hierarchy);

    AppendBe32(command, 9);
    AppendBe32(command, 0x40000009);
    AppendBe16(command, 0);
    command.push_back(0);
    AppendBe16(command, 0);

    AppendBe16(command, 4);
    AppendBe16(command, 0);
    AppendBe16(command, 0);
    command.insert(command.end(), publicTemplate.begin(), publicTemplate.end());
    AppendBe16(command, 0);
    AppendBe32(command, 0);

    WriteBe32(command.data() + 2, (uint32_t)command.size());

    std::vector<BYTE> response(4096);
    UINT32 responseSize = (UINT32)response.size();
    TBS_RESULT result = Tbsip_Submit_Command(context,
                                             TBS_COMMAND_LOCALITY_ZERO,
                                             TBS_COMMAND_PRIORITY_NORMAL,
                                             command.data(),
                                             (UINT32)command.size(),
                                             response.data(),
                                             &responseSize);
    if (result != TBS_SUCCESS || responseSize < 20)
        return false;

    if (ReadBe32(response.data() + 6) != 0)
        return false;

    const uint32_t parameterSize = ReadBe32(response.data() + 14);
    const size_t outPublicOffset = 18;
    if (parameterSize < 2 || outPublicOffset + 2 > responseSize)
        return false;

    const uint16_t publicSize = ReadBe16(response.data() + outPublicOffset);
    if (publicSize == 0 || publicSize + 2u > parameterSize || outPublicOffset + 2u + publicSize > responseSize)
        return false;

    publicArea.assign(response.begin() + outPublicOffset + 2,
                      response.begin() + outPublicOffset + 2 + publicSize);
    return true;
}

bool GetTpm2PublicHash(std::string& hashHex, std::string& warning) {
    if (GetTpmEndorsementPublicKeyHashFromPowerShell(hashHex)) {
        warning.clear();
        return true;
    }

    if (GetTpmPlatformProviderPublicHash(hashHex)) {
        warning.clear();
        return true;
    }

    TBS_CONTEXT_PARAMS2 params = {};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.requestRaw = 1;
    params.includeTpm20 = 1;

    TBS_HCONTEXT context = nullptr;
    TBS_RESULT result = Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&params), &context);
    if (result != TBS_SUCCESS) {
        warning = "TPM 2.0 public hash unavailable: could not open TPM Base Services";
        return false;
    }

    const uint32_t handles[] = {
        0x81010001,
        0x81010002,
        0x81000001,
        0x81000000
    };

    bool ok = false;
    std::vector<BYTE> publicArea;
    for (uint32_t handle : handles) {
        if (ReadTpm2PublicArea(context, handle, publicArea) &&
            Sha256Hex(publicArea.data(), publicArea.size(), hashHex)) {
            ok = true;
            break;
        }
    }

    if (!ok) {
        const std::vector<BYTE> srkTemplate = BuildTpm2RsaStoragePublicTemplate();
        if (CreateTpm2PrimaryPublicArea(context, 0x40000001, srkTemplate, publicArea) &&
            Sha256Hex(publicArea.data(), publicArea.size(), hashHex)) {
            ok = true;
        }
    }

    Tbsip_Context_Close(context);

    if (!ok)
        warning = "TPM 2.0 public hash unavailable: TPM public area command failed";
    else
        warning.clear();
    return ok;
}

bool IsExecutablePrefetchFile(const std::wstring& text) {
    if (text.size() < 3)
        return false;
    std::wstring upper = ToUpperInvariant(text);
    if (upper.substr(upper.size() - 3) != L".PF")
        return false;

    return upper.find(L".EXE-") != std::wstring::npos || upper.find(L".EXE.PF") != std::wstring::npos;
}

bool FileExistsW(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

ULONGLONG FileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER value = {};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

FILETIME GetBootFileTime() {
    FILETIME nowFt = {};
    GetSystemTimeAsFileTime(&nowFt);
    ULONGLONG now = FileTimeToU64(nowFt);
    ULONGLONG uptime100ns = GetTickCount64() * 10000ULL;
    ULONGLONG boot = now > uptime100ns ? now - uptime100ns : now;
    FILETIME out = {};
    out.dwLowDateTime = (DWORD)boot;
    out.dwHighDateTime = (DWORD)(boot >> 32);
    return out;
}

void FileTimeToLocalStrings(const FILETIME& ft, std::string& date, std::string& time) {
    FILETIME localFt = {};
    SYSTEMTIME st = {};
    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);
    char dateBuf[32] = {};
    char timeBuf[32] = {};
    sprintf_s(dateBuf, "%02u/%02u/%04u", st.wDay, st.wMonth, st.wYear);
    sprintf_s(timeBuf, "%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
    date = dateBuf;
    time = timeBuf;
}

static std::wstring TrimWide(std::wstring text) {
    auto isSpace = [](wchar_t c) {
        return c == L' ' || c == L'\r' || c == L'\n' || c == L'\t';
    };
    while (!text.empty() && isSpace(text.front()))
        text.erase(text.begin());
    while (!text.empty() && isSpace(text.back()))
        text.pop_back();
    return text;
}

static std::wstring ReadRegString(HKEY root, const wchar_t* subkey, const wchar_t* valueName) {
    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = RegGetValueW(root, subkey, valueName,
                               RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                               &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || bytes < sizeof(wchar_t))
        return L"";

    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    status = RegGetValueW(root, subkey, valueName,
                          RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                          &type, value.data(), &bytes);
    if (status != ERROR_SUCCESS)
        return L"";

    while (!value.empty() && value.back() == L'\0')
        value.pop_back();

    if (type == REG_EXPAND_SZ) {
        DWORD needed = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
        if (needed > 1) {
            std::wstring expanded(needed, L'\0');
            if (ExpandEnvironmentStringsW(value.c_str(), expanded.data(), needed) > 0) {
                while (!expanded.empty() && expanded.back() == L'\0')
                    expanded.pop_back();
                value = expanded;
            }
        }
    }

    return TrimWide(value);
}

static std::vector<std::wstring> ReadRegMultiString(HKEY root, const wchar_t* subkey, const wchar_t* valueName) {
    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = RegGetValueW(root, subkey, valueName, RRF_RT_REG_MULTI_SZ, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || bytes < sizeof(wchar_t) * 2)
        return {};

    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 2, L'\0');
    status = RegGetValueW(root, subkey, valueName, RRF_RT_REG_MULTI_SZ, &type, buffer.data(), &bytes);
    if (status != ERROR_SUCCESS)
        return {};

    std::vector<std::wstring> values;
    const wchar_t* p = buffer.data();
    while (*p) {
        std::wstring item = TrimWide(p);
        if (!item.empty())
            values.push_back(item);
        p += wcslen(p) + 1;
    }
    return values;
}

static bool ReadRegDword(HKEY root, const wchar_t* subkey, const wchar_t* valueName, DWORD& out) {
    DWORD type = 0;
    DWORD bytes = sizeof(out);
    LONG status = RegGetValueW(root, subkey, valueName, RRF_RT_REG_DWORD, &type, &out, &bytes);
    return status == ERROR_SUCCESS;
}

static std::wstring NormalizeBiosDate(std::wstring value) {
    value = TrimWide(value);
    wchar_t sep = value.find(L'/') != std::wstring::npos ? L'/' : L'-';
    size_t a = value.find(sep);
    size_t b = a == std::wstring::npos ? std::wstring::npos : value.find(sep, a + 1);
    if (a == std::wstring::npos || b == std::wstring::npos)
        return value;

    int first = _wtoi(value.substr(0, a).c_str());
    int second = _wtoi(value.substr(a + 1, b - a - 1).c_str());
    std::wstring year = value.substr(b + 1);
    if (first <= 0 || second <= 0 || year.size() < 4)
        return value;

    if (first <= 12 && second > 12) {
        wchar_t out[32] = {};
        swprintf_s(out, L"%02d/%02d/%s", second, first, year.c_str());
        return out;
    }
    return value;
}

static std::string CollectBiosVersionDate() {
    const wchar_t* key = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    std::wstring version = ReadRegString(HKEY_LOCAL_MACHINE, key, L"BIOSVersion");
    if (version.empty()) {
        auto values = ReadRegMultiString(HKEY_LOCAL_MACHINE, key, L"SystemBiosVersion");
        if (!values.empty())
            version = values.front();
    }

    std::wstring date = NormalizeBiosDate(ReadRegString(HKEY_LOCAL_MACHINE, key, L"BIOSReleaseDate"));
    if (!version.empty() && !date.empty())
        return WideToUtf8(version + L", " + date);
    if (!version.empty())
        return WideToUtf8(version);
    if (!date.empty())
        return WideToUtf8(date);
    return "-";
}

static std::string CollectBiosMode() {
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    using GetFirmwareTypeFn = BOOL (WINAPI*)(PFIRMWARE_TYPE);
    auto getFirmwareType = kernel ? reinterpret_cast<GetFirmwareTypeFn>(
        GetProcAddress(kernel, "GetFirmwareType")) : nullptr;

    if (getFirmwareType) {
        FIRMWARE_TYPE type = FirmwareTypeUnknown;
        if (getFirmwareType(&type)) {
            if (type == FirmwareTypeUefi)
                return "UEFI";
            if (type == FirmwareTypeBios)
                return "Legacy";
            if (type == FirmwareTypeMax)
                return "Unknown";
        }
    }

    BYTE dummy = 0;
    GetFirmwareEnvironmentVariableW(L"", L"{00000000-0000-0000-0000-000000000000}", &dummy, 0);
    return GetLastError() == ERROR_INVALID_FUNCTION ? "Legacy" : "UEFI";
}

static std::string CollectDeviceName() {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = (DWORD)std::size(name);
    if (GetComputerNameW(name, &size) && size > 0)
        return WideToUtf8(name);
    return "-";
}

static std::string CollectSystemType() {
    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
    case PROCESSOR_ARCHITECTURE_ARM:   return "ARM";
    default:                           return "Unknown";
    }
}

static std::string CollectPageFiles() {
    const wchar_t* key = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
    auto entries = ReadRegMultiString(HKEY_LOCAL_MACHINE, key, L"PagingFiles");
    std::vector<std::wstring> paths;
    for (std::wstring entry : entries) {
        if (entry.rfind(L"\\??\\", 0) == 0)
            entry = entry.substr(4);
        size_t space = entry.find(L' ');
        std::wstring path = TrimWide(space == std::wstring::npos ? entry : entry.substr(0, space));
        if (!path.empty())
            paths.push_back(path);
    }

    if (paths.empty()) {
        std::wstring root = GetWindowsDriveRoot();
        if (!root.empty())
            paths.push_back(JoinPathW(root, L"pagefile.sys"));
    }

    if (paths.empty())
        return "-";

    std::wstring joined;
    for (size_t i = 0; i < paths.size(); ++i) {
        if (i > 0)
            joined += L", ";
        joined += paths[i];
    }
    return WideToUtf8(joined);
}

static std::string CollectExplorerStartTime() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return "-";

    FILETIME best = {};
    bool found = false;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, L"explorer.exe") != 0)
                continue;

            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!process)
                continue;

            FILETIME created = {}, exitTime = {}, kernel = {}, user = {};
            if (GetProcessTimes(process, &created, &exitTime, &kernel, &user)) {
                if (!found || CompareFileTime(&created, &best) < 0) {
                    best = created;
                    found = true;
                }
            }
            CloseHandle(process);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (!found)
        return "-";

    std::string date, time;
    FileTimeToLocalStrings(best, date, time);
    return date + " " + time;
}

static std::string CollectOsVersion() {
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::wstring product = ReadRegString(HKEY_LOCAL_MACHINE, key, L"ProductName");
    std::wstring display = ReadRegString(HKEY_LOCAL_MACHINE, key, L"DisplayVersion");
    if (display.empty())
        display = ReadRegString(HKEY_LOCAL_MACHINE, key, L"ReleaseId");

    OSVERSIONINFOW os = {};
    os.dwOSVersionInfoSize = sizeof(os);
    using RtlGetVersionFn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto rtlGetVersion = ntdll ? reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion")) : nullptr;
    if (rtlGetVersion)
        rtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&os));

    if (product.empty())
        product = L"Windows";
    if (os.dwBuildNumber >= 22000) {
        size_t pos = product.find(L"Windows 10");
        if (pos != std::wstring::npos)
            product.replace(pos, 10, L"Windows 11");
    }

    if (!display.empty() && product.find(display) == std::wstring::npos)
        product += L" " + display;

    DWORD ubr = 0;
    std::wstring build = ReadRegString(HKEY_LOCAL_MACHINE, key, L"CurrentBuildNumber");
    if (build.empty())
        build = ReadRegString(HKEY_LOCAL_MACHINE, key, L"CurrentBuild");

    DWORD buildNumber = os.dwBuildNumber;
    if (buildNumber == 0 && !build.empty())
        buildNumber = (DWORD)_wtoi(build.c_str());

    std::wstringstream version;
    if (os.dwMajorVersion != 0 || buildNumber != 0) {
        version << L" (" << os.dwMajorVersion << L"." << os.dwMinorVersion << L"." << buildNumber;
        if (ReadRegDword(HKEY_LOCAL_MACHINE, key, L"UBR", ubr))
            version << L"." << ubr;
        version << L")";
    }

    return WideToUtf8(product + version.str());
}

void CollectSystemOverview(ScannerUI::ScanData& data) {
    std::string bootDate, bootTime;
    FileTimeToLocalStrings(GetBootFileTime(), bootDate, bootTime);

    data.boot = bootDate + " " + bootTime;
    data.explorer = CollectExplorerStartTime();
    data.biosVersion = CollectBiosVersionDate();
    data.biosMode = CollectBiosMode();
    data.osVersion = CollectOsVersion();
    data.device = CollectDeviceName();
    data.pagefile = CollectPageFiles();
    data.sysType = CollectSystemType();
}

std::wstring DevicePathToDosPath(const std::wstring& path) {
    if (path.rfind(L"\\Device\\", 0) != 0)
        return path;

    DWORD drives = GetLogicalDrives();
    wchar_t target[1024] = {};
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        if ((drives & (1 << (letter - L'A'))) == 0)
            continue;

        wchar_t driveName[] = { letter, L':', L'\0' };
        DWORD len = QueryDosDeviceW(driveName, target, (DWORD)std::size(target));
        if (len == 0)
            continue;

        std::wstring device = target;
        if (path.rfind(device, 0) == 0) {
            return std::wstring(1, letter) + L":" + path.substr(device.size());
        }
    }
    return path;
}




bool IsAuthenticodeSigned(const std::wstring& path) {
    return DetectionFilter::IsTrustedSignedCached(path);
}

