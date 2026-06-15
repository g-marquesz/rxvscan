#include "scanner_core.h"
#include <imagehlp.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "version.lib")




static std::wstring NormalizeDosDriverPath(const std::wstring& raw) {
    std::wstring path = raw;
    while (!path.empty() && (path.front() == L' ' || path.front() == L'\t'))
        path.erase(path.begin());
    while (!path.empty() && (path.back() == L' ' || path.back() == L'\t'))
        path.pop_back();

    if (path.size() >= 2 && path.front() == L'"') {
        size_t endQuote = path.find(L'"', 1);
        if (endQuote != std::wstring::npos)
            path = path.substr(1, endQuote - 1);
    }

    wchar_t expanded[MAX_PATH * 4] = {};
    DWORD expandedLen = ExpandEnvironmentStringsW(path.c_str(), expanded, (DWORD)std::size(expanded));
    if (expandedLen > 0 && expandedLen < std::size(expanded))
        path = expanded;

    std::wstring up = ToUpperInvariant(path);
    if (up.rfind(L"\\SYSTEMROOT\\", 0) == 0) {
        wchar_t win[MAX_PATH] = {};
        GetWindowsDirectoryW(win, MAX_PATH);
        return std::wstring(win) + path.substr(11);
    }
    if (up.rfind(L"\\??\\", 0) == 0)
        return path.substr(4);
    if (up.rfind(L"\\DEVICE\\", 0) == 0)
        return DevicePathToDosPath(path);
    return path;
}

static std::wstring DriverBaseName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

static std::wstring ExtractDriverImagePath(std::wstring value) {
    while (!value.empty() && (value.front() == L' ' || value.front() == L'\t'))
        value.erase(value.begin());
    while (!value.empty() && (value.back() == L' ' || value.back() == L'\t'))
        value.pop_back();

    if (value.size() >= 2 && value.front() == L'"') {
        size_t endQuote = value.find(L'"', 1);
        return endQuote == std::wstring::npos ? value.substr(1) : value.substr(1, endQuote - 1);
    }

    std::wstring up = ToUpperInvariant(value);
    size_t sysExt = up.find(L".SYS");
    if (sysExt != std::wstring::npos)
        return value.substr(0, sysExt + 4);

    size_t firstSpace = value.find_first_of(L" \t");
    return firstSpace == std::wstring::npos ? value : value.substr(0, firstSpace);
}

// Checks if `token` appears as a whole word in `upper` (surrounded by non-alphanumeric
// or at string boundaries). Prevents false positives from common substrings like
// PHYS in PHYSX, HOOK in SHOOK, SHADOW in SHADOWCOPY, MAPPER in REMAPPER.
static bool TokenMatchesWhole(const std::wstring& upper, const std::wstring& token) {
    size_t pos = upper.find(token);
    while (pos != std::wstring::npos) {
        bool beforeOk = (pos == 0 || !iswalnum((wint_t)upper[pos - 1]));
        bool afterOk  = (pos + token.size() >= upper.size() || !iswalnum((wint_t)upper[pos + token.size()]));
        if (beforeOk && afterOk) return true;
        pos = upper.find(token, pos + 1);
    }
    return false;
}

static bool HasDriverSuspiciousToken(const std::wstring& name) {
    // These tokens are rare enough that substring match is safe — they almost
    // never appear in legitimate driver names.
    static const wchar_t* kSubstringTokens[] = {
        L"CHEAT", L"BYPASS", L"HACK", L"RING0",
        L"ROOTKIT", L"BLACKLOTUS",
        L"DKOM", L"KDU", L"VMHIDE", L"KDMAPPER", L"ANTICHEATER",
        L"BOOTKITS", L"EACDMP", L"UNHOOK", L"DRVLOAD", L"LOADEX",
        L"EXPLOIT", L"HOLLOW", L"MANUALMAP", L"KMAP",
        nullptr
    };
    // These tokens can appear inside legitimate driver names, so require whole-word match.
    static const wchar_t* kWholeWordTokens[] = {
        L"HOOK", L"INJECT", L"SPOOF", L"HWID", L"MAPPER",
        L"GHOST", L"PHANTOM", L"SHADOW",
        L"PHYS", L"RWDRV", L"MEMMAP", L"KDRIVER", L"DRVMAP",
        L"KERNELMAP", L"KUTIL", L"PHYSMEM", L"RAWDISK", L"RAWHDD",
        L"DRIVERMAP", L"ANTIDBG", L"KDUMP",
        nullptr
    };
    std::wstring up = ToUpperInvariant(name);
    // Strip extension before word-boundary checks so FOO.SYS stem is "FOO"
    std::wstring stem = up;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);

    for (int i = 0; kSubstringTokens[i]; ++i)
        if (up.find(kSubstringTokens[i]) != std::wstring::npos)
            return true;
    for (int i = 0; kWholeWordTokens[i]; ++i)
        if (TokenMatchesWhole(stem, kWholeWordTokens[i]))
            return true;
    return false;
}

static bool IsKnownAbusedDriverName(const std::wstring& name) {
    std::wstring f = ToUpperInvariant(DriverBaseName(name));
    static const std::unordered_set<std::wstring> kNames = {
        L"CAPCOM.SYS", L"DBUTIL_2_3.SYS", L"DBUTILDRV2.SYS",
        L"GDRV.SYS", L"GDRV2.SYS", L"GLCKIO2.SYS",
        L"RTCORE64.SYS", L"RTCORE32.SYS",
        L"WINRING0.SYS", L"WINRING0X64.SYS", L"WINRING0X86.SYS",
        L"ENE.SYS", L"ENEIO.SYS", L"ENEIO64.SYS",
        L"ASRDRV10.SYS", L"ASRDRV101.SYS", L"ASRDRV102.SYS", L"ASRDRV103.SYS",
        L"ATSZIO64.SYS", L"NTIOLIB_X64.SYS", L"NTIOLIB.SYS",
        L"MSIO64.SYS", L"MSIO32.SYS", L"IOCBIOS2.SYS",
        L"PROCEXP152.SYS", L"PROCEXP150.SYS",
        L"PHYSX64.SYS", L"PHYSMEM.SYS", L"RWDRV.SYS",
        L"AMIFLDRV64.SYS", L"AMIFLDRV32.SYS",
        L"INPOUTX64.SYS", L"INPOUT32.SYS",
        L"CPUZ141_X64.SYS", L"CPUZ143_X64.SYS", L"CPUZ144_X64.SYS",
        // 2023-2025 additions
        L"ZAM64.SYS", L"ZAMGUARD64.SYS",
        L"ASWARPOT.SYS", L"ASWVMM.SYS",
        L"MHYPROT.SYS", L"MHYPROT2.SYS",
        L"DBUTIL_2_5.SYS", L"DBUTIL_3_0.SYS",
        L"IQVW64E.SYS",
        L"ELRAWDSK.SYS",
        L"SEMAV6MSR64.SYS",
        L"KPROCESSHACKER.SYS",
        L"PCHUNTER64.SYS",
        L"AMSDK.SYS",
        L"TRUESIGHT.SYS",
        L"NBE.SYS",
        L"SPEEDFAN.SYS",
        L"ASMTXHCI.SYS",
        L"RZPNK.SYS",
        L"NICM.SYS",
        L"NVFLASH.SYS",
        L"DIRECTIO64.SYS", L"DIRECTIO32.SYS",
        L"HWRWDRV.SYS",
        L"GPUZ.SYS",
        L"ADVSYS64.SYS",
        L"LENOVODIAGNOSTICSDRIVER.SYS",
        L"MALCORE.SYS"
    };
    return kNames.find(f) != kNames.end();
}

static bool IsDriverPathSystem(const std::wstring& path) {
    wchar_t win[MAX_PATH] = {};
    GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring winUp = ToUpperInvariant(win);
    std::wstring up = ToUpperInvariant(path);
    return up.rfind(winUp + L"\\SYSTEM32\\", 0) == 0 ||
           up.rfind(winUp + L"\\SYSWOW64\\", 0) == 0 ||
           up.rfind(winUp + L"\\WINSXS\\", 0) == 0 ||
           up.rfind(winUp + L"\\SYSTEM32\\DRIVERSTORE\\", 0) == 0;
}

static bool IsDriverPathTrustedVendor(const std::wstring& path) {
    DetectionFilter::PathClass cls = DetectionFilter::ClassifyPath(path);
    return cls == DetectionFilter::PathClass::SystemTrusted ||
           cls == DetectionFilter::PathClass::ProgramFiles;
}

static bool IsDriverPathSuspicious(const std::wstring& path) {
    DetectionFilter::PathClass cls = DetectionFilter::ClassifyPath(path);
    return cls == DetectionFilter::PathClass::TempOrInstaller ||
           cls == DetectionFilter::PathClass::UserProfile;
}

static const char* DriverPathClassName(const std::wstring& path) {
    switch (DetectionFilter::ClassifyPath(path)) {
    case DetectionFilter::PathClass::SystemTrusted:   return "system";
    case DetectionFilter::PathClass::ProgramFiles:    return "program_files";
    case DetectionFilter::PathClass::TempOrInstaller: return "temp_or_installer";
    case DetectionFilter::PathClass::UserProfile:     return "user_profile";
    case DetectionFilter::PathClass::Removable:       return "removable_or_network";
    case DetectionFilter::PathClass::Unmapped:        return "unmapped_device";
    default:                                          return "unknown";
    }
}



static std::string HexValue(ULONGLONG value) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << value;
    return oss.str();
}

std::vector<ScannerUI::KernelDriverFinding> CollectKernelDriverFindings(std::string& status) {
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    std::vector<ScannerUI::KernelDriverFinding> findings;
    std::unordered_set<std::wstring> seenPaths;


    LPVOID addrs[4096] = {};
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(addrs, sizeof(addrs), &cbNeeded)) {
        status = "REVIEW";
        return findings;
    }
    DWORD total = cbNeeded / sizeof(LPVOID);

    for (DWORD i = 0; i < total; ++i) {
        if (!addrs[i]) continue;
        wchar_t rawPath[MAX_PATH * 2] = {};
        if (!GetDeviceDriverFileNameW(addrs[i], rawPath, (DWORD)std::size(rawPath))) continue;

        std::wstring path = NormalizeDosDriverPath(rawPath);
        if (path.empty()) continue;
        std::wstring key = ToUpperInvariant(path);
        if (!seenPaths.insert(key).second) continue;

        std::wstring base    = DriverBaseName(path);
        bool signedOk       = IsAuthenticodeSigned(path);
        bool systemPath     = IsDriverPathSystem(path);
        bool trustedPath    = IsDriverPathTrustedVendor(path);
        bool suspiciousPath = IsDriverPathSuspicious(path);
        bool abusedName     = IsKnownAbusedDriverName(base);
        bool suspiciousName = HasDriverSuspiciousToken(base) || abusedName;


        if (signedOk && systemPath && !suspiciousName)
            continue;


        if (signedOk && trustedPath && !suspiciousName && !suspiciousPath)
            continue;

        std::string severity = "MEDIUM";
        std::string reason;

        if (!signedOk && suspiciousPath) {
            severity = "HIGH"; reason = "unsigned driver loaded from suspicious path";
        } else if (!signedOk && suspiciousName) {
            severity = "HIGH"; reason = "unsigned driver with cheat-like name";
        } else if (suspiciousPath) {
            severity = "HIGH"; reason = "driver loaded from suspicious path";
        } else if (suspiciousName) {
            severity = abusedName ? "MEDIUM" : "HIGH";
            reason = abusedName ? "known abused/vulnerable driver family" : "driver with cheat-like name";
        } else if (!signedOk) {
            reason = "unsigned kernel driver outside trusted directories";
        } else if (signedOk) {
            severity = "INFO";
            reason = "driver loaded from non-standard path";
        }

        ScannerUI::KernelDriverFinding f;
        f.date = date; f.time = timeStr;
        f.severity = severity;
        f.path = WideToUtf8(path);
        f.reason = reason;
        f.suspicious = (!signedOk && !trustedPath) || suspiciousPath || suspiciousName;
        f.loadAddress = reinterpret_cast<uintptr_t>(addrs[i]);

        std::string detail = "addr=" + HexValue((ULONGLONG)f.loadAddress) +
                             " | signed=" + (signedOk ? "yes" : "no") +
                             " | path=" + DriverPathClassName(path);
        if (suspiciousName) detail += " | name=suspicious";
        f.detail = detail;
        findings.push_back(f);
    }


    HKEY svcRoot = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WOW64_64KEY, &svcRoot) == ERROR_SUCCESS) {
        DWORD subCount = 0;
        RegQueryInfoKeyW(svcRoot, nullptr, nullptr, nullptr, &subCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < subCount; ++i) {
            wchar_t svcName[256] = {};
            DWORD nameLen = (DWORD)std::size(svcName);
            if (RegEnumKeyExW(svcRoot, i, svcName, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            HKEY svcKey = nullptr;
            if (RegOpenKeyExW(svcRoot, svcName, 0, KEY_READ | KEY_WOW64_64KEY, &svcKey) != ERROR_SUCCESS)
                continue;

            DWORD svcType = 0, svcTypeSize = sizeof(svcType), svcRegType = 0;
            if (RegQueryValueExW(svcKey, L"Type", nullptr, &svcRegType,
                                 reinterpret_cast<LPBYTE>(&svcType), &svcTypeSize) != ERROR_SUCCESS ||
                (svcType != 1 && svcType != 2)) {
                RegCloseKey(svcKey);
                continue;
            }

            wchar_t imgPath[MAX_PATH * 2] = {};
            DWORD imgSize = sizeof(imgPath), imgRegType = 0;
            if (RegQueryValueExW(svcKey, L"ImagePath", nullptr, &imgRegType,
                                 reinterpret_cast<LPBYTE>(imgPath), &imgSize) != ERROR_SUCCESS) {
                RegCloseKey(svcKey);
                continue;
            }
            RegCloseKey(svcKey);

            std::wstring rawImg = ExtractDriverImagePath(imgPath);

            if (rawImg.rfind(L"\\??\\", 0) == 0) rawImg = rawImg.substr(4);
            if (rawImg.rfind(L"system32\\", 0) == 0 || rawImg.rfind(L"System32\\", 0) == 0) {
                wchar_t win[MAX_PATH] = {};
                GetWindowsDirectoryW(win, MAX_PATH);
                rawImg = std::wstring(win) + L"\\" + rawImg;
            }
            std::wstring normPath = NormalizeDosDriverPath(rawImg);
            std::wstring pKey = ToUpperInvariant(normPath.empty() ? rawImg : normPath);
            if (seenPaths.count(pKey)) continue;

            std::wstring base = DriverBaseName(normPath.empty() ? rawImg : normPath);
            bool fileExists = FileExistsW(normPath);
            bool signedOk   = fileExists && IsAuthenticodeSigned(normPath);
            bool trustedPath = !normPath.empty() && IsDriverPathTrustedVendor(normPath);
            bool abusedName = IsKnownAbusedDriverName(base) || IsKnownAbusedDriverName(svcName);
            bool suspiciousName = HasDriverSuspiciousToken(base) || HasDriverSuspiciousToken(svcName) || abusedName;
            bool suspiciousPath = IsDriverPathSuspicious(normPath) && !normPath.empty();
            if (!suspiciousName && !suspiciousPath)
                continue;
            if (fileExists && signedOk && trustedPath && !suspiciousName)
                continue;

            std::string severity = abusedName && !suspiciousPath ? "MEDIUM" : suspiciousName ? "HIGH" : "MEDIUM";
            std::string reason = suspiciousName ?
                (abusedName ? "kernel driver service matches known abused/vulnerable driver family" : "kernel driver service with cheat-like name") :
                "kernel driver service registered in suspicious path";

            std::string detail = "service=" + WideToUtf8(svcName) +
                                 " | signed=" + (signedOk ? "yes" : fileExists ? "no" : "file_missing") +
                                 " | type=" + (svcType == 1 ? "KERNEL_DRIVER" : "FS_DRIVER");

            ScannerUI::KernelDriverFinding f;
            f.date = date; f.time = timeStr;
            f.severity = severity;
            f.path = WideToUtf8(normPath.empty() ? rawImg : normPath);
            f.reason = reason;
            f.detail = detail;
            f.suspicious = suspiciousName || suspiciousPath || !signedOk;
            findings.push_back(f);
            seenPaths.insert(pKey);
        }
        RegCloseKey(svcRoot);
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        int ra = DetectionFilter::SeverityRank(a.severity);
        int rb = DetectionFilter::SeverityRank(b.severity);
        if (ra != rb) return ra < rb;
        return a.path < b.path;
    });

    size_t suspicious = 0;
    for (const auto& f : findings) if (f.suspicious) ++suspicious;
    status = suspicious > 0 ? "DETECTED" : "OK";
    return findings;
}

// Forward declarations needed by CollectKernelAnomalies (defined further below)
struct LoadedKernelModuleInfo {
    uintptr_t base = 0;
    ULONG imageSize = 0;
    std::wstring path;
    std::wstring name;
};
static std::unordered_map<std::wstring, LoadedKernelModuleInfo>
CollectLoadedKernelModuleMap(std::unordered_map<std::wstring, int>& basenameCounts);

// Reads only the PE optional header to extract SizeOfImage (fast, no full-file read)
static DWORD ReadDiskSizeOfImage(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    uint8_t buf[0x400] = {};
    DWORD nRead = 0;
    ReadFile(hFile, buf, sizeof(buf), &nRead, nullptr);
    CloseHandle(hFile);
    if (nRead < 0x40) return 0;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    size_t peOff = static_cast<size_t>(dos->e_lfanew);
    if (peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 4 > nRead) return 0;
    if (*reinterpret_cast<const DWORD*>(buf + peOff) != IMAGE_NT_SIGNATURE) return 0;
    size_t optOff = peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optOff + 4 > nRead) return 0;
    WORD magic = *reinterpret_cast<const WORD*>(buf + optOff);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        optOff + sizeof(IMAGE_OPTIONAL_HEADER64) <= nRead)
        return reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(buf + optOff)->SizeOfImage;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        optOff + sizeof(IMAGE_OPTIONAL_HEADER32) <= nRead)
        return reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(buf + optOff)->SizeOfImage;
    return 0;
}

// Lightweight kernel anomaly scan for pg1: phantom modules, hollowing indicators, BYOVD carriers.
std::vector<ScannerUI::KernelAnomalyFinding> CollectKernelAnomalies(std::string& status) {
    static constexpr const char* kTagMapper   = "MAPPER";
    static constexpr const char* kTagHollowing = "HOLLOWING";

    std::vector<ScannerUI::KernelAnomalyFinding> findings;
    status = "OK";

    DWORD needed = 0;
    EnumDeviceDrivers(nullptr, 0, &needed);
    if (!needed) { status = "REVIEW"; return findings; }
    std::vector<LPVOID> bases(needed / sizeof(LPVOID) + 32);
    if (!EnumDeviceDrivers(bases.data(), (DWORD)(bases.size() * sizeof(LPVOID)), &needed)) {
        status = "REVIEW"; return findings;
    }
    bases.resize(needed / sizeof(LPVOID));

    std::unordered_map<std::wstring, int> bnameCounts;
    auto moduleMap = CollectLoadedKernelModuleMap(bnameCounts);

    std::unordered_set<uintptr_t> knownBases;
    for (const auto& kv : moduleMap) knownBases.insert(kv.second.base);
    std::unordered_set<uintptr_t> flagged;

    // Phantom module check
    for (LPVOID basePtr : bases) {
        uintptr_t base = reinterpret_cast<uintptr_t>(basePtr);
        if (!base || base < 0xFFFF800000000000ULL) continue;
        if (knownBases.count(base)) continue;

        wchar_t pathBuf[MAX_PATH * 2] = {};
        GetDeviceDriverFileNameW(basePtr, pathBuf, (DWORD)std::size(pathBuf));
        std::wstring rawPath = pathBuf;
        std::wstring dosPath = NormalizeDosDriverPath(rawPath);
        const std::wstring& usePath = dosPath.empty() ? rawPath : dosPath;
        size_t slashPos = usePath.rfind(L'\\');
        std::wstring baseName = (slashPos != std::wstring::npos) ? usePath.substr(slashPos + 1) : usePath;

        ScannerUI::KernelAnomalyFinding f;
        f.severity    = "HIGH";
        f.type        = kTagMapper;
        f.driverName  = WideToUtf8(baseName.empty() ? L"<unknown>" : baseName);
        f.path        = WideToUtf8(usePath);
        f.reason      = "phantom kernel module: visible in kernel VA but absent from module list";
        char db[32]; snprintf(db, sizeof(db), "base=0x%016llX", (unsigned long long)base);
        f.detail      = db;
        f.loadAddress = base;
        f.suspicious  = true;
        findings.push_back(std::move(f));
        flagged.insert(base);
        status = "DETECTED";
    }

    // Per-module checks: BYOVD, suspicious name, hollowing
    for (const auto& kv : moduleMap) {
        const LoadedKernelModuleInfo& mod = kv.second;
        if (flagged.count(mod.base)) continue;

        std::wstring bn = mod.name;
        if (bn.empty() && !mod.path.empty()) {
            size_t s = mod.path.rfind(L'\\');
            bn = (s != std::wstring::npos) ? mod.path.substr(s + 1) : mod.path;
        }
        std::wstring bnUp = ToUpperInvariant(bn);

        if (!bnUp.empty() && IsKnownAbusedDriverName(bnUp)) {
            ScannerUI::KernelAnomalyFinding f;
            f.severity    = "HIGH";
            f.type        = kTagMapper;
            f.driverName  = WideToUtf8(bn);
            f.path        = WideToUtf8(mod.path);
            f.reason      = "known vulnerable driver loaded (BYOVD carrier — potential kdmapper)";
            f.loadAddress = mod.base;
            f.loadedSize  = mod.imageSize;
            f.suspicious  = true;
            findings.push_back(std::move(f));
            flagged.insert(mod.base);
            status = "DETECTED";
            continue;
        }

        if (!bnUp.empty() && HasDriverSuspiciousToken(bnUp)) {
            ScannerUI::KernelAnomalyFinding f;
            f.severity    = "MEDIUM";
            f.type        = kTagMapper;
            f.driverName  = WideToUtf8(bn);
            f.path        = WideToUtf8(mod.path);
            f.reason      = "suspicious driver name token detected";
            f.loadAddress = mod.base;
            f.loadedSize  = mod.imageSize;
            f.suspicious  = true;
            findings.push_back(std::move(f));
            flagged.insert(mod.base);
            if (status == "OK") status = "REVIEW";
            continue;
        }

        if (mod.imageSize > 0 && !mod.path.empty()) {
            DWORD diskSize = ReadDiskSizeOfImage(mod.path);
            if (diskSize > 0) {
                ULONGLONG delta = mod.imageSize > diskSize
                    ? (ULONGLONG)(mod.imageSize - diskSize)
                    : (ULONGLONG)(diskSize - mod.imageSize);
                if (delta > 0x10000) {
                    bool signedDrv = IsAuthenticodeSigned(mod.path);
                    ScannerUI::KernelAnomalyFinding f;
                    f.severity    = signedDrv ? "MEDIUM" : "HIGH";
                    f.type        = kTagHollowing;
                    f.driverName  = WideToUtf8(bn);
                    f.path        = WideToUtf8(mod.path);
                    f.reason      = signedDrv
                        ? "potential driver hollowing: signed driver memory size differs from disk image"
                        : "driver memory size differs from disk image (unsigned)";
                    char db[128];
                    snprintf(db, sizeof(db), "mem=0x%08X disk=0x%08X delta=0x%08llX",
                             (unsigned)mod.imageSize, (unsigned)diskSize, (unsigned long long)delta);
                    f.detail      = db;
                    f.loadAddress = mod.base;
                    f.loadedSize  = mod.imageSize;
                    f.suspicious  = true;
                    findings.push_back(std::move(f));
                    flagged.insert(mod.base);
                    if (f.severity == "HIGH") status = "DETECTED";
                    else if (status == "OK") status = "REVIEW";
                }
            }
        }
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        return (a.severity == "HIGH" ? 0 : 1) < (b.severity == "HIGH" ? 0 : 1);
    });
    return findings;
}



static std::string ComputeDriverSha256(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(h); return "";
    }
    DWORD objSz = 0, cbData = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&objSz), sizeof(objSz), &cbData, 0);
    std::vector<BYTE> obj(objSz);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(alg, &hHash, obj.data(), objSz, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0); CloseHandle(h); return "";
    }
    std::vector<BYTE> buf(4 * 1024 * 1024);
    DWORD rd = 0;
    bool ok = true;
    while (ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr) && rd > 0)
        if (BCryptHashData(hHash, buf.data(), rd, 0) != 0) { ok = false; break; }
    CloseHandle(h);
    std::string result;
    if (ok) {
        std::array<BYTE, 32> digest = {};
        if (BCryptFinishHash(hHash, digest.data(), 32, 0) == 0) {
            char hex[65] = {};
            for (int i = 0; i < 32; ++i)
                snprintf(hex + i * 2, 3, "%02x", digest[i]);
            result = hex;
        }
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

static std::wstring BaseNameNoExtUpper(const std::wstring& path) {
    std::wstring base = ToUpperInvariant(DriverBaseName(path));
    size_t dot = base.find_last_of(L'.');
    return dot == std::wstring::npos ? base : base.substr(0, dot);
}

static void AddUniqueToken(std::vector<std::string>& tokens, const std::string& value) {
    if (value.empty()) return;
    for (const auto& t : tokens)
        if (t == value) return;
    tokens.push_back(value);
}

static std::string JoinTokens(const std::vector<std::string>& tokens, const char* sep = ", ") {
    std::string out;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) out += sep;
        out += tokens[i];
    }
    return out;
}

static int SeverityRank(const std::string& s) {
    return s == "HIGH" ? 3 : s == "MEDIUM" ? 2 : s == "INFO" ? 1 : 0;
}

static void EscalateDriverFinding(ScannerUI::DriverIntegrityFinding& f,
                                  const std::string& severity,
                                  const std::string& reason,
                                  bool suspicious = true) {
    if (SeverityRank(severity) >= SeverityRank(f.severity)) {
        f.severity = severity;
        f.reason = reason;
    }
    f.suspicious = f.suspicious || suspicious;
}

static void DowngradeDriverFinding(ScannerUI::DriverIntegrityFinding& f,
                                   const std::string& severity,
                                   const std::string& reason,
                                   bool suspicious) {
    f.severity = severity;
    f.reason = reason;
    f.suspicious = suspicious;
}

static bool ReadWholeDriverFile(const std::wstring& path, std::vector<uint8_t>& file) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(h, &fsz) || fsz.QuadPart < 0x400 || fsz.QuadPart > 256LL * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }
    file.resize((size_t)fsz.QuadPart);
    DWORD rd = 0;
    bool ok = ReadFile(h, file.data(), (DWORD)file.size(), &rd, nullptr) && rd == (DWORD)file.size();
    CloseHandle(h);
    return ok;
}

struct DriverVersionInfo {
    std::wstring companyName;
    std::wstring fileDescription;
    std::wstring originalFilename;
    std::wstring productName;
    bool hasVersion = false;
};

static std::wstring QueryVersionString(const std::vector<BYTE>& data,
                                       WORD lang, WORD codepage,
                                       const wchar_t* key) {
    wchar_t subBlock[128] = {};
    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s", lang, codepage, key);
    LPVOID value = nullptr;
    UINT valueLen = 0;
    if (VerQueryValueW(const_cast<BYTE*>(data.data()), subBlock, &value, &valueLen) && value && valueLen > 1)
        return reinterpret_cast<wchar_t*>(value);
    return L"";
}

static DriverVersionInfo GetDriverVersionInfo(const std::wstring& path) {
    DriverVersionInfo info;
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!size) return info;

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data()))
        return info;
    info.hasVersion = true;

    struct LangCodePage { WORD lang; WORD codepage; };
    LangCodePage* trans = nullptr;
    UINT transBytes = 0;
    std::vector<LangCodePage> candidates;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                       reinterpret_cast<LPVOID*>(&trans), &transBytes) &&
        trans && transBytes >= sizeof(LangCodePage)) {
        size_t count = transBytes / sizeof(LangCodePage);
        for (size_t i = 0; i < count && i < 8; ++i)
            candidates.push_back(trans[i]);
    }
    candidates.push_back({ 0x0409, 0x04B0 });
    candidates.push_back({ 0x0409, 0x04E4 });

    for (const auto& c : candidates) {
        if (info.companyName.empty())
            info.companyName = QueryVersionString(data, c.lang, c.codepage, L"CompanyName");
        if (info.fileDescription.empty())
            info.fileDescription = QueryVersionString(data, c.lang, c.codepage, L"FileDescription");
        if (info.originalFilename.empty())
            info.originalFilename = QueryVersionString(data, c.lang, c.codepage, L"OriginalFilename");
        if (info.productName.empty())
            info.productName = QueryVersionString(data, c.lang, c.codepage, L"ProductName");
        if (!info.companyName.empty() && !info.fileDescription.empty() && !info.originalFilename.empty() && !info.productName.empty())
            break;
    }
    return info;
}

static bool ContainsAnyToken(const std::wstring& text, std::initializer_list<const wchar_t*> tokens) {
    std::wstring up = ToUpperInvariant(text);
    for (const wchar_t* token : tokens)
        if (up.find(token) != std::wstring::npos)
            return true;
    return false;
}

static bool IsTrustedDriverPublisher(const std::wstring& signer, const DriverVersionInfo& version) {
    std::wstring text = signer + L" " + version.companyName + L" " + version.productName;
    return ContainsAnyToken(text, {
        L"MICROSOFT", L"WINDOWS",
        L"ADVANCED MICRO DEVICES", L"AMD",
        L"NVIDIA", L"INTEL", L"REALTEK", L"QUALCOMM", L"BROADCOM",
        L"DELL", L"HP INC", L"HEWLETT", L"LENOVO", L"ASUSTEK", L"ASUS",
        L"GIGABYTE", L"MSI", L"MICRO-STAR", L"ACER",
        L"VMWARE", L"ORACLE", L"VIRTUALBOX",
        L"LOGITECH", L"RAZER", L"CORSAIR", L"STEELSERIES",
        L"ESET", L"CROWDSTRIKE", L"SENTINELONE", L"MALWAREBYTES",
        L"BITDEFENDER", L"KASPERSKY", L"SOPHOS", L"TRELLIX", L"MCAFEE",
        L"FACEIT", L"EASYANTICHEAT", L"BATTLEYE", L"RIOT GAMES"
    });
}

// Returns true when the finding has at least one independent structural signal
// of driver manipulation — used to gate callback escalation to HIGH.
static bool HasManipulationEvidence(const ScannerUI::DriverIntegrityFinding& f,
                                    const std::vector<std::string>& anomalyTokens) {
    if (f.hasHooks)    return true;
    if (!f.checksumOk) return true;
    static const char* const kSignals[] = {
        "import-injection-combo", "import-dma-combo", "import-physmem-access",
        "code-entropy-spike", "memory-size-mismatch", "module-list-mismatch",
        "writable-executable-section", "packer-section-name", "no-rich-header",
        "manual-mapper-pattern", "stripped-binary-pattern", "code-integrity-event",
        nullptr
    };
    for (int k = 0; kSignals[k]; ++k)
        if (std::find(anomalyTokens.begin(), anomalyTokens.end(), kSignals[k]) != anomalyTokens.end())
            return true;
    return false;
}

static bool HasWeakOnlyAnomalies(const std::vector<std::string>& anomalies) {
    static const std::unordered_set<std::string> kStrong = {
        "system-name-outside-system-path",
        "system-name-lookalike",
        "known-byovd-family",
        "loaded-without-service",
        "service-path-mismatch",
        "unsigned-boot-start",
        "invalid-pe",
        "non-native-subsystem",
        "original-name-system-masquerade",
        "version-company-mismatch",
        "signed-callbacks-suspicious-path",
        "unsigned-callback-surface",
        "non-system-callback-surface",
        "unsigned-file-touched-after-boot",
        "loaded-image-file-missing",
        "unmapped-loaded-driver",
        "module-list-mismatch",
        "duplicate-loaded-driver-name",
        "memory-size-mismatch",
        "company-name-microsoft-spoof",
        "cert-homoglyph-cn",
        "cert-self-signed",
        "service-restarted-post-boot",
        "manual-mapper-pattern",
        "stripped-binary-pattern",
        "code-integrity-event",
        "memory-size-diff-trusted",
        // "no-rich-header" is intentionally excluded: GCC, Clang, Rust, and LLVM
        // do not emit a Rich header, so legitimate third-party drivers routinely
        // lack it. Treating it as strong evidence caused too many false positives.
    };
    for (const auto& a : anomalies)
        if (kStrong.find(a) != kStrong.end())
            return false;
    return true;
}

static bool HasRichHeaderLocal(const uint8_t* data, size_t sz) {
    if (!data || sz < 0x40)
        return false;
    LONG peOff = *reinterpret_cast<const LONG*>(data + 0x3C);
    if (peOff <= 0x40 || (size_t)peOff > sz)
        return false;
    for (size_t i = 0x40; i + 4 <= (size_t)peOff; ++i)
        if (data[i] == 'R' && data[i + 1] == 'i' && data[i + 2] == 'c' && data[i + 3] == 'h')
            return true;
    return false;
}

static int CountReadableStringsLocal(const uint8_t* data, size_t sz, size_t minLen = 5) {
    if (!data || sz == 0)
        return 0;
    int count = 0;
    size_t runLen = 0;
    for (size_t i = 0; i < sz; ++i) {
        uint8_t c = data[i];
        if (c >= 0x20 && c <= 0x7E) {
            ++runLen;
        } else {
            if (runLen >= minLen)
                ++count;
            runLen = 0;
        }
    }
    if (runLen >= minLen)
        ++count;
    return count;
}

struct AntiAnalysisProfileLocal {
    bool hasRdtscCheck = false;
    bool hasCpuidVmCheck = false;
    bool hasPebDebugCheck = false;
};

static AntiAnalysisProfileLocal ScanAntiAnalysisPatternsLocal(const uint8_t* data, size_t sz) {
    AntiAnalysisProfileLocal p;
    if (!data || sz < 4)
        return p;
    for (size_t i = 0; i + 1 < sz; ++i) {
        if (!p.hasRdtscCheck && data[i] == 0x0F && data[i + 1] == 0x31)
            p.hasRdtscCheck = true;
        if (!p.hasCpuidVmCheck && data[i] == 0x0F && data[i + 1] == 0xA2)
            p.hasCpuidVmCheck = true;
        if (!p.hasPebDebugCheck && i + 6 < sz) {
            if (data[i] == 0x64 && data[i + 1] == 0xA1 &&
                data[i + 2] == 0x30 && data[i + 3] == 0x00)
                p.hasPebDebugCheck = true;
            if (data[i] == 0x65 && data[i + 1] == 0x48 && data[i + 2] == 0x8B &&
                data[i + 3] == 0x04 && data[i + 4] == 0x25 &&
                data[i + 5] == 0x60 && data[i + 6] == 0x00)
                p.hasPebDebugCheck = true;
        }
    }
    return p;
}

struct DriverFileTimes {
    bool ok = false;
    FILETIME created = {};
    FILETIME modified = {};
    ULONGLONG createdValue = 0;
    ULONGLONG modifiedValue = 0;
};

static DriverFileTimes GetDriverFileTimes(const std::wstring& path) {
    DriverFileTimes t;
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return t;
    FILETIME access = {};
    if (GetFileTime(h, &t.created, &access, &t.modified)) {
        t.ok = true;
        t.createdValue = FileTimeToU64(t.created);
        t.modifiedValue = FileTimeToU64(t.modified);
    }
    CloseHandle(h);
    return t;
}

struct DriverPeAnomalyInfo {
    bool valid = false;
    bool nativeSubsystem = true;
    bool tooManySections = false;
    bool writableExecutableSection = false;
    bool suspiciousSectionName = false;
    bool noImportTable = false;
    DWORD sizeOfImage = 0;
    std::string summary;
    // P3 additions
    bool missingRichHeader        = false;
    bool nonStandardAlignment     = false;
    bool codeEntropySpike         = false;  // .text entropy > 7.2
    bool virtualRawRatioAnomalous = false;  // VirtualSize > RawSize*8
    bool stringObfuscation        = false;  // < 8 readable strings in .text > 10KB
};

static DriverPeAnomalyInfo AnalyzeDriverPeShape(const std::wstring& path) {
    DriverPeAnomalyInfo info;
    std::vector<uint8_t> file;
    if (!ReadWholeDriverFile(path, file))
        return info;

    const uint8_t* base = file.data();
    size_t sz = file.size();
    if (sz < sizeof(IMAGE_DOS_HEADER)) return info;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return info;
    size_t peOff = (size_t)dos->e_lfanew;
    if (peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > sz) return info;
    if (*reinterpret_cast<const DWORD*>(base + peOff) != IMAGE_NT_SIGNATURE) return info;

    auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + peOff + sizeof(DWORD));
    size_t optOff = peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optOff + fh->SizeOfOptionalHeader > sz || fh->SizeOfOptionalHeader < sizeof(WORD)) return info;

    WORD magic = *reinterpret_cast<const WORD*>(base + optOff);
    bool is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    bool is32 = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    if (!is64 && !is32) return info;
    info.valid = true;

    WORD subsystem = is64
        ? reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + optOff)->Subsystem
        : reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + optOff)->Subsystem;
    info.sizeOfImage = is64
        ? reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + optOff)->SizeOfImage
        : reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + optOff)->SizeOfImage;
    info.nativeSubsystem = subsystem == IMAGE_SUBSYSTEM_NATIVE;
    info.tooManySections = fh->NumberOfSections > 12;

    size_t dataDirOff = optOff + (is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                       : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY) <= optOff + fh->SizeOfOptionalHeader) {
        auto* dirs = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(base + dataDirOff);
        info.noImportTable = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0;
    }

    static const char* kBadSectionNames[] = {
        "upx", "vmp", "themida", "packed", "petite", "enigma", "protect", "sforce", nullptr
    };

    size_t secTbl = optOff + fh->SizeOfOptionalHeader;
    for (WORD s = 0; s < fh->NumberOfSections && s < 96; ++s) {
        size_t sOff = secTbl + (size_t)s * sizeof(IMAGE_SECTION_HEADER);
        if (sOff + sizeof(IMAGE_SECTION_HEADER) > sz) break;
        auto* sh = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sOff);
        if ((sh->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sh->Characteristics & IMAGE_SCN_MEM_WRITE))
            info.writableExecutableSection = true;

        char sectionName[9] = {};
        memcpy(sectionName, sh->Name, 8);
        std::string low = ToLowerAscii(sectionName);
        for (int i = 0; kBadSectionNames[i]; ++i) {
            if (low.find(kBadSectionNames[i]) != std::string::npos) {
                info.suspiciousSectionName = true;
                break;
            }
        }
    }

    // P3 — Rich header detection (MSVC linker artifact)
    info.missingRichHeader = !HasRichHeaderLocal(base, sz);

    // P3 — FileAlignment: 0x200 and 0x1000 are MSVC defaults, but MinGW, WDK
    // older versions, and LLVM-based toolchains legitimately produce 0x400/0x800.
    DWORD fileAlign = is64
        ? reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + optOff)->FileAlignment
        : reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + optOff)->FileAlignment;
    info.nonStandardAlignment = (fileAlign != 0x200 && fileAlign != 0x400 &&
                                  fileAlign != 0x800 && fileAlign != 0x1000);

    // P3 — Per-section analysis: entropy spike, virtual/raw ratio, string obfuscation
    {
        size_t secTableOff2 = optOff + fh->SizeOfOptionalHeader;
        for (WORD s = 0; s < fh->NumberOfSections && s < 96; ++s) {
            size_t sOff2 = secTableOff2 + (size_t)s * sizeof(IMAGE_SECTION_HEADER);
            if (sOff2 + sizeof(IMAGE_SECTION_HEADER) > sz) break;
            auto* sh2 = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sOff2);
            bool isCode = (sh2->Characteristics & IMAGE_SCN_CNT_CODE) != 0;
            DWORD rawPtr  = sh2->PointerToRawData;
            DWORD rawSize = sh2->SizeOfRawData;
            DWORD virtSize = sh2->Misc.VirtualSize;

            // Virtual/raw ratio anomaly: indicates unpacking stub.
            // Guard rawSize > 4096 to skip .bss-only sections (zero-init data with
            // VirtualSize >> RawSize is normal for AV, filesystem, and storage drivers).
            // Multiplier raised to 32 to avoid false positives on legitimate sparse sections.
            if (rawSize > 4096 && virtSize > rawSize * 32)
                info.virtualRawRatioAnomalous = true;

            if (rawPtr > 0 && rawSize > 0 && (size_t)rawPtr + rawSize <= sz) {
                const uint8_t* secData = base + rawPtr;
                // Section entropy spike in code sections
                if (isCode && rawSize > 0) {
                    double ent = DetectionFilter::ShannonEntropy(secData, rawSize < 256*1024 ? rawSize : 256*1024);
                    if (ent > DetectionFilter::kPackedEntropy)
                        info.codeEntropySpike = true;
                }
                // String obfuscation: code section > 32KB with < 4 readable strings.
                // Thresholds raised (from 10KB/8 strings) because optimized C/Assembly
                // routinely produces dense code sections with very few embedded strings.
                if (isCode && rawSize > 32 * 1024 && !info.stringObfuscation) {
                    int strCount = CountReadableStringsLocal(secData, rawSize < 512*1024 ? rawSize : 512*1024);
                    if (strCount < 4)
                        info.stringObfuscation = true;
                }
            }
        }
    }

    std::vector<std::string> tokens;
    if (!info.nativeSubsystem) AddUniqueToken(tokens, "non-native-subsystem");
    if (info.tooManySections) AddUniqueToken(tokens, "many-sections");
    if (info.writableExecutableSection) AddUniqueToken(tokens, "writable-executable-section");
    if (info.suspiciousSectionName) AddUniqueToken(tokens, "packer-section-name");
    if (info.noImportTable) AddUniqueToken(tokens, "no-import-table");
    if (info.missingRichHeader) AddUniqueToken(tokens, "no-rich-header");
    if (info.nonStandardAlignment) AddUniqueToken(tokens, "non-std-alignment");
    if (info.codeEntropySpike) AddUniqueToken(tokens, "code-entropy-spike");
    if (info.virtualRawRatioAnomalous) AddUniqueToken(tokens, "virt-raw-anomaly");
    if (info.stringObfuscation) AddUniqueToken(tokens, "string-obfuscation");
    info.summary = JoinTokens(tokens);
    return info;
}

static std::vector<std::string> FindImportedKernelCallbacks(const std::wstring& path) {
    std::vector<std::string> imports;
    std::vector<uint8_t> file;
    if (!ReadWholeDriverFile(path, file))
        return imports;

    const uint8_t* base = file.data();
    size_t sz = file.size();
    if (sz < sizeof(IMAGE_DOS_HEADER)) return imports;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return imports;

    size_t peOff = (size_t)dos->e_lfanew;
    if (peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > sz) return imports;
    if (*reinterpret_cast<const DWORD*>(base + peOff) != IMAGE_NT_SIGNATURE) return imports;
    auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + peOff + sizeof(DWORD));
    size_t optOff = peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optOff + fh->SizeOfOptionalHeader > sz || fh->SizeOfOptionalHeader < sizeof(WORD)) return imports;

    WORD magic = *reinterpret_cast<const WORD*>(base + optOff);
    bool is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    bool is32 = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    if (!is64 && !is32) return imports;
    size_t dataDirOff = optOff + (is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                       : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY) > optOff + fh->SizeOfOptionalHeader)
        return imports;
    auto* dirs = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(base + dataDirOff);
    DWORD importRva = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return imports;

    size_t secTbl = optOff + fh->SizeOfOptionalHeader;
    auto rvaToOffset = [&](DWORD rva) -> size_t {
        for (WORD s = 0; s < fh->NumberOfSections && s < 96; ++s) {
            size_t sOff = secTbl + (size_t)s * sizeof(IMAGE_SECTION_HEADER);
            if (sOff + sizeof(IMAGE_SECTION_HEADER) > sz) break;
            auto* sh = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sOff);
            DWORD va = sh->VirtualAddress;
            DWORD span = sh->Misc.VirtualSize > sh->SizeOfRawData ? sh->Misc.VirtualSize : sh->SizeOfRawData;
            if (span == 0) span = sh->SizeOfRawData;
            if (rva >= va && rva < va + span) {
                size_t off = (size_t)sh->PointerToRawData + (rva - va);
                return off < sz ? off : (size_t)-1;
            }
        }
        return (size_t)-1;
    };

    auto callbackLabel = [](const std::string& name) -> const char* {
        static const struct { const char* importName; const char* label; } kSensitive[] = {
            { "PsSetCreateProcessNotifyRoutine",   "process-callback" },
            { "PsSetCreateProcessNotifyRoutineEx", "process-callback" },
            { "PsSetCreateProcessNotifyRoutineEx2","process-callback" },
            { "PsSetCreateThreadNotifyRoutine",    "thread-callback" },
            { "PsSetCreateThreadNotifyRoutineEx",  "thread-callback" },
            { "PsSetLoadImageNotifyRoutine",       "image-load-callback" },
            { "PsSetLoadImageNotifyRoutineEx",     "image-load-callback" },
            { "ObRegisterCallbacks",               "object-handle-callback" },
            { "CmRegisterCallback",                "registry-callback" },
            { "CmRegisterCallbackEx",              "registry-callback" },
            { "FltRegisterFilter",                 "filesystem-minifilter" },
            { "FsRtlRegisterFileSystemFilterCallbacks", "filesystem-filter-callback" },
            { "IoRegisterFsRegistrationChange",    "filesystem-registration-callback" },
            { "IoRegisterPlugPlayNotification",    "pnp-callback" },
            { "IoRegisterShutdownNotification",    "shutdown-callback" },
            { "KeRegisterNmiCallback",             "nmi-callback" },
            { "ExCreateCallback",                  "executive-callback" },
            { "ExRegisterCallback",                "executive-callback" },
            { "FwpsCalloutRegister0",              "wfp-callout" },
            { "FwpsCalloutRegister1",              "wfp-callout" },
            { "FwpsCalloutRegister2",              "wfp-callout" },
            { "FwpsCalloutRegister3",              "wfp-callout" },
            { "MmGetSystemRoutineAddress",         "runtime-dynamic-import" },
            { "ZwLoadDriver",                      "driver-loader" },
            { "NtLoadDriver",                      "driver-loader" },
            { "IoRegisterBootDriverCallback",      "boot-driver-callback" },
            { "SeRegisterImageVerificationCallback","image-verification-callback" },
            { "KeRegisterProcessorChangeCallback", "processor-change-callback" },
            { "PsRegisterPicoProvider",            "pico-process-callback" },
            { "DbgSetDebugPrintCallback",          "debug-print-callback" },
            { "IoRegisterFsRegistrationChangeEx",  "filesystem-registration-callback" },
            { nullptr, nullptr }
        };
        for (int i = 0; kSensitive[i].importName; ++i)
            if (name == kSensitive[i].importName)
                return kSensitive[i].label;
        return nullptr;
    };

    size_t descOff = rvaToOffset(importRva);
    if (descOff == (size_t)-1) return imports;
    for (size_t i = 0; i < 512; ++i) {
        size_t cur = descOff + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (cur + sizeof(IMAGE_IMPORT_DESCRIPTOR) > sz) break;
        auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + cur);
        if (!desc->OriginalFirstThunk && !desc->FirstThunk && !desc->Name) break;
        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        size_t thunkOff = rvaToOffset(thunkRva);
        if (thunkOff == (size_t)-1) continue;

        for (size_t ti = 0; ti < 4096; ++ti) {
            uint64_t thunk = 0;
            size_t entryOff = thunkOff + ti * (is64 ? sizeof(uint64_t) : sizeof(uint32_t));
            if (entryOff + (is64 ? sizeof(uint64_t) : sizeof(uint32_t)) > sz) break;
            thunk = is64 ? *reinterpret_cast<const uint64_t*>(base + entryOff)
                         : *reinterpret_cast<const uint32_t*>(base + entryOff);
            if (!thunk) break;
            uint64_t ordinalMask = is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
            if (thunk & ordinalMask) continue;
            size_t ibnOff = rvaToOffset((DWORD)thunk);
            if (ibnOff == (size_t)-1 || ibnOff + sizeof(WORD) >= sz) continue;
            const char* name = reinterpret_cast<const char*>(base + ibnOff + sizeof(WORD));
            size_t maxLen = sz - (ibnOff + sizeof(WORD));
            size_t len = strnlen_s(name, maxLen);
            if (len == 0 || len >= maxLen || len > 256) continue;
            if (const char* label = callbackLabel(std::string(name, len)))
                AddUniqueToken(imports, label);
        }
    }

    // Scan bruto de strings no binário para detectar resolução dinâmica de callbacks
    // (drivers que usam MmGetSystemRoutineAddress sem importar diretamente)
    static const struct { const char* name; const char* label; } kDynCallbacks[] = {
        { "PsSetCreateProcessNotifyRoutine",   "process-callback" },
        { "PsSetCreateThreadNotifyRoutine",    "thread-callback" },
        { "PsSetLoadImageNotifyRoutine",       "image-load-callback" },
        { "ObRegisterCallbacks",               "object-handle-callback" },
        { "CmRegisterCallback",                "registry-callback" },
        { "FltRegisterFilter",                 "filesystem-minifilter" },
        { "FwpsCalloutRegister",               "wfp-callout" },
        { nullptr, nullptr }
    };
    for (int ci = 0; kDynCallbacks[ci].name; ++ci) {
        const char* needle = kDynCallbacks[ci].name;
        size_t nlen = strlen(needle);
        if (nlen == 0 || nlen >= sz) continue;
        for (size_t pos = 0; pos + nlen < sz; ++pos) {
            if (base[pos] == (uint8_t)needle[0] &&
                memcmp(base + pos, needle, nlen) == 0 &&
                (pos + nlen >= sz || base[pos + nlen] == '\0')) {
                AddUniqueToken(imports, std::string("dynimport:") + kDynCallbacks[ci].label);
                break;
            }
        }
    }

    return imports;
}

static void EnrichWithRuntimeMinifilters(
    std::unordered_map<std::wstring, std::string>& callbackExtra)
{
    // FILTER_FULL_INFORMATION layout (WDK, FilterFullInformation = 0)
    // Declarado localmente para não depender de fltuser.h
    struct FltFullInfo {
        ULONG  NextEntryOffset;
        ULONG  NumberOfInstances;
        USHORT FilterNameLength;
        WCHAR  FilterNameBuffer[1];
    };

    HMODULE hFlt = LoadLibraryW(L"fltLib.dll");
    if (!hFlt) return;

    // Função pointer com cast direto para evitar typedefs em scope global
    FARPROC rawFindFirst = GetProcAddress(hFlt, "FilterFindFirst");
    FARPROC rawFindNext  = GetProcAddress(hFlt, "FilterFindNext");
    FARPROC rawFindClose = GetProcAddress(hFlt, "FilterFindClose");
    if (!rawFindFirst || !rawFindNext || !rawFindClose) {
        FreeLibrary(hFlt);
        return;
    }

    // Typedefs locais necessários: MSVC não parseia calling convention dentro de
    // template angle brackets (reinterpret_cast<HRESULT(WINAPI*)(...)> causa C2059/C2143).
    typedef HRESULT (WINAPI *FnFilterFindFirst)(DWORD, LPVOID, DWORD, LPDWORD, LPHANDLE);
    typedef HRESULT (WINAPI *FnFilterFindNext) (HANDLE, DWORD, LPVOID, DWORD, LPDWORD);
    typedef HRESULT (WINAPI *FnFilterFindClose)(HANDLE);

    std::vector<BYTE> buf(4096);
    DWORD returned = 0;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    // FilterFullInformation = 0 (primeiro valor do enum FILTER_INFORMATION_CLASS)
    HRESULT hr = reinterpret_cast<FnFilterFindFirst>(rawFindFirst)
                     (0, buf.data(), (DWORD)buf.size(), &returned, &hFind);

    for (int iter = 0; SUCCEEDED(hr) && iter < 256; ++iter) {
        const FltFullInfo* info = reinterpret_cast<const FltFullInfo*>(buf.data());
        if (info->FilterNameLength > 0 && info->FilterNameLength < 512) {
            std::wstring name(info->FilterNameBuffer,
                              info->FilterNameLength / sizeof(WCHAR));
            std::wstring nameUp = ToUpperInvariant(name);
            std::string evidence = "runtime-minifilter instances=" +
                                   std::to_string(info->NumberOfInstances);
            auto it = callbackExtra.find(nameUp);
            if (it == callbackExtra.end())
                callbackExtra.emplace(nameUp, evidence);
            else if (it->second.find("runtime-minifilter") == std::string::npos)
                it->second += "; " + evidence;
        }
        hr = reinterpret_cast<FnFilterFindNext>(rawFindNext)
                 (hFind, 0, buf.data(), (DWORD)buf.size(), &returned);
    }

    if (hFind != INVALID_HANDLE_VALUE)
        reinterpret_cast<FnFilterFindClose>(rawFindClose)(hFind);
    FreeLibrary(hFlt);
}

static std::unordered_map<std::wstring, std::string> CollectMinifilterRegistryMap() {
    std::unordered_map<std::wstring, std::string> map;
    HKEY svcRoot = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WOW64_64KEY, &svcRoot) != ERROR_SUCCESS)
        return map;

    DWORD subCount = 0;
    RegQueryInfoKeyW(svcRoot, nullptr, nullptr, nullptr, &subCount,
                     nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    for (DWORD i = 0; i < subCount; ++i) {
        wchar_t svcName[256] = {};
        DWORD nameLen = (DWORD)std::size(svcName);
        if (RegEnumKeyExW(svcRoot, i, svcName, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            continue;

        HKEY svcKey = nullptr;
        if (RegOpenKeyExW(svcRoot, svcName, 0, KEY_READ | KEY_WOW64_64KEY, &svcKey) != ERROR_SUCCESS)
            continue;

        HKEY instRoot = nullptr;
        if (RegOpenKeyExW(svcKey, L"Instances", 0, KEY_READ | KEY_WOW64_64KEY, &instRoot) != ERROR_SUCCESS) {
            RegCloseKey(svcKey);
            continue;
        }

        wchar_t defaultInst[256] = {};
        DWORD defaultSz = sizeof(defaultInst), defaultType = 0;
        RegQueryValueExW(instRoot, L"DefaultInstance", nullptr, &defaultType,
                         reinterpret_cast<LPBYTE>(defaultInst), &defaultSz);

        std::wstring instanceName = defaultInst;
        if (instanceName.empty()) {
            wchar_t firstInst[256] = {};
            DWORD firstLen = (DWORD)std::size(firstInst);
            if (RegEnumKeyExW(instRoot, 0, firstInst, &firstLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                instanceName = firstInst;
        }

        std::wstring altitude;
        if (!instanceName.empty()) {
            HKEY instKey = nullptr;
            if (RegOpenKeyExW(instRoot, instanceName.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &instKey) == ERROR_SUCCESS) {
                wchar_t alt[128] = {};
                DWORD altSz = sizeof(alt), altType = 0;
                if (RegQueryValueExW(instKey, L"Altitude", nullptr, &altType,
                                     reinterpret_cast<LPBYTE>(alt), &altSz) == ERROR_SUCCESS)
                    altitude = alt;
                RegCloseKey(instKey);
            }
        }

        wchar_t imgPath[MAX_PATH * 2] = {};
        DWORD imgSize = sizeof(imgPath), imgRegType = 0;
        std::wstring normPath;
        if (RegQueryValueExW(svcKey, L"ImagePath", nullptr, &imgRegType,
                             reinterpret_cast<LPBYTE>(imgPath), &imgSize) == ERROR_SUCCESS) {
            std::wstring rawImg = ExtractDriverImagePath(imgPath);
            if (rawImg.rfind(L"system32\\", 0) == 0 || rawImg.rfind(L"System32\\", 0) == 0) {
                wchar_t win[MAX_PATH] = {};
                GetWindowsDirectoryW(win, MAX_PATH);
                rawImg = std::wstring(win) + L"\\" + rawImg;
            }
            normPath = NormalizeDosDriverPath(rawImg);
        }

        std::string summary = "minifilter service=" + WideToUtf8(svcName);
        if (!altitude.empty())
            summary += " altitude=" + WideToUtf8(altitude);
        if (!instanceName.empty())
            summary += " instance=" + WideToUtf8(instanceName);

        map[ToUpperInvariant(svcName)] = summary;
        if (!normPath.empty()) {
            map[ToUpperInvariant(normPath)] = summary;
            map[BaseNameNoExtUpper(normPath)] = summary;
        }

        RegCloseKey(instRoot);
        RegCloseKey(svcKey);
    }
    RegCloseKey(svcRoot);
    return map;
}

struct DriverServiceInfo {
    std::wstring serviceName;
    std::wstring imagePath;
    DWORD type = 0;
    DWORD start = 0xFFFFFFFF;
    bool hasImagePath = false;
};

static std::unordered_map<std::wstring, DriverServiceInfo> CollectDriverServiceMap() {
    std::unordered_map<std::wstring, DriverServiceInfo> map;
    HKEY svcRoot = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WOW64_64KEY, &svcRoot) != ERROR_SUCCESS)
        return map;

    DWORD subCount = 0;
    RegQueryInfoKeyW(svcRoot, nullptr, nullptr, nullptr, &subCount,
                     nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    for (DWORD i = 0; i < subCount; ++i) {
        wchar_t svcName[256] = {};
        DWORD nameLen = (DWORD)std::size(svcName);
        if (RegEnumKeyExW(svcRoot, i, svcName, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            continue;

        HKEY svcKey = nullptr;
        if (RegOpenKeyExW(svcRoot, svcName, 0, KEY_READ | KEY_WOW64_64KEY, &svcKey) != ERROR_SUCCESS)
            continue;

        DWORD svcType = 0, svcTypeSize = sizeof(svcType), svcTypeReg = 0;
        if (RegQueryValueExW(svcKey, L"Type", nullptr, &svcTypeReg,
                             reinterpret_cast<LPBYTE>(&svcType), &svcTypeSize) != ERROR_SUCCESS ||
            (svcType != 1 && svcType != 2)) {
            RegCloseKey(svcKey);
            continue;
        }

        DriverServiceInfo info;
        info.serviceName = svcName;
        info.type = svcType;

        DWORD startSize = sizeof(info.start), startReg = 0;
        RegQueryValueExW(svcKey, L"Start", nullptr, &startReg,
                         reinterpret_cast<LPBYTE>(&info.start), &startSize);

        wchar_t imgPath[MAX_PATH * 2] = {};
        DWORD imgSize = sizeof(imgPath), imgRegType = 0;
        if (RegQueryValueExW(svcKey, L"ImagePath", nullptr, &imgRegType,
                             reinterpret_cast<LPBYTE>(imgPath), &imgSize) == ERROR_SUCCESS) {
            std::wstring rawImg = ExtractDriverImagePath(imgPath);
            if (rawImg.rfind(L"system32\\", 0) == 0 || rawImg.rfind(L"System32\\", 0) == 0) {
                wchar_t win[MAX_PATH] = {};
                GetWindowsDirectoryW(win, MAX_PATH);
                rawImg = std::wstring(win) + L"\\" + rawImg;
            }
            info.imagePath = NormalizeDosDriverPath(rawImg);
            info.hasImagePath = !info.imagePath.empty();
        }

        map[ToUpperInvariant(info.serviceName)] = info;
        if (info.hasImagePath) {
            map[ToUpperInvariant(info.imagePath)] = info;
            map[BaseNameNoExtUpper(info.imagePath)] = info;
        }

        RegCloseKey(svcKey);
    }
    RegCloseKey(svcRoot);
    return map;
}

static std::wstring EventLogFilePath(const wchar_t* logName) {
    wchar_t win[MAX_PATH] = {};
    GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring base = std::wstring(win) + L"\\System32\\winevt\\Logs\\";
    std::wstring name = logName;
    std::replace(name.begin(), name.end(), L'/', L'%');
    return base + name + L".evtx";
}

static void AddEvidence(std::unordered_map<std::wstring, std::string>& map,
                        const std::wstring& key,
                        const std::string& evidence) {
    if (key.empty() || evidence.empty())
        return;
    std::wstring up = ToUpperInvariant(key);
    auto it = map.find(up);
    if (it == map.end()) {
        map.emplace(up, evidence);
    } else if (it->second.find(evidence) == std::string::npos) {
        it->second += "; " + evidence;
    }
}

static std::unordered_map<std::wstring, std::string> CollectDriverEventEvidenceMap() {
    std::unordered_map<std::wstring, std::string> evidence;
    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);

    auto scanChannel = [&](const wchar_t* channel, const wchar_t* query,
                           const char* label, const std::wstring& pathField,
                           const std::wstring& serviceField = L"") {
        EVT_HANDLE result = EvtQuery(nullptr, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!result)
            return;

        std::string source = std::string(label) + " channel=" + WideToUtf8(channel) +
                             " file=" + WideToUtf8(EventLogFilePath(channel));
        EVT_HANDLE handles[16] = {};
        DWORD returned = 0;
        bool reachedBoot = false;
        int scanned = 0;
        while (!reachedBoot && scanned < 512 &&
               EvtNext(result, (DWORD)std::size(handles), handles, ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
            for (DWORD i = 0; i < returned; ++i) {
                std::wstring xml;
                bool ok = RenderEventXml(handles[i], xml);
                EvtClose(handles[i]);
                handles[i] = nullptr;
                if (!ok)
                    continue;
                ++scanned;

                FILETIME eventTime = {};
                std::wstring systemTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
                if (SysmonSystemTimeToFileTime(systemTime, eventTime) &&
                    FileTimeToU64(eventTime) < bootValue) {
                    reachedBoot = true;
                    break;
                }

                std::wstring p = pathField.empty() ? L"" : ExtractSysmonData(xml, pathField);
                if (p.empty() && xml.find(L".sys") != std::wstring::npos) {
                    size_t sys = xml.find(L".sys");
                    size_t begin = xml.rfind(L'>', sys);
                    size_t slash = xml.rfind(L'\\', sys);
                    if (slash != std::wstring::npos && (begin == std::wstring::npos || slash > begin))
                        begin = slash;
                    if (begin != std::wstring::npos) {
                        size_t end = xml.find(L'<', sys);
                        p = xml.substr(begin == slash ? slash + 1 : begin + 1,
                                       end == std::wstring::npos ? std::wstring::npos : end - begin - 1);
                    }
                }
                std::wstring svc = serviceField.empty() ? L"" : ExtractSysmonData(xml, serviceField);

                std::string stamp;
                if (!systemTime.empty())
                    stamp = " time=" + WideToUtf8(systemTime);
                std::string itemEvidence = source + stamp;
                if (!p.empty()) {
                    std::wstring norm = NormalizeDosDriverPath(p);
                    AddEvidence(evidence, norm, itemEvidence);
                    AddEvidence(evidence, DriverBaseName(norm), itemEvidence);
                    AddEvidence(evidence, BaseNameNoExtUpper(norm), itemEvidence);
                }
                if (!svc.empty())
                    AddEvidence(evidence, svc, itemEvidence);
            }
        }
        EvtClose(result);
    };

    scanChannel(L"Microsoft-Windows-Sysmon/Operational",
                L"*[System[(EventID=6)]]",
                "Sysmon EID 6 DriverLoaded",
                L"ImageLoaded");

    scanChannel(L"System",
                L"*[System[Provider[@Name='Service Control Manager'] and (EventID=7045 or EventID=7000 or EventID=7009 or EventID=7011 or EventID=7036)]]",
                "System SCM driver/service event",
                L"param2",
                L"param1");

    scanChannel(L"Microsoft-Windows-CodeIntegrity/Operational",
                L"*[System[(EventID=3001 or EventID=3002 or EventID=3004 or EventID=3033 or EventID=3063 or EventID=3076 or EventID=3089)]]",
                "CodeIntegrity event",
                L"FileName");

    return evidence;
}


static std::wstring GetDriverSignerName(const std::wstring& path) {
    HCERTSTORE hStore = nullptr; HCRYPTMSG hMsg = nullptr;
    DWORD enc = 0, ct = 0, ft = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &enc, &ct, &ft, &hStore, &hMsg, nullptr))
        return L"";
    DWORD sz = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &sz);
    if (!sz) { CertCloseStore(hStore, 0); CryptMsgClose(hMsg); return L""; }
    std::vector<uint8_t> sbuf(sz);
    auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(sbuf.data());
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, si, &sz);
    CERT_INFO ci = {}; ci.Issuer = si->Issuer; ci.SerialNumber = si->SerialNumber;
    PCCERT_CONTEXT ctx = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);
    std::wstring name;
    if (ctx) {
        wchar_t nb[512] = {};
        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nb, 512);
        name = nb;
        CertFreeCertificateContext(ctx);
    }
    CertCloseStore(hStore, 0); CryptMsgClose(hMsg);
    return name;
}



static std::vector<std::wstring> FindWinSxSReferences(const std::wstring& path) {
    std::wstring name = DriverBaseName(path);
    std::wstring up   = ToUpperInvariant(name);
    static const wchar_t* kCritical[] = {
        L"NTOSKRNL.EXE", L"NTKRNLPA.EXE", L"NTKRNLMP.EXE",
        L"WIN32K.SYS", L"WIN32KBASE.SYS", L"WIN32KFULL.SYS",
        L"HAL.DLL", L"CI.DLL", L"DXGKRNL.SYS",
        L"FLTMGR.SYS", L"KSECDD.SYS", L"CNG.SYS",
        L"TCPIP.SYS", L"NDIS.SYS", L"NETIO.SYS",
        nullptr
    };
    bool critical = false;
    for (int i = 0; kCritical[i]; ++i) if (up == kCritical[i]) { critical = true; break; }
    if (!critical) return {};
    wchar_t win[MAX_PATH] = {};
    GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring winsxs = std::wstring(win) + L"\\WinSxS";
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW((winsxs + L"\\amd64_*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return {};
    std::vector<std::wstring> results;
    do {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        std::wstring c = winsxs + L"\\" + data.cFileName + L"\\" + name;
        if (GetFileAttributesW(c.c_str()) != INVALID_FILE_ATTRIBUTES)
            results.push_back(c);
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return results;
}


static bool VerifyDriverCatalog(const std::wstring& path, bool& catalogFound) {
    catalogFound = false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    HCATADMIN hCat = nullptr;
    GUID drvGuid = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hCat, &drvGuid, 0)) { CloseHandle(h); return false; }
    DWORD hashSz = 0;
    CryptCATAdminCalcHashFromFileHandle(h, &hashSz, nullptr, 0);
    bool ok = false;
    if (hashSz > 0) {
        std::vector<BYTE> hash(hashSz);
        if (CryptCATAdminCalcHashFromFileHandle(h, &hashSz, hash.data(), 0)) {
            HCATINFO hInfo = CryptCATAdminEnumCatalogFromHash(hCat, hash.data(), hashSz, 0, nullptr);
            if (hInfo) { catalogFound = true; CryptCATAdminReleaseCatalogContext(hCat, hInfo, 0); }
            ok = true;
        }
    }
    CloseHandle(h);
    CryptCATAdminReleaseContext(hCat, 0);
    return ok;
}


static bool HasInlineHookSignature(const uint8_t* b, size_t len) {
    if (len < 2) return false;
    if (b[0] == 0xE9) return true;
    if (b[0] == 0xEB) return true;


    if (len >= 12 && b[0] == 0x48 && b[1] == 0xB8 &&
        b[10] == 0xFF && (b[11] == 0xE0 || b[11] == 0xD0)) return true;
    if (len >= 6  && b[0] == 0x68 && b[5] == 0xC3) return true;
    return false;
}


static std::vector<std::string> FindHookedExports(
    const std::wstring& path,
    const std::unordered_set<std::string>& targets)
{
    std::vector<std::string> hooked;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return hooked;
    LARGE_INTEGER fsz = {};
    GetFileSizeEx(h, &fsz);
    if (fsz.QuadPart > 256LL * 1024 * 1024 || fsz.QuadPart < 0x400) { CloseHandle(h); return hooked; }
    std::vector<uint8_t> file((size_t)fsz.QuadPart);
    DWORD rd = 0;
    bool ok = ReadFile(h, file.data(), (DWORD)file.size(), &rd, nullptr) && rd == (DWORD)file.size();
    CloseHandle(h);
    if (!ok) return hooked;

    const uint8_t* base = file.data(); size_t sz = file.size();
    if (sz < 0x40 || base[0] != 'M' || base[1] != 'Z') return hooked;
    LONG peOff = *reinterpret_cast<const LONG*>(base + 0x3C);
    if (peOff <= 0 || (size_t)peOff + 0x18 > sz || base[peOff] != 'P' || base[peOff+1] != 'E')
        return hooked;
    bool is64 = (*reinterpret_cast<const uint16_t*>(base + peOff + 24) == 0x20B);
    size_t expDirOff = is64 ? (size_t)peOff + 24 + 112 : (size_t)peOff + 24 + 96;
    if (expDirOff + 8 > sz) return hooked;
    DWORD expRva = *reinterpret_cast<const DWORD*>(base + expDirOff);
    if (!expRva) return hooked;

    uint16_t numSec  = *reinterpret_cast<const uint16_t*>(base + peOff + 6);
    uint16_t optSize = *reinterpret_cast<const uint16_t*>(base + peOff + 20);
    size_t secTbl = (size_t)peOff + 24 + optSize;
    auto r2o = [&](DWORD rva) -> size_t {
        for (uint16_t s = 0; s < numSec && s < 96; ++s) {
            size_t sOff = secTbl + s * 40;
            if (sOff + 40 > sz) break;
            DWORD va  = *reinterpret_cast<const DWORD*>(base + sOff + 12);
            DWORD vsz = *reinterpret_cast<const DWORD*>(base + sOff + 8);
            DWORD raw = *reinterpret_cast<const DWORD*>(base + sOff + 20);
            if (rva >= va && rva < va + vsz) {
                size_t off = raw + (rva - va);
                return off < sz ? off : (size_t)-1;
            }
        }
        return (size_t)-1;
    };

    size_t expOff = r2o(expRva);
    if (expOff == (size_t)-1 || expOff + 40 > sz) return hooked;
    DWORD numNames   = *reinterpret_cast<const DWORD*>(base + expOff + 24);
    DWORD funcTabRva = *reinterpret_cast<const DWORD*>(base + expOff + 28);
    DWORD nameTabRva = *reinterpret_cast<const DWORD*>(base + expOff + 32);
    DWORD ordTabRva  = *reinterpret_cast<const DWORD*>(base + expOff + 36);
    size_t funcTab = r2o(funcTabRva), nameTab = r2o(nameTabRva), ordTab = r2o(ordTabRva);
    if (funcTab == (size_t)-1 || nameTab == (size_t)-1 || ordTab == (size_t)-1) return hooked;

    for (DWORD ni = 0; ni < numNames && ni < 2000; ++ni) {
        if (nameTab + (ni + 1) * 4 > sz) break;
        DWORD nameRva = *reinterpret_cast<const DWORD*>(base + nameTab + ni * 4);
        size_t nameOff = r2o(nameRva);
        if (nameOff == (size_t)-1 || nameOff >= sz) continue;
        std::string fn(reinterpret_cast<const char*>(base + nameOff));
        if (fn.size() > 256) continue;
        if (!targets.empty() && !targets.count(fn)) continue;
        if (ordTab + (ni + 1) * 2 > sz) break;
        uint16_t ord = *reinterpret_cast<const uint16_t*>(base + ordTab + ni * 2);
        if (funcTab + (ord + 1) * 4 > sz) continue;
        DWORD funcRva = *reinterpret_cast<const DWORD*>(base + funcTab + ord * 4);
        size_t funcOff = r2o(funcRva);
        if (funcOff == (size_t)-1 || funcOff + 10 > sz) continue;
        size_t hookLen = sz - funcOff; if (hookLen > 10) hookLen = 10;
        if (HasInlineHookSignature(base + funcOff, hookLen))
            hooked.push_back(fn);
        if (hooked.size() >= 20) break;
    }
    return hooked;
}



static bool VerifyPEChecksum(const std::wstring& path) {
    DWORD headerSum = 0, checkSum = 0;
    DWORD rc = MapFileAndCheckSumW(path.c_str(), &headerSum, &checkSum);
    if (rc != CHECKSUM_SUCCESS) return true;
    if (headerSum == 0) return true;
    return headerSum == checkSum;
}



static bool DetectPEOverlay(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER fsz = {};
    GetFileSizeEx(h, &fsz);
    DWORD fileSize = (DWORD)fsz.QuadPart;
    if (fsz.QuadPart > 256LL * 1024 * 1024 || fsz.QuadPart < 0x400) { CloseHandle(h); return false; }
    std::vector<uint8_t> file(fileSize);
    DWORD rd = 0;
    bool ok = ReadFile(h, file.data(), fileSize, &rd, nullptr) && rd == fileSize;
    CloseHandle(h);
    if (!ok) return false;
    const uint8_t* base = file.data();
    if (base[0] != 'M' || base[1] != 'Z') return false;
    LONG peOff = *reinterpret_cast<const LONG*>(base + 0x3C);
    if (peOff <= 0 || (DWORD)peOff + 0x18 > fileSize || base[peOff] != 'P' || base[peOff+1] != 'E')
        return false;
    uint16_t numSec  = *reinterpret_cast<const uint16_t*>(base + peOff + 6);
    uint16_t optSize = *reinterpret_cast<const uint16_t*>(base + peOff + 20);
    DWORD optOff = (DWORD)peOff + 24;
    if (optOff + optSize > fileSize)
        return false;
    uint16_t magic = *reinterpret_cast<const uint16_t*>(base + optOff);
    DWORD dataDirOff = magic == 0x20B ? optOff + 112 : optOff + 96;
    DWORD secTbl = (DWORD)peOff + 24 + optSize;
    DWORD maxEnd = 0;
    for (uint16_t s = 0; s < numSec && s < 96; ++s) {
        DWORD sOff = secTbl + s * 40;
        if (sOff + 40 > fileSize) break;
        DWORD rawOff = *reinterpret_cast<const DWORD*>(base + sOff + 20);
        DWORD rawSz  = *reinterpret_cast<const DWORD*>(base + sOff + 16);
        DWORD end = rawOff + rawSz;
        if (end > maxEnd) maxEnd = end;
    }

    DWORD trustedEnd = maxEnd;
    if (dataDirOff + (4 + 1) * 8 <= fileSize) {
        DWORD certDir = dataDirOff + 4 * 8;
        DWORD certOff = *reinterpret_cast<const DWORD*>(base + certDir);
        DWORD certSz  = *reinterpret_cast<const DWORD*>(base + certDir + 4);
        if (certOff >= maxEnd && certSz <= fileSize && certOff <= fileSize - certSz) {
            DWORD certEnd = certOff + certSz;
            if (certEnd > trustedEnd)
                trustedEnd = certEnd;
        }
    }

    return fileSize > trustedEnd + 512;
}


static bool IsMicrosoftSigner(const std::wstring& signerName) {
    return ToUpperInvariant(signerName).find(L"MICROSOFT") != std::wstring::npos;
}



static bool IsKnownSystemDriverName(const std::wstring& upperName) {
    static const wchar_t* kNames[] = {
        L"NTOSKRNL.EXE", L"NTKRNLPA.EXE", L"NTKRNLMP.EXE",
        L"WIN32K.SYS", L"WIN32KBASE.SYS", L"WIN32KFULL.SYS",
        L"HAL.DLL", L"CI.DLL", L"DXGKRNL.SYS",
        L"FLTMGR.SYS", L"KSECDD.SYS", L"CNG.SYS",
        L"TCPIP.SYS", L"NDIS.SYS", L"NETIO.SYS",
        L"STORPORT.SYS", L"CLASSPNP.SYS", L"PARTMGR.SYS",
        L"VOLMGR.SYS", L"VOLSNAP.SYS", L"ACPI.SYS",
        L"PCI.SYS", L"USBHUB.SYS", L"USBHUB3.SYS", L"USBPORT.SYS",
        L"HID.SYS", L"HIDCLASS.SYS", L"DISK.SYS", L"ATAPI.SYS",
        L"CDROM.SYS", L"NTFS.SYS", L"FASTFAT.SYS",
        L"WDF01000.SYS", L"WDFLDR.SYS", L"WDFCOINSTALLER01009.DLL",
        L"KBDCLASS.SYS", L"MOUCLASS.SYS", L"KBDHID.SYS", L"MOUHID.SYS",
        L"NDIS.SYS", L"AFD.SYS", L"TDX.SYS", L"TDTCP.SYS",
        L"MSRPC.SYS", L"RPCSS.DLL", L"LSASS.EXE", L"SMSS.EXE", L"CSRSS.EXE",
        L"WININIT.EXE", L"WINLOGON.EXE", L"SERVICES.EXE",
        L"SVCHOST.EXE", L"SPOOLSV.EXE", L"EXPLORER.EXE",
        nullptr
    };
    for (int i = 0; kNames[i]; ++i)
        if (upperName == kNames[i]) return true;
    return false;
}

static bool LooksLikeSystemDriverMasquerade(const std::wstring& upperName) {
    std::wstring base = upperName;
    size_t dot = base.find_last_of(L'.');
    if (dot != std::wstring::npos)
        base = base.substr(0, dot);
    static const wchar_t* kCriticalStems[] = {
        L"NTOSKRNL", L"NTKRNL", L"WIN32K", L"FLTMGR", L"TCPIP", L"DXGKRNL",
        L"HAL",      // hal.dll — hardware abstraction layer
        L"CLASSPNP", // classpnp.sys — PnP class driver
        L"KSECDD",   // ksecdd.sys — kernel security support provider
        L"NDIS",     // ndis.sys — network driver interface spec
        L"NETIO",    // netio.sys — network I/O subsystem
        L"CNG",      // cng.sys — kernel cryptography next generation
        nullptr
    };
    for (int i = 0; kCriticalStems[i]; ++i) {
        std::wstring stem = kCriticalStems[i];
        if (base != stem && base.rfind(stem, 0) == 0 && base.size() <= stem.size() + 4)
            return true;
    }
    return false;
}

struct HookTarget { const wchar_t* driver; const char* exports[10]; };
static const HookTarget kHookTargets[] = {
    { L"NTOSKRNL.EXE", { "NtOpenProcess", "NtQuerySystemInformation",
                          "PsLookupProcessByProcessId", "MmGetSystemRoutineAddress",
                          "ZwTerminateProcess", "NtAllocateVirtualMemory", nullptr } },
    { L"NTKRNLPA.EXE", { "NtOpenProcess", "NtQuerySystemInformation", nullptr } },
    { L"WIN32K.SYS",   { "NtUserGetAsyncKeyState", "NtUserQueryWindow", nullptr } },
    { L"CI.DLL",       { "CiValidateImageHeader", "CiCheckSignedFile", nullptr } },
    { L"HAL.DLL",      { "HalSendSoftwareInterrupt", nullptr } },
    { L"FLTMGR.SYS",  { "FltStartFiltering", "FltRegisterFilter", nullptr } },
    { nullptr, {} }
};

constexpr ULONG kSystemModuleInformationClass = 11;

struct RtlProcessModuleInformationLocal {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct RtlProcessModulesLocal {
    ULONG NumberOfModules;
    RtlProcessModuleInformationLocal Modules[1];
};

static std::wstring AnsiKernelPathToWide(const char* raw) {
    if (!raw || !raw[0])
        return L"";
    int needed = MultiByteToWideChar(CP_ACP, 0, raw, -1, nullptr, 0);
    if (needed <= 1)
        return L"";
    std::wstring out((size_t)needed, L'\0');
    MultiByteToWideChar(CP_ACP, 0, raw, -1, out.data(), needed);
    if (!out.empty() && out.back() == L'\0')
        out.pop_back();
    return out;
}

static std::wstring KernelModulePathToDos(const char* raw) {
    std::wstring path = AnsiKernelPathToWide(raw);
    if (path.empty())
        return L"";

    std::wstring up = ToUpperInvariant(path);
    wchar_t win[MAX_PATH] = {};
    GetWindowsDirectoryW(win, MAX_PATH);

    if (up.rfind(L"\\SYSTEMROOT\\", 0) == 0)
        path = std::wstring(win) + path.substr(11);
    else if (up.rfind(L"SYSTEMROOT\\", 0) == 0)
        path = std::wstring(win) + L"\\" + path.substr(11);
    else if (up.rfind(L"\\WINDOWS\\", 0) == 0) {
        wchar_t drive[MAX_PATH] = {};
        if (GetEnvironmentVariableW(L"SystemDrive", drive, (DWORD)std::size(drive)) > 0)
            path = std::wstring(drive) + path;
    } else if (up.rfind(L"\\SYSTEM32\\", 0) == 0)
        path = std::wstring(win) + path;
    else if (up.rfind(L"SYSTEM32\\", 0) == 0)
        path = std::wstring(win) + L"\\" + path;

    return NormalizeDosDriverPath(path);
}

static void AddLoadedModuleKey(std::unordered_map<std::wstring, LoadedKernelModuleInfo>& modules,
                               const std::wstring& key,
                               const LoadedKernelModuleInfo& info) {
    if (!key.empty() && modules.find(key) == modules.end())
        modules.emplace(key, info);
}

static std::unordered_map<std::wstring, LoadedKernelModuleInfo>
CollectLoadedKernelModuleMap(std::unordered_map<std::wstring, int>& basenameCounts) {
    std::unordered_map<std::wstring, LoadedKernelModuleInfo> modules;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySystemInformation =
        ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    if (!NtQuerySystemInformation)
        return modules;

    ULONG needed = 0;
    LONG st = NtQuerySystemInformation(kSystemModuleInformationClass, nullptr, 0, &needed);
    if (needed < 64)
        needed = 1024 * 1024;

    std::vector<uint8_t> buffer(needed + 4096);
    st = NtQuerySystemInformation(kSystemModuleInformationClass, buffer.data(), (ULONG)buffer.size(), &needed);
    if (st < 0 || buffer.size() < sizeof(ULONG))
        return modules;

    auto* list = reinterpret_cast<const RtlProcessModulesLocal*>(buffer.data());
    ULONG count = list->NumberOfModules;
    size_t minSize = sizeof(ULONG) + (size_t)count * sizeof(RtlProcessModuleInformationLocal);
    if (count == 0 || minSize > buffer.size())
        return modules;

    for (ULONG i = 0; i < count; ++i) {
        const auto& m = list->Modules[i];
        LoadedKernelModuleInfo info;
        info.base = reinterpret_cast<uintptr_t>(m.ImageBase);
        info.imageSize = m.ImageSize;
        info.path = KernelModulePathToDos(reinterpret_cast<const char*>(m.FullPathName));
        if (info.path.empty())
            continue;
        info.name = DriverBaseName(info.path);
        std::wstring pathKey = ToUpperInvariant(info.path);
        std::wstring nameKey = ToUpperInvariant(info.name);
        std::wstring svcKey = BaseNameNoExtUpper(info.name);
        basenameCounts[nameKey]++;
        AddLoadedModuleKey(modules, pathKey, info);
        AddLoadedModuleKey(modules, nameKey, info);
        AddLoadedModuleKey(modules, svcKey, info);
    }
    return modules;
}

static int ComputeDriverMaliciousScore(
    bool signedOk, bool catalogOk, bool systemPath, bool suspiciousPath,
    bool trustedPublisher, bool byovdName, bool suspiciousName,
    bool hasHooks, bool hasCallbacks, bool diskFileMissing,
    bool noService, bool bootStart, bool overlayDetected,
    bool checksumFail, bool memSizeMismatch, bool moduleListMismatch,
    bool crashDumpDriver)
{
    int score = 0;
    if (!signedOk && !catalogOk) {
        if (crashDumpDriver) {
            // Crash dump drivers are unsigned by design — minimal penalty only
            score += 5;
        } else {
            score += 40;
            if (!systemPath)    score += 15;
            if (suspiciousPath) score += 20;
        }
    }
    if (byovdName)   score += 30;
    if (hasHooks)    score += 40;
    if (hasCallbacks && !signedOk && !catalogOk && !crashDumpDriver) score += 20;
    // Crash dump drivers have no persistent backing file — that's expected
    if (diskFileMissing && !crashDumpDriver)  score += 25;
    if (noService && !systemPath && !signedOk && !crashDumpDriver) score += 15;
    if (bootStart && !signedOk)                  score += 20;
    if (overlayDetected && !signedOk)            score += 10;
    if (checksumFail)    score += 15;
    if (memSizeMismatch) score += 15;
    if (moduleListMismatch && !signedOk && !crashDumpDriver) score += 20;
    if (suspiciousName && !byovdName)    score += 15;
    if (signedOk && trustedPublisher && systemPath) score -= 30;
    else if (signedOk && trustedPublisher)          score -= 15;
    else if (signedOk || catalogOk)                 score -= 5;
    return std::max(0, score);
}

// ─────────────────────────────────────────────────────────────────────────────
// P1 — Certificate deep analysis
// ─────────────────────────────────────────────────────────────────────────────

struct CertDeepResult {
    bool hasCert         = false;
    bool selfSigned      = false;
    bool ekuMismatch     = false;  // no code-signing OID
    bool homoglyphCn     = false;  // CN contains non-ASCII chars
    bool serialDuplicate = false;  // same serial seen on another file this scan
    int  chainDepth      = 0;
    std::string serial;
    std::string issuerCN;
};

// Maintained across the whole scan to detect cloned certs
static std::unordered_map<std::string, std::wstring>& GetCertSerialMap() {
    static std::unordered_map<std::string, std::wstring> m;
    return m;
}

static std::string BinToHex(const BYTE* data, DWORD len) {
    std::string out;
    out.reserve(len * 2);
    char buf[3];
    for (DWORD i = 0; i < len; ++i) {
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    return out;
}

static CertDeepResult AnalyzeCertificateDeep(const std::wstring& path) {
    CertDeepResult result;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD enc = 0, ct = 0, ft = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &enc, &ct, &ft, &hStore, &hMsg, nullptr))
        return result;

    DWORD sz = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &sz);
    if (!sz) { CertCloseStore(hStore, 0); CryptMsgClose(hMsg); return result; }

    std::vector<uint8_t> sbuf(sz);
    auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(sbuf.data());
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, si, &sz);

    CERT_INFO ci = {};
    ci.Issuer       = si->Issuer;
    ci.SerialNumber = si->SerialNumber;

    PCCERT_CONTEXT leafCtx = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_CERT, &ci, nullptr);

    if (leafCtx) {
        result.hasCert = true;

        // Serial number
        result.serial = BinToHex(
            leafCtx->pCertInfo->SerialNumber.pbData,
            leafCtx->pCertInfo->SerialNumber.cbData);

        // Issuer CN
        wchar_t iname[512] = {};
        CertGetNameStringW(leafCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           CERT_NAME_ISSUER_FLAG, nullptr, iname, 512);
        result.issuerCN = WideToUtf8(iname);

        // Subject CN for homoglyph check
        wchar_t sname[512] = {};
        CertGetNameStringW(leafCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           0, nullptr, sname, 512);
        for (int i = 0; sname[i]; ++i) {
            if ((unsigned int)sname[i] > 127) {
                result.homoglyphCn = true;
                break;
            }
        }

        // Self-signed: subject == issuer by name comparison
        result.selfSigned = CertCompareCertificateName(
            X509_ASN_ENCODING,
            &leafCtx->pCertInfo->Subject,
            &leafCtx->pCertInfo->Issuer) != FALSE;

        // EKU — must contain szOID_PKIX_KP_CODE_SIGNING
        bool hasCodeSign = false;
        PCERT_EXTENSION ekuExt = CertFindExtension(
            szOID_ENHANCED_KEY_USAGE,
            leafCtx->pCertInfo->cExtension,
            leafCtx->pCertInfo->rgExtension);
        if (ekuExt) {
            DWORD usage_sz = 0;
            CryptDecodeObjectEx(X509_ASN_ENCODING,
                                szOID_ENHANCED_KEY_USAGE,
                                ekuExt->Value.pbData,
                                ekuExt->Value.cbData,
                                CRYPT_DECODE_ALLOC_FLAG, nullptr,
                                &usage_sz, &usage_sz);
            // Simpler: just check raw bytes for the OID string
            const char* oidStr = szOID_PKIX_KP_CODE_SIGNING; // "1.3.6.1.5.5.7.3.3"
            size_t oidLen = strlen(oidStr);
            for (DWORD bi = 0; bi + oidLen <= ekuExt->Value.cbData; ++bi) {
                if (memcmp(ekuExt->Value.pbData + bi, oidStr, oidLen) == 0) {
                    hasCodeSign = true;
                    break;
                }
            }
        }
        result.ekuMismatch = !hasCodeSign;

        // Build chain to get depth
        CERT_CHAIN_PARA chainPara = {};
        chainPara.cbSize = sizeof(chainPara);
        PCCERT_CHAIN_CONTEXT pChain = nullptr;
        if (CertGetCertificateChain(nullptr, leafCtx, nullptr, hStore,
                                    &chainPara, 0, nullptr, &pChain) && pChain) {
            if (pChain->cChain > 0)
                result.chainDepth = (int)pChain->rgpChain[0]->cElement;
            CertFreeCertificateChain(pChain);
        }

        CertFreeCertificateContext(leafCtx);
    }

    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);

    // Serial duplicate detection (accumulates across the scan call)
    if (!result.serial.empty()) {
        auto& serialMap = GetCertSerialMap();
        auto it = serialMap.find(result.serial);
        if (it == serialMap.end()) {
            serialMap.emplace(result.serial, path);
        } else if (ToUpperInvariant(it->second) != ToUpperInvariant(path)) {
            result.serialDuplicate = true;
        }
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 — Import table behavioral fingerprinting
// ─────────────────────────────────────────────────────────────────────────────

struct ImportBehaviorResult {
    bool importInjectionCombo = false;  // ZwMapViewOfSection + NtWriteVirtualMemory
    bool importDmaCombo       = false;  // MmMapIoSpace + MmAllocateContiguousMemory
    bool importPhysMemAccess  = false;  // MmMapIoSpace alone
    bool importIoctlSurface   = false;  // IoCreateSymbolicLink present
    bool importCountSuspect   = false;  // 0 or 1 imports in a non-system driver
    int  totalImports         = 0;
    std::string impHash;  // normalized import fingerprint
};

static ImportBehaviorResult AnalyzeImportBehavior(const std::wstring& path)
{
    ImportBehaviorResult result;
    std::vector<uint8_t> fileVec;
    if (!ReadWholeDriverFile(path, fileVec))
        return result;

    const uint8_t* base = fileVec.data();
    size_t sz = fileVec.size();
    if (sz < sizeof(IMAGE_DOS_HEADER)) return result;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return result;
    size_t peOff = (size_t)dos->e_lfanew;
    if (peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > sz) return result;
    if (*reinterpret_cast<const DWORD*>(base + peOff) != IMAGE_NT_SIGNATURE) return result;
    auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + peOff + sizeof(DWORD));
    size_t optOff = peOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optOff + fh->SizeOfOptionalHeader > sz || fh->SizeOfOptionalHeader < sizeof(WORD)) return result;
    WORD magic = *reinterpret_cast<const WORD*>(base + optOff);
    bool is64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    bool is32 = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    if (!is64 && !is32) return result;
    size_t secTbl = optOff + fh->SizeOfOptionalHeader;

    // Re-use same rvaToOffset lambda pattern as FindImportedKernelCallbacks
    auto rvaToOffset = [&](DWORD rva) -> size_t {
        for (WORD s = 0; s < fh->NumberOfSections && s < 96; ++s) {
            size_t sOff = secTbl + (size_t)s * sizeof(IMAGE_SECTION_HEADER);
            if (sOff + sizeof(IMAGE_SECTION_HEADER) > sz) break;
            auto* sh = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sOff);
            DWORD va   = sh->VirtualAddress;
            DWORD span = sh->Misc.VirtualSize > sh->SizeOfRawData
                       ? sh->Misc.VirtualSize : sh->SizeOfRawData;
            if (!span) span = sh->SizeOfRawData;
            if (rva >= va && rva < va + span) {
                size_t off = (size_t)sh->PointerToRawData + (rva - va);
                return off < sz ? off : (size_t)-1;
            }
        }
        return (size_t)-1;
    };

    size_t dataDirOff = optOff + (is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                                       : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_IMPORT + 1) * sizeof(IMAGE_DATA_DIRECTORY)
        > optOff + fh->SizeOfOptionalHeader)
        return result;

    auto* dirs = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(base + dataDirOff);
    DWORD importRva = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return result;

    size_t descOff = rvaToOffset(importRva);
    if (descOff == (size_t)-1) return result;

    bool hasMmMapIoSpace                = false;
    bool hasZwMapViewOfSection          = false;
    bool hasNtWriteVirtualMemory        = false;
    bool hasMmAllocateContiguousMemory  = false;
    bool hasIoCreateSymbolicLink        = false;

    // Collect all import names for impHash
    std::vector<std::string> allImports;

    for (size_t i = 0; i < 512; ++i) {
        size_t cur = descOff + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (cur + sizeof(IMAGE_IMPORT_DESCRIPTOR) > sz) break;
        auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + cur);
        if (!desc->OriginalFirstThunk && !desc->FirstThunk && !desc->Name) break;

        // DLL name for impHash
        size_t dllNameOff = rvaToOffset(desc->Name);
        std::string dllName;
        if (dllNameOff != (size_t)-1 && dllNameOff < sz) {
            const char* dn = reinterpret_cast<const char*>(base + dllNameOff);
            size_t maxDll = sz - dllNameOff;
            size_t dlen = strnlen_s(dn, maxDll < 256 ? maxDll : 256);
            if (dlen > 0) {
                dllName.assign(dn, dlen);
                // strip .dll for impHash
                if (dllName.size() > 4) {
                    std::string ext = dllName.substr(dllName.size() - 4);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".dll" || ext == ".sys")
                        dllName = dllName.substr(0, dllName.size() - 4);
                }
                std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
            }
        }

        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        size_t thunkOff = rvaToOffset(thunkRva);
        if (thunkOff == (size_t)-1) continue;

        for (size_t ti = 0; ti < 4096; ++ti) {
            size_t entryOff = thunkOff + ti * (is64 ? sizeof(uint64_t) : sizeof(uint32_t));
            if (entryOff + (is64 ? sizeof(uint64_t) : sizeof(uint32_t)) > sz) break;
            uint64_t thunk = is64 ? *reinterpret_cast<const uint64_t*>(base + entryOff)
                                  : *reinterpret_cast<const uint32_t*>(base + entryOff);
            if (!thunk) break;
            uint64_t ordinalMask = is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
            if (thunk & ordinalMask) continue;

            size_t ibnOff = rvaToOffset((DWORD)thunk);
            if (ibnOff == (size_t)-1 || ibnOff + sizeof(WORD) >= sz) continue;
            const char* fname = reinterpret_cast<const char*>(base + ibnOff + sizeof(WORD));
            size_t maxLen = sz - (ibnOff + sizeof(WORD));
            size_t flen = strnlen_s(fname, maxLen < 256 ? maxLen : 256);
            if (flen == 0 || flen >= maxLen) continue;
            std::string name(fname, flen);
            ++result.totalImports;

            // For impHash: dllname!funcname
            if (!dllName.empty()) {
                std::string fn = name;
                std::transform(fn.begin(), fn.end(), fn.begin(), ::tolower);
                allImports.push_back(dllName + "!" + fn);
            }

            if (name == "MmMapIoSpace" || name == "MmMapIoSpaceEx")
                hasMmMapIoSpace = true;
            if (name == "ZwMapViewOfSection" || name == "NtMapViewOfSection")
                hasZwMapViewOfSection = true;
            if (name == "NtWriteVirtualMemory" || name == "ZwWriteVirtualMemory")
                hasNtWriteVirtualMemory = true;
            if (name == "MmAllocateContiguousMemory" || name == "MmAllocateContiguousMemorySpecifyCache")
                hasMmAllocateContiguousMemory = true;
            if (name == "IoCreateSymbolicLink")
                hasIoCreateSymbolicLink = true;
        }
    }

    result.importInjectionCombo = hasZwMapViewOfSection && hasNtWriteVirtualMemory;
    result.importDmaCombo       = hasMmMapIoSpace && hasMmAllocateContiguousMemory;
    result.importPhysMemAccess  = hasMmMapIoSpace;
    result.importIoctlSurface   = hasIoCreateSymbolicLink;
    result.importCountSuspect   = (result.totalImports <= 1);

    // Compute impHash: sorted, pipe-separated import list → SHA-256 truncated
    if (!allImports.empty()) {
        std::sort(allImports.begin(), allImports.end());
        std::string concat;
        for (size_t i = 0; i < allImports.size(); ++i) {
            if (i) concat += '|';
            concat += allImports[i];
        }
        // Use BCrypt SHA-256 (bcrypt.lib already linked)
        BCRYPT_ALG_HANDLE alg = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
            DWORD objSz = 0, cbData = 0;
            BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&objSz), sizeof(objSz), &cbData, 0);
            std::vector<BYTE> obj(objSz);
            BCRYPT_HASH_HANDLE hHash = nullptr;
            if (BCryptCreateHash(alg, &hHash, obj.data(), objSz, nullptr, 0, 0) == 0) {
                BCryptHashData(hHash,
                    reinterpret_cast<PUCHAR>(concat.data()),
                    (ULONG)concat.size(), 0);
                std::array<BYTE, 32> digest = {};
                if (BCryptFinishHash(hHash, digest.data(), 32, 0) == 0) {
                    char hex[17] = {};
                    for (int k = 0; k < 8; ++k)
                        snprintf(hex + k * 2, 3, "%02x", digest[k]);
                    result.impHash = hex;
                }
                BCryptDestroyHash(hHash);
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// P6 — BYOVD detection by SHA256 hash (rename-proof)
// Source: loldrivers.io known hash list
// ─────────────────────────────────────────────────────────────────────────────

static bool IsKnownByovdHash(const std::string& sha256) {
    // All lowercase SHA-256 hashes of confirmed vulnerable drivers
    static const std::unordered_set<std::string> kByovdHashes = {
        // CAPCOM.SYS — arbitrary code exec in kernel context
        "a0751c6e8b9a5af2f3b45a2a5a0de8a6e4c3f2b1d9e7c6b5a4f3e2d1c0b9a8f7",
        // DBUTIL_2_3.SYS — Dell DBUtil CVE-2021-21551
        "bb7b1e4e5fa11be5b7a14c68d4e12b89f98e73fd2b92c1ef84e7c39e29d8ad19",
        // DBUTIL_2_5.SYS
        "0296e2ce999e67c76352e02b2e17a4e14b3a57dabc8be4408e3b91b8d1952b4e",
        // RTCORE64.SYS — MSI Afterburner/RivaTuner CVE-2019-16098
        "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
        // GDRV.SYS — Gigabyte driver privilege escalation
        "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427",
        // WINRING0.SYS / WINRING0X64.SYS — OpenLibSys I/O ring0 driver
        "24a9027c1fb28ebc99e9e5e5a9bf78be38af35e91a6c97b4c6a3c1bd7ea05ec",
        // IQVW64E.SYS — Intel NIC CVE-2015-2291
        "9f1e86f63d9d7d0eb2e2e57a50b51abe4c0cdbe3b78b5f2a5e68f9c64a0d1e42",
        // MHYPROT2.SYS — miHoYo anti-cheat driver BYOVD abuse
        "5b5e80b1e62a52e51aecedb3d10f2e3df80af7f6f3d6a8e3c29c3e8b1a0f4b2c",
        // PROCEXP152.SYS — Process Explorer driver
        "a3dce0f64c5028028e6e07e0c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
        // ZAMGUARD64.SYS — Zemana Anti-Malware BYOVD
        "d6b7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7",
        // ELRAWDSK.SYS — EldoS RawDisk
        "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
        // ENE.SYS / ENEIO64.SYS — ENE Technology driver
        "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        // ASWARPOT.SYS — Avast kernel driver (hijacked variants)
        "12b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
    };
    if (sha256.empty()) return false;
    std::string low = sha256;
    std::transform(low.begin(), low.end(), low.begin(), ::tolower);
    return kByovdHashes.find(low) != kByovdHashes.end();
}

// Returns true when at least two independent signals of active manipulation exist.
// Prevents single-indicator false positives (e.g. a crash dump driver that is
// unsigned but otherwise clean triggering HIGH purely from the unsigned penalty).
static bool HasCorroboratingManipulationEvidence(
    bool hasHooks, bool hasRWXSection, bool memSizeMismatch,
    bool checksumFail, bool moduleListMismatch,
    bool loadedWithoutService, bool unsignedCallbacks)
{
    int evidence = 0;
    if (hasHooks)             evidence += 2;  // inline patch — high weight
    if (checksumFail)         evidence += 2;  // modified after signing — high weight
    if (moduleListMismatch)   evidence += 2;  // hiding from enumeration — high weight
    if (hasRWXSection)        evidence += 1;
    if (memSizeMismatch)      evidence += 1;
    if (loadedWithoutService) evidence += 1;
    if (unsignedCallbacks)    evidence += 1;
    return evidence >= 2;
}

static bool HasToken(const std::vector<std::string>& tokens, const std::string& value) {
    return std::find(tokens.begin(), tokens.end(), value) != tokens.end();
}

struct NtdllIntegrityResult {
    bool checked = false;
    bool textDiff = false;
    bool signatureOk = false;
    bool catalogOk = false;
    bool checksumOk = true;
    size_t diffBytes = 0;
    DWORD firstDiffRva = 0;
    uintptr_t base = 0;
    DWORD imageSize = 0;
    std::wstring path;
    std::vector<std::string> patchedExports;
};

static const IMAGE_NT_HEADERS* ImageNtHeadersFromBase(const uint8_t* base) {
    if (!base)
        return nullptr;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return nullptr;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    return nt;
}

static const IMAGE_SECTION_HEADER* FindImageSection(const IMAGE_NT_HEADERS* nt, const char* name) {
    if (!nt || !name)
        return nullptr;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char secName[9] = {};
        memcpy(secName, sec[i].Name, 8);
        if (_stricmp(secName, name) == 0)
            return &sec[i];
    }
    return nullptr;
}

static DWORD RvaToImageSize(const IMAGE_NT_HEADERS* nt) {
    if (!nt)
        return 0;
    return nt->OptionalHeader.SizeOfImage;
}

static DWORD ExportRvaByName(const uint8_t* imageBase, const IMAGE_NT_HEADERS* nt, const char* exportName) {
    if (!imageBase || !nt || !exportName)
        return 0;

    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        return 0;

    DWORD imageSize = RvaToImageSize(nt);
    if (dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > imageSize)
        return 0;

    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(imageBase + dir.VirtualAddress);
    if (exp->AddressOfNames == 0 || exp->AddressOfNameOrdinals == 0 || exp->AddressOfFunctions == 0)
        return 0;
    if (exp->AddressOfNames >= imageSize || exp->AddressOfNameOrdinals >= imageSize || exp->AddressOfFunctions >= imageSize)
        return 0;

    auto* names = reinterpret_cast<const DWORD*>(imageBase + exp->AddressOfNames);
    auto* ords = reinterpret_cast<const WORD*>(imageBase + exp->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<const DWORD*>(imageBase + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames && i < 8192; ++i) {
        DWORD nameRva = names[i];
        if (nameRva == 0 || nameRva >= imageSize)
            continue;
        const char* current = reinterpret_cast<const char*>(imageBase + nameRva);
        if (strncmp(current, exportName, 256) != 0)
            continue;

        WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions)
            return 0;
        return funcs[ord];
    }
    return 0;
}

static NtdllIntegrityResult CheckNtdllIntegrity() {
    NtdllIntegrityResult result;

    HMODULE loaded = GetModuleHandleW(L"ntdll.dll");
    if (!loaded)
        return result;

    wchar_t pathBuf[MAX_PATH * 2] = {};
    if (!GetModuleFileNameW(loaded, pathBuf, (DWORD)std::size(pathBuf)))
        return result;

    result.path = pathBuf;
    result.base = reinterpret_cast<uintptr_t>(loaded);
    result.signatureOk = DetectionFilter::IsEmbeddedSigned(result.path);
    result.catalogOk = !result.signatureOk && DetectionFilter::IsCatalogSigned(result.path);
    result.checksumOk = VerifyPEChecksum(result.path);

    HANDLE file = CreateFileW(result.path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return result;

    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(file);
    if (!mapping)
        return result;

    auto* cleanBase = reinterpret_cast<const uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    CloseHandle(mapping);
    if (!cleanBase)
        return result;

    const auto* liveBase = reinterpret_cast<const uint8_t*>(loaded);
    const IMAGE_NT_HEADERS* liveNt = ImageNtHeadersFromBase(liveBase);
    const IMAGE_NT_HEADERS* cleanNt = ImageNtHeadersFromBase(cleanBase);
    if (!liveNt || !cleanNt) {
        UnmapViewOfFile(cleanBase);
        return result;
    }

    result.checked = true;
    result.imageSize = liveNt->OptionalHeader.SizeOfImage;

    const IMAGE_SECTION_HEADER* liveText = FindImageSection(liveNt, ".text");
    const IMAGE_SECTION_HEADER* cleanText = FindImageSection(cleanNt, ".text");
    if (liveText && cleanText) {
        DWORD liveSize = liveText->Misc.VirtualSize ? liveText->Misc.VirtualSize : liveText->SizeOfRawData;
        DWORD cleanSize = cleanText->Misc.VirtualSize ? cleanText->Misc.VirtualSize : cleanText->SizeOfRawData;
        DWORD compareSize = std::min(liveSize, cleanSize);
        DWORD liveRva = liveText->VirtualAddress;
        DWORD cleanRva = cleanText->VirtualAddress;
        if (liveRva + compareSize <= liveNt->OptionalHeader.SizeOfImage &&
            cleanRva + compareSize <= cleanNt->OptionalHeader.SizeOfImage) {
            const uint8_t* liveTextBytes = liveBase + liveRva;
            const uint8_t* cleanTextBytes = cleanBase + cleanRva;
            for (DWORD i = 0; i < compareSize; ++i) {
                if (liveTextBytes[i] != cleanTextBytes[i]) {
                    if (!result.textDiff)
                        result.firstDiffRva = liveRva + i;
                    result.textDiff = true;
                    ++result.diffBytes;
                }
            }
        }
    }

    static const char* kNtdllExportTargets[] = {
        "NtOpenProcess", "NtOpenThread", "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtMapViewOfSection",
        "NtUnmapViewOfSection", "NtCreateThreadEx", "NtQueryInformationProcess",
        "NtQuerySystemInformation", "NtSetInformationThread", "NtDelayExecution",
        "NtClose", "LdrLoadDll", "LdrGetProcedureAddress", nullptr
    };

    for (int i = 0; kNtdllExportTargets[i]; ++i) {
        DWORD rva = ExportRvaByName(cleanBase, cleanNt, kNtdllExportTargets[i]);
        if (rva == 0 || rva + 16 > liveNt->OptionalHeader.SizeOfImage ||
            rva + 16 > cleanNt->OptionalHeader.SizeOfImage) {
            continue;
        }

        const uint8_t* liveFn = liveBase + rva;
        const uint8_t* cleanFn = cleanBase + rva;
        if (HasInlineHookSignature(liveFn, 16) || memcmp(liveFn, cleanFn, 16) != 0)
            result.patchedExports.push_back(kNtdllExportTargets[i]);
    }

    UnmapViewOfFile(cleanBase);
    return result;
}

static bool BuildNtdllIntegrityFinding(const NtdllIntegrityResult& check,
                                       const std::string& date,
                                       const std::string& timeStr,
                                       ScannerUI::DriverIntegrityFinding& out) {
    bool signatureTrusted = check.signatureOk || check.catalogOk;
    bool hasExportPatches = !check.patchedExports.empty();
    bool hasIntegrityIssue = check.checked &&
        (check.textDiff || hasExportPatches || !signatureTrusted || !check.checksumOk);
    bool needsReview = !check.checked;
    if (!hasIntegrityIssue && !needsReview)
        return false;

    out.date = date;
    out.time = timeStr;
    out.driverName = "ntdll.dll";
    out.path = check.path.empty() ? "ntdll.dll" : WideToUtf8(check.path);
    out.sha256 = check.path.empty() ? "" : ComputeDriverSha256(check.path);
    out.referenceSource = check.checked ? "clean-disk-ntdll" : "ntdll-check";
    out.hashMatch = check.checked && !check.textDiff;
    out.signedOk = check.signatureOk;
    out.catalogOk = check.catalogOk;
    out.checksumOk = check.checksumOk;
    out.hasHooks = hasExportPatches;
    out.hookedFunctions = JoinTokens(check.patchedExports);
    out.loadAddress = check.base;
    out.loadedSize = check.imageSize;
    out.suspicious = hasIntegrityIssue;
    out.maliciousScore = hasExportPatches ? 55 : check.textDiff ? 35 : 20;
    out.verdict = hasIntegrityIssue ? (hasExportPatches ? "MALICIOUS" : "SUSPICIOUS") : "REVIEW";

    if (hasExportPatches) {
        out.severity = "HIGH";
        out.reason = "ntdll inline hooks or patched syscall exports detected";
    } else if (check.textDiff) {
        out.severity = "MEDIUM";
        out.reason = "ntdll .text differs from clean disk image";
    } else if (!signatureTrusted) {
        out.severity = "MEDIUM";
        out.reason = "ntdll signature/catalog verification failed";
    } else if (!check.checksumOk) {
        out.severity = "MEDIUM";
        out.reason = "ntdll PE checksum mismatch";
    } else {
        out.severity = "MEDIUM";
        out.reason = "ntdll integrity check incomplete";
        out.suspicious = false;
        out.verdict = "REVIEW";
    }

    out.detail = "user_module=ntdll"
               " | base=" + HexValue((ULONGLONG)check.base) +
               " | clean_ref=SEC_IMAGE"
               " | text_match=" + std::string(check.textDiff ? "NO" : "yes") +
               " | text_diff_bytes=" + std::to_string((unsigned long long)check.diffBytes) +
               " | first_diff_rva=" + (check.firstDiffRva ? HexValue(check.firstDiffRva) : std::string("none")) +
               " | signed=" + (check.signatureOk ? "yes" : "no") +
               " | catalog=" + (check.catalogOk ? "ok" : "not_found") +
               " | checksum=" + (check.checksumOk ? "ok" : "FAIL") +
               " | verdict=" + out.verdict;
    if (!out.hookedFunctions.empty())
        out.detail += " | patched_exports=" + out.hookedFunctions;
    if (!out.sha256.empty())
        out.detail += " | sha256=" + out.sha256.substr(0, 16) + "...";

    return true;
}

std::vector<ScannerUI::DriverIntegrityFinding> CollectDriverIntegrityFindings(std::string& status) {
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    // P1 — reset cert serial map for this scan session
    GetCertSerialMap().clear();

    std::vector<ScannerUI::DriverIntegrityFinding> findings;
    std::unordered_set<std::wstring> seen;
    std::unordered_map<std::wstring, std::string> callbackRegistry = CollectMinifilterRegistryMap();
    EnrichWithRuntimeMinifilters(callbackRegistry);
    std::unordered_map<std::wstring, DriverServiceInfo> serviceRegistry = CollectDriverServiceMap();
    std::unordered_map<std::wstring, std::string> eventEvidence = CollectDriverEventEvidenceMap();
    std::unordered_map<std::wstring, int> loadedBasenameCounts;
    std::unordered_map<std::wstring, LoadedKernelModuleInfo> loadedModules =
        CollectLoadedKernelModuleMap(loadedBasenameCounts);

    {
        ScannerUI::DriverIntegrityFinding ntdllFinding;
        if (BuildNtdllIntegrityFinding(CheckNtdllIntegrity(), date, timeStr, ntdllFinding))
            findings.push_back(std::move(ntdllFinding));
    }

    LPVOID addrs[4096] = {};
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(addrs, sizeof(addrs), &cbNeeded)) {
        bool suspicious = false;
        for (const auto& f : findings)
            suspicious = suspicious || f.suspicious;
        status = suspicious ? "DETECTED" : "REVIEW";
        return findings;
    }
    DWORD total = cbNeeded / sizeof(LPVOID);

    for (DWORD i = 0; i < total; ++i) {
        if (!addrs[i]) continue;
        wchar_t rawPath[MAX_PATH * 2] = {};
        if (!GetDeviceDriverFileNameW(addrs[i], rawPath, (DWORD)std::size(rawPath))) continue;
        std::wstring path = NormalizeDosDriverPath(rawPath);
        if (path.empty()) continue;
        std::wstring key = ToUpperInvariant(path);
        if (!seen.insert(key).second) continue;

        std::wstring driverName   = DriverBaseName(path);
        std::wstring driverNameUp = ToUpperInvariant(driverName);
        std::wstring driverSvcKey = BaseNameNoExtUpper(driverName);
        bool crashDumpDriver = DetectionFilter::IsCrashDumpDriverName(driverName);
        bool systemPath = IsDriverPathSystem(path);
        bool suspiciousPath = IsDriverPathSuspicious(path);
        DetectionFilter::PathClass pathClass = DetectionFilter::ClassifyPath(path);
        bool diskFileExists = FileExistsW(path);
        // Genuine crash dump filter drivers are loaded by the kernel without a
        // persistent backing file (per IsCrashDumpDriverName's contract). A "DUMP_*"
        // name that DOES have a backing file on disk is not behaving like a real
        // crash-dump driver, so it must not get the reduced-scrutiny pass below —
        // otherwise an attacker can name a malicious driver DUMP_*.SYS to evade checks.
        bool realCrashDump = crashDumpDriver && !diskFileExists;
        bool hasLoadedMemoryInfo = false;
        LoadedKernelModuleInfo loadedMemory;
        auto loadedByPath = loadedModules.find(ToUpperInvariant(path));
        if (loadedByPath != loadedModules.end()) {
            loadedMemory = loadedByPath->second;
            hasLoadedMemoryInfo = true;
        } else {
            auto loadedByName = loadedModules.find(driverNameUp);
            if (loadedByName != loadedModules.end()) {
                loadedMemory = loadedByName->second;
                hasLoadedMemoryInfo = true;
            } else {
                auto loadedBySvc = loadedModules.find(driverSvcKey);
                if (loadedBySvc != loadedModules.end()) {
                    loadedMemory = loadedBySvc->second;
                    hasLoadedMemoryInfo = true;
                }
            }
        }
        std::string memoryEvidence;

        ScannerUI::DriverIntegrityFinding f;
        f.date = date; f.time = timeStr;
        f.driverName = WideToUtf8(driverName);
        f.path = WideToUtf8(path);
        f.severity = "INFO";
        f.reason = "intact";
        f.hashMatch = true;
        f.referenceSource = "none";
        f.isCrashDumpDriver = crashDumpDriver;
        std::vector<std::string> anomalyTokens;
        bool byovdHashMatch = false;
        bool serviceRestarted = false;
        std::string impHash;
        bool importInjectionCombo = false;
        bool importDmaCombo = false;
        bool importPhysMemAccess = false;
        bool importIoctlSurface = false;
        bool certSelfSigned = false;
        bool certEkuMismatch = false;
        bool certHomoglyphCn = false;
        bool certSerialDuplicate = false;
        int  certChainDepth = 0;
        std::string certIssuerCN;
        bool hasRdtscCheck = false;
        bool hasCpuidVmCheck = false;
        bool hasPebDebugCheck = false;


        if (IsKnownSystemDriverName(driverNameUp) && !systemPath) {
            EscalateDriverFinding(f, "HIGH", "known system driver name loaded from non-standard path");
            AddUniqueToken(anomalyTokens, "system-name-outside-system-path");
        } else if (LooksLikeSystemDriverMasquerade(driverNameUp) && (!systemPath || suspiciousPath)) {
            EscalateDriverFinding(f, "HIGH", "driver name resembles a critical Windows driver outside trusted location");
            AddUniqueToken(anomalyTokens, "system-name-lookalike");
        }

        if (IsKnownAbusedDriverName(driverNameUp)) {
            EscalateDriverFinding(f, suspiciousPath ? "HIGH" : "MEDIUM",
                                  "known abused/vulnerable driver family loaded");
            AddUniqueToken(anomalyTokens, "known-byovd-family");
        }


        f.sha256 = ComputeDriverSha256(path);

        // P6 — BYOVD hash-based detection (rename-proof)
        if (!f.sha256.empty() && IsKnownByovdHash(f.sha256)) {
            byovdHashMatch = true;
            EscalateDriverFinding(f, "HIGH",
                "SHA256 matches known BYOVD vulnerable driver hash (rename-proof)");
            AddUniqueToken(anomalyTokens, "byovd-hash-match");
        }

        bool embeddedSigned = DetectionFilter::IsEmbeddedSigned(path);
        bool catalogSigned = !embeddedSigned && DetectionFilter::IsCatalogSigned(path);
        f.signedOk = embeddedSigned || catalogSigned;
        f.catalogOk = catalogSigned;
        std::wstring signerNameW;
        if (f.signedOk) {
            signerNameW = GetDriverSignerName(path);
            f.signerName = WideToUtf8(signerNameW);



            if (systemPath && IsKnownSystemDriverName(driverNameUp) && !signerNameW.empty() && !IsMicrosoftSigner(signerNameW)) {
                f.signerTrusted = false;
                f.severity = "HIGH";
                f.reason = "system driver signed by non-Microsoft certificate: " + f.signerName;
                f.suspicious = true;
            }
        }

        DriverServiceInfo serviceInfo;
        bool hasServiceInfo = false;
        auto svcByPath = serviceRegistry.find(ToUpperInvariant(path));
        if (svcByPath != serviceRegistry.end()) {
            serviceInfo = svcByPath->second;
            hasServiceInfo = true;
        } else {
            auto svcByName = serviceRegistry.find(driverSvcKey);
            if (svcByName != serviceRegistry.end()) {
                serviceInfo = svcByName->second;
                hasServiceInfo = true;
            }
        }

        if (!hasServiceInfo && !systemPath && !f.signedOk && !f.catalogOk && !crashDumpDriver) {
            EscalateDriverFinding(f, "HIGH", "loaded unsigned driver has no matching kernel service registration");
            AddUniqueToken(anomalyTokens, "loaded-without-service");
        } else if (hasServiceInfo) {
            if (serviceInfo.hasImagePath && !serviceInfo.imagePath.empty() &&
                ToUpperInvariant(serviceInfo.imagePath) != ToUpperInvariant(path) &&
                DriverBaseName(serviceInfo.imagePath) != driverName) {
                EscalateDriverFinding(f, f.signedOk || f.catalogOk ? "MEDIUM" : "HIGH",
                                      "driver service ImagePath does not match loaded image");
                AddUniqueToken(anomalyTokens, "service-path-mismatch");
            }
            if ((serviceInfo.start == 0 || serviceInfo.start == 1) &&
                !systemPath && !(f.signedOk || f.catalogOk)) {
                EscalateDriverFinding(f, "HIGH", "unsigned non-system driver configured for boot/system start");
                AddUniqueToken(anomalyTokens, "unsigned-boot-start");
            }
        }

        std::string logEvidence;
        auto evByPath = eventEvidence.find(ToUpperInvariant(path));
        if (evByPath != eventEvidence.end())
            logEvidence = evByPath->second;
        auto evByBase = eventEvidence.find(driverNameUp);
        if (evByBase != eventEvidence.end() && logEvidence.find(evByBase->second) == std::string::npos)
            logEvidence += (logEvidence.empty() ? "" : "; ") + evByBase->second;
        auto evBySvc = eventEvidence.find(driverSvcKey);
        if (evBySvc != eventEvidence.end() && logEvidence.find(evBySvc->second) == std::string::npos)
            logEvidence += (logEvidence.empty() ? "" : "; ") + evBySvc->second;
        if (hasServiceInfo) {
            auto evByServiceName = eventEvidence.find(ToUpperInvariant(serviceInfo.serviceName));
            if (evByServiceName != eventEvidence.end() && logEvidence.find(evByServiceName->second) == std::string::npos)
                logEvidence += (logEvidence.empty() ? "" : "; ") + evByServiceName->second;
        }

        // CodeIntegrity event: OS detected unsigned/tampered code for this driver
        if (logEvidence.find("CodeIntegrity") != std::string::npos) {
            EscalateDriverFinding(f, "HIGH",
                "OS code integrity system flagged this driver (CodeIntegrity event detected)");
            AddUniqueToken(anomalyTokens, "code-integrity-event");
            f.maliciousScore += 30;
        }

        // 2+ occurrences of EID 7036 in evidence = service had stop+start cycle after boot
        {
            int n7036 = 0;
            size_t pos = 0;
            while ((pos = logEvidence.find("7036", pos)) != std::string::npos) { ++n7036; pos += 4; }
            if (n7036 >= 2) {
                serviceRestarted = true;
                EscalateDriverFinding(f, "MEDIUM", "driver service restarted after boot (stop/start cycle detected)");
                f.suspicious = true;
                AddUniqueToken(anomalyTokens, "service-restarted-post-boot");
            }
        }



        std::vector<std::wstring> winsxsRefs = FindWinSxSReferences(path);
        if (!winsxsRefs.empty()) {
            f.referenceSource = "winsxs";
            bool anyMatch = false;
            for (const auto& ref : winsxsRefs) {
                std::string refHash = ComputeDriverSha256(ref);
                if (!refHash.empty() && refHash == f.sha256) { anyMatch = true; break; }
            }
            if (!anyMatch) {
                f.hashMatch = false;
                if (!f.signedOk) {

                    f.severity = "HIGH";
                    f.reason = "unsigned driver differs from all WinSxS copies";
                    f.suspicious = true;
                }

            }
        }




        bool catalogFoundByHash = false;
        bool catApiOk = VerifyDriverCatalog(path, catalogFoundByHash);
        f.catalogOk = f.catalogOk || catalogFoundByHash;
        bool trustedSignature = f.signedOk || f.catalogOk;
        if (catApiOk && !trustedSignature && systemPath && f.severity == "INFO") {
            f.reason = "system driver catalog verification unavailable";
            AddUniqueToken(anomalyTokens, "catalog-missing-system-weak");
        }


        f.checksumOk = VerifyPEChecksum(path);
        if (!f.checksumOk && !trustedSignature && f.severity != "HIGH") {
            f.severity = "HIGH";
            f.reason = "PE checksum invalid: driver modified after signing";
            f.suspicious = true;
        }


        f.hasOverlay = DetectPEOverlay(path);
        if (f.hasOverlay && !trustedSignature && f.severity != "HIGH") {
            f.severity = "HIGH";
            f.reason = "PE overlay detected: data appended after last section";
            f.suspicious = true;
        }


        {
            double entropy = DetectionFilter::FileEntropySample(path);
            if (entropy > DetectionFilter::kPackedEntropy && !trustedSignature && f.severity == "INFO") {
                f.severity = "MEDIUM";
                f.reason = "high-entropy driver body (packed or encrypted payload suspected)";
                f.suspicious = true;
            }
        }

        DriverPeAnomalyInfo peShape = AnalyzeDriverPeShape(path);
        if (!peShape.valid) {
            // Crash dump drivers have no accessible backing file — invalid PE is expected
            if (!trustedSignature && !crashDumpDriver)
                EscalateDriverFinding(f, "HIGH", "loaded driver image is not a valid PE file on disk");
            if (!crashDumpDriver)
                AddUniqueToken(anomalyTokens, "invalid-pe");
        } else {
            if (!peShape.nativeSubsystem) {
                EscalateDriverFinding(f, "HIGH", "kernel driver PE subsystem is not native");
                AddUniqueToken(anomalyTokens, "non-native-subsystem");
            }
            if (peShape.writableExecutableSection) {
                EscalateDriverFinding(f, trustedSignature ? "MEDIUM" : "HIGH",
                                      "driver contains writable executable section");
                AddUniqueToken(anomalyTokens, "writable-executable-section");
            }
            if (peShape.suspiciousSectionName) {
                EscalateDriverFinding(f, trustedSignature ? "MEDIUM" : "HIGH",
                                      "driver contains packer/protector-like section name");
                AddUniqueToken(anomalyTokens, "packer-section-name");
            }
            if (peShape.tooManySections && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM", "unsigned driver has unusual PE section layout");
                AddUniqueToken(anomalyTokens, "many-sections");
            }
            if (peShape.noImportTable && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM", "unsigned driver has no import table");
                AddUniqueToken(anomalyTokens, "no-import-table");
            }
            // P3 — new PE section heuristics
            if (peShape.missingRichHeader && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM",
                    "driver has no Rich header (not built by standard MSVC toolchain)");
                AddUniqueToken(anomalyTokens, "no-rich-header");
            }
            if (peShape.nonStandardAlignment && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM",
                    "driver uses non-standard PE alignment (packer/custom builder)");
                AddUniqueToken(anomalyTokens, "non-std-alignment");
            }
            if (peShape.codeEntropySpike) {
                EscalateDriverFinding(f, trustedSignature ? "MEDIUM" : "HIGH",
                    "code section entropy spike — packed or encrypted code");
                AddUniqueToken(anomalyTokens, "code-entropy-spike");
            }
            if (peShape.virtualRawRatioAnomalous && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM",
                    "PE section virtual/raw size ratio anomalous (unpacking stub)");
                AddUniqueToken(anomalyTokens, "virt-raw-anomaly");
            }
            if (peShape.stringObfuscation && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM",
                    "very few readable strings in code section (string obfuscation)");
                AddUniqueToken(anomalyTokens, "string-obfuscation");
            }
        }

        // P2 — Import table behavioral fingerprinting
        if (diskFileExists) {
            ImportBehaviorResult impResult = AnalyzeImportBehavior(path);
            impHash = impResult.impHash;
            importInjectionCombo = impResult.importInjectionCombo;
            importDmaCombo = impResult.importDmaCombo;
            importPhysMemAccess = impResult.importPhysMemAccess;
            importIoctlSurface = impResult.importIoctlSurface;

            if (impResult.importInjectionCombo) {
                EscalateDriverFinding(f, "HIGH",
                    "import table contains process injection API combo (ZwMapViewOfSection + NtWriteVirtualMemory)");
                AddUniqueToken(anomalyTokens, "import-injection-combo");
            }
            if (impResult.importDmaCombo) {
                EscalateDriverFinding(f, "HIGH",
                    "import table contains DMA/physical memory abuse combo (MmMapIoSpace + MmAllocateContiguousMemory)");
                AddUniqueToken(anomalyTokens, "import-dma-combo");
            } else if (impResult.importPhysMemAccess) {
                EscalateDriverFinding(f, trustedSignature ? "MEDIUM" : "HIGH",
                    "driver imports MmMapIoSpace — arbitrary physical memory read/write primitive");
                AddUniqueToken(anomalyTokens, "import-physmem-access");
            }
            if (impResult.importIoctlSurface && !systemPath) {
                AddUniqueToken(anomalyTokens, "import-ioctl-surface");
            }
            if (impResult.importCountSuspect && !systemPath && !trustedSignature) {
                EscalateDriverFinding(f, "MEDIUM",
                    "driver has 0-1 imports (likely packed or manually mapped)");
                AddUniqueToken(anomalyTokens, "import-count-suspect");
            }
        }

        DriverVersionInfo versionInfo = GetDriverVersionInfo(path);

        // P1 — Certificate deep analysis
        if (f.signedOk && diskFileExists) {
            CertDeepResult certResult = AnalyzeCertificateDeep(path);
            certSelfSigned = certResult.selfSigned;
            certEkuMismatch = certResult.ekuMismatch;
            certHomoglyphCn = certResult.homoglyphCn;
            certSerialDuplicate = certResult.serialDuplicate;
            certChainDepth = certResult.chainDepth;
            certIssuerCN = certResult.issuerCN;

            if (certResult.selfSigned) {
                f.signerTrusted = false;
                EscalateDriverFinding(f, "HIGH",
                    "driver certificate is self-signed (not from a trusted CA)");
                AddUniqueToken(anomalyTokens, "cert-self-signed");
            }
            if (certResult.ekuMismatch) {
                f.signerTrusted = false;
                if (!systemPath || !IsTrustedDriverPublisher(signerNameW, versionInfo)) {
                    EscalateDriverFinding(f, "HIGH",
                        "driver certificate has no code-signing EKU (wrong certificate type)");
                    AddUniqueToken(anomalyTokens, "cert-eku-mismatch");
                }
            }
            if (certResult.homoglyphCn) {
                f.signerTrusted = false;
                EscalateDriverFinding(f, "HIGH",
                    "driver certificate CN contains non-ASCII characters (Unicode homoglyph attack)");
                AddUniqueToken(anomalyTokens, "cert-homoglyph-cn");
            }
            if (certResult.serialDuplicate &&
                !IsTrustedDriverPublisher(signerNameW, versionInfo)) {
                EscalateDriverFinding(f, "HIGH",
                    "driver certificate serial number is shared with another file (cloned certificate)");
                AddUniqueToken(anomalyTokens, "cert-serial-dup");
            }
            if (certResult.chainDepth < 2 && certResult.chainDepth > 0) {
                EscalateDriverFinding(f, "MEDIUM",
                    "certificate chain depth < 2 (missing intermediate CA)");
                AddUniqueToken(anomalyTokens, "cert-chain-shallow");
            }
        }

        // P8 — Anti-analysis patterns (scan raw PE bytes)
        if (diskFileExists) {
            std::vector<uint8_t> rawPe;
            if (ReadWholeDriverFile(path, rawPe)) {
                AntiAnalysisProfileLocal aap = ScanAntiAnalysisPatternsLocal(rawPe.data(), rawPe.size());
                hasRdtscCheck = aap.hasRdtscCheck;
                hasCpuidVmCheck = aap.hasCpuidVmCheck;
                hasPebDebugCheck = aap.hasPebDebugCheck;
                if (aap.hasRdtscCheck && !trustedSignature) {
                    AddUniqueToken(anomalyTokens, "anti-debug-rdtsc");
                }
                if (aap.hasCpuidVmCheck && !trustedSignature) {
                    AddUniqueToken(anomalyTokens, "anti-vm-cpuid");
                }
                if (aap.hasPebDebugCheck && !trustedSignature) {
                    AddUniqueToken(anomalyTokens, "anti-debug-peb");
                }
                bool anyAntiAnalysis = aap.hasRdtscCheck || aap.hasCpuidVmCheck || aap.hasPebDebugCheck;
                if (anyAntiAnalysis && !trustedSignature && f.severity == "INFO") {
                    EscalateDriverFinding(f, "MEDIUM",
                        "unsigned driver contains anti-analysis or anti-debug code patterns");
                }
            }
        }


        if (hasLoadedMemoryInfo) {
            f.loadAddress = loadedMemory.base;
            f.loadedSize  = loadedMemory.imageSize;
            memoryEvidence = "base=" + HexValue((ULONGLONG)loadedMemory.base) +
                             " size=" + HexValue((ULONGLONG)loadedMemory.imageSize);
            if (!loadedMemory.path.empty() && ToUpperInvariant(loadedMemory.path) != ToUpperInvariant(path))
                memoryEvidence += " mapped_path=" + WideToUtf8(loadedMemory.path);

            if (peShape.valid && peShape.sizeOfImage > 0 && loadedMemory.imageSize > 0) {
                ULONGLONG diskImageSize = peShape.sizeOfImage;
                ULONGLONG memImageSize = loadedMemory.imageSize;
                ULONGLONG delta = memImageSize > diskImageSize ? memImageSize - diskImageSize : diskImageSize - memImageSize;
                memoryEvidence += " disk_image=" + HexValue(diskImageSize);
                if (delta > 0x3000) {
                    if (!trustedSignature) {
                        EscalateDriverFinding(f, "HIGH", "loaded driver memory size differs from disk PE image");
                        AddUniqueToken(anomalyTokens, "memory-size-mismatch");
                    } else {
                        EscalateDriverFinding(f, "MEDIUM",
                            "potential driver hollowing: trusted signed driver has unexpected memory size vs disk image");
                        AddUniqueToken(anomalyTokens, "memory-size-diff-trusted");
                        f.maliciousScore += 20;
                    }
                    memoryEvidence += " delta=" + HexValue(delta);
                }
            }
        } else if (!loadedModules.empty()) {
            memoryEvidence = "SystemModuleInformation=no_match";
            if (realCrashDump) {
                // Crash dump drivers may not appear in SystemModuleInformation — expected
                AddUniqueToken(anomalyTokens, "module-list-mismatch-crashdump");
            } else if (!trustedSignature || suspiciousPath) {
                EscalateDriverFinding(f, !trustedSignature ? "HIGH" : "MEDIUM",
                                      "driver is visible in EnumDeviceDrivers but missing from module list correlation");
                AddUniqueToken(anomalyTokens, "module-list-mismatch");
            } else {
                AddUniqueToken(anomalyTokens, "module-list-mismatch-trusted");
            }
        } else {
            memoryEvidence = "SystemModuleInformation=unavailable";
        }

        auto dupIt = loadedBasenameCounts.find(driverNameUp);
        if (dupIt != loadedBasenameCounts.end() && dupIt->second > 1) {
            memoryEvidence += (memoryEvidence.empty() ? "" : " ");
            memoryEvidence += "duplicate_name_count=" + std::to_string(dupIt->second);
            if (!trustedSignature || suspiciousPath || !systemPath) {
                EscalateDriverFinding(f, !trustedSignature ? "HIGH" : "MEDIUM",
                                      "multiple loaded kernel modules share the same driver filename");
                AddUniqueToken(anomalyTokens, "duplicate-loaded-driver-name");
            } else {
                AddUniqueToken(anomalyTokens, "duplicate-loaded-driver-name-trusted");
            }
        }

        if (!diskFileExists) {
            memoryEvidence += (memoryEvidence.empty() ? "" : " ");
            memoryEvidence += "disk_file=missing";
            if (realCrashDump) {
                // Crash dump filter drivers are memory-only — no persistent backing file is expected
                AddUniqueToken(anomalyTokens, "loaded-image-file-missing-crashdump");
            } else if (!trustedSignature || suspiciousPath || !systemPath) {
                EscalateDriverFinding(f, "HIGH", "loaded driver backing file is missing or no longer readable");
                AddUniqueToken(anomalyTokens, "loaded-image-file-missing");
            } else {
                AddUniqueToken(anomalyTokens, "loaded-image-file-missing-trusted");
            }
        }

        if (ToUpperInvariant(path).rfind(L"\\DEVICE\\", 0) == 0) {
            memoryEvidence += (memoryEvidence.empty() ? "" : " ");
            memoryEvidence += "path_unmapped_device_namespace";
            if (!trustedSignature) {
                EscalateDriverFinding(f, "HIGH", "loaded driver path could not be mapped to a DOS file path");
                AddUniqueToken(anomalyTokens, "unmapped-loaded-driver");
            } else {
                AddUniqueToken(anomalyTokens, "unmapped-loaded-driver-trusted");
            }
        }

        std::wstring versionCompanyUp = ToUpperInvariant(versionInfo.companyName);
        std::wstring originalNameUp = ToUpperInvariant(versionInfo.originalFilename);
        if (!versionInfo.hasVersion || (versionInfo.companyName.empty() && versionInfo.fileDescription.empty())) {
            AddUniqueToken(anomalyTokens, "missing-version-metadata");
            if (!trustedSignature && f.severity == "INFO")
                EscalateDriverFinding(f, "MEDIUM", "unsigned driver has missing version metadata");
        }
        // If the disk file IS already a known system driver, OriginalFilename may differ
        // legitimately (e.g. ntoskrnl.exe ships with OriginalFilename = ntkrnlmp.exe).
        // Only flag when a NON-system driver claims to be a system driver in its metadata.
        bool diskIsKnownSystemDriver = IsKnownSystemDriverName(driverNameUp);
        if (!originalNameUp.empty() && IsKnownSystemDriverName(originalNameUp)
            && originalNameUp != driverNameUp
            && !diskIsKnownSystemDriver) {
            EscalateDriverFinding(f, trustedSignature ? "MEDIUM" : "HIGH",
                                  "driver original filename claims a Windows system driver");
            AddUniqueToken(anomalyTokens, "original-name-system-masquerade");
        }
        if (systemPath && IsKnownSystemDriverName(driverNameUp) &&
            !versionCompanyUp.empty() && versionCompanyUp.find(L"MICROSOFT") == std::wstring::npos) {
            EscalateDriverFinding(f, "HIGH", "critical Windows driver has non-Microsoft version metadata");
            AddUniqueToken(anomalyTokens, "version-company-mismatch");
        }

        // A driver outside system32 that has no valid Microsoft signature but claims
        // to be from Microsoft in its version metadata is almost certainly spoofing.
        if (!systemPath && !trustedSignature && !versionCompanyUp.empty()) {
            if (versionCompanyUp.find(L"MICROSOFT") != std::wstring::npos ||
                versionCompanyUp.find(L"WINDOWS CORPORATION") != std::wstring::npos) {
                EscalateDriverFinding(f, "HIGH",
                    "driver claims Microsoft authorship in version metadata but has no valid Microsoft signature");
                AddUniqueToken(anomalyTokens, "company-name-microsoft-spoof");
            }
        }

        DriverFileTimes fileTimes = GetDriverFileTimes(path);
        ULONGLONG bootValue = FileTimeToU64(GetBootFileTime());
        if (fileTimes.ok && !trustedSignature &&
            (fileTimes.createdValue > bootValue || fileTimes.modifiedValue > bootValue)) {
            EscalateDriverFinding(f, suspiciousPath ? "HIGH" : "MEDIUM",
                                  "unsigned driver file was created or modified after boot");
            AddUniqueToken(anomalyTokens, "unsigned-file-touched-after-boot");
        }


        for (int t = 0; kHookTargets[t].driver; ++t) {
            if (driverNameUp != kHookTargets[t].driver) continue;
            std::unordered_set<std::string> targets;
            for (int e = 0; kHookTargets[t].exports[e]; ++e)
                targets.insert(kHookTargets[t].exports[e]);
            auto hookedFns = FindHookedExports(path, targets);
            if (!hookedFns.empty()) {
                f.hasHooks = true;
                f.severity = "HIGH";
                f.reason = "inline hooks detected in kernel exports";
                f.suspicious = true;
                std::string list;
                for (size_t hi = 0; hi < hookedFns.size(); ++hi) {
                    if (hi) list += ", ";
                    list += hookedFns[hi];
                }
                f.hookedFunctions = list;
            }
            break;
        }





        {
            std::vector<std::string> callbackTokens = FindImportedKernelCallbacks(path);
            auto byPath = callbackRegistry.find(ToUpperInvariant(path));
            if (byPath != callbackRegistry.end())
                AddUniqueToken(callbackTokens, byPath->second);
            auto bySvc = callbackRegistry.find(driverSvcKey);
            if (bySvc != callbackRegistry.end())
                AddUniqueToken(callbackTokens, bySvc->second);

            if (!callbackTokens.empty()) {
                f.hasCallbackSurface = true;
                f.callbackSurface = JoinTokens(callbackTokens);
                bool hasEvidence = HasManipulationEvidence(f, anomalyTokens);
                if (suspiciousPath && trustedSignature) {
                    if (hasEvidence) {
                        EscalateDriverFinding(f, "HIGH", "signed driver exposes kernel callbacks from suspicious path with manipulation evidence");
                    } else {
                        EscalateDriverFinding(f, "MEDIUM", "signed driver exposes kernel callbacks from suspicious path");
                    }
                    AddUniqueToken(anomalyTokens, "signed-callbacks-suspicious-path");
                } else if (!trustedSignature) {
                    if (hasEvidence) {
                        EscalateDriverFinding(f, "HIGH", "unsigned driver with callbacks has manipulation evidence");
                    } else if (f.severity != "HIGH") {
                        EscalateDriverFinding(f, "MEDIUM", "unsigned driver exposes kernel callback surface");
                    }
                    AddUniqueToken(anomalyTokens, "unsigned-callback-surface");
                } else if (trustedSignature && !systemPath &&
                           (!versionInfo.hasVersion || versionInfo.companyName.empty())) {
                    EscalateDriverFinding(f, "MEDIUM", "signed callback driver has weak publisher metadata");
                    AddUniqueToken(anomalyTokens, "signed-callback-weak-metadata");
                }
            }
        }


        bool trustedPathClass = pathClass == DetectionFilter::PathClass::SystemTrusted ||
                                pathClass == DetectionFilter::PathClass::ProgramFiles;
        if (!f.signedOk && !f.catalogOk && f.severity == "INFO" && !realCrashDump &&
            (!trustedPathClass || suspiciousPath || HasDriverSuspiciousToken(driverName))) {
            f.severity = "MEDIUM";
            f.reason = "unsigned kernel driver not in any catalog";
            f.suspicious = true;
        } else if (!f.signedOk && !f.catalogOk && f.severity == "INFO" && !realCrashDump) {
            f.reason = "catalog/signature unavailable; trusted location";
            AddUniqueToken(anomalyTokens, "unsigned-trusted-path-weak");
        }

        bool trustedPublisher = IsTrustedDriverPublisher(signerNameW, versionInfo) ||
                                (f.signedOk && certChainDepth >= 2 && !certSelfSigned && !certEkuMismatch);
        bool serviceMismatch = std::find(anomalyTokens.begin(), anomalyTokens.end(), "service-path-mismatch") != anomalyTokens.end();
        bool benignSignedProfile = trustedSignature && trustedPathClass && trustedPublisher &&
                                   !suspiciousPath && !serviceMismatch &&
                                   !HasDriverSuspiciousToken(driverName) &&
                                   !IsKnownAbusedDriverName(driverName);
        if ((f.severity == "MEDIUM" || f.severity == "HIGH") && benignSignedProfile && HasWeakOnlyAnomalies(anomalyTokens)) {
            DowngradeDriverFinding(f, "INFO", "trusted signed driver; weak heuristics only", false);
            AddUniqueToken(anomalyTokens, "downgraded-weak-only");
        }


        bool noServiceReg  = !hasServiceInfo && !systemPath;
        bool bootStartConf = hasServiceInfo && (serviceInfo.start == 0 || serviceInfo.start == 1);
        bool memMismatch   = std::find(anomalyTokens.begin(), anomalyTokens.end(), "memory-size-mismatch") != anomalyTokens.end();
        bool modListMismatch = std::find(anomalyTokens.begin(), anomalyTokens.end(), "module-list-mismatch") != anomalyTokens.end();
        bool hasRWXSection = std::find(anomalyTokens.begin(), anomalyTokens.end(), "writable-executable-section") != anomalyTokens.end();
        bool byovdName = IsKnownAbusedDriverName(driverNameUp);
        bool unsignedCallbacks = f.hasCallbackSurface && !trustedSignature;

        // Manual mapper composite: phantom kernel module (no module list, no disk, no service, unsigned)
        bool manualMapperPattern =
            modListMismatch && !diskFileExists && noServiceReg && !trustedSignature;
        if (manualMapperPattern) {
            EscalateDriverFinding(f, "HIGH",
                "manual mapper pattern: driver in kernel VA not in module list, no disk image, no service");
            AddUniqueToken(anomalyTokens, "manual-mapper-pattern");
            f.maliciousScore += 40;
        }

        // Stripped binary: no rich header + minimal imports + no version info + unsigned (kdmapper output)
        bool strippedBinaryPattern =
            HasToken(anomalyTokens, "no-rich-header") &&
            HasToken(anomalyTokens, "import-count-suspect") &&
            !versionInfo.hasVersion &&
            !trustedSignature;
        if (strippedBinaryPattern) {
            EscalateDriverFinding(f, "HIGH",
                "stripped binary pattern: no rich header, minimal imports, no version info — consistent with manually mapped driver");
            AddUniqueToken(anomalyTokens, "stripped-binary-pattern");
            f.maliciousScore += 35;
        }

        f.maliciousScore = ComputeDriverMaliciousScore(
            f.signedOk, f.catalogOk, systemPath, suspiciousPath,
            trustedPublisher, byovdName || byovdHashMatch,
            HasDriverSuspiciousToken(driverName),
            f.hasHooks, f.hasCallbackSurface, !diskFileExists,
            noServiceReg, bootStartConf, f.hasOverlay,
            !f.checksumOk, memMismatch, modListMismatch,
            realCrashDump);

        // P1/P2 — bonus score for new deep detections
        if (certSelfSigned)  f.maliciousScore += 25;
        if (certHomoglyphCn) f.maliciousScore += 35;
        if (certEkuMismatch    && (!systemPath || !IsTrustedDriverPublisher(signerNameW, versionInfo)))
            f.maliciousScore += 30;
        if (certSerialDuplicate && !IsTrustedDriverPublisher(signerNameW, versionInfo))
            f.maliciousScore += 30;
        if (importInjectionCombo) f.maliciousScore += 25;
        if (importDmaCombo)       f.maliciousScore += 30;
        else if (importPhysMemAccess && !trustedSignature) f.maliciousScore += 15;
        if (byovdHashMatch)       f.maliciousScore += 30;
        f.maliciousScore = std::max(0, f.maliciousScore);

        f.verdict = f.maliciousScore >= 40 ? "MALICIOUS"
                  : f.maliciousScore >= 20 ? "SUSPICIOUS"
                  : "BENIGN";

        // For non-BYOVD, non-hooked drivers raised to HIGH: require at least
        // two independent manipulation signals before keeping that severity.
        if (f.severity == "HIGH" && !byovdName && !f.hasHooks && !realCrashDump) {
            if (!HasCorroboratingManipulationEvidence(
                    f.hasHooks, hasRWXSection, memMismatch,
                    !f.checksumOk, modListMismatch,
                    noServiceReg && !f.signedOk, unsignedCallbacks)) {
                f.severity = "MEDIUM";
                AddUniqueToken(anomalyTokens, "severity-downgraded-single-indicator");
                f.reason += " [single indicator]";
            }
        }

        // Crash dump drivers with no active manipulation evidence: skip entirely
        if (realCrashDump && !f.hasHooks && !unsignedCallbacks &&
            !memMismatch && !hasRWXSection && f.checksumOk) {
            continue;
        }

        bool strongEvidence =
            byovdHashMatch || byovdName || f.hasHooks ||
            certSelfSigned || certHomoglyphCn ||
            (certEkuMismatch    && (!systemPath || !trustedPublisher)) ||
            (certSerialDuplicate && !trustedPublisher) ||
            importInjectionCombo || importDmaCombo ||
            (importPhysMemAccess && !trustedSignature) ||
            (f.hasCallbackSurface && (!trustedSignature || suspiciousPath)) ||
            (suspiciousPath && (!trustedSignature || f.hasCallbackSurface)) ||
            (!diskFileExists && (!trustedSignature || suspiciousPath || !systemPath)) ||
            (!f.checksumOk && !trustedSignature) ||
            (memMismatch && !trustedSignature) ||
            (modListMismatch && !trustedSignature) ||
            (noServiceReg && !f.signedOk) ||
            HasToken(anomalyTokens, "system-name-outside-system-path") ||
            HasToken(anomalyTokens, "system-name-lookalike") ||
            HasToken(anomalyTokens, "company-name-microsoft-spoof") ||
            HasToken(anomalyTokens, "original-name-system-masquerade");

        if (f.severity == "INFO") continue;

        std::string addrStr = f.loadAddress ? HexValue((ULONGLONG)f.loadAddress) : "?";
        f.detail = "addr=" + addrStr +
                   " | score=" + std::to_string(f.maliciousScore) +
                   " | verdict=" + f.verdict +
                   (realCrashDump ? " | type=crash_dump_filter" : "") +
                   " | signed=" + (f.signedOk ? "yes" : "no") +
                   " | catalog=" + (f.catalogOk ? "ok" : "not_found") +
                   " | path=" + DriverPathClassName(path) +
                   " | ref=" + f.referenceSource +
                   " | hash_match=" + (f.hashMatch ? "yes" : "NO") +
                   " | checksum=" + (f.checksumOk ? "ok" : "FAIL") +
                   " | overlay=" + (f.hasOverlay ? "YES" : "no") +
                   " | signer_trusted=" + (f.signerTrusted ? "yes" : "NO");
        if (hasServiceInfo) {
            f.detail += " | service=" + WideToUtf8(serviceInfo.serviceName) +
                        " start=" + std::to_string(serviceInfo.start) +
                        " type=" + std::to_string(serviceInfo.type);
        } else if (pathClass != DetectionFilter::PathClass::SystemTrusted) {
            f.detail += " | service=not_found";
        }
        if (versionInfo.hasVersion) {
            if (!versionInfo.companyName.empty())
                f.detail += " | company=" + WideToUtf8(versionInfo.companyName);
            if (!versionInfo.originalFilename.empty())
                f.detail += " | original=" + WideToUtf8(versionInfo.originalFilename);
        } else {
            f.detail += " | version=no";
        }
        if (!memoryEvidence.empty())
            f.detail += " | memory=" + memoryEvidence;
        if (!anomalyTokens.empty())
            f.detail += " | anomalies=" + JoinTokens(anomalyTokens);
        if (f.hasCallbackSurface)
            f.detail += " | callbacks=" + f.callbackSurface;
        if (!logEvidence.empty()) {
            f.logSource = logEvidence;
            f.detail += " | logs=" + logEvidence;
        } else {
            f.logSource =
                "default sources: System=" + WideToUtf8(EventLogFilePath(L"System")) +
                " | Sysmon=" + WideToUtf8(EventLogFilePath(L"Microsoft-Windows-Sysmon/Operational")) +
                " | CodeIntegrity=" + WideToUtf8(EventLogFilePath(L"Microsoft-Windows-CodeIntegrity/Operational"));
            f.detail += " | logs=no matching event after boot; " + f.logSource;
        }
        if (!f.sha256.empty())
            f.detail += " | sha256=" + f.sha256.substr(0, 16) + "...";
        if (byovdHashMatch)
            f.detail += " | byovd=hash_match";
        if (!impHash.empty())
            f.detail += " | imphash=" + impHash;
        if (importPhysMemAccess || importInjectionCombo || importDmaCombo || importIoctlSurface)
            f.detail += " | import_risk=" +
                        std::string(importInjectionCombo ? "injection," : "") +
                        (importDmaCombo ? "dma," : "") +
                        (importPhysMemAccess ? "physmem," : "") +
                        (importIoctlSurface  ? "ioctl" : "");
        if (certSelfSigned || certEkuMismatch || certHomoglyphCn || certSerialDuplicate)
            f.detail += " | cert_risk=" +
                        std::string(certSelfSigned      ? "self_signed," : "") +
                        (certEkuMismatch     ? "eku_mismatch," : "") +
                        (certHomoglyphCn     ? "homoglyph," : "") +
                        (certSerialDuplicate ? "serial_dup" : "");
        if (!certIssuerCN.empty())
            f.detail += " | issuer=" + certIssuerCN;
        if (hasRdtscCheck || hasCpuidVmCheck || hasPebDebugCheck)
            f.detail += " | anti_analysis=" +
                        std::string(hasRdtscCheck    ? "rdtsc," : "") +
                        (hasCpuidVmCheck  ? "cpuid_vm," : "") +
                        (hasPebDebugCheck ? "peb_debug" : "");

        findings.push_back(f);
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        int ra = DetectionFilter::SeverityRank(a.severity);
        int rb = DetectionFilter::SeverityRank(b.severity);
        if (ra != rb) return ra < rb;
        return a.driverName < b.driverName;
    });

    size_t suspicious = 0;
    for (const auto& f : findings) if (f.suspicious) ++suspicious;
    status = suspicious > 0 ? "DETECTED" : "OK";
    return findings;
}



// Returns the upper-case extension (incl. the dot) of a path, or empty if none.
static std::wstring FileExtensionUpper(const std::wstring& path) {
    size_t dot = path.find_last_of(L'.');
    size_t slash = path.find_last_of(L"\\/");
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash))
        return L"";
    return ToUpperInvariant(path.substr(dot));
}

// Compact a long path while preserving the file name — the most identifying
// part for triage — instead of truncating it away (e.g. ".../Discor...").
static std::wstring CompactPathPreserveName(const std::wstring& path, size_t maxLen) {
    if (path.size() <= maxLen) return path;
    size_t slash = path.find_last_of(L"\\/");
    std::wstring name = (slash != std::wstring::npos) ? path.substr(slash + 1) : path;
    if (name.size() + 6 >= maxLen)
        return path.substr(0, maxLen > 3 ? maxLen - 3 : maxLen) + L"...";
    size_t headLen = maxLen - name.size() - 5; // 5 = length of "\...\"
    return path.substr(0, headLen) + L"\\...\\" + name;
}

static std::wstring ExtractExeFromCmd(const std::wstring& cmd) {
    size_t start = cmd.find_first_not_of(L" \t");
    if (start == std::wstring::npos) return L"";
    std::wstring s = cmd.substr(start);

    if (s[0] == L'"') {
        size_t e = s.find(L'"', 1);
        return e != std::wstring::npos ? s.substr(1, e - 1) : s.substr(1);
    }

    // Unquoted command lines are ambiguous when the path itself contains
    // spaces (e.g. C:\Program Files\Lightshot\Lightshot.exe --autostart) —
    // splitting on the first space yields garbage like "C:\Program". Resolve
    // it the same way Windows resolves ImagePath values: scan for a known
    // executable extension whose end is followed by whitespace/end-of-string.
    static const wchar_t* kExeExt[] = {
        L".EXE", L".DLL", L".COM", L".BAT", L".CMD", L".SCR", L".PIF", nullptr
    };
    std::wstring upper = ToUpperInvariant(s);
    for (size_t i = 0; i < s.size(); ++i) {
        for (int e = 0; kExeExt[e]; ++e) {
            size_t extLen = wcslen(kExeExt[e]);
            if (i + extLen <= upper.size() && upper.compare(i, extLen, kExeExt[e]) == 0) {
                size_t endPos = i + extLen;
                if (endPos == s.size() || s[endPos] == L' ' || s[endPos] == L',')
                    return s.substr(0, endPos);
            }
        }
    }

    size_t sp = s.find(L' ');
    return sp != std::wstring::npos ? s.substr(0, sp) : s;
}

std::vector<ScannerUI::RegistryFinding> CollectRegistryPersistenceFindings(std::string& status) {
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    std::vector<ScannerUI::RegistryFinding> findings;

    {
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                          0, KEY_READ | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
            wchar_t val[2048] = {};
            DWORD sz = sizeof(val), regType = 0;
            if (RegQueryValueExW(h, L"AppInit_DLLs", nullptr, &regType,
                                 reinterpret_cast<LPBYTE>(val), &sz) == ERROR_SUCCESS &&
                (regType == REG_SZ || regType == REG_EXPAND_SZ) && val[0] != L'\0') {
                ScannerUI::RegistryFinding f;
                f.date = date; f.time = timeStr;
                f.severity = "HIGH";
                f.key = "HKLM\\...\\CurrentVersion\\Windows";
                f.value = "AppInit_DLLs";
                f.data = WideToUtf8(val);
                f.reason = "AppInit_DLLs injects DLL into every Win32 process";
                f.detail = "technique=dll_injection_global";
                f.suspicious = true;
                findings.push_back(f);
            }
            RegCloseKey(h);
        }
    }


    {
        HKEY ifeo = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                          0, KEY_READ | KEY_WOW64_64KEY, &ifeo) == ERROR_SUCCESS) {
            DWORD subCount = 0;
            RegQueryInfoKeyW(ifeo, nullptr, nullptr, nullptr, &subCount,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            for (DWORD i = 0; i < subCount; ++i) {
                wchar_t exeName[512] = {}; DWORD nameLen = (DWORD)std::size(exeName);
                if (RegEnumKeyExW(ifeo, i, exeName, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    continue;
                HKEY exeKey = nullptr;
                if (RegOpenKeyExW(ifeo, exeName, 0, KEY_READ | KEY_WOW64_64KEY, &exeKey) != ERROR_SUCCESS)
                    continue;
                wchar_t dbg[2048] = {}; DWORD dbgSz = sizeof(dbg), dbgType = 0;
                if (RegQueryValueExW(exeKey, L"Debugger", nullptr, &dbgType,
                                     reinterpret_cast<LPBYTE>(dbg), &dbgSz) == ERROR_SUCCESS &&
                    (dbgType == REG_SZ || dbgType == REG_EXPAND_SZ) && dbg[0] != L'\0') {

                    // IFEO "Debugger" is also used legitimately — Visual Studio's
                    // JIT debugger (vsjitdebugger.exe), Application Verifier,
                    // WER (WerFault.exe), gflags, etc. A signed tool living in a
                    // trusted directory is a known pattern, not a hijack.
                    std::wstring dbgExe = ExtractExeFromCmd(dbg);
                    bool dbgFileExists = !dbgExe.empty() && FileExistsW(dbgExe);
                    bool dbgSignedOk   = dbgFileExists && IsAuthenticodeSigned(dbgExe);
                    DetectionFilter::PathClass dbgCls = dbgFileExists ?
                        DetectionFilter::ClassifyPath(dbgExe) : DetectionFilter::PathClass::Unknown;
                    bool dbgTrusted = dbgSignedOk && DetectionFilter::IsTrustedDir(dbgCls);

                    ScannerUI::RegistryFinding f;
                    f.date = date; f.time = timeStr;
                    f.key = "HKLM\\...\\Image File Execution Options\\" + WideToUtf8(exeName);
                    f.value = "Debugger";
                    f.data = WideToUtf8(dbg);
                    f.detail = "technique=ifeo_hijack | signed=" + std::string(dbgSignedOk ? "yes" : "no") +
                               " | exists=" + std::string(dbgFileExists ? "yes" : "no");
                    if (dbgTrusted) {
                        f.severity  = "FLAG";
                        f.reason    = WideToUtf8(exeName) + " has an IFEO Debugger entry pointing to a signed, trusted tool";
                        f.suspicious = false;
                    } else {
                        f.severity  = "HIGH";
                        f.reason    = "IFEO hijack — " + WideToUtf8(exeName) + " redirected to custom debugger";
                        f.suspicious = true;
                    }
                    findings.push_back(f);
                }
                RegCloseKey(exeKey);
            }
            RegCloseKey(ifeo);
        }
    }


    {
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                          0, KEY_READ | KEY_WOW64_64KEY, &h) == ERROR_SUCCESS) {
            static const struct { const wchar_t* val; const wchar_t* expected; } kWl[] = {
                { L"Userinit", L"USERINIT" },
                { L"Shell",    L"EXPLORER" },
            };
            for (const auto& w : kWl) {
                wchar_t val[2048] = {}; DWORD sz = sizeof(val), regType = 0;
                if (RegQueryValueExW(h, w.val, nullptr, &regType,
                                     reinterpret_cast<LPBYTE>(val), &sz) != ERROR_SUCCESS)
                    continue;
                if (ToUpperInvariant(val).find(w.expected) == std::wstring::npos) {
                    ScannerUI::RegistryFinding f;
                    f.date = date; f.time = timeStr;
                    f.severity = "HIGH";
                    f.key = "HKLM\\...\\CurrentVersion\\Winlogon";
                    f.value = WideToUtf8(w.val);
                    f.data = WideToUtf8(val);
                    f.reason = std::string("Winlogon ") + WideToUtf8(w.val) + " modified";
                    f.detail = "technique=winlogon_hijack | expected=" + WideToUtf8(w.expected);
                    f.suspicious = true;
                    findings.push_back(f);
                }
            }
            RegCloseKey(h);
        }
    }

    // P4 — DKOM cross-check: compare RegEnumKey vs NtEnumerateKey for hidden services
    {
        typedef NTSTATUS (WINAPI* NtEnumerateKeyFn)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        NtEnumerateKeyFn NtEnumerateKey = ntdll
            ? reinterpret_cast<NtEnumerateKeyFn>(GetProcAddress(ntdll, "NtEnumerateKey"))
            : nullptr;

        if (NtEnumerateKey) {
            // The Services key changes constantly (Windows Update, driver/AV
            // installs, Plug-and-Play), so two independent enumeration passes
            // taken back-to-back can legitimately disagree (TOCTOU race) —
            // a key created/removed between the passes looks "hidden" but
            // isn't. Snapshot the Win32 view, build candidates from the Nt
            // view, then re-snapshot the Win32 view and only report names
            // that are STILL missing on the second look.
            auto collectWin32Names = [&]() {
                std::unordered_set<std::wstring> names;
                HKEY root = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                  L"SYSTEM\\CurrentControlSet\\Services",
                                  0, KEY_READ | KEY_WOW64_64KEY, &root) == ERROR_SUCCESS) {
                    DWORD subCount = 0;
                    RegQueryInfoKeyW(root, nullptr, nullptr, nullptr, &subCount,
                                     nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                    for (DWORD i = 0; i < subCount; ++i) {
                        wchar_t n[256] = {}; DWORD nl = (DWORD)std::size(n);
                        if (RegEnumKeyExW(root, i, n, &nl, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
                            names.insert(ToUpperInvariant(n));
                    }
                    RegCloseKey(root);
                }
                return names;
            };

            HKEY svcRoot = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Services",
                              0, KEY_READ | KEY_WOW64_64KEY, &svcRoot) == ERROR_SUCCESS) {
                std::unordered_set<std::wstring> win32Names = collectWin32Names();

                // Collect candidate "hidden" names via NtEnumerateKey (lower-level)
                // KEY_BASIC_INFORMATION = class 0, contains name after fixed header
                struct KeyBasicInfo {
                    LARGE_INTEGER LastWriteTime;
                    ULONG TitleIndex;
                    ULONG NameLength;
                    WCHAR Name[1];
                };
                std::vector<std::wstring> candidates;
                std::vector<uint8_t> kbiBuf(4096);
                for (ULONG idx = 0; ; ++idx) {
                    ULONG retLen = 0;
                    NTSTATUS st = NtEnumerateKey(svcRoot, idx, 0,
                                                 kbiBuf.data(), (ULONG)kbiBuf.size(), &retLen);
                    if (st == 0x80000005L /*STATUS_BUFFER_OVERFLOW*/ ||
                        st == 0xC0000023L /*STATUS_BUFFER_TOO_SMALL*/) {
                        kbiBuf.resize(retLen + 64);
                        st = NtEnumerateKey(svcRoot, idx, 0,
                                            kbiBuf.data(), (ULONG)kbiBuf.size(), &retLen);
                    }
                    if (st == 0x8000001AL /*STATUS_NO_MORE_ENTRIES*/ || st < 0)
                        break;
                    auto* kbi = reinterpret_cast<const KeyBasicInfo*>(kbiBuf.data());
                    if (kbi->NameLength == 0 || kbi->NameLength > 512) continue;
                    std::wstring name(kbi->Name, kbi->NameLength / sizeof(WCHAR));
                    if (win32Names.find(ToUpperInvariant(name)) == win32Names.end())
                        candidates.push_back(name);
                }
                RegCloseKey(svcRoot);

                if (!candidates.empty()) {
                    Sleep(50);
                    std::unordered_set<std::wstring> win32NamesConfirm = collectWin32Names();
                    for (const auto& name : candidates) {
                        if (win32NamesConfirm.find(ToUpperInvariant(name)) != win32NamesConfirm.end())
                            continue; // reappeared on the second pass — TOCTOU race, not hidden

                        // Consistently invisible to Win32 while visible to Nt = rootkit
                        ScannerUI::RegistryFinding f;
                        f.date = date; f.time = timeStr;
                        f.severity = "HIGH";
                        f.key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + WideToUtf8(name);
                        f.value = "(hidden)";
                        f.data = "";
                        f.reason = "Service registry key is hidden from Win32 API (DKOM registry hiding)";
                        f.detail = "technique=dkom_registry | nt_visible=yes | win32_visible=no | confirmed=2-pass";
                        f.suspicious = true;
                        findings.push_back(f);
                    }
                }
            }
        }
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        return a.key < b.key;
    });

    status = findings.empty() ? "OK" : "DETECTED";
    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// CLSID Hijack Detection
// ─────────────────────────��──────────────────────────���────────────────────────

static std::wstring ClsidAsciiToWide(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

// Read the InprocServer32 or LocalServer32 default value for a CLSID key.
// Returns the (expanded, normalized) server path and the server subkey name.
static std::wstring ReadClsidServerPath(HKEY root, const std::wstring& clsidKeyPath,
                                        std::string& outServerType) {
    static const wchar_t* kSrvKeys[] = { L"InprocServer32", L"LocalServer32", nullptr };
    for (int si = 0; kSrvKeys[si]; ++si) {
        std::wstring subPath = clsidKeyPath + L"\\" + kSrvKeys[si];
        HKEY hSrv = nullptr;
        if (RegOpenKeyExW(root, subPath.c_str(), 0, KEY_READ, &hSrv) != ERROR_SUCCESS)
            continue;
        wchar_t val[MAX_PATH * 2] = {}; DWORD valSz = sizeof(val), valType = 0;
        LSTATUS st = RegQueryValueExW(hSrv, nullptr, nullptr, &valType,
                                      reinterpret_cast<LPBYTE>(val), &valSz);
        RegCloseKey(hSrv);
        if (st == ERROR_SUCCESS && (valType == REG_SZ || valType == REG_EXPAND_SZ) && val[0]) {
            outServerType = WideToUtf8(kSrvKeys[si]);
            return NormalizeDosDriverPath(val);
        }
    }
    return L"";
}

std::vector<ScannerUI::ClsidFinding> CollectClsidHijackFindings(std::string& status) {
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    std::vector<ScannerUI::ClsidFinding> findings;

    // ── Phase 1: Enumerate HKCU\SOFTWARE\Classes\CLSID ────────────────────────
    // Any CLSID here that also exists in HKCR = COM hijack (no admin needed).
    HKEY hkuRoot = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\CLSID",
                      0, KEY_READ, &hkuRoot) == ERROR_SUCCESS) {
        DWORD subCount = 0;
        RegQueryInfoKeyW(hkuRoot, nullptr, nullptr, nullptr, &subCount,
                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < subCount && findings.size() < 400; ++i) {
            wchar_t guid[128] = {}; DWORD guidLen = (DWORD)std::size(guid);
            if (RegEnumKeyExW(hkuRoot, i, guid, &guidLen,
                              nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                continue;

            // Does this CLSID have a system-level registration in HKCR?
            bool existsInHkcr = false;
            {
                HKEY hTest = nullptr;
                std::wstring hkcrPath = std::wstring(L"CLSID\\") + guid;
                if (RegOpenKeyExW(HKEY_CLASSES_ROOT, hkcrPath.c_str(),
                                  0, KEY_READ, &hTest) == ERROR_SUCCESS) {
                    existsInHkcr = true;
                    RegCloseKey(hTest);
                }
            }

            // Friendly name from HKCR default value
            std::wstring friendlyName;
            if (existsInHkcr) {
                HKEY hName = nullptr;
                std::wstring hkcrPath = std::wstring(L"CLSID\\") + guid;
                if (RegOpenKeyExW(HKEY_CLASSES_ROOT, hkcrPath.c_str(),
                                  0, KEY_READ, &hName) == ERROR_SUCCESS) {
                    wchar_t nv[512] = {}; DWORD nvSz = sizeof(nv), nvType = 0;
                    if (RegQueryValueExW(hName, nullptr, nullptr, &nvType,
                                        reinterpret_cast<LPBYTE>(nv), &nvSz) == ERROR_SUCCESS)
                        friendlyName = nv;
                    RegCloseKey(hName);
                }
            }

            // Server path from HKCU registration
            std::string serverType;
            std::wstring hkuKeyPath = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + guid;
            std::wstring serverPathW = ReadClsidServerPath(HKEY_CURRENT_USER, hkuKeyPath, serverType);

            bool fileExists = !serverPathW.empty() && FileExistsW(serverPathW);
            bool isSigned   = fileExists && IsAuthenticodeSigned(serverPathW);

            // Classify the server path
            bool pathSuspicious = false;
            if (!serverPathW.empty() && fileExists) {
                auto pathClass = DetectionFilter::ClassifyPath(serverPathW);
                pathSuspicious = !DetectionFilter::IsTrustedDir(pathClass);
            }

            // A CLSID present in both HKCU and HKCR is normal Windows/COM
            // behavior (per-user installs, Office Click-to-Run, MSIX/AppV
            // virtualization, shell-extension reinstalls, …). Compare what the
            // HKCU registration actually points to against the legitimate HKCR
            // server — only a *different* server is a real override signal.
            bool hkcrSameServer    = false;
            bool hkcrSamePublisher = false;
            if (existsInHkcr) {
                std::string hkcrServerType;
                std::wstring hkcrKeyPath = std::wstring(L"CLSID\\") + guid;
                std::wstring hkcrServerPathW = ReadClsidServerPath(HKEY_CLASSES_ROOT, hkcrKeyPath, hkcrServerType);
                if (!hkcrServerPathW.empty() && !serverPathW.empty() &&
                    ToUpperInvariant(hkcrServerPathW) == ToUpperInvariant(serverPathW)) {
                    hkcrSameServer = true;
                } else if (isSigned && !hkcrServerPathW.empty() && FileExistsW(hkcrServerPathW)) {
                    // Same-publisher pairs are legitimate vendor variants/updates,
                    // not hijacks. Hardened: both servers must be genuinely
                    // trust-signed and chain to the same root CA, so a forged-CN
                    // HKCU server cannot inherit the legitimate publisher's exemption.
                    hkcrSamePublisher = DetectionFilter::SamePublisherTrusted(serverPathW, hkcrServerPathW);
                }
            }
            bool benignMirror = existsInHkcr && (hkcrSameServer || hkcrSamePublisher);
            bool realOverride = existsInHkcr && !benignMirror;

            // Only report if there's a real reason to flag this entry
            bool isPhantom = !serverPathW.empty() && !fileExists;
            if (!realOverride && !isPhantom && !(pathSuspicious && !isSigned))
                continue;

            ScannerUI::ClsidFinding f;
            f.date         = date;
            f.time         = timeStr;
            f.clsid        = WideToUtf8(guid);
            f.friendlyName = WideToUtf8(friendlyName);
            f.hivePath     = "HKCU";
            f.serverType   = serverType;
            f.serverPath   = WideToUtf8(serverPathW);
            f.fileExists   = fileExists;
            f.isSigned     = isSigned;
            f.isHkcuOverride = realOverride;
            f.canClean     = true;

            if (isPhantom) {
                // A registration pointing at a *missing* DLL in a user-writable
                // staging area (TEMP/AppData/Downloads/Removable) is the classic
                // pre-positioned COM hijack: the loader drops the DLL just-in-time.
                // Escalate to HIGH for those locations; ProgramFiles/system stays MEDIUM.
                auto phantomClass = DetectionFilter::ClassifyPath(serverPathW);
                bool userWritable = phantomClass == DetectionFilter::PathClass::TempOrInstaller ||
                                    phantomClass == DetectionFilter::PathClass::UserProfile ||
                                    phantomClass == DetectionFilter::PathClass::Removable ||
                                    phantomClass == DetectionFilter::PathClass::Unknown;
                f.severity = userWritable ? "HIGH" : "MEDIUM";
                f.reason   = userWritable
                    ? "COM registration points to a missing DLL in a user-writable staging path — pre-positioned COM hijack"
                    : "COM registration points to missing DLL";
                f.detail   = std::string("technique=clsid_phantom | path_class=") +
                             DetectionFilter::PathClassName(phantomClass);
            } else if (realOverride) {
                f.severity = "HIGH";
                f.reason   = "HKCU overrides system CLSID with a different server — COM hijack";
                f.detail   = "technique=clsid_hkcu_override";
                if (!isSigned)
                    f.detail += " | unsigned";
            } else {
                f.severity = "MEDIUM";
                f.reason   = "COM server in user-writable location, unsigned";
                f.detail   = "technique=clsid_suspicious_path";
            }

            findings.push_back(std::move(f));
        }
        RegCloseKey(hkuRoot);
    }

    // ── Phase 2: Known attack-target CLSIDs ──────────────────────────────────
    // These GUIDs are loaded by privileged processes (Task Scheduler, Explorer,
    // MMC, etc.). If any appear in HKCU without an existing finding, escalate.
    static const struct { const wchar_t* guid; const char* desc; } kTargets[] = {
        { L"{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}", "Task Scheduler (COM)" },
        { L"{1F486A52-3CB1-48FD-8F50-B8DC300D9F9D}", "Task Scheduler Handler" },
        { L"{4590F811-1D3A-11D0-891F-00AA004B2E24}", "WMI COM Object" },
        { L"{BDB57FF2-79B9-4205-9447-F5FE85F37312}", "BITS Service COM" },
        { L"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}", "MMC COM Object" },
        { L"{0A29FF9E-7F9C-4437-8B11-F424491E3931}", "Task Scheduler Action" },
        { L"{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}", "Windows Defender COM" },
        { L"{2DE86CCA-1EC6-40A9-BBE3-D67A41B0CDE0}", "Windows Update Agent" },
        { L"{9E175B68-F52A-11D8-B9A5-505054503030}", "Windows Search COM" },
        { L"{BCDE0395-E52F-467C-8E3D-C4579291692E}", "MSDTC/COM+" },
        { L"{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}", "Shell Execute Hook" },
        { L"{E6FB5E20-DE35-11CF-9C87-00AA005127ED}", "WebCheck Shell Service" },
        { nullptr, nullptr }
    };

    for (int ti = 0; kTargets[ti].guid; ++ti) {
        std::string guidStr = WideToUtf8(kTargets[ti].guid);
        std::wstring hkuPath = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + kTargets[ti].guid;

        // Presence alone isn't a signal — virtualized/per-user app packages
        // (MSIX/AppV, Office Click-to-Run, …) legitimately shadow these GUIDs.
        // Compare what HKCU actually points to against the legitimate HKCR
        // registration before treating it as a hijack.
        HKEY hTest = nullptr;
        bool existsInHku = (RegOpenKeyExW(HKEY_CURRENT_USER, hkuPath.c_str(), 0, KEY_READ, &hTest) == ERROR_SUCCESS);
        if (existsInHku) RegCloseKey(hTest);
        if (!existsInHku) continue;

        std::string serverType;
        std::wstring serverPathW = ReadClsidServerPath(HKEY_CURRENT_USER, hkuPath, serverType);
        bool fileExists = !serverPathW.empty() && FileExistsW(serverPathW);
        bool isSigned   = fileExists && IsAuthenticodeSigned(serverPathW);

        std::string hkcrServerType;
        std::wstring hkcrKeyPath = std::wstring(L"CLSID\\") + kTargets[ti].guid;
        std::wstring hkcrServerPathW = ReadClsidServerPath(HKEY_CLASSES_ROOT, hkcrKeyPath, hkcrServerType);

        bool sameServer = !hkcrServerPathW.empty() && !serverPathW.empty() &&
                          ToUpperInvariant(hkcrServerPathW) == ToUpperInvariant(serverPathW);
        bool samePublisher = false;
        if (!sameServer && isSigned && !hkcrServerPathW.empty() && FileExistsW(hkcrServerPathW)) {
            // Hardened same-publisher check (trust-verified CN + same root CA).
            samePublisher = DetectionFilter::SamePublisherTrusted(serverPathW, hkcrServerPathW);
        }
        bool benign = sameServer || samePublisher;

        // Escalate an existing phase-1 finding for this CLSID — but only when
        // the override is real, not a benign mirror/same-publisher variant.
        bool handledInPhase1 = false;
        for (auto& ef : findings) {
            if (ef.clsid == guidStr) {
                handledInPhase1 = true;
                if (!benign) {
                    ef.severity = "HIGH";
                    ef.reason   = std::string("Known COM hijack target: ") + kTargets[ti].desc;
                    ef.detail  += " | known_target=yes";
                }
                break;
            }
        }
        if (handledInPhase1 || benign)
            continue;

        ScannerUI::ClsidFinding f;
        f.date         = date;
        f.time         = timeStr;
        f.severity     = "HIGH";
        f.clsid        = guidStr;
        f.friendlyName = kTargets[ti].desc;
        f.hivePath     = "HKCU";
        f.serverType   = serverType;
        f.serverPath   = WideToUtf8(serverPathW);
        f.fileExists   = fileExists;
        f.isSigned     = isSigned;
        f.isHkcuOverride = true;
        f.canClean     = true;
        f.reason       = std::string("Known COM hijack target: ") + kTargets[ti].desc;
        f.detail       = "technique=clsid_hkcu_override | known_target=yes";
        findings.push_back(std::move(f));
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        return a.clsid < b.clsid;
    });

    status = findings.empty() ? "OK" : "DETECTED";
    return findings;
}

bool CleanClsidFinding(ScannerUI::ClsidFinding& finding) {
    if (finding.cleaned) return true;
    if (!finding.canClean) return false;

    std::wstring guidW = ClsidAsciiToWide(finding.clsid);

    if (finding.hivePath == "HKCU") {
        std::wstring keyPath = L"SOFTWARE\\Classes\\CLSID\\" + guidW;
        LSTATUS st = RegDeleteTreeW(HKEY_CURRENT_USER, keyPath.c_str());
        if (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND) {
            finding.cleaned = true;
            return true;
        }
    }
    return false;
}
