#include "scanner_core.h"
#include <setupapi.h>
#pragma comment(lib, "setupapi.lib")

// {4D36E968-E325-11CE-BFC1-08002BE10318} — display device class
static const GUID kDisplayClass = {
    0x4D36E968, 0xE325, 0x11CE,
    { 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18 }
};
// {CA3E0642-10D2-4652-9D61-A8BD3A652041} — camera device class
static const GUID kCameraClass = {
    0xCA3E0642, 0x10D2, 0x4652,
    { 0x9D, 0x61, 0xA8, 0xBD, 0x3A, 0x65, 0x20, 0x41 }
};

static void AddStreamModFinding(std::vector<ScannerUI::StreamModFinding>& out,
                                 const std::string& type,
                                 const std::string& process,
                                 const std::string& target,
                                 const std::string& detail,
                                 const std::string& severity)
{
    ScannerUI::StreamModFinding f;
    f.type     = type;
    f.process  = process;
    f.target   = target;
    f.detail   = detail;
    f.severity = severity;
    out.push_back(std::move(f));
}

// ─────────────────────────────────────────────────────────────────────────────
// P1 — SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)
// ─────────────────────────────────────────────────────────────────────────────

static const DWORD kWdaExclude = 0x00000011;

static bool IsWhitelistedCaptureProcess(const std::wstring& nameUp) {
    static const wchar_t* kList[] = {
        L"WINLOGON.EXE", L"LSASS.EXE", L"SECURITYHEALTHSYSTRAY.EXE",
        L"CREDENTIALUIBROKER.EXE", L"SMARTSCREEN.EXE", L"TASKMGR.EXE",
        L"SECURITYHEALTHSERVICE.EXE", L"LOCKAPP.EXE", L"LOGONUI.EXE",
        L"APPLICATIONFRAMEHOST.EXE", L"TEXTINPUTHOST.EXE",
        L"KEEPASS.EXE", L"KEEPASSXC.EXE", L"1PASSWORD.EXE", L"BITWARDEN.EXE",
        L"DASHLANE.EXE", L"LASTPASS.EXE", L"NORDPASS.EXE"
    };
    for (const auto* w : kList)
        if (nameUp == w) return true;
    return false;
}

struct CaptureExcludeCtx { std::vector<ScannerUI::StreamModFinding>* out; };

static BOOL CALLBACK CaptureExcludeProc(HWND hWnd, LPARAM lParam) {
    DWORD affinity = 0;
    if (!GetWindowDisplayAffinity(hWnd, &affinity) || affinity != kWdaExclude)
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (!pid || pid == GetCurrentProcessId())
        return TRUE;

    std::wstring procPath = ProcessFullPathW(pid);
    std::wstring procName = BaseNameFromPath(procPath);
    for (auto& c : procName) c = towupper(c);
    if (IsWhitelistedCaptureProcess(procName))
        return TRUE;

    char title[256] = {};
    GetWindowTextA(hWnd, title, sizeof(title));

    std::string detail = "Window excluded from all screen capture (WDA_EXCLUDEFROMCAPTURE)";
    if (title[0]) { detail += ": \""; detail += title; detail += "\""; }

    auto* ctx = reinterpret_cast<CaptureExcludeCtx*>(lParam);
    AddStreamModFinding(*ctx->out,
        "CAPTURE_EXCLUDE",
        WideToUtf8(procPath),
        title[0] ? std::string(title) : WideToUtf8(procName),
        detail,
        "HIGH");
    return TRUE;
}

static void ScanCaptureExcludedWindows(std::vector<ScannerUI::StreamModFinding>& out) {
    CaptureExcludeCtx ctx{ &out };
    EnumWindows(CaptureExcludeProc, reinterpret_cast<LPARAM>(&ctx));
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 — OBS / Streamlabs plugin integrity (disk) + M2 entropy + M1 runtime injection
// ─────────────────────────────────────────────────────────────────────────────

static bool HasSuspiciousPluginKeyword(const std::wstring& name) {
    std::wstring up = name;
    for (auto& c : up) c = towupper(c);
    static const wchar_t* kBad[] = {
        L"CHEAT", L"BYPASS", L"SPOOF", L"INJECT",
        L"HOOK", L"HACK", L"RING0", L"CAPTURE_FILTER", L"EXCLUDE"
    };
    for (const auto* b : kBad)
        if (up.find(b) != std::wstring::npos) return true;
    return false;
}

static std::vector<std::wstring> GetObsPluginDirs() {
    std::vector<std::wstring> dirs;
    wchar_t buf[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"ProgramFiles", buf, MAX_PATH)) {
        std::wstring pf = buf;
        dirs.push_back(pf + L"\\obs-studio\\obs-plugins\\64bit");
        dirs.push_back(pf + L"\\obs-studio\\obs-plugins\\32bit");
        dirs.push_back(pf + L"\\Streamlabs\\obs-plugins\\64bit");
        dirs.push_back(pf + L"\\Streamlabs OBS\\obs-plugins\\64bit");
    }
    if (GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH)) {
        std::wstring appdata = buf;
        dirs.push_back(appdata + L"\\obs-studio\\plugins");
    }
    return dirs;
}

// M2: Shannon entropy for a file — uses FileEntropySample from detection_filters.h
static std::string EntropyStr(double e) {
    char buf[16]; snprintf(buf, sizeof(buf), "%.2f", e);
    return buf;
}

static void ScanStreamingPlugins(std::vector<ScannerUI::StreamModFinding>& out) {
    for (const auto& dir : GetObsPluginDirs()) {
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW((dir + L"\\*.dll").c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring pluginPath = dir + L"\\" + fd.cFileName;
            bool suspicious = HasSuspiciousPluginKeyword(fd.cFileName);
            bool signed_    = IsAuthenticodeSigned(pluginPath);

            if (!signed_ || suspicious) {
                // M2: calculate entropy to distinguish packed/obfuscated plugins
                double entropy = DetectionFilter::FileEntropySample(pluginPath, 65536);
                bool packed    = entropy >= DetectionFilter::kPackedEntropy;

                std::string detail;
                if (suspicious)
                    detail = "Suspicious keyword in OBS plugin name";
                else if (packed)
                    detail = "Unsigned + high-entropy OBS plugin (packed/obfuscated, entropy=" + EntropyStr(entropy) + ")";
                else
                    detail = "Unsigned OBS plugin (entropy=" + EntropyStr(entropy) + ")";

                std::string sev = (suspicious || packed) ? "HIGH" : "MEDIUM";
                AddStreamModFinding(out, "OBS_PLUGIN", WideToUtf8(dir),
                                    WideToUtf8(pluginPath), detail, sev);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

// M1: Scan loaded modules inside running OBS/Streamlabs process
static bool IsObsProcess(const std::wstring& nameUp) {
    static const wchar_t* kObs[] = {
        L"OBS64.EXE", L"OBS32.EXE", L"OBS.EXE",
        L"STREAMLABS.EXE", L"STREAMLABSOBS.EXE", L"SLOBS.EXE"
    };
    for (const auto* n : kObs)
        if (nameUp == n) return true;
    return false;
}

static void ScanObsRuntimeModules(std::vector<ScannerUI::StreamModFinding>& out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return; }

    do {
        wchar_t nameUp[MAX_PATH];
        wcsncpy_s(nameUp, pe.szExeFile, _TRUNCATE);
        for (auto& c : nameUp) c = towupper(c);
        if (!IsObsProcess(nameUp)) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (!hProc) continue;

        // Get OBS install directory to whitelist its own modules
        std::wstring obsPath  = ProcessFullPathW(pe.th32ProcessID);
        std::wstring obsDir   = obsPath;
        size_t slash = obsDir.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            obsDir = obsDir.substr(0, slash);
        // parent directory (e.g. obs-studio\bin\64bit → obs-studio)
        slash = obsDir.find_last_of(L"\\/");
        std::wstring obsRoot = (slash != std::wstring::npos) ? obsDir.substr(0, slash) : obsDir;
        slash = obsRoot.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
            obsRoot = obsRoot.substr(0, slash);

        std::wstring obsRootUp = obsRoot;
        for (auto& c : obsRootUp) c = towupper(c);

        std::vector<ModuleRange> modules;
        if (CollectProcessModules(hProc, modules)) {
            for (const auto& mod : modules) {
                if (mod.path.empty()) continue;
                std::wstring modUp = mod.path;
                for (auto& c : modUp) c = towupper(c);

                // Allow system paths and OBS install path
                if (modUp.find(L"\\WINDOWS\\") != std::wstring::npos) continue;
                if (!obsRootUp.empty() && modUp.find(obsRootUp) != std::wstring::npos) continue;

                // Check APPDATA obs-studio (user plugins)
                wchar_t appdataBuf[MAX_PATH] = {};
                if (GetEnvironmentVariableW(L"APPDATA", appdataBuf, MAX_PATH)) {
                    std::wstring adUp = appdataBuf;
                    for (auto& c : adUp) c = towupper(c);
                    adUp += L"\\OBS-STUDIO";
                    if (modUp.find(adUp) != std::wstring::npos) continue;
                }

                // Remaining module is not from OBS or Windows — check signature
                if (IsAuthenticodeSigned(mod.path)) continue;

                std::string detail = "Unsigned non-OBS module loaded in " +
                                     WideToUtf8(std::wstring(pe.szExeFile)) +
                                     " — possible runtime injection";
                AddStreamModFinding(out, "OBS_INJECT",
                                    WideToUtf8(obsPath),
                                    WideToUtf8(mod.path),
                                    detail, "HIGH");
            }
        }
        CloseHandle(hProc);
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
}

// ─────────────────────────────────────────────────────────────────────────────
// P3 — Virtual display adapter + M3 driver signature verification
// ─────────────────────────────────────────────────────────────────────────────

static bool IsKnownVirtualDisplay(const std::wstring& desc) {
    std::wstring up = desc;
    for (auto& c : up) c = towupper(c);
    static const wchar_t* kVirtual[] = {
        L"PARSECVDD", L"IDDSAMPLEDRIVER", L"IDD_SAMPLE",
        L"VIRTUALDISPLAY", L"VIRTUAL DISPLAY", L"USBMMIDD",
        L"INDIRECT DISPLAY", L"VDDMIRROR", L"TESTDISPLAY",
        L"SPOUTCAM", L"GE9VDD", L"LOOKING GLASS"
    };
    for (const auto* v : kVirtual)
        if (up.find(v) != std::wstring::npos) return true;
    return false;
}

// M3: Resolve driver binary path from service name
static std::wstring GetDriverBinaryPath(const std::wstring& serviceName) {
    std::wstring regKey = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";

    wchar_t imagePath[MAX_PATH * 2] = {};
    DWORD size = sizeof(imagePath);
    DWORD type = 0;
    RegQueryValueExW(hKey, L"ImagePath", nullptr, &type, (LPBYTE)imagePath, &size);
    RegCloseKey(hKey);

    if (!imagePath[0]) return L"";

    wchar_t expanded[MAX_PATH * 2] = {};
    ExpandEnvironmentStringsW(imagePath, expanded, MAX_PATH * 2);

    // Strip \??\ prefix used in kernel driver paths
    std::wstring path = expanded;
    if (path.rfind(L"\\??\\", 0) == 0) path = path.substr(4);
    if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t windir[MAX_PATH] = {};
        GetWindowsDirectoryW(windir, MAX_PATH);
        path = std::wstring(windir) + path.substr(11);
    }
    return path;
}

static void ScanVirtualDisplayAdapters(std::vector<ScannerUI::StreamModFinding>& out) {
    HDEVINFO devInfo = SetupDiGetClassDevsW(&kDisplayClass, nullptr, nullptr, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData = {};
    devData.cbSize = sizeof(devData);
    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devInfo, idx, &devData); ++idx) {
        wchar_t desc[256] = {};
        if (!SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_DEVICEDESC,
                                               nullptr, (PBYTE)desc, sizeof(desc), nullptr))
            continue;
        if (!IsKnownVirtualDisplay(desc)) continue;

        wchar_t hwid[512] = {};
        SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_HARDWAREID,
                                          nullptr, (PBYTE)hwid, sizeof(hwid), nullptr);

        // M3: get service name → driver binary path → signature check
        wchar_t svcName[256] = {};
        SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_SERVICE,
                                          nullptr, (PBYTE)svcName, sizeof(svcName), nullptr);

        std::wstring driverPath;
        bool driverSigned = true;
        if (svcName[0]) {
            driverPath   = GetDriverBinaryPath(svcName);
            if (!driverPath.empty())
                driverSigned = IsAuthenticodeSigned(driverPath);
        }

        // Cryptographic + structural filter: if the backing driver is Authenticode-signed
        // AND resides in System32/SysWOW64, it is a Microsoft kernel component (e.g.
        // WUDFRd.sys — Windows Driver Framework Reflector). No need to report.
        if (!driverPath.empty() && driverSigned) {
            auto drvCls = DetectionFilter::ClassifyPath(driverPath);
            if (drvCls == DetectionFilter::PathClass::SystemTrusted)
                continue;
        }

        std::string detail = "Virtual display adapter: ";
        detail += WideToUtf8(desc);
        if (hwid[0]) { detail += " ["; detail += WideToUtf8(hwid); detail += "]"; }
        if (!driverPath.empty()) {
            detail += " | driver: ";
            detail += WideToUtf8(driverPath);
            detail += driverSigned ? " [signed]" : " [UNSIGNED]";
        }

        // M3: unsigned virtual display driver → HIGH instead of FLAG
        std::string sev = (!driverPath.empty() && !driverSigned) ? "HIGH" : "FLAG";
        AddStreamModFinding(out, "VIRTUAL_DISPLAY", "-", WideToUtf8(desc), detail, sev);
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

// ─────────────────────────────────────────────────────────────────────────────
// P4 — DWM integrity: injected modules + RWX + M4 inline hook detection
// ─────────────────────────────────────────────────────────────────────────────

static DWORD FindDwmPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            wchar_t up[MAX_PATH];
            wcsncpy_s(up, pe.szExeFile, _TRUNCATE);
            for (auto& c : up) c = towupper(c);
            if (wcscmp(up, L"DWM.EXE") == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool IsSystemModulePath(const std::wstring& path) {
    std::wstring up = path;
    for (auto& c : up) c = towupper(c);
    return up.find(L"\\WINDOWS\\") != std::wstring::npos;
}

// M4: Check if first bytes of a function look like a trampoline hook
static bool IsHookPattern(const BYTE* b, size_t len, std::string& patternDesc) {
    if (len < 6) return false;
    // JMP rel32: E9 xx xx xx xx
    if (b[0] == 0xE9) {
        patternDesc = "JMP rel32 (E9)";
        return true;
    }
    // JMP [rip+x]: FF 25 xx xx xx xx
    if (b[0] == 0xFF && b[1] == 0x25) {
        patternDesc = "JMP [rip+x] (FF 25)";
        return true;
    }
    // PUSH imm32; RET: 68 xx xx xx xx C3
    if (b[0] == 0x68 && len >= 6 && b[5] == 0xC3) {
        patternDesc = "PUSH+RET trampoline (68..C3)";
        return true;
    }
    // MOV RAX, imm64; JMP RAX: 48 B8 ... FF E0 (12 bytes)
    if (b[0] == 0x48 && b[1] == 0xB8 && len >= 12 && b[10] == 0xFF && b[11] == 0xE0) {
        patternDesc = "MOV RAX,imm64; JMP RAX (48 B8..FF E0)";
        return true;
    }
    return false;
}

// M4: Find remote base address of a named DLL in a target process (from already collected modules)
static uintptr_t FindModuleBase(const std::vector<ModuleRange>& modules, const wchar_t* dllNameUp) {
    for (const auto& m : modules) {
        std::wstring nameUp = BaseNameFromPath(m.path);
        for (auto& c : nameUp) c = towupper(c);
        if (nameUp == dllNameUp)
            return m.begin;
    }
    return 0;
}

struct HookCheckEntry { const wchar_t* dll; const char* func; };

static void ScanDwmInlineHooks(HANDLE hProc, const std::vector<ModuleRange>& modules,
                                std::vector<ScannerUI::StreamModFinding>& out) {
    // Functions known to be abused for DWM/composition hooking
    static const HookCheckEntry kTargets[] = {
        { L"DWMAPI.DLL",  "DwmFlush"                      },
        { L"DWMAPI.DLL",  "DwmBeginComposition"            },
        { L"DWMAPI.DLL",  "DwmEndComposition"              },
        { L"DXGI.DLL",    "CreateDXGIFactory"              },
        { L"DXGI.DLL",    "CreateDXGIFactory1"             },
        { L"D3D11.DLL",   "D3D11CreateDevice"              },
        { L"D3D11.DLL",   "D3D11CreateDeviceAndSwapChain"  },
    };

    for (const auto& t : kTargets) {
        uintptr_t remoteBase = FindModuleBase(modules, t.dll);
        if (!remoteBase) continue;

        // Load DLL locally (without resolving imports) to get function RVA
        HMODULE hLocal = LoadLibraryExW(t.dll, nullptr,
                                        DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
        if (!hLocal) continue;

        FARPROC localFunc = GetProcAddress(hLocal, t.func);
        if (!localFunc) { FreeLibrary(hLocal); continue; }

        uintptr_t localBase = (uintptr_t)hLocal & ~0xFFFULL; // align to page
        // For LOAD_LIBRARY_AS_DATAFILE the handle has the low bit set; strip it
        uintptr_t hBase = ((uintptr_t)hLocal) & ~(uintptr_t)3;
        uintptr_t rva   = (uintptr_t)localFunc - hBase;
        FreeLibrary(hLocal);
        (void)localBase;

        uintptr_t remoteFunc = remoteBase + rva;
        BYTE buf[16] = {};
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteFunc), buf, sizeof(buf), &read)
            || read < 6)
            continue;

        std::string patternDesc;
        if (!IsHookPattern(buf, read, patternDesc)) continue;

        char addrBuf[32];
        snprintf(addrBuf, sizeof(addrBuf), "0x%016llX", (unsigned long long)remoteFunc);
        std::string detail = std::string(t.func) + " in " + WideToUtf8(std::wstring(t.dll)) +
                             " patched with " + patternDesc + " at " + addrBuf;
        AddStreamModFinding(out, "DWM_HOOK", "dwm.exe", std::string(t.func), detail, "HIGH");
    }
}

static void ScanDwmIntegrity(std::vector<ScannerUI::StreamModFinding>& out) {
    DWORD dwmPid = FindDwmPid();
    if (!dwmPid) return;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwmPid);
    if (!hProc) return;

    std::vector<ModuleRange> modules;
    if (CollectProcessModules(hProc, modules)) {
        for (const auto& mod : modules) {
            if (mod.path.empty()) continue;

            // Trust the Windows directory — it's OS-protected and all legitimate DWM
            // components live there. Checking signatures within \WINDOWS\ causes false
            // positives because IsCatalogSigned uses a driver GUID that doesn't cover
            // all user-mode system DLLs. Any non-Windows DLL in DWM = injection.
            if (IsSystemModulePath(mod.path)) continue;

            // Content-based annotation (does not affect whether we flag — all non-Windows
            // DLLs in DWM are suspicious by definition).
            BYTE hdr[4096] = {}; SIZE_T hg = 0;
            ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(mod.begin), hdr, sizeof(hdr), &hg);
            bool hasGfxExports = DetectionFilter::ExportsGraphicsSymbol(hdr, hg, mod.begin);
            bool isSigned = IsAuthenticodeSigned(mod.path);

            std::string detail = "DLL injetada no compositor dwm.exe";
            if (hasGfxExports)
                detail += " | EXPORTA FUNCOES GRAFICAS (indicativo de chams)";
            if (!isSigned)
                detail += " | NAO assinada";

            AddStreamModFinding(out, "DWM_INJECT", "dwm.exe",
                WideToUtf8(mod.path), detail, "HIGH");
        }
        // M4: inline hook detection
        ScanDwmInlineHooks(hProc, modules, out);
    }

    // Private executable memory in DWM:
    // RWX = always HIGH (write+exec simultaneously is inherently hostile).
    // RX  = HIGH only with hard evidence: high entropy (≥7.2, packed shellcode)
    //        or PE header (manually-mapped DLL). Normal system stubs are filtered out.
    MEMORY_BASIC_INFORMATION mbi = {};
    std::unordered_set<uintptr_t> seenDwm;
    for (uintptr_t addr = 0x10000; addr < 0x00007FFFFFFEFFFF; ) {
        SIZE_T ret = VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
        if (!ret) break;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + (mbi.RegionSize ? mbi.RegionSize : 0x1000);
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
        DWORD baseProtect = mbi.Protect & 0xff;
        bool isRwx = (baseProtect == PAGE_EXECUTE_READWRITE || baseProtect == PAGE_EXECUTE_WRITECOPY);
        bool isRx  = (baseProtect == PAGE_EXECUTE || baseProtect == PAGE_EXECUTE_READ);
        if (!isRwx && !isRx) continue;
        if (mbi.RegionSize < 0x1000) continue; // 4KB minimum — ignore tiny system stubs

        uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
        if (!seenDwm.insert(allocBase).second) continue;

        // RX-only regions: require hard evidence before flagging
        if (isRx && !isRwx) {
            bool hasPE = DetectionFilter::HasPEHeader(hProc, mbi.BaseAddress);
            double entropy = DetectionFilter::ProcessRegionEntropy(hProc, mbi.BaseAddress, (size_t)mbi.RegionSize);
            bool highEntropy = entropy >= DetectionFilter::kPackedEntropy;
            if (!hasPE && !highEntropy) continue;
        }

        char addrBuf[32];
        snprintf(addrBuf, sizeof(addrBuf), "0x%016llX", (unsigned long long)(uintptr_t)mbi.BaseAddress);
        std::string detail = std::string(isRwx ? "RWX" : "RX") +
                             " memoria privada executavel em dwm.exe em " + addrBuf +
                             " (" + std::to_string(mbi.RegionSize) + " bytes)" +
                             (isRwx ? " — trampoline de hook" : " — shellcode pos-setup ou DLL mapeada");
        AddStreamModFinding(out, "DWM_HOOK", "dwm.exe", addrBuf, detail, "HIGH");
    }
    CloseHandle(hProc);
}

// ─────────────────────────────────────────────────────────────────────────────
// P5 — Topmost layered transparent overlay windows + M7 semi-transparent
// ─────────────────────────────────────────────────────────────────────────────

static bool IsWhitelistedOverlayProcess(const std::wstring& nameUp) {
    static const wchar_t* kList[] = {
        L"GAMEBARFTSERVER.EXE", L"GAMEBAR.EXE", L"GAMEBAREXPERIENCEHOST.EXE",
        L"DISCORD.EXE", L"STEAM.EXE", L"EPICGAMESLAUNCHER.EXE",
        L"NVSPCAPS64.EXE", L"NVSPCAPS.EXE", L"NVCONTAINER.EXE",
        L"NVSPHELPER64.EXE", L"AFTERBURNER.EXE", L"MSIAFTERBURNER.EXE",
        L"RIVATUNERSTATISTICSSERVER.EXE", L"OBS64.EXE", L"OBS32.EXE",
        L"OBS.EXE", L"STREAMLABS OBS.EXE", L"SLOBS.EXE",
        L"EXPLORER.EXE", L"SHELLEXPERIENCEHOST.EXE",
        L"STARTMENUEXPERIENCEHOST.EXE", L"SEARCHHOST.EXE",
        L"TEXTINPUTHOST.EXE", L"DWMREDIR.EXE",
        L"NVIDIA OVERLAY.EXE", L"NVOLAY.EXE",
        L"PLAYNITE.EXE", L"XBOXAPP.EXE", L"GAMINGSERVICES.EXE",
        L"GEFORCE EXPERIENCE.EXE", L"NVNGXUPDATER.EXE",
        L"TEAMSPEAK3.EXE", L"MUMBLE.EXE"
    };
    for (const auto* w : kList)
        if (nameUp == w) return true;
    return false;
}

struct OverlayScanCtx { std::vector<ScannerUI::StreamModFinding>* out; };

static BOOL CALLBACK OverlayScanProc(HWND hWnd, LPARAM lParam) {
    if (!IsWindowVisible(hWnd)) return TRUE;

    LONG_PTR exStyle = GetWindowLongPtrA(hWnd, GWL_EXSTYLE);
    bool layered     = (exStyle & WS_EX_LAYERED)     != 0;
    bool topmost     = (exStyle & WS_EX_TOPMOST)     != 0;
    bool transparent = (exStyle & WS_EX_TRANSPARENT) != 0;
    if (!layered || !topmost || !transparent) return TRUE;

    BYTE  alpha = 255;
    DWORD flags = 0;
    GetLayeredWindowAttributes(hWnd, nullptr, &alpha, &flags);
    if (!(flags & LWA_ALPHA)) return TRUE;

    // M7: flag fully invisible (alpha 0-8) as MEDIUM/FLAG, semi-transparent (9-80) as FLAG for unsigned
    const bool fullyInvisible  = alpha <= 8;
    const bool semiTransparent = alpha > 8 && alpha <= 80;
    if (!fullyInvisible && !semiTransparent) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (!pid || pid == GetCurrentProcessId()) return TRUE;

    std::wstring procPath = ProcessFullPathW(pid);
    std::wstring procName = BaseNameFromPath(procPath);
    for (auto& c : procName) c = towupper(c);
    if (IsWhitelistedOverlayProcess(procName)) return TRUE;

    bool signed_ = !procPath.empty() && IsAuthenticodeSigned(procPath);

    // M7: semi-transparent signed process = too common to flag
    if (semiTransparent && signed_) return TRUE;

    char title[256] = {};
    GetWindowTextA(hWnd, title, sizeof(title));

    char alphaStr[16]; snprintf(alphaStr, sizeof(alphaStr), "%u", (unsigned)alpha);
    std::string detail = fullyInvisible
        ? "Invisible topmost overlay (WS_EX_LAYERED|TOPMOST|TRANSPARENT, alpha="
        : "Semi-transparent topmost overlay (WS_EX_LAYERED|TOPMOST|TRANSPARENT, alpha=";
    detail += alphaStr;
    detail += ")";
    if (title[0]) { detail += ", title: \""; detail += title; detail += "\""; }
    if (!signed_)  detail += " [process unsigned]";

    // Severity: fully invisible unsigned = MEDIUM, fully invisible signed = FLAG
    //           semi-transparent unsigned = FLAG
    std::string sev = (fullyInvisible && !signed_) ? "MEDIUM" : "FLAG";

    auto* ctx = reinterpret_cast<OverlayScanCtx*>(lParam);
    AddStreamModFinding(*ctx->out,
        "OVERLAY",
        WideToUtf8(procPath),
        title[0] ? std::string(title) : "(no title)",
        detail, sev);
    return TRUE;
}

static void ScanSuspiciousOverlayWindows(std::vector<ScannerUI::StreamModFinding>& out) {
    OverlayScanCtx ctx{ &out };
    EnumWindows(OverlayScanProc, reinterpret_cast<LPARAM>(&ctx));
}

// ─────────────────────────────────────────────────────────────────────────────
// P6 (M5) — NvFBC AllowInternal registry flag
// ─────────────────────────────────────────────────────────────────────────────

static void ScanNvfbcRegistry(std::vector<ScannerUI::StreamModFinding>& out) {
    static const struct { HKEY root; const wchar_t* path; } kKeys[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global\\NvFBC" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\NVIDIA Corporation\\Global\\NvFBC" },
    };
    for (const auto& k : kKeys) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(k.root, k.path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        DWORD value = 0, size = sizeof(value), type = 0;
        LSTATUS st = RegQueryValueExW(hKey, L"AllowInternal", nullptr, &type,
                                      (LPBYTE)&value, &size);
        RegCloseKey(hKey);

        if (st == ERROR_SUCCESS && type == REG_DWORD && value == 1) {
            std::string regPath = (k.root == HKEY_LOCAL_MACHINE)
                ? "HKLM\\SOFTWARE\\NVIDIA Corporation\\Global\\NvFBC\\AllowInternal"
                : "HKCU\\SOFTWARE\\NVIDIA Corporation\\Global\\NvFBC\\AllowInternal";
            AddStreamModFinding(out,
                "NVFBC_ALLOW", "-", regPath,
                "NvFBC AllowInternal=1 — any process can capture GPU frame buffer directly "
                "(bypasses normal Windows capture pipeline)",
                "HIGH");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P7 (M6) — Virtual camera / capture device detection
// ─────────────────────────────────────────────────────────────────────────────

static bool IsKnownVirtualCamera(const std::wstring& desc, bool& isSuspicious) {
    std::wstring up = desc;
    for (auto& c : up) c = towupper(c);

    static const wchar_t* kSuspicious[] = {
        L"CHEAT", L"BYPASS", L"CAPTURE_FILTER", L"SPOOF", L"HACK"
    };
    for (const auto* s : kSuspicious) {
        if (up.find(s) != std::wstring::npos) { isSuspicious = true; return true; }
    }

    static const wchar_t* kVirtual[] = {
        L"OBS VIRTUAL", L"OBS-CAMERA", L"VIRTUALCAM", L"VIRTUAL CAM",
        L"MANYCAM", L"XSPLIT VCAM", L"XSPLIT VCam", L"SPLITCAM",
        L"DXTORY", L"SNAP CAMERA", L"MMHMM",
        L"NVIDIA BROADCAST", L"RTXVOICE",
        L"AMD LINK", L"AMD VIRTUAL",
        L"LOGI CAPTURE", L"LOGITECH CAPTURE",
        L"IRIUN", L"DROIDCAM", L"EPOCCAM",
        L"NDI VIRTUAL", L"SPOUT", L"SPOUTCAM"
    };
    for (const auto* v : kVirtual) {
        if (up.find(v) != std::wstring::npos) { isSuspicious = false; return true; }
    }
    return false;
}

static void ScanVirtualCameraDevices(std::vector<ScannerUI::StreamModFinding>& out) {
    HDEVINFO devInfo = SetupDiGetClassDevsW(&kCameraClass, nullptr, nullptr, DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devData = {};
    devData.cbSize = sizeof(devData);
    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devInfo, idx, &devData); ++idx) {
        wchar_t desc[256] = {};
        if (!SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_DEVICEDESC,
                                               nullptr, (PBYTE)desc, sizeof(desc), nullptr))
            continue;
        bool suspicious = false;
        if (!IsKnownVirtualCamera(desc, suspicious)) continue;

        wchar_t hwid[512] = {};
        SetupDiGetDeviceRegistryPropertyW(devInfo, &devData, SPDRP_HARDWAREID,
                                          nullptr, (PBYTE)hwid, sizeof(hwid), nullptr);

        std::string detail = "Virtual camera device: ";
        detail += WideToUtf8(desc);
        if (hwid[0]) { detail += " ["; detail += WideToUtf8(hwid); detail += "]"; }
        if (suspicious)
            detail += " — suspicious keyword in device name";

        AddStreamModFinding(out, "VIRTUAL_CAMERA", "-", WideToUtf8(desc),
                            detail, suspicious ? "HIGH" : "FLAG");
    }
    SetupDiDestroyDeviceInfoList(devInfo);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

std::vector<ScannerUI::StreamModFinding> CollectStreamModFindings(std::string& status) {
    std::vector<ScannerUI::StreamModFinding> findings;

    ScanCaptureExcludedWindows(findings);   // P1
    ScanStreamingPlugins(findings);         // P2 disk + M2 entropy
    ScanObsRuntimeModules(findings);        // M1 OBS runtime injection
    ScanVirtualDisplayAdapters(findings);   // P3 + M3 driver signing
    ScanDwmIntegrity(findings);             // P4 + M4 inline hooks
    ScanSuspiciousOverlayWindows(findings); // P5 + M7 semi-transparent
    ScanNvfbcRegistry(findings);            // P6 NvFBC AllowInternal
    ScanVirtualCameraDevices(findings);     // P7 virtual camera

    if (findings.empty()) {
        status = "OK";
    } else {
        bool hasHigh = false;
        for (const auto& f : findings)
            if (f.severity == "HIGH") { hasHigh = true; break; }
        status = hasHigh ? "DETECTED" : "REVIEW";
    }
    return findings;
}
