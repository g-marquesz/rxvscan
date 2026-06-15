#include "scanner_core.h"

using NtQueryVirtualMemoryFn = LONG (WINAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
using NtGetNextThreadFn      = LONG (WINAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);

static std::string HexAddress(uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << value;
    return oss.str();
}

static std::string ProtectionToString(DWORD protect) {
    DWORD base = protect & 0xff;
    std::string out;
    switch (base) {
    case PAGE_EXECUTE: out = "EXECUTE"; break;
    case PAGE_EXECUTE_READ: out = "EXECUTE_READ"; break;
    case PAGE_EXECUTE_READWRITE: out = "EXECUTE_READWRITE"; break;
    case PAGE_EXECUTE_WRITECOPY: out = "EXECUTE_WRITECOPY"; break;
    case PAGE_READONLY: out = "READONLY"; break;
    case PAGE_READWRITE: out = "READWRITE"; break;
    case PAGE_WRITECOPY: out = "WRITECOPY"; break;
    case PAGE_NOACCESS: out = "NOACCESS"; break;
    default: out = "UNKNOWN"; break;
    }
    if ((protect & PAGE_GUARD) != 0) out += "|GUARD";
    if ((protect & PAGE_NOCACHE) != 0) out += "|NOCACHE";
    if ((protect & PAGE_WRITECOMBINE) != 0) out += "|WRITECOMBINE";
    return out;
}

static bool IsExecutableProtection(DWORD protect) {
    DWORD base = protect & 0xff;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWriteExecuteProtection(DWORD protect) {
    DWORD base = protect & 0xff;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

// Tag constants are defined in scanner_core.h under namespace ScanTag.
static constexpr const char* kTagManualMapping = ScanTag::ManualMapping;
static constexpr const char* kTagMapper        = ScanTag::Mapper;
static constexpr const char* kTagMemoryInject  = ScanTag::MemoryInject;
static constexpr const char* kTagThreadInject  = ScanTag::ThreadInject;
static constexpr const char* kTagMemoryProtect = ScanTag::MemoryProtect;
static constexpr const char* kTagThreadProtect = ScanTag::ThreadProtect;
static constexpr const char* kTagGfxHookThread = ScanTag::GfxHookThread;
static constexpr const char* kTagGfxHookMemory = ScanTag::GfxHookMemory;
static constexpr const char* kTagModulePatch   = ScanTag::ModulePatch;
static constexpr const char* kTagModuleAnomaly = ScanTag::ModuleAnomaly;
static constexpr const char* kTagInjectHandle  = ScanTag::InjectHandle;

static bool AddressInsideModule(uintptr_t address, const std::vector<ModuleRange>& modules) {
    for (const auto& module : modules) {
        if (address >= module.begin && address < module.end)
            return true;
    }
    return false;
}

std::wstring BaseNameFromPath(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

static bool IsKnownEmulatorProcess(const std::wstring& exe) {
    static const std::unordered_set<std::wstring> names = {
        L"HD-PLAYER.EXE", L"ANDROIDEMULATOR.EXE", L"ANDROIDPROCESS.EXE",
        L"MEMU.EXE", L"MEMUHEADLESS.EXE", L"MEMUSVC.EXE",
        L"NOX.EXE", L"NOXVMHANDLE.EXE", L"NOXVM.EXE",
        L"DNPLAYER.EXE", L"LDVBOXHEADLESS.EXE", L"LD9BOXHEADLESS.EXE",
        L"MUMUPLAYER.EXE", L"MUMUVMMHEADLESS.EXE", L"MUMUEMULATOR.EXE",
        L"BLUESTACKS.EXE", L"BSTMHDANDROID.EXE"
    };
    return names.find(ToUpperInvariant(exe)) != names.end();
}

static bool IsHdPlayerProcess(const std::wstring& exe) {
    return ToUpperInvariant(exe) == L"HD-PLAYER.EXE";
}

static bool IsKnownJitHost(const std::wstring& exe) {
    static const std::unordered_set<std::wstring> names = {
        // Browsers (V8/SpiderMonkey/Chakra JIT)
        L"CHROME.EXE", L"FIREFOX.EXE", L"MSEDGE.EXE", L"OPERA.EXE", L"BRAVE.EXE",
        L"VIVALDI.EXE", L"THORIUM.EXE",
        // JVM-based
        L"JAVA.EXE", L"JAVAW.EXE", L"JAVAWS.EXE",
        // .NET / Mono
        L"DOTNET.EXE", L"CSC.EXE", L"VBCSCOMPILER.EXE",
        L"MONO.EXE", L"MONO-SGEN.EXE",
        // Node / Deno / Bun
        L"NODE.EXE", L"DENO.EXE", L"BUN.EXE",
        // Scripting runtimes
        L"POWERSHELL.EXE", L"PWSH.EXE",
        L"RUBY.EXE", L"RUBY23.EXE", L"RUBY24.EXE", L"RUBY25.EXE",
        L"PHP.EXE", L"PHP-CGI.EXE",
        L"PYTHON.EXE", L"PYTHONW.EXE", L"PYTHON3.EXE",
        L"PERL.EXE",
        // LuaJIT / Lua
        L"LUAJIT.EXE", L"LUA.EXE",
        // Game engines with script JIT
        L"UNITY.EXE", L"UNITYHUB.EXE",
    };
    return names.find(ToUpperInvariant(exe)) != names.end();
}

std::vector<DWORD> FindEmulatorProcesses() {
    std::vector<DWORD> pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return pids;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (IsKnownEmulatorProcess(entry.szExeFile))
                pids.push_back(entry.th32ProcessID);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pids;
}

static std::string FormatFileTimeLocal(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
        return "-";
    std::string date;
    std::string time;
    FileTimeToLocalStrings(ft, date, time);
    return date + " " + time;
}

static std::string FindLastHdPlayerPrefetchTime() {
    wchar_t windowsDir[MAX_PATH] = {};
    UINT len = GetWindowsDirectoryW(windowsDir, (UINT)std::size(windowsDir));
    if (len == 0 || len >= std::size(windowsDir))
        return "-";

    std::wstring search = std::wstring(windowsDir) + L"\\Prefetch\\HD-PLAYER.EXE-*.pf";
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(search.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE)
        return "-";

    FILETIME newest = {};
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            continue;
        if (FileTimeToU64(data.ftLastWriteTime) > FileTimeToU64(newest))
            newest = data.ftLastWriteTime;
    } while (FindNextFileW(find, &data));

    FindClose(find);
    return FormatFileTimeLocal(newest);
}

EmulatorRuntimeInfo CollectEmulatorRuntimeInfo() {
    EmulatorRuntimeInfo info;
    FILETIME oldestStart = {};

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (!IsHdPlayerProcess(entry.szExeFile))
                    continue;

                info.hdPlayerOpen = true;
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                if (!process)
                    continue;

                FILETIME createTime = {}, exitTime = {}, kernelTime = {}, userTime = {};
                if (GetProcessTimes(process, &createTime, &exitTime, &kernelTime, &userTime)) {
                    if (oldestStart.dwLowDateTime == 0 && oldestStart.dwHighDateTime == 0)
                        oldestStart = createTime;
                    else if (FileTimeToU64(createTime) < FileTimeToU64(oldestStart))
                        oldestStart = createTime;
                }
                CloseHandle(process);
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    if (info.hdPlayerOpen) {
        info.openedAt = FormatFileTimeLocal(oldestStart);
        if (info.openedAt == "-") {
            std::string lastOpened = FindLastHdPlayerPrefetchTime();
            info.openedAt = lastOpened == "-" ? "Open (time unavailable)" : "Last opened: " + lastOpened;
        }
    } else {
        std::string lastOpened = FindLastHdPlayerPrefetchTime();
        info.openedAt = lastOpened == "-" ? "Closed" : "Last opened: " + lastOpened;
    }

    return info;
}

bool CollectProcessModules(HANDLE process, std::vector<ModuleRange>& modules) {
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process, nullptr, 0, &needed, LIST_MODULES_ALL) || needed == 0)
        return false;

    std::vector<HMODULE> handles(needed / sizeof(HMODULE));
    if (!EnumProcessModulesEx(process, handles.data(), needed, &needed, LIST_MODULES_ALL))
        return false;

    handles.resize(needed / sizeof(HMODULE));
    for (HMODULE module : handles) {
        MODULEINFO info = {};
        wchar_t path[MAX_PATH * 4] = {};
        if (!GetModuleInformation(process, module, &info, sizeof(info)))
            continue;
        GetModuleFileNameExW(process, module, path, (DWORD)std::size(path));

        ModuleRange range;
        range.begin = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
        range.end = range.begin + info.SizeOfImage;
        range.path = path;
        modules.push_back(range);
    }

    std::sort(modules.begin(), modules.end(), [](const auto& a, const auto& b) {
        return a.begin < b.begin;
    });
    return true;
}

std::string ProcessName(HANDLE process) {
    wchar_t path[MAX_PATH * 4] = {};
    if (GetModuleFileNameExW(process, nullptr, path, (DWORD)std::size(path)) == 0)
        return "unknown";
    return WideToUtf8(BaseNameFromPath(path));
}

std::string ProcessPathByPid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process)
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return "pid:" + std::to_string(pid);

    wchar_t path[MAX_PATH * 4] = {};
    DWORD len = (DWORD)std::size(path);
    std::string out;
    if (QueryFullProcessImageNameW(process, 0, path, &len))
        out = WideToUtf8(path);
    else
        out = ProcessName(process);
    CloseHandle(process);
    return out.empty() ? ("pid:" + std::to_string(pid)) : out;
}

std::wstring ProcessBaseNameByPid(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process)
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return L"";

    wchar_t path[MAX_PATH * 4] = {};
    DWORD len = (DWORD)std::size(path);
    std::wstring out;
    if (QueryFullProcessImageNameW(process, 0, path, &len))
        out = BaseNameFromPath(path);
    CloseHandle(process);
    return out;
}



std::wstring ProcessImageDirW(HANDLE process) {
    wchar_t path[MAX_PATH * 4] = {};
    DWORD len = (DWORD)std::size(path);
    if (!QueryFullProcessImageNameW(process, 0, path, &len))
        return L"";
    std::wstring full = path;
    size_t slash = full.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"" : full.substr(0, slash);
}

std::wstring ProcessFullPathW(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return L"";
    wchar_t path[MAX_PATH * 4] = {};
    DWORD len = (DWORD)std::size(path);
    std::wstring out;
    if (QueryFullProcessImageNameW(process, 0, path, &len))
        out = path;
    CloseHandle(process);
    return out;
}

static void AddEmulatorFinding(std::vector<ScannerUI::EmulatorFinding>& out,
                               const std::string& process,
                               const std::string& type,
                               uintptr_t address,
                               const std::string& detail,
                               const std::string& severity = "FLAG") {
    if (out.size() >= 96)
        return;

    ScannerUI::EmulatorFinding finding;
    finding.process = process;
    finding.type = type;
    finding.address = address == 0 ? "-" : HexAddress(address);
    finding.detail = detail;
    finding.severity = severity;
    out.push_back(finding);
}

static void ScanUnsignedModules(HANDLE process, const std::string& processName,
                                const std::vector<ModuleRange>& modules,
                                const std::wstring& installDir,
                                const std::wstring& exePath,
                                std::vector<ScannerUI::EmulatorFinding>& out) {
    for (const auto& module : modules) {
        std::wstring file = BaseNameFromPath(module.path);
        std::wstring upper = ToUpperInvariant(file);
        bool dllLike = upper.size() >= 4 && upper.substr(upper.size() - 4) == L".DLL";
        if (!dllLike || module.path.empty())
            continue;



        if (!installDir.empty() && DetectionFilter::PathIsUnder(module.path, DetectionFilter::UpperW(installDir)))
            continue;
        // Signed module path: trust same-publisher DLLs and the broad set of legitimately
        // cross-publisher loads (Windows system runtime in System32, OEM drivers,
        // ProgramFiles app DLLs, UserProfile-installed apps). What still warrants a
        // finding is a signed-but-foreign-publisher DLL loading from a sketchy path
        // (Temp/installer staging or unmapped paths) — that is a typical cheat-DLL
        // delivery vector that previously slipped past the unsigned-only filter.
        // Signed cheats from System32 paths require admin write and are caught by
        // CollectGraphicsHookFindings / ScanDxgiVtableIntegrity / ScanNtdllStubIntegrity.
        if (IsAuthenticodeSigned(module.path)) {
            if (!exePath.empty() && DetectionFilter::SamePublisherTrusted(module.path, exePath))
                continue;
            DetectionFilter::PathClass mcls = DetectionFilter::ClassifyPath(module.path);
            if (mcls != DetectionFilter::PathClass::TempOrInstaller &&
                mcls != DetectionFilter::PathClass::Unknown &&
                mcls != DetectionFilter::PathClass::Unmapped)
                continue;
            std::wstring modCn = DetectionFilter::GetSignerCommonNameUpperCached(module.path);
            // Microsoft-signed runtime support DLLs dropped via installer are routine.
            if (modCn.compare(0, 9, L"MICROSOFT") == 0)
                continue;
            std::string detail = "DLL assinada por publisher estranho carregada de local nao-confiavel: " +
                                 WideToUtf8(file) +
                                 " | signer=" + WideToUtf8(modCn) +
                                 " | path_class=" + DetectionFilter::PathClassName(mcls);
            AddEmulatorFinding(out, processName, "DLL", module.begin, detail, "MEDIUM");
            continue;
        }

        double entropy = DetectionFilter::FileEntropySample(module.path);
        bool packed = entropy >= DetectionFilter::kPackedEntropy;
        DetectionFilter::PathClass cls = DetectionFilter::ClassifyPath(module.path);

        // Unsigned & not catalog-signed inside System32/Program Files is unusual (genuine
        // Windows/vendor DLLs are always signed or cataloged), but low-entropy/unpacked
        // third-party DLLs do exist there. Surface at low severity instead of dropping —
        // a malicious DLL placed here with admin rights must not vanish from the report.
        if (DetectionFilter::IsTrustedDir(cls) && !packed) {
            // Catalog fallback: WinVerifyTrust above can fail transiently (slow catalog
            // warm-up, locked cat files, etc.) on legitimate System32 DLLs that are only
            // catalog-signed (OPENGL32.dll, GLU32.dll, etc.). If CryptCATAdmin reports
            // the file's hash IS in an installed catalog, the file is MS-shipped — do
            // not flag. Only NotFound (catalog system worked, hash absent) is suspicious.
            // Unverifiable (cat service failed) is not treated as evidence either way.
            if (DetectionFilter::QueryWindowsCatalogState(module.path) ==
                DetectionFilter::CatalogState::Found)
                continue;
            std::string detail = "DLL sem assinatura (nao cataloged) em diretorio confiavel: " +
                                 WideToUtf8(file) +
                                 " | entropy=" + DetectionFilter::EntropyToStr(entropy) +
                                 " | path_class=" + DetectionFilter::PathClassName(cls);
            AddEmulatorFinding(out, processName, "DLL", module.begin, detail, "FLAG");
            continue;
        }

        // Only flag unsigned DLLs if they are packed OR come from a clearly suspicious path.
        // UserProfile and ProgramFiles can have legitimate unsigned DLLs (game engines, etc.).
        bool suspiciousPath = cls == DetectionFilter::PathClass::TempOrInstaller ||
                              cls == DetectionFilter::PathClass::Unknown ||
                              cls == DetectionFilter::PathClass::Unmapped;
        if (!packed && !suspiciousPath)
            continue;

        std::string detail = "DLL sem assinatura" + std::string(packed ? " (packed)" : "") +
                             ": " + WideToUtf8(file) +
                             " | entropy=" + DetectionFilter::EntropyToStr(entropy) +
                             " | path_class=" + DetectionFilter::PathClassName(cls);
        AddEmulatorFinding(out, processName, "DLL", module.begin, detail, packed ? "HIGH" : "MEDIUM");
    }
}



static std::unordered_set<uintptr_t> CollectThreadAllocBases(
    DWORD pid, HANDLE process, const std::vector<ModuleRange>& modules) {
    std::unordered_set<uintptr_t> bases;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto queryThread = ntdll ? reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread")) : nullptr;
    if (!queryThread)
        return bases;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return bases;
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != pid)
                continue;
            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!thread)
                thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!thread)
                continue;
            PVOID start = nullptr;
            if (queryThread(thread, 9, &start, sizeof(start), nullptr) >= 0 && start) {
                uintptr_t addr = reinterpret_cast<uintptr_t>(start);
                if (!AddressInsideModule(addr, modules)) {
                    MEMORY_BASIC_INFORMATION mbi = {};
                    if (VirtualQueryEx(process, start, &mbi, sizeof(mbi)) == sizeof(mbi))
                        bases.insert(reinterpret_cast<uintptr_t>(mbi.AllocationBase));
                }
            }
            CloseHandle(thread);
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);
    return bases;
}

static void ScanExecutablePrivateMemory(HANDLE process, const std::string& processName,
                                        const std::vector<ModuleRange>& modules,
                                        std::vector<ScannerUI::EmulatorFinding>& out,
                                        const std::unordered_set<uintptr_t>* activeThreadBases = nullptr,
                                        bool isEmulatorProcess = false,
                                        bool reportManualMap = true,
                                        bool useWinScanTags = false,
                                        const std::unordered_set<uintptr_t>* gfxHookDests = nullptr) {
    // Compute upper address bound: highest module end + 512 MB, minimum 2 GB.
    // This avoids iterating terabytes of reserved-but-uncommitted address space.
    uintptr_t maxModuleEnd = 0;
    for (const auto& m : modules)
        if (m.end > maxModuleEnd) maxModuleEnd = m.end;
    constexpr uintptr_t kMinScan   = 2ULL * 1024 * 1024 * 1024;       // 2 GB floor
    constexpr uintptr_t kHeadroom  = 512ULL * 1024 * 1024;             // 512 MB above modules
    const uintptr_t kScanLimit = (maxModuleEnd + kHeadroom > kMinScan)
                                 ? (maxModuleEnd + kHeadroom) : kMinScan;

    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi = {};
    std::unordered_set<uintptr_t> seenAllocBases;
    while (address < kScanLimit &&
           VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t end = base + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && IsExecutableProtection(mbi.Protect) && !AddressInsideModule(base, modules)) {


            uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            if (mbi.AllocationBase && !seenAllocBases.insert(allocBase).second) {
                if (end <= address) break;
                address = end;
                continue;
            }
            bool privateMem = (mbi.Type == MEM_PRIVATE);
            bool writeExec = IsWriteExecuteProtection(mbi.Protect);
            double entropy = DetectionFilter::ProcessRegionEntropy(process, mbi.BaseAddress, (size_t)mbi.RegionSize);
            bool hasPeHeader = privateMem && DetectionFilter::HasPEHeader(process, mbi.BaseAddress);
            if (hasPeHeader && !reportManualMap) {
                if (end <= address) break;
                address = end;
                continue;
            }



            if (activeThreadBases != nullptr && !hasPeHeader) {
                if (activeThreadBases->count(allocBase) == 0) {
                    if (end <= address) break;
                    address = end;
                    continue;
                }
            }
            DetectionFilter::RegionVerdict v = DetectionFilter::ClassifyExecRegion(
                writeExec, (size_t)mbi.RegionSize, entropy, privateMem, hasPeHeader,
                isEmulatorProcess);
            if (v.keep) {
                bool isGfxPayload = gfxHookDests && gfxHookDests->count(allocBase) > 0;
                std::string detail = hasPeHeader
                    ? "DLL manualmente mapeada (reflective injection) | protect=" + ProtectionToString(mbi.Protect) + " | " + v.note
                    : "Memoria executavel fora de modulo | protect=" + ProtectionToString(mbi.Protect) + " | " + v.note;
                if (isGfxPayload)
                    detail += " | CONFIRMADO: payload de hook OpenGL/grafico";
                const char* tag;
                if (useWinScanTags) {
                    if (hasPeHeader)
                        tag = kTagManualMapping;
                    else if (isGfxPayload)
                        tag = kTagGfxHookMemory;
                    else
                        tag = kTagMemoryInject;
                } else {
                    tag = "MEMORY";
                }
                std::string sev = (isGfxPayload && v.severity != "HIGH") ? "HIGH" : v.severity;
                AddEmulatorFinding(out, processName, tag, base, detail, sev);
            } else if (!v.keep && useWinScanTags && privateMem && mbi.RegionSize >= 256) {
                // Mudanca 6: regions discarded by ClassifyExecRegion may still be shellcode.
                // Read up to 4 KB and check for definitive shellcode byte patterns:
                //   hasPebDebugCheck = mov rax/rbx, gs:[60h] — PEB walking (loader-free shellcode)
                //   hasRdtscCheck + hasCpuidVmCheck = timing+VM evasion (common in loaders)
                // These sequences are extremely rare in legitimate JIT/managed-runtime output.
                BYTE sc[4096]; SIZE_T scGot = 0;
                SIZE_T toRead = mbi.RegionSize < sizeof(sc) ? mbi.RegionSize : sizeof(sc);
                if (ReadProcessMemory(process, mbi.BaseAddress, sc, toRead, &scGot) && scGot >= 16) {
                    auto profile = DetectionFilter::ScanAntiAnalysisPatterns(sc, scGot);
                    bool shellcode = profile.hasPebDebugCheck ||
                                     (profile.hasRdtscCheck && profile.hasCpuidVmCheck);
                    if (shellcode) {
                        std::string scNote = "Padroes de shellcode por bytes: ";
                        if (profile.hasPebDebugCheck) scNote += "PEB-walk(gs:[60h]) ";
                        if (profile.hasRdtscCheck)    scNote += "RDTSC ";
                        if (profile.hasCpuidVmCheck)  scNote += "CPUID-vmcheck";
                        std::string detail = "Regiao com padroes comportamentais de shellcode | protect=" +
                                             ProtectionToString(mbi.Protect) + " | " + scNote;
                        AddEmulatorFinding(out, processName, kTagMemoryInject, base, detail, "HIGH");
                    }
                }
            }
        }

        if (end <= address)
            break;
        address = end;
    }
}

static void ScanThreadStartAddresses(DWORD pid, const std::string& processName, HANDLE process,
                                     const std::vector<ModuleRange>& modules,
                                     std::vector<ScannerUI::EmulatorFinding>& out,
                                     bool isEmulatorProcess = false,
                                     bool reportManualMap = true,
                                     bool useWinScanTags = false,
                                     const std::unordered_set<uintptr_t>* gfxHookDests = nullptr) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto queryThread = ntdll ? reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread")) : nullptr;
    if (!queryThread)
        return;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != pid)
                continue;

            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread)
                thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread)
                continue;

            PVOID start = nullptr;
            if (queryThread(thread, 9, &start, sizeof(start), nullptr) >= 0 && start != nullptr) {
                uintptr_t startAddress = reinterpret_cast<uintptr_t>(start);
                if (!AddressInsideModule(startAddress, modules)) {


                    bool suppress = false;
                    bool forceEmulatorThreadReport = false;
                    bool threadProtected = false;
                    std::string extra;
                    MEMORY_BASIC_INFORMATION mbi = {};
                    bool hasPeHeader = false;
                    if (VirtualQueryEx(process, start, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                        threadProtected = (mbi.Protect & PAGE_GUARD) != 0;
                        bool privateMem = (mbi.Type == MEM_PRIVATE);
                        double entropy = DetectionFilter::ProcessRegionEntropy(process, mbi.BaseAddress, (size_t)mbi.RegionSize);
                        hasPeHeader = privateMem && DetectionFilter::HasPEHeader(process, mbi.BaseAddress);
                        if (hasPeHeader && !reportManualMap) {
                            suppress = true;
                            extra = " | manual map direcionado ao WinScan";
                        } else {
                        DetectionFilter::RegionVerdict v = DetectionFilter::ClassifyExecRegion(
                            IsWriteExecuteProtection(mbi.Protect), (size_t)mbi.RegionSize, entropy, privateMem, hasPeHeader,
                            isEmulatorProcess);
                        extra = " | " + v.note;
                        if (isEmulatorProcess && privateMem && !hasPeHeader &&
                            IsWriteExecuteProtection(mbi.Protect) &&
                            mbi.RegionSize <= 512ull * 1024ull &&
                            entropy >= 7.55) {
                            suppress = false;
                            forceEmulatorThreadReport = true;
                            extra += " | thread ativa em RWX pequeno de alta entropia";
                        } else {
                            suppress = !v.keep;
                        }
                        }
                    }
                    if (!suppress) {
                        // Only report threads with conclusive indicators to avoid noise.
                        bool hasRwx = IsWriteExecuteProtection(mbi.Protect);
                        bool conclusive = hasPeHeader || forceEmulatorThreadReport || hasRwx;
                        if (!conclusive)
                            continue;

                        uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
                        bool isGfxThread = gfxHookDests && allocBase && gfxHookDests->count(allocBase) > 0;

                        std::string msg = hasPeHeader
                            ? "Thread em DLL reflective mapeada | tid=" + std::to_string(entry.th32ThreadID) + extra
                            : (forceEmulatorThreadReport
                                ? "Thread suspeita fora de modulo | tid=" + std::to_string(entry.th32ThreadID) + extra
                                : "Thread start em regiao RWX | tid=" + std::to_string(entry.th32ThreadID) + extra);
                        if (isGfxThread)
                            msg += " | CONFIRMADO: thread em payload de hook OpenGL/grafico";

                        const char* tag;
                        if (useWinScanTags) {
                            if (isGfxThread)
                                tag = kTagGfxHookThread;
                            else if (threadProtected)
                                tag = kTagThreadProtect;
                            else
                                tag = kTagThreadInject;
                        } else {
                            tag = "THREAD";
                        }
                        std::string sev = (isGfxThread || hasPeHeader || hasRwx) ? "HIGH"
                                          : (forceEmulatorThreadReport ? "HIGH" : "MEDIUM");
                        AddEmulatorFinding(out, processName, tag, startAddress, msg, sev);
                    }
                }
            }
            CloseHandle(thread);
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

// ─── Mudanca 4: PE structural anomaly scan for loaded modules ─────────────────
// Detects binary patching (checksum mismatch), packer sections, and missing Rich
// headers without relying on module name, path, or file size.
// Trust gate: IsTrustedSignedCached only — signature is the only reliable signal.
static void ScanLoadedModuleAnomalies(HANDLE /*process*/, const std::string& processName,
                                      const std::vector<ModuleRange>& modules,
                                      std::vector<ScannerUI::EmulatorFinding>& out) {
    for (const auto& mod : modules) {
        if (mod.path.empty())
            continue;
        // Skip cryptographically verified modules — content integrity is confirmed.
        if (DetectionFilter::IsTrustedSignedCached(mod.path))
            continue;

        DetectionFilter::EfiPeInfo pe = DetectionFilter::AnalyzeEfiPe(mod.path);
        if (!pe.valid)
            continue;

        std::string modName = WideToUtf8(BaseNameFromPath(mod.path));

        // ── 1. Checksum mismatch: binary was patched after compilation ─────────
        if (DetectionFilter::CheckPeChecksumMismatch(mod.path, pe.storedChecksum)) {
            std::string detail = "Modulo com checksum PE diferente do disco: " + modName +
                                 " | checksum armazenado != calculado | indicador de patching binario";
            if (out.size() < ScanLimits::kMaxSysmemFindings)
                out.push_back({ processName, kTagModulePatch,
                                HexAddress(mod.begin), detail, "HIGH" });
            continue; // one finding per module is enough
        }

        // ── 2. Packer sections: .vmp, .themida, packed, etc. ──────────────────
        if (pe.badSections) {
            std::string detail = "Modulo com secoes de packer/protecao: " + modName +
                                 " | secoes anomalas detectadas (obfuscator/packer)";
            if (out.size() < ScanLimits::kMaxSysmemFindings)
                out.push_back({ processName, kTagModuleAnomaly,
                                HexAddress(mod.begin), detail, "HIGH" });
        }
    }
}

// ─── Mudanca 5: Intra-process injection handle scan ───────────────────────────
// Enumerates all system handles owned by 'pid' and flags any that point to a
// DIFFERENT process with combined write+thread-create rights — the classic
// injection combo. Uses NtQuerySystemInformation(SystemHandleInformation) which
// gives all handles system-wide; we filter by owner PID then resolve target PID.
static void ScanSuspiciousHandlesInProcess(DWORD pid, const std::string& procName,
                                           std::vector<ScannerUI::EmulatorFinding>& out) {
    // Se o processo FONTE e assinado por publisher reconhecido, seus handles inter-processo
    // sao legitimos (NVIDIA service, Steam launcher, VS debugger, etc.).
    // Esta verificacao usa Authenticode — nao depende de nome, pasta ou tamanho do processo.
    std::wstring sourcePath = ProcessFullPathW(pid);
    if (!sourcePath.empty() && DetectionFilter::IsTrustedSignedCached(sourcePath))
        return;

    constexpr DWORD kInjectCombo = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto querySystem = ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    if (!querySystem)
        return;

    ULONG bufSize = 1u << 20;
    std::vector<BYTE> buf(bufSize);
    ULONG needed = 0;
    LONG st = querySystem(64, buf.data(), bufSize, &needed);
    while (st == (LONG)0xC0000004L || st == (LONG)0xC0000023L) {
        bufSize = needed > bufSize ? needed + (1u << 16) : bufSize * 2;
        buf.assign(bufSize, 0);
        st = querySystem(64, buf.data(), bufSize, &needed);
    }
    if (st < 0)
        return;

    // Open the target process so we can DuplicateHandle its handles.
    HANDLE targetProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!targetProc)
        return;

    auto* info = reinterpret_cast<SystemHandleInformationEx*>(buf.data());
    std::unordered_set<std::string> seen;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& h = info->Handles[i];
        if ((DWORD)h.UniqueProcessId != pid)
            continue;
        // Must have BOTH write AND create-thread to qualify as injection combo.
        if ((h.GrantedAccess & kInjectCombo) != kInjectCombo)
            continue;

        // Duplicate the handle into our process to resolve the target PID.
        HANDLE dup = nullptr;
        if (!DuplicateHandle(targetProc, (HANDLE)(ULONG_PTR)h.HandleValue,
                             GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;
        DWORD targetPid = GetProcessId(dup);
        CloseHandle(dup);

        if (targetPid == 0 || targetPid == pid)
            continue; // skip null or self-handle

        // Deduplicate by (targetPid, access) to avoid flood from multi-handle injectors.
        std::string key = std::to_string(targetPid) + ":" +
                          std::to_string(h.GrantedAccess);
        if (!seen.insert(key).second)
            continue;

        // Trust: if BOTH processes are signed by the same publisher this is an
        // inter-process JIT or telemetry channel (e.g. Chrome renderer → browser).
        std::wstring targetPath = ProcessFullPathW(targetPid);
        if (!targetPath.empty() && DetectionFilter::IsTrustedSignedCached(targetPath))
            continue;

        std::ostringstream detail;
        detail << "Handle de injecao detectado: pid=" << pid
               << " possui handle no pid=" << targetPid
               << " | access=0x" << std::hex << std::uppercase << h.GrantedAccess
               << " | VM_WRITE+CREATE_THREAD+VM_OPERATION confirmados";
        if (out.size() < ScanLimits::kMaxSysmemFindings)
            out.push_back({ procName, kTagInjectHandle,
                            HexAddress((uintptr_t)h.HandleValue), detail.str(), "HIGH" });

        if (out.size() >= ScanLimits::kMaxSysmemFindings)
            break;
    }

    CloseHandle(targetProc);
}

static void ScanAnomalousModuleProtections(HANDLE process, const std::string& processName,
                                           const std::vector<ModuleRange>& modules,
                                           std::vector<ScannerUI::EmulatorFinding>& out,
                                           const std::unordered_set<uintptr_t>* gfxHookDests = nullptr) {
    for (const auto& mod : modules) {
        if (mod.path.empty())
            continue;
        // Mudanca 3: removido IsTrustedDir — localizacao nao e criterio de confianca.
        // Um cheat pode colocar uma DLL em System32 com privilegio admin. Apenas assinatura
        // valida (conteudo criptograficamente verificado) e aceita como confianca.
        if (DetectionFilter::IsTrustedSignedCached(mod.path))
            continue;

        // Determine if this module is graphics-related (content-based, not name-based).
        // RWX in a non-graphics, non-suspect module is downgraded to MEDIUM to avoid
        // false positives from game engines and other unsigned-but-legitimate modules.
        BYTE modHdr[4096] = {}; SIZE_T mhg = 0;
        ReadProcessMemory(process, (LPCVOID)mod.begin, modHdr, sizeof(modHdr), &mhg);
        bool isGfxModule = DetectionFilter::ExportsGraphicsSymbol(modHdr, mhg, mod.begin);

        std::wstring file = BaseNameFromPath(mod.path);
        bool flaggedThisMod = false;
        uintptr_t addr = mod.begin;
        while (addr < mod.end && !flaggedThisMod) {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
                break;
            if (mbi.State == MEM_COMMIT && IsWriteExecuteProtection(mbi.Protect) &&
                mbi.RegionSize >= 4096) {
                uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
                bool isGfxHookTarget = gfxHookDests && allocBase && gfxHookDests->count(allocBase) > 0;
                // HIGH only when the module is graphics-related or is a confirmed hook destination.
                // Otherwise downgrade to MEDIUM (suspicious but not conclusive).
                std::string sev = (isGfxModule || isGfxHookTarget) ? "HIGH" : "MEDIUM";
                std::string detail = "RWX em codigo de modulo: " + WideToUtf8(file) +
                                     " | protect=" + ProtectionToString(mbi.Protect) +
                                     " | addr=" + HexAddress(addr);
                if (isGfxHookTarget)
                    detail += " | CONFIRMADO: modulo e destino de hook grafico";
                else if (!isGfxModule)
                    detail += " | modulo sem exports graficos (rebaixado para MEDIUM)";
                if (out.size() < 128)
                    out.push_back({ processName, kTagMemoryProtect, HexAddress(addr), detail, sev });
                flaggedThisMod = true;
            }
            uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    }
}

// ─── Hidden DLL detection: PEB module list vs VAD cross-reference ────────────
// Finds MEM_IMAGE regions that are not listed in the PEB InLoadOrderModuleList.
// Manual mappers unlink injected DLLs from the PEB to hide them from module
// enumeration APIs — this detects the remaining mapped image regions.
static void ScanHiddenMappedDlls(HANDLE process, const std::string& procName,
                                  const std::vector<ModuleRange>& modules,
                                  std::vector<ScannerUI::EmulatorFinding>& out) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueryVirtMem = ntdll ? reinterpret_cast<NtQueryVirtualMemoryFn>(
        GetProcAddress(ntdll, "NtQueryVirtualMemory")) : nullptr;
    if (!NtQueryVirtMem) return;

    // Build lookup sets from the known module list
    std::unordered_set<uintptr_t> knownBases;
    std::unordered_set<std::wstring> knownPaths;
    for (const auto& m : modules) {
        knownBases.insert(m.begin);
        if (!m.path.empty())
            knownPaths.insert(ToUpperInvariant(m.path));
    }

    uintptr_t addr = 0x10000;
    MEMORY_BASIC_INFORMATION mbi = {};
    std::unordered_set<uintptr_t> seenAlloc;

    while (addr < 0x00007FFFFFFEFFFF && out.size() < ScanLimits::kMaxSysmemFindings) {
        SIZE_T ret = VirtualQueryEx(process, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (!ret) break;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) continue;

        uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
        if (!seenAlloc.insert(allocBase).second) continue;
        if (knownBases.count(allocBase)) continue; // visible in PEB → legitimate

        // Query the mapped filename via NtQueryVirtualMemory class 2 (MemoryMappedFilenameInformation)
        constexpr size_t kBufSize = (MAX_PATH * 2 + 16) * sizeof(wchar_t);
        alignas(8) BYTE nameBuf[kBufSize] = {};
        SIZE_T retLen = 0;
        LONG st = NtQueryVirtMem(process, mbi.AllocationBase, 2, nameBuf, kBufSize, &retLen);
        if (st < 0) {
            // Can't get filename — still flag anonymous MEM_IMAGE (very suspicious)
            std::string detail = "MEM_IMAGE region nao listada na PEB (sem nome) | base=" + HexAddress(allocBase);
            AddEmulatorFinding(out, procName, kTagManualMapping, allocBase, detail, "HIGH");
            continue;
        }

        // UNICODE_STRING layout on x64: USHORT Length(0), MaxLen(2), padding(4), PWSTR Buffer(8)
        // The Buffer pointer points into our own nameBuf (kernel fills it in).
        USHORT strLen = *reinterpret_cast<const USHORT*>(nameBuf);
        if (strLen == 0 || strLen > (USHORT)(kBufSize - 16)) continue;
        PWSTR bufPtr = nullptr;
        memcpy(&bufPtr, nameBuf + 8, sizeof(PWSTR));
        if (!bufPtr) continue;
        std::wstring devicePath(bufPtr, strLen / sizeof(wchar_t));
        std::wstring dosPath = DevicePathToDosPath(devicePath);

        if (dosPath.empty()) dosPath = devicePath;
        std::wstring dosUp = ToUpperInvariant(dosPath);

        if (knownPaths.count(dosUp)) continue; // same file, different mapping base — skip

        std::string detail = "DLL injetada oculta na PEB (module unlinking): " +
                             WideToUtf8(dosPath) +
                             " | base=" + HexAddress(allocBase) +
                             " | nao aparece no modulo list";
        AddEmulatorFinding(out, procName, kTagManualMapping, allocBase, detail, "HIGH");
    }
}

// ─── Working Set private executable page analysis ────────────────────────────
// Uses QueryWorkingSetEx to identify pages that are genuinely private (not COW)
// and executable. Private executable pages with PE headers = manual-mapped DLLs
// that changed their protection after loading (e.g. stripped PE header but left
// RX executable sections).
static void ScanPrivateExecutableWorkingSet(HANDLE process, const std::string& procName,
                                             const std::vector<ModuleRange>& modules,
                                             std::vector<ScannerUI::EmulatorFinding>& out) {
    // Collect candidate page addresses from private executable regions
    struct WSExEntry { PVOID VirtualAddress; ULONG_PTR VirtualAttributes; };

    std::vector<WSExEntry> entries;
    entries.reserve(1024);

    uintptr_t addr = 0x10000;
    MEMORY_BASIC_INFORMATION mbi = {};
    while (addr < 0x00007FFFFFFEFFFF && entries.size() < 4096) {
        SIZE_T ret = VirtualQueryEx(process, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (!ret) break;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
        DWORD base = mbi.Protect & 0xff;
        bool isExec = (base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
                       base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY);
        if (!isExec) continue;
        if (AddressInsideModule((uintptr_t)mbi.BaseAddress, modules)) continue;

        WSExEntry e;
        e.VirtualAddress     = mbi.BaseAddress;
        e.VirtualAttributes  = 0;
        entries.push_back(e);
    }

    if (entries.empty()) return;

    // Call QueryWorkingSetEx to get physical page attributes
    if (!QueryWorkingSetEx(process, entries.data(), (DWORD)(entries.size() * sizeof(WSExEntry))))
        return;

    std::unordered_set<uintptr_t> reported;
    for (const auto& e : entries) {
        // VirtualAttributes bit 0 = Valid (physically present in working set)
        bool valid = (e.VirtualAttributes & 1) != 0;
        if (!valid) continue; // page swapped out — skip

        uintptr_t pageBase = (uintptr_t)e.VirtualAddress;
        // Deduplicate by allocation base
        MEMORY_BASIC_INFORMATION mbi2 = {};
        if (VirtualQueryEx(process, e.VirtualAddress, &mbi2, sizeof(mbi2)) != sizeof(mbi2)) continue;
        uintptr_t allocBase = (uintptr_t)mbi2.AllocationBase;
        if (!reported.insert(allocBase).second) continue;

        // Check for PE header in this truly private executable page
        if (DetectionFilter::HasPEHeader(process, e.VirtualAddress)) {
            std::string detail = "Working set: pagina executavel privada com PE header | addr=" +
                                 HexAddress(pageBase) + " | alloc=" + HexAddress(allocBase) +
                                 " | indica DLL manualmente mapeada (header nao apagado)";
            AddEmulatorFinding(out, procName, kTagManualMapping, allocBase, detail, "HIGH");
        }
    }
}

// ─── NtGetNextThread: enumerate ALL threads including DKOM-hidden ones ────────
// Supplements the existing Toolhelp-based thread scan. NtGetNextThread walks the
// kernel thread list directly, revealing threads hidden from Toolhelp by DKOM.
// Also follows JMP chains from thread start addresses to detect trampolines.
struct HiddenThreadCandidate {
    DWORD tid = 0;
    uintptr_t start = 0;
    uintptr_t evidenceAddress = 0;
    bool hasStart = false;
    bool suspiciousStart = false;
    std::string reason;
    std::string severity = "HIGH";
};

static bool CollectToolhelpThreadIdsForPid(DWORD pid, std::unordered_set<DWORD>& tids) {
    tids.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                tids.insert(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return true;
}

static void ScanHiddenThreadsViaKernel(DWORD pid, const std::string& procName, HANDLE process,
                                        const std::vector<ModuleRange>& modules,
                                        std::vector<ScannerUI::EmulatorFinding>& out,
                                        bool isEmulatorProcess,
                                        const std::unordered_set<uintptr_t>* gfxHookDests = nullptr) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtGetNextThread = ntdll ? reinterpret_cast<NtGetNextThreadFn>(
        GetProcAddress(ntdll, "NtGetNextThread")) : nullptr;
    auto queryThread = ntdll ? reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread")) : nullptr;
    if (!NtGetNextThread || !queryThread) return;

    // Collect Toolhelp TIDs for DKOM comparison (first snapshot)
    std::unordered_set<DWORD> toolhelpTids;
    if (!CollectToolhelpThreadIdsForPid(pid, toolhelpTids))
        return;

    HANDLE prevThread = nullptr;
    HANDLE nextThread = nullptr;
    constexpr DWORD kThreadAccess = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;

    // Collect DKOM suspects during traversal without flagging immediately.
    // A thread created between the Toolhelp snapshot and the NtGetNextThread walk
    // would appear missing from Toolhelp due to timing — not actual DKOM hiding.
    std::unordered_map<DWORD, HiddenThreadCandidate> suspectDkomThreads;

    while (NtGetNextThread(process, prevThread, kThreadAccess, 0, 0, &nextThread) >= 0) {
        if (prevThread) CloseHandle(prevThread);
        prevThread = nextThread;

        DWORD tid = GetThreadId(nextThread);

        // DKOM check: collect suspects; confirmation happens after the loop
        HiddenThreadCandidate* dkomCandidate = nullptr;
        if (tid && !toolhelpTids.count(tid)) {
            HiddenThreadCandidate& candidate = suspectDkomThreads[tid];
            candidate.tid = tid;
            dkomCandidate = &candidate;
        }

        // Get start address
        PVOID startAddr = nullptr;
        if (queryThread(nextThread, 9, &startAddr, sizeof(startAddr), nullptr) < 0 || !startAddr)
            continue;

        uintptr_t start = (uintptr_t)startAddr;
        if (dkomCandidate) {
            dkomCandidate->start = start;
            dkomCandidate->hasStart = true;
        }
        if (AddressInsideModule(start, modules)) {
            // Start is inside a module — follow JMP chain to detect trampolines
            BYTE prolog[16] = {}; SIZE_T pg = 0;
            if (!ReadProcessMemory(process, (LPCVOID)start, prolog, sizeof(prolog), &pg) || pg < 5)
                continue;
            // Quick JMP detection
            bool hasJmp = (prolog[0] == 0xE9 || (prolog[0] == 0xFF && prolog[1] == 0x25) ||
                           (prolog[0] == 0x48 && prolog[1] == 0xB8 && pg >= 12 &&
                            prolog[10] == 0xFF && prolog[11] == 0xE0));
            if (!hasJmp) continue;

            // Follow up to 5 hops
            uintptr_t chainEnd = start;
            for (int hop = 0; hop < 5; ++hop) {
                BYTE buf[16] = {}; SIZE_T g = 0;
                if (!ReadProcessMemory(process, (LPCVOID)chainEnd, buf, sizeof(buf), &g) || g < 5) break;
                if (buf[0] == 0xE9) {
                    INT32 rel = *reinterpret_cast<const INT32*>(buf+1);
                    chainEnd = chainEnd + 5 + (uintptr_t)(intptr_t)rel;
                } else if (buf[0] == 0xFF && buf[1] == 0x25 && g >= 6) {
                    INT32 disp = *reinterpret_cast<const INT32*>(buf+2);
                    uintptr_t slot = chainEnd + 6 + (uintptr_t)(intptr_t)disp;
                    uintptr_t tgt = 0; SIZE_T r = 0;
                    if (!ReadProcessMemory(process, (LPCVOID)slot, &tgt, sizeof(tgt), &r) || r < 8) break;
                    chainEnd = tgt;
                } else if (buf[0] == 0x48 && buf[1] == 0xB8 && g >= 12 && buf[10] == 0xFF && buf[11] == 0xE0) {
                    chainEnd = *reinterpret_cast<const uintptr_t*>(buf+2);
                } else break;
            }

            if (!AddressInsideModule(chainEnd, modules) && out.size() < ScanLimits::kMaxSysmemFindings) {
                // Validate destination memory before flagging — AV/security hooks legitimately
                // redirect trampolines into other signed modules or known stubs.
                MEMORY_BASIC_INFORMATION mbiDst = {};
                if (VirtualQueryEx(process, (LPCVOID)chainEnd, &mbiDst, sizeof(mbiDst)) == sizeof(mbiDst)) {
                    bool dstPrivate  = (mbiDst.Type == MEM_PRIVATE);
                    bool dstHasPe    = dstPrivate && DetectionFilter::HasPEHeader(process, mbiDst.BaseAddress);
                    double dstEntropy = DetectionFilter::ProcessRegionEntropy(
                        process, mbiDst.BaseAddress, (size_t)mbiDst.RegionSize);
                    DetectionFilter::RegionVerdict vDst = DetectionFilter::ClassifyExecRegion(
                        IsWriteExecuteProtection(mbiDst.Protect), (size_t)mbiDst.RegionSize,
                        dstEntropy, dstPrivate, dstHasPe, isEmulatorProcess);
                    if (!dstHasPe && !vDst.keep) continue;
                }
                {
                MEMORY_BASIC_INFORMATION mbiChain = {};
                uintptr_t chainAllocBase = 0;
                if (VirtualQueryEx(process, (LPCVOID)chainEnd, &mbiChain, sizeof(mbiChain)) == sizeof(mbiChain))
                    chainAllocBase = reinterpret_cast<uintptr_t>(mbiChain.AllocationBase);
                bool isGfxThread = gfxHookDests && chainAllocBase && gfxHookDests->count(chainAllocBase) > 0;

                std::string detail = "thread start com trampoline saindo do modulo | tid=" +
                                     std::to_string(tid) +
                                     " | start=" + HexAddress(start) +
                                     " | chain_end=" + HexAddress(chainEnd);
                if (isGfxThread)
                    detail += " | CONFIRMADO: thread em payload de hook OpenGL/grafico";
                if (dkomCandidate) {
                    dkomCandidate->suspiciousStart = true;
                    dkomCandidate->evidenceAddress = chainEnd;
                    dkomCandidate->reason = isGfxThread
                        ? "hidden thread start trampoline: confirmed gfx hook payload"
                        : "hidden thread start trampoline leaves module";
                    dkomCandidate->severity = "HIGH";
                }
                AddEmulatorFinding(out, procName,
                                   isGfxThread ? kTagGfxHookThread : kTagThreadInject,
                                   chainEnd, detail, "HIGH");
                }
            }
        } else {
            // Start address outside all known modules — apply the same memory-characteristic
            // analysis used by the Toolhelp scan to avoid flagging JIT engine threads (ART,
            // V8, .NET CLR) that legitimately start in anonymous private memory.
            if (out.size() >= ScanLimits::kMaxSysmemFindings) continue;
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(process, (LPCVOID)start, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;

            bool privateMem  = (mbi.Type == MEM_PRIVATE);
            bool hasPeHeader = privateMem && DetectionFilter::HasPEHeader(process, mbi.BaseAddress);
            double entropy   = DetectionFilter::ProcessRegionEntropy(
                process, mbi.BaseAddress, (size_t)mbi.RegionSize);

            // Mapped memory without a PE header is a file mapping or data region — not suspicious
            if (!privateMem && !hasPeHeader) continue;

            DetectionFilter::RegionVerdict v = DetectionFilter::ClassifyExecRegion(
                IsWriteExecuteProtection(mbi.Protect), (size_t)mbi.RegionSize,
                entropy, privateMem, hasPeHeader, isEmulatorProcess);

            bool hasRwx     = IsWriteExecuteProtection(mbi.Protect);
            bool conclusive = hasPeHeader || hasRwx || v.severity == "HIGH";
            if (!conclusive || !v.keep) continue;

            uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            bool isGfxThread = gfxHookDests && allocBase && gfxHookDests->count(allocBase) > 0;
            std::string detail = "thread start em memoria anonima | tid=" + std::to_string(tid) +
                                 " | start=" + HexAddress(start) +
                                 " | " + v.note;
            if (isGfxThread)
                detail += " | CONFIRMADO: thread em payload de hook OpenGL/grafico";
            if (dkomCandidate) {
                dkomCandidate->suspiciousStart = true;
                dkomCandidate->evidenceAddress = start;
                dkomCandidate->reason = isGfxThread ? "anon thread: confirmed gfx hook payload" : v.note;
                dkomCandidate->severity = isGfxThread ? "HIGH" : v.severity;
            }
            AddEmulatorFinding(out, procName,
                               isGfxThread ? kTagGfxHookThread : kTagThreadInject,
                               start, detail, isGfxThread ? "HIGH" : v.severity);
        }
    }
    if (prevThread) CloseHandle(prevThread);

    // DKOM double-confirmation: retake Toolhelp snapshot after the traversal.
    // Only flag threads absent from BOTH snapshots — eliminates timing-based false positives
    // where a thread was created between the first snapshot and the NtGetNextThread walk.
    if (!suspectDkomThreads.empty()) {
        std::unordered_set<DWORD> confirmTids1;
        std::unordered_set<DWORD> confirmTids2;
        if (!CollectToolhelpThreadIdsForPid(pid, confirmTids1))
            return;
        Sleep(140);
        if (!CollectToolhelpThreadIdsForPid(pid, confirmTids2))
            return;

        for (const auto& kv : suspectDkomThreads) {
            const HiddenThreadCandidate& candidate = kv.second;
            if (confirmTids1.count(candidate.tid) || confirmTids2.count(candidate.tid))
                continue;

            // Emulator runtimes create and retire many worker/JIT threads. A Toolhelp/NtGetNextThread
            // mismatch alone is too weak, so require malicious thread-start evidence as well.
            if (isEmulatorProcess && !candidate.suspiciousStart)
                continue;

            if (out.size() >= ScanLimits::kMaxSysmemFindings)
                break;

            std::string detail = "thread oculta do Toolhelp (DKOM) | tid=" +
                                 std::to_string(candidate.tid) +
                                 " | visivel via NtGetNextThread";
            if (candidate.hasStart)
                detail += " | start=" + HexAddress(candidate.start);
            if (!candidate.reason.empty())
                detail += " | evidence=" + candidate.reason;

            AddEmulatorFinding(out, procName, kTagThreadProtect,
                               candidate.evidenceAddress, detail, candidate.severity);
        }
    }
}

struct SecurityHandleEvent {
    int eventId = 0;
    ULONGLONG time = 0;
    FILETIME fileTime = {};
    std::wstring processId;
    std::wstring handleId;
    std::wstring processName;
    std::wstring objectName;
    std::wstring objectType;
    std::wstring accessMask;
};

struct OpenSecurityHandle {
    ULONGLONG time = 0;
    FILETIME fileTime = {};
    std::wstring processName;
    std::wstring objectName;
    std::wstring objectType;
    std::wstring accessMask;
};

static std::wstring UpperTrimW(std::wstring text) {
    while (!text.empty() && iswspace(text.front()))
        text.erase(text.begin());
    while (!text.empty() && iswspace(text.back()))
        text.pop_back();
    return ToUpperInvariant(text);
}

static std::wstring NormalizeSecurityId(std::wstring text) {
    text = UpperTrimW(text);
    if (text.empty())
        return L"-";
    return text;
}

static std::string FormatLocalFileTime(const FILETIME& ft) {
    std::string date, time;
    FileTimeToLocalStrings(ft, date, time);
    return date + " " + time;
}

static std::string FormatHandleDuration(ULONGLONG ticks100ns) {
    ULONGLONG totalSeconds = ticks100ns / 10000000ULL;
    ULONGLONG minutes = totalSeconds / 60ULL;
    ULONGLONG seconds = totalSeconds % 60ULL;
    std::ostringstream oss;
    oss << minutes << "m " << seconds << "s";
    return oss.str();
}

static bool IsEmulatorHandleContext(const SecurityHandleEvent& ev) {
    std::wstring procName = BaseNameFromPath(ev.processName);
    if (!procName.empty() && IsKnownEmulatorProcess(procName))
        return true;

    std::wstring objectUpper = ToUpperInvariant(ev.objectName);
    static const wchar_t* kNames[] = {
        L"HD-PLAYER.EXE", L"ANDROIDEMULATOR.EXE", L"ANDROIDPROCESS.EXE",
        L"MEMU.EXE", L"NOX.EXE", L"DNPLAYER.EXE", L"MUMUPLAYER.EXE",
        L"BLUESTACKS.EXE", L"BSTMHDANDROID.EXE"
    };
    for (const wchar_t* name : kNames) {
        if (objectUpper.find(name) != std::wstring::npos)
            return true;
    }
    return false;
}

static void CollectEmulatorHandleLifetimeFindings(std::vector<ScannerUI::EmulatorFinding>& out) {
    const wchar_t* channel = L"Security";
    const wchar_t* query = L"*[System[(EventID=4656 or EventID=4658)]]";
    EVT_HANDLE result = EvtQuery(nullptr, channel, query,
                                 EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!result)
        return;

    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);
    std::vector<SecurityHandleEvent> events;
    constexpr DWORD kBatch = 16;
    constexpr size_t kMaxSecurityEvents = 6000;
    EVT_HANDLE handles[kBatch] = {};
    DWORD returned = 0;
    bool reachedBoot = false;

    while (!reachedBoot && events.size() < kMaxSecurityEvents &&
           EvtNext(result, kBatch, handles, ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            std::wstring xml;
            if (RenderEventXml(handles[i], xml)) {
                FILETIME eventTime = {};
                std::wstring systemTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
                if (SysmonSystemTimeToFileTime(systemTime, eventTime)) {
                    ULONGLONG eventValue = FileTimeToU64(eventTime);
                    if (eventValue < bootValue) {
                        reachedBoot = true;
                    } else {
                        SecurityHandleEvent ev;
                        std::wstring idText = ExtractXmlTag(xml, L"EventID");
                        ev.eventId = idText.empty() ? 0 : _wtoi(idText.c_str());
                        ev.time = eventValue;
                        ev.fileTime = eventTime;
                        ev.processId = NormalizeSecurityId(ExtractSysmonData(xml, L"ProcessId"));
                        ev.handleId = NormalizeSecurityId(ExtractSysmonData(xml, L"HandleId"));
                        ev.processName = ExtractSysmonData(xml, L"ProcessName");
                        ev.objectName = ExtractSysmonData(xml, L"ObjectName");
                        ev.objectType = ExtractSysmonData(xml, L"ObjectType");
                        ev.accessMask = ExtractSysmonData(xml, L"AccessMask");
                        if (ev.handleId != L"-" && ev.processId != L"-" &&
                            (ev.eventId == 4658 || IsEmulatorHandleContext(ev)))
                            events.push_back(std::move(ev));
                    }
                }
            }
            EvtClose(handles[i]);
            handles[i] = nullptr;
        }
    }
    EvtClose(result);

    std::reverse(events.begin(), events.end());

    std::unordered_map<std::wstring, OpenSecurityHandle> openHandles;
    std::unordered_set<std::wstring> reported;
    constexpr ULONGLONG kMinOpenTime = 5ULL * 60ULL * 10000000ULL;
    size_t emitted = 0;

    for (const auto& ev : events) {
        std::wstring key = ev.processId + L":" + ev.handleId;
        if (ev.eventId == 4656) {
            OpenSecurityHandle open;
            open.time = ev.time;
            open.fileTime = ev.fileTime;
            open.processName = ev.processName;
            open.objectName = ev.objectName;
            open.objectType = ev.objectType;
            open.accessMask = ev.accessMask;
            openHandles[key] = std::move(open);
            continue;
        }

        if (ev.eventId != 4658)
            continue;

        auto it = openHandles.find(key);
        if (it == openHandles.end())
            continue;

        const OpenSecurityHandle& open = it->second;
        if (ev.time > open.time && ev.time - open.time >= kMinOpenTime) {
            std::wstring reportKey = key + L":" + std::to_wstring(open.time) + L":" + std::to_wstring(ev.time);
            if (reported.insert(reportKey).second) {
                std::string source = WideToUtf8(open.processName.empty() ? ev.processName : open.processName);
                std::string target = WideToUtf8(open.objectName.empty() ? ev.objectName : open.objectName);
                std::string objectType = WideToUtf8(open.objectType.empty() ? ev.objectType : open.objectType);
                std::string access = WideToUtf8(open.accessMask.empty() ? ev.accessMask : open.accessMask);

                if (source.empty()) source = "PID " + WideToUtf8(ev.processId);
                if (target.empty()) target = "-";
                if (objectType.empty()) objectType = "-";
                if (access.empty()) access = "-";

                std::string detail =
                    "handle aberto por " + FormatHandleDuration(ev.time - open.time) +
                    " e encerrado | opened=" + FormatLocalFileTime(open.fileTime) +
                    " | closed=" + FormatLocalFileTime(ev.fileTime) +
                    " | source=" + source +
                    " | object=" + target +
                    " | type=" + objectType +
                    " | access=" + access +
                    " | handle=" + WideToUtf8(ev.handleId);

                AddEmulatorFinding(out, "Security Object Access", ScanTag::Handle,
                                   0, detail, "MEDIUM");
                if (++emitted >= 80 || out.size() >= ScanLimits::kMaxSysmemFindings)
                    break;
            }
        }
        openHandles.erase(it);
    }
}

std::vector<ScannerUI::EmulatorFinding> CollectEmulatorIntegrityFindings() {
    std::vector<ScannerUI::EmulatorFinding> findings;
    std::vector<DWORD> pids = FindEmulatorProcesses();

    for (DWORD pid : pids) {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            continue;

        std::string name = ProcessName(process);
        std::string nameWithPid = name + " [" + std::to_string(pid) + "]";
        std::wstring installDir = ProcessImageDirW(process);
        // Process names from ProcessName() are ASCII-safe — direct copy is valid here.
        std::wstring nameW(name.begin(), name.end());
        std::wstring exePathW = ProcessFullPathW(pid);
        // Process-name match alone is not a trust signal — a malicious process can be
        // renamed to a known emulator runtime to relax RWX/JIT heuristics. Only treat
        // it as an emulator runtime when the executable is also signed and trusted-dir.
        bool isEmuRuntime = DetectionFilter::IsKnownEmulatorRuntime(nameW) &&
                            DetectionFilter::IsTrustedSignedCached(exePathW) &&
                            DetectionFilter::IsTrustedDir(DetectionFilter::ClassifyPath(exePathW));
        std::vector<ModuleRange> modules;
        if (CollectProcessModules(process, modules)) {
            // Collect graphics hook destinations first — used to tag injected threads/memory
            // as confirmed OpenGL/gfx chams rather than generic injection.
            auto gfxDests = CollectGfxHookDestBases(process, modules);
            const std::unordered_set<uintptr_t>* pGfxDests = gfxDests.empty() ? nullptr : &gfxDests;

            ScanUnsignedModules(process, nameWithPid, modules, installDir, exePathW, findings);
            ScanExecutablePrivateMemory(process, nameWithPid, modules, findings, nullptr, isEmuRuntime, false, false, pGfxDests);
            ScanThreadStartAddresses(pid, nameWithPid, process, modules, findings, isEmuRuntime, false, false, pGfxDests);
            // Advanced detections (only for emulator PIDs — expensive)
            ScanHiddenMappedDlls(process, nameWithPid, modules, findings);
            ScanPrivateExecutableWorkingSet(process, nameWithPid, modules, findings);
            ScanHiddenThreadsViaKernel(pid, nameWithPid, process, modules, findings, isEmuRuntime, pGfxDests);
        }

        CloseHandle(process);
    }

    CollectEmulatorHandleLifetimeFindings(findings);

    return findings;
}

// P7 — Direct syscall stub pattern matching.
// Detects structured syscall stubs from multiple evasion frameworks rather than
// bare 0x0F 0x05 bytes — eliminates false positives from JIT/data.
//
// Pattern A  (SysWhispers2/3 canonical):  4C 8B D1  B8 <ssn_lo> <ssn_hi> 00 00  0F 05  C3
// Pattern B  (simple/SW1 style):                    B8 <ssn_lo> <ssn_hi> 00 00  0F 05  C3
// Pattern C  (HellsGate/FreshyCalls):    49 89 CA  B8 <ssn_lo> <ssn_hi> 00 00  0F 05  C3
// Pattern D  (SW1 32-bit style):          B8 <ssn_lo> <ssn_hi> 00 00  BA 08 03 FE 7F  0F 05  C3
// Pattern E  (Tartarus Gate jmp-over):   E9 ?? ?? ?? ?? [4C 8B D1 within 32 bytes ahead]
//            Detects the jump trampoline that skips a hooked ntdll stub.

struct SyscallStubResult {
    int totalStubs   = 0;
    int classicStubs = 0;  // Pattern A: SysWhispers2/3
    int simpleStubs  = 0;  // Pattern B: minimal stub
    int hellsGate    = 0;  // Pattern C: HellsGate mov r9
    int sw1Stubs     = 0;  // Pattern D: SysWhispers1 32-bit style
    int tartarusGate = 0;  // Pattern E: jmp-over trampoline
};

static SyscallStubResult CountSyscallStubs(const uint8_t* buf, size_t sz)
{
    SyscallStubResult r;
    if (sz < 8) return r;

    for (size_t i = 0; i + 7 < sz; ++i) {
        // Pattern A: 4C 8B D1  B8 ?? ?? 00 00  0F 05  C3  (11 bytes, SysWhispers2/3)
        if (i + 10 < sz
            && buf[i+0] == 0x4C && buf[i+1] == 0x8B && buf[i+2] == 0xD1
            && buf[i+3] == 0xB8
            && buf[i+6] == 0x00 && buf[i+7] == 0x00
            && buf[i+8] == 0x0F && buf[i+9] == 0x05
            && buf[i+10] == 0xC3)
        {
            ++r.classicStubs;
            ++r.totalStubs;
            i += 10;
            continue;
        }
        // Pattern C: 49 89 CA  B8 ?? ?? 00 00  0F 05  C3  (11 bytes, HellsGate / FreshyCalls)
        if (i + 10 < sz
            && buf[i+0] == 0x49 && buf[i+1] == 0x89 && buf[i+2] == 0xCA
            && buf[i+3] == 0xB8
            && buf[i+6] == 0x00 && buf[i+7] == 0x00
            && buf[i+8] == 0x0F && buf[i+9] == 0x05
            && buf[i+10] == 0xC3)
        {
            ++r.hellsGate;
            ++r.totalStubs;
            i += 10;
            continue;
        }
        // Pattern D: B8 ?? ?? 00 00  BA 08 03 FE 7F  0F 05  C3  (13 bytes, SysWhispers1)
        if (i + 12 < sz
            && buf[i+0] == 0xB8
            && buf[i+3] == 0x00 && buf[i+4] == 0x00
            && buf[i+5] == 0xBA && buf[i+6] == 0x08 && buf[i+7] == 0x03
            && buf[i+8] == 0xFE && buf[i+9] == 0x7F
            && buf[i+10] == 0x0F && buf[i+11] == 0x05
            && buf[i+12] == 0xC3)
        {
            ++r.sw1Stubs;
            ++r.totalStubs;
            i += 12;
            continue;
        }
        // Pattern B: B8 ?? ?? 00 00  0F 05  C3  (8 bytes, simple)
        if (i + 7 < sz
            && buf[i+0] == 0xB8
            && buf[i+3] == 0x00 && buf[i+4] == 0x00
            && buf[i+5] == 0x0F && buf[i+6] == 0x05
            && buf[i+7] == 0xC3)
        {
            ++r.simpleStubs;
            ++r.totalStubs;
            i += 7;
            continue;
        }
        // Pattern E: E9 ?? ?? ?? ??  ... 4C 8B D1 within 32 bytes  (Tartarus Gate jmp-over)
        if (i + 36 < sz && buf[i] == 0xE9) {
            bool found = false;
            for (size_t j = i + 5; j + 2 < sz && j < i + 37; ++j) {
                if (buf[j] == 0x4C && buf[j+1] == 0x8B && buf[j+2] == 0xD1) {
                    found = true;
                    break;
                }
            }
            if (found) {
                ++r.tartarusGate;
                ++r.totalStubs;
                i += 4;
                continue;
            }
        }
    }
    return r;
}

static void ScanDirectSyscalls(HANDLE process, const std::string& procName,
                                const std::vector<ModuleRange>& modules,
                                std::vector<ScannerUI::EmulatorFinding>& out)
{
    // Find ntdll VA range — exclude its own stubs from detection
    uintptr_t ntdllBegin = 0, ntdllEnd = 0;
    for (const auto& m : modules) {
        if (ToUpperInvariant(BaseNameFromPath(m.path)) == L"NTDLL.DLL") {
            ntdllBegin = m.begin;
            ntdllEnd   = m.end;
            break;
        }
    }

    // Compute upper scan bound (same strategy as ScanExecutablePrivateMemory)
    uintptr_t maxModEnd = 0;
    for (const auto& m : modules)
        if (m.end > maxModEnd) maxModEnd = m.end;
    const uintptr_t kSyscallScanLimit = (maxModEnd + 512ULL * 1024 * 1024 > 2ULL * 1024 * 1024 * 1024)
                                        ? (maxModEnd + 512ULL * 1024 * 1024)
                                        : (2ULL * 1024 * 1024 * 1024);

    constexpr size_t kMaxRead = 128 * 1024;
    std::vector<uint8_t> buf(kMaxRead);
    std::unordered_set<uintptr_t> seenAllocBases;
    uintptr_t addr = 0;

    while (addr < kSyscallScanLimit && out.size() < ScanLimits::kMaxSyscallDetections) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t next = base + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Type  != MEM_PRIVATE) continue;
        if (!IsExecutableProtection(mbi.Protect)) continue;
        if (ntdllBegin && base >= ntdllBegin && base < ntdllEnd) continue;
        if (AddressInsideModule(base, modules)) continue;

        // Deduplicate by AllocationBase — one report per allocation
        uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        if (!seenAllocBases.insert(allocBase).second) continue;

        SIZE_T toRead = mbi.RegionSize < kMaxRead ? mbi.RegionSize : kMaxRead;
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, mbi.BaseAddress, buf.data(), toRead, &got) || got < 8)
            continue;

        SyscallStubResult stubs = CountSyscallStubs(buf.data(), got);
        if (stubs.totalStubs == 0) continue;

        bool isRwx = IsWriteExecuteProtection(mbi.Protect);

        // Severity logic:
        // - Pattern A/C/D (SW2/HellsGate/SW1) = HIGH always
        // - Pattern E (TartarusGate) alone without RWX = MEDIUM: 0xE9 + 4C 8B D1 can
        //   appear in legitimate x64 code (profilers, debugger trampolines, VS tooling)
        // - TartarusGate + RWX, or mixed with other patterns = HIGH
        // - 2+ stubs of any kind = HIGH (syscall dispatch table)
        // - 1 simple stub in RWX = HIGH (runtime-generated stub)
        // - 1 simple stub in RX = MEDIUM
        bool onlyTartarus = stubs.tartarusGate > 0
                         && stubs.classicStubs == 0
                         && stubs.hellsGate == 0
                         && stubs.sw1Stubs == 0;
        std::string severity;
        if (stubs.classicStubs > 0 || stubs.hellsGate > 0 || stubs.sw1Stubs > 0)
            severity = "HIGH";
        else if (onlyTartarus && isRwx)
            severity = "HIGH";
        else if (onlyTartarus && !isRwx)
            severity = "MEDIUM";
        else if (stubs.totalStubs >= 2)
            severity = "HIGH";
        else if (isRwx)
            severity = "HIGH";
        else
            severity = "MEDIUM";

        // Build pattern description
        std::string patternDesc;
        if (stubs.classicStubs > 0)  patternDesc += "SW2/3 ";
        if (stubs.hellsGate > 0)     patternDesc += "HellsGate ";
        if (stubs.sw1Stubs > 0)      patternDesc += "SW1 ";
        if (stubs.tartarusGate > 0)  patternDesc += "TartarusGate ";
        if (stubs.simpleStubs > 0)   patternDesc += "simple ";
        if (!patternDesc.empty() && patternDesc.back() == ' ')
            patternDesc.pop_back();

        std::string tableNote = stubs.totalStubs >= 5 ? " | type=syscall_table" : "";

        ScannerUI::EmulatorFinding f;
        f.process  = procName;
        f.type     = kTagMemoryInject;
        f.address  = HexAddress(allocBase);
        f.severity = severity;
        f.detail   = std::to_string(stubs.totalStubs) + " syscall stub(s) detected"
                   + " | patterns=[" + patternDesc + "]"
                   + " | SW2=" + std::to_string(stubs.classicStubs)
                   + " HG=" + std::to_string(stubs.hellsGate)
                   + " SW1=" + std::to_string(stubs.sw1Stubs)
                   + " TG=" + std::to_string(stubs.tartarusGate)
                   + " simple=" + std::to_string(stubs.simpleStubs)
                   + " | rwx=" + (isRwx ? "yes" : "no")
                   + " | alloc_base=" + HexAddress(allocBase)
                   + tableNote;
        out.push_back(f);
    }
}

// Scan private executable memory regions for plaintext strings that appear in injected
// DLLs: reflective loader export names, .NET namespace metadata, shellcode markers, etc.
// Only private regions outside loaded modules are checked, so false positives are minimal.
static void ScanSuspiciousStringsInMemory(
    HANDLE process, const std::string& procName,
    const std::vector<ModuleRange>& modules,
    std::vector<ScannerUI::EmulatorFinding>& out)
{
    struct Token { const char* str; const char* sev; };
    static const Token kTokens[] = {
        // HIGH — essentially impossible in legitimate private executable memory
        { "reflectiveloader",     "HIGH" },  // export name from reflective DLL injection framework
        { "system.windows.forms", "HIGH" },  // .NET managed assembly metadata (injected managed DLL)
        { "system.reflection",    "HIGH" },  // .NET in-memory assembly loading namespace
        { "shellcode",            "HIGH" },  // literal string in shellcode payloads/loaders
        // HIGH — highly specific to injection tooling
        { "dllinjection",         "HIGH" },  // class/namespace name in injection tools
        { "injectdll",            "HIGH" },  // function name pattern in DLL loaders
        { "reflective",           "HIGH" },  // component name in reflective loaders
        { "manualmap",            "HIGH" },  // manual mapper string in PE loaders
        { nullptr, nullptr }
    };

    uintptr_t maxModEnd = 0;
    for (const auto& m : modules)
        if (m.end > maxModEnd) maxModEnd = m.end;
    const uintptr_t kLimit = (maxModEnd + 512ULL*1024*1024 > 2ULL*1024*1024*1024)
                             ? maxModEnd + 512ULL*1024*1024
                             : 2ULL*1024*1024*1024;

    constexpr size_t kMaxRead = 64 * 1024;
    std::vector<uint8_t> buf(kMaxRead);
    std::unordered_set<uintptr_t> seen;
    uintptr_t addr = 0;

    while (addr < kLimit && out.size() < ScanLimits::kMaxSysmemFindings) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t next = base + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT) continue;
        if (!IsExecutableProtection(mbi.Protect)) continue;
        if (AddressInsideModule(base, modules)) continue;

        uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        if (!seen.insert(allocBase).second) continue;

        SIZE_T toRead = mbi.RegionSize < kMaxRead ? mbi.RegionSize : kMaxRead;
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, mbi.BaseAddress, buf.data(), toRead, &got) || got < 16)
            continue;

        // Extract printable ASCII strings (>= 8 chars) and match against token list.
        // One finding per AllocationBase — goto breaks out on first match.
        std::string cur;
        cur.reserve(128);
        for (SIZE_T i = 0; i < got; ++i) {
            uint8_t c = buf[i];
            if (c >= 0x20 && c <= 0x7E) {
                cur += (char)c;
            } else {
                if (cur.size() >= 8) {
                    std::string low = cur;
                    std::transform(low.begin(), low.end(), low.begin(),
                                   [](unsigned char ch){ return (unsigned char)tolower(ch); });
                    for (int k = 0; kTokens[k].str; ++k) {
                        if (low.find(kTokens[k].str) != std::string::npos) {
                            std::string snip = cur.size() > 64
                                             ? cur.substr(0, 64) + "..." : cur;
                            AddEmulatorFinding(out, procName, kTagMemoryInject, allocBase,
                                "suspicious string in private exec memory: \""
                                + snip + "\" | alloc=" + HexAddress(allocBase),
                                kTokens[k].sev);
                            goto next_string_region;
                        }
                    }
                }
                cur.clear();
            }
        }
        next_string_region:;
    }
}

std::vector<ScannerUI::EmulatorFinding> CollectSystemMemoryFindings(std::string& status) {
    std::vector<ScannerUI::EmulatorFinding> findings;
    DWORD ownPid = GetCurrentProcessId();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        status = "Snapshot failed";
        return findings;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (findings.size() >= ScanLimits::kMaxSysmemFindings)
                break;
            DWORD pid = entry.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == ownPid)
                continue;
            // Removido: IsKnownJitHost skip. Processos JIT (Chrome, Java, Node, .NET, etc.)
            // sao alvos comuns de injecao — o ClassifyExecRegion ainda descarta regioes JIT
            // legitimas por conteudo (entropia + tamanho), nao por nome de processo.

            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                continue;

            bool systemTrustedProcess = false;
            bool programFilesSigned   = false;
            std::wstring imagePath = ProcessFullPathW(pid);
            if (!imagePath.empty()) {
                DetectionFilter::PathClass cls = DetectionFilter::ClassifyPath(imagePath);
                systemTrustedProcess = cls == DetectionFilter::PathClass::SystemTrusted;
                // Signed binaries in ProgramFiles (IDEs, game clients, tools) generate
                // TartarusGate-like patterns from profilers/trampolines; skip syscall scan.
                if (cls == DetectionFilter::PathClass::ProgramFiles)
                    programFilesSigned = DetectionFilter::IsTrustedSignedCached(imagePath);
            }

            DWORD64 procScanStart = GetTickCount64();
            std::string procName = WideToUtf8(entry.szExeFile) + " [" + std::to_string(pid) + "]";
            std::vector<ModuleRange> modules;
            if (CollectProcessModules(process, modules)) {
                std::vector<ScannerUI::EmulatorFinding> perProcess;
                auto threadBases = CollectThreadAllocBases(pid, process, modules);
                // Process-name match alone is not a trust signal — only relax RWX/JIT
                // heuristics when the executable is also signed and trusted-dir.
                bool isEmuRuntime = DetectionFilter::IsKnownEmulatorRuntime(entry.szExeFile) &&
                                    DetectionFilter::IsTrustedSignedCached(imagePath) &&
                                    DetectionFilter::IsTrustedDir(DetectionFilter::ClassifyPath(imagePath));

                // Collect graphics hook destinations first — used to cross-reference
                // injected threads/memory and confirm OpenGL/gfx chams payloads.
                auto gfxDests = CollectGfxHookDestBases(process, modules);
                const std::unordered_set<uintptr_t>* pGfxDests = gfxDests.empty() ? nullptr : &gfxDests;

                ScanExecutablePrivateMemory(process, procName, modules, perProcess, &threadBases, isEmuRuntime, true, true, pGfxDests);
                // Mudanca 2: thread scan agora roda em TODOS os processos, incluindo sistema.
                // Thread fora de modulo em lsass/svchost/csrss = indicador critico de injecao.
                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanThreadStartAddresses(pid, procName, process, modules, perProcess, isEmuRuntime, true, true, pGfxDests);
                }
                // M1: ScanAnomalousModuleProtections desacoplado do gate systemTrustedProcess.
                // RWX em regiao MEM_IMAGE = sinal estrutural de hollowing/sideload — vale tambem
                // para svchost/lsass/csrss legitimos sendo hollowados. O custo do scan e baixo.
                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanAnomalousModuleProtections(process, procName, modules, perProcess, pGfxDests);
                }
                size_t findingsBeforeStructural = perProcess.size();
                // Mudanca 4: analise estrutural de modulos carregados (PE anomalias)
                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanLoadedModuleAnomalies(process, procName, modules, perProcess);
                }
                // M1 override: se as varreduras estruturais ja flagaram em processo trusted,
                // o processo virou suspeito — roda os scans caros (handles/syscalls/strings)
                // mesmo nele para investigar a payload. Para processos limpos, gate mantido.
                bool suspectedInjection = perProcess.size() > findingsBeforeStructural;
                bool deepScanGate    = !systemTrustedProcess || suspectedInjection;
                bool deepCostlyGate  = (!systemTrustedProcess && !programFilesSigned) || suspectedInjection;
                // Mudanca 5: handles intra-processo com direitos de injecao
                if (deepScanGate &&
                    GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanSuspiciousHandlesInProcess(pid, procName, perProcess);
                }
                if (deepCostlyGate &&
                    GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanDirectSyscalls(process, procName, modules, perProcess);
                }
                if (deepCostlyGate &&
                    GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanSuspiciousStringsInMemory(process, procName, modules, perProcess);
                }
                for (auto& f : perProcess) {
                    if (findings.size() >= ScanLimits::kMaxSysmemFindings)
                        break;
                    // Incluir MEDIUM com prefixo identificador — nao mais descartar silenciosamente
                    if (f.severity == "MEDIUM")
                        f.detail = "[SUSPEITO] " + f.detail;
                    findings.push_back(std::move(f));
                }
            }
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    status = findings.empty() ? "OK" : "DETECTED";
    return findings;
}

static bool HasSuspiciousProcessToken(const std::wstring& name) {
    static const wchar_t* kNames[] = {

        L"CHEATENGINE", L"OLLYDBG", L"X64DBG", L"X32DBG",
        L"ARTMONEY", L"TSEARCH", L"GAMECHEATER",

        L"INJECTOR", L"RING0LOADER", L"KLOADER",
        L"DLLINJECTOR", L"MANUALMAPPER",

        L"HWID_SPOOF", L"HWIDSPOOF", L"SERIALSPOOF",
        L"HWID_CHANGER", L"HWIDCHANGER",

        L"EAC_BYPASS", L"BE_BYPASS", L"VGKBYPASS",
        L"GAMEGUARD_BYPASS", L"NPROTECT_BYPASS",

        L"PCHUNTER", L"PROCEXP64_", L"APIMONITOR",
        nullptr
    };
    std::wstring up = ToUpperInvariant(name);

    size_t dot = up.rfind(L'.');
    std::wstring nameNoExt = dot != std::wstring::npos ? up.substr(0, dot) : up;

    for (int i = 0; kNames[i]; ++i) {
        if (up.find(kNames[i]) != std::wstring::npos ||
            nameNoExt == kNames[i])
            return true;
    }
    return false;
}

static bool IsKnownDeveloperToolProcess(const std::wstring& name) {
    std::wstring up = ToUpperInvariant(name);
    static const std::unordered_set<std::wstring> kNames = {
        L"NODE.EXE", L"NODE_REPL.EXE", L"NPM.EXE", L"NPX.EXE",
        L"PYTHON.EXE", L"PYTHONW.EXE", L"PIP.EXE",
        L"CODE.EXE", L"GIT.EXE", L"MSBUILD.EXE", L"CL.EXE",
        L"POWERSHELL.EXE", L"PWSH.EXE", L"CMD.EXE",
        L"CONHOST.EXE", L"WINDOWSTERMINAL.EXE"
    };
    return kNames.find(up) != kNames.end();
}

static bool IsBenignUserLaunchPath(const std::wstring& path) {
    std::wstring up = ToUpperInvariant(path);
    return up.find(L"\\ONEDRIVE\\DESKTOP\\") != std::wstring::npos ||
           up.find(L"\\DESKTOP\\") != std::wstring::npos ||
           up.find(L"\\DOCUMENTS\\") != std::wstring::npos ||
           up.find(L"\\DOWNLOADS\\") != std::wstring::npos ||
           up.find(L"\\SOURCE\\REPOS\\") != std::wstring::npos ||
           up.find(L"\\PROJETOS\\") != std::wstring::npos ||
           up.find(L"\\PROJECTS\\") != std::wstring::npos;
}

std::vector<ScannerUI::EmulatorFinding> CollectSuspiciousProcesses(std::string& status) {
    std::vector<ScannerUI::EmulatorFinding> findings;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        status = "REVIEW";
        return findings;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        status = "OK";
        return findings;
    }

    DWORD selfPid = GetCurrentProcessId();
    do {
        if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4 ||
            entry.th32ProcessID == selfPid)
            continue;

        std::wstring procName = entry.szExeFile;
        bool nameMatch = HasSuspiciousProcessToken(procName);


        std::wstring fullPath = ProcessFullPathW(entry.th32ProcessID);
        bool signedOk = !fullPath.empty() && IsAuthenticodeSigned(fullPath);
        DetectionFilter::PathClass cls = fullPath.empty() ?
            DetectionFilter::PathClass::Unknown :
            DetectionFilter::ClassifyPath(fullPath);
        bool tempOrInstallerPath = cls == DetectionFilter::PathClass::TempOrInstaller;
        bool userProfilePath = cls == DetectionFilter::PathClass::UserProfile;


        if (nameMatch) {
            ScannerUI::EmulatorFinding f;
            f.process = WideToUtf8(procName);
            f.type = kTagMapper;
            f.address = "PID:" + std::to_string(entry.th32ProcessID);
            f.detail = "name=blacklisted | signed=" + std::string(signedOk ? "yes" : "no") +
                       " | path=" + WideToUtf8(fullPath.empty() ? L"unknown" : fullPath);
            f.severity = "HIGH";
            findings.push_back(f);
            continue;
        }


        if (!signedOk && !fullPath.empty() && tempOrInstallerPath &&
            !IsKnownDeveloperToolProcess(procName)) {
            double entropy = DetectionFilter::FileEntropySample(fullPath);
            bool packed = entropy >= DetectionFilter::kPackedEntropy;
            if (!packed)
                continue;
            ScannerUI::EmulatorFinding f;
            f.process = WideToUtf8(procName);
            f.type = kTagMapper;
            f.address = "PID:" + std::to_string(entry.th32ProcessID);
            f.detail = "unsigned packed process in temp/installer path | entropy=" +
                       DetectionFilter::EntropyToStr(entropy) +
                       " | path=" + WideToUtf8(fullPath);
            f.severity = "MEDIUM";
            findings.push_back(f);
        } else if (!signedOk && !fullPath.empty() && userProfilePath &&
                   !IsBenignUserLaunchPath(fullPath) &&
                   !IsKnownDeveloperToolProcess(procName)) {
            double entropy = DetectionFilter::FileEntropySample(fullPath);
            bool packed = entropy >= DetectionFilter::kPackedEntropy;
            if (!packed)
                continue;
            ScannerUI::EmulatorFinding f;
            f.process = WideToUtf8(procName);
            f.type = kTagMapper;
            f.address = "PID:" + std::to_string(entry.th32ProcessID);
            f.detail = "unsigned packed process in user profile path | entropy=" +
                       DetectionFilter::EntropyToStr(entropy) +
                       " | path=" + WideToUtf8(fullPath);
            f.severity = "MEDIUM";
            findings.push_back(f);
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);

    // P4 — DKOM: cross-check Toolhelp vs NtQuerySystemInformation for hidden processes
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        NtQuerySystemInformationFn NtQuerySysInfo = ntdll
            ? reinterpret_cast<NtQuerySystemInformationFn>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"))
            : nullptr;

        if (NtQuerySysInfo) {
            ULONG needed = 0;
            NtQuerySysInfo(5, nullptr, 0, &needed);
            if (needed < 64) needed = 2 * 1024 * 1024;
            std::vector<uint8_t> buf(needed + 4096);
            LONG st = NtQuerySysInfo(5, buf.data(), (ULONG)buf.size(), &needed);
            if (st >= 0) {
                std::unordered_set<DWORD> ntPids;
                size_t off = 0;
                while (off + 8 <= buf.size()) {
                    ULONG next = *reinterpret_cast<const ULONG*>(buf.data() + off);
                    size_t pidOff = off + (sizeof(void*) == 8 ? 0x50 : 0x44);
                    if (pidOff + sizeof(ULONG_PTR) <= buf.size()) {
                        DWORD pid = (DWORD)*reinterpret_cast<const ULONG_PTR*>(buf.data() + pidOff);
                        if (pid != 0) ntPids.insert(pid);
                    }
                    if (!next) break;
                    off += next;
                    if (off >= buf.size()) break;
                }

                HANDLE snap3 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap3 != INVALID_HANDLE_VALUE) {
                    std::unordered_set<DWORD> win32Pids;
                    PROCESSENTRY32W e3 = {}; e3.dwSize = sizeof(e3);
                    if (Process32FirstW(snap3, &e3)) {
                        do { win32Pids.insert(e3.th32ProcessID); }
                        while (Process32NextW(snap3, &e3));
                    }
                    CloseHandle(snap3);

                    for (DWORD pid : ntPids) {
                        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;
                        if (win32Pids.find(pid) == win32Pids.end()) {
                            ScannerUI::EmulatorFinding f;
                            f.process  = "PID:" + std::to_string(pid);
                            f.type     = kTagMemoryProtect;
                            f.address  = "PID:" + std::to_string(pid);
                            f.detail   = "process visible in NtQuerySystemInformation but hidden from Toolhelp (DKOM)";
                            f.severity = "HIGH";
                            findings.push_back(f);
                        }
                    }

                    // Thread count divergence: Toolhelp thread count vs NtQuerySystemInformation
                    // A higher thread count in NT than in Toolhelp = hidden threads (DKOM on threads)
                    {
                        // Build map: pid -> NT thread count from the buffer we already have
                        std::unordered_map<DWORD, DWORD> ntThreadCounts;
                        size_t off2 = 0;
                        while (off2 + 8 <= buf.size()) {
                            ULONG next = *reinterpret_cast<const ULONG*>(buf.data() + off2);
                            size_t pidOff  = off2 + (sizeof(void*) == 8 ? 0x50 : 0x44);
                            size_t tcntOff = off2 + (sizeof(void*) == 8 ? 0x28 : 0x24);
                            if (pidOff  + sizeof(ULONG_PTR) <= buf.size() &&
                                tcntOff + sizeof(ULONG) <= buf.size()) {
                                DWORD pid = (DWORD)*reinterpret_cast<const ULONG_PTR*>(buf.data() + pidOff);
                                DWORD cnt = *reinterpret_cast<const ULONG*>(buf.data() + tcntOff);
                                if (pid != 0) ntThreadCounts[pid] = cnt;
                            }
                            if (!next) break;
                            off2 += next;
                            if (off2 >= buf.size()) break;
                        }

                        // First pass: compare against Toolhelp snapshot and collect candidates.
                        // We do not flag yet — a single measurement can diverge due to threads
                        // being born or dying between the two independent snapshot calls.
                        HANDLE snapT = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                        if (snapT != INVALID_HANDLE_VALUE) {
                            std::unordered_map<DWORD, DWORD> th32ThreadCounts;
                            THREADENTRY32 te = {}; te.dwSize = sizeof(te);
                            if (Thread32First(snapT, &te)) {
                                do { th32ThreadCounts[te.th32OwnerProcessID]++; }
                                while (Thread32Next(snapT, &te));
                            }
                            CloseHandle(snapT);

                            std::unordered_set<DWORD> candidatePids;
                            for (const auto& kv : ntThreadCounts) {
                                DWORD pid   = kv.first;
                                DWORD ntCnt = kv.second;
                                if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;
                                // Processes with very high thread counts have too much variance
                                // between snapshots to produce a reliable divergence signal.
                                if (ntCnt > 200) continue;
                                auto it = th32ThreadCounts.find(pid);
                                DWORD th32Cnt = (it != th32ThreadCounts.end()) ? it->second : 0;
                                // Require 4+ more threads in NT than Toolhelp to flag.
                                // A delta of 1-3 is within normal timing variance between the
                                // two snapshot APIs (threads can be born/die between calls).
                                if (ntCnt > th32Cnt + 3)
                                    candidatePids.insert(pid);
                            }

                            // Second pass: re-measure after 80 ms and only flag PIDs that
                            // still show divergence — eliminates transient timing artifacts.
                            if (!candidatePids.empty()) {
                                Sleep(80);
                                ULONG needed2 = 0;
                                NtQuerySysInfo(5, nullptr, 0, &needed2);
                                if (needed2 < 64) needed2 = 2 * 1024 * 1024;
                                std::vector<uint8_t> buf2(needed2 + 4096);
                                LONG st2 = NtQuerySysInfo(5, buf2.data(), (ULONG)buf2.size(), &needed2);
                                if (st2 >= 0) {
                                    std::unordered_map<DWORD, DWORD> ntThreadCounts2;
                                    size_t off3 = 0;
                                    while (off3 + 8 <= buf2.size()) {
                                        ULONG next3 = *reinterpret_cast<const ULONG*>(buf2.data() + off3);
                                        size_t pidOff3  = off3 + (sizeof(void*) == 8 ? 0x50 : 0x44);
                                        size_t tcntOff3 = off3 + (sizeof(void*) == 8 ? 0x28 : 0x24);
                                        if (pidOff3  + sizeof(ULONG_PTR) <= buf2.size() &&
                                            tcntOff3 + sizeof(ULONG)    <= buf2.size()) {
                                            DWORD pid3 = (DWORD)*reinterpret_cast<const ULONG_PTR*>(buf2.data() + pidOff3);
                                            DWORD cnt3 = *reinterpret_cast<const ULONG*>(buf2.data() + tcntOff3);
                                            if (pid3 != 0) ntThreadCounts2[pid3] = cnt3;
                                        }
                                        if (!next3) break;
                                        off3 += next3;
                                        if (off3 >= buf2.size()) break;
                                    }

                                    std::unordered_map<DWORD, DWORD> th32ThreadCounts2;
                                    HANDLE snapT2 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                                    if (snapT2 != INVALID_HANDLE_VALUE) {
                                        THREADENTRY32 te2 = {}; te2.dwSize = sizeof(te2);
                                        if (Thread32First(snapT2, &te2)) {
                                            do { th32ThreadCounts2[te2.th32OwnerProcessID]++; }
                                            while (Thread32Next(snapT2, &te2));
                                        }
                                        CloseHandle(snapT2);

                                        for (DWORD pid : candidatePids) {
                                            auto ntIt2 = ntThreadCounts2.find(pid);
                                            if (ntIt2 == ntThreadCounts2.end()) continue;
                                            DWORD ntCnt2 = ntIt2->second;
                                            if (ntCnt2 > 200) continue;
                                            auto thIt2 = th32ThreadCounts2.find(pid);
                                            DWORD th32Cnt2 = (thIt2 != th32ThreadCounts2.end()) ? thIt2->second : 0;
                                            if (ntCnt2 > th32Cnt2 + 3) {
                                                ScannerUI::EmulatorFinding f;
                                                f.process  = "PID:" + std::to_string(pid);
                                                f.type     = kTagMemoryProtect;
                                                f.address  = "PID:" + std::to_string(pid);
                                                f.detail   = "thread count divergence: NT=" + std::to_string(ntCnt2) +
                                                             " Toolhelp=" + std::to_string(th32Cnt2) +
                                                             " | possible hidden threads (DKOM)";
                                                f.severity = "HIGH";
                                                findings.push_back(f);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    status = findings.empty() ? "OK" : "DETECTED";
    return findings;
}
