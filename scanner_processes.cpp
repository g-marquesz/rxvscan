#include "scanner_core.h"
#pragma comment(lib, "version.lib")

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

static bool IsWritableOrWriteExecuteProtection(DWORD protect) {
    DWORD base = protect & 0xff;
    return base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

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

        L"CHROME.EXE", L"FIREFOX.EXE", L"MSEDGE.EXE", L"OPERA.EXE", L"BRAVE.EXE",
        L"VIVALDI.EXE", L"THORIUM.EXE",

        L"JAVA.EXE", L"JAVAW.EXE", L"JAVAWS.EXE",

        L"DOTNET.EXE", L"CSC.EXE", L"VBCSCOMPILER.EXE",
        L"MONO.EXE", L"MONO-SGEN.EXE",

        L"NODE.EXE", L"DENO.EXE", L"BUN.EXE",

        L"POWERSHELL.EXE", L"PWSH.EXE",
        L"RUBY.EXE", L"RUBY23.EXE", L"RUBY24.EXE", L"RUBY25.EXE",
        L"PHP.EXE", L"PHP-CGI.EXE",
        L"PYTHON.EXE", L"PYTHONW.EXE", L"PYTHON3.EXE",
        L"PERL.EXE",

        L"LUAJIT.EXE", L"LUA.EXE",

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








        if (IsAuthenticodeSigned(module.path)) {
            if (!exePath.empty() && DetectionFilter::SamePublisherTrusted(module.path, exePath))
                continue;
            DetectionFilter::PathClass mcls = DetectionFilter::ClassifyPath(module.path);
            if (mcls != DetectionFilter::PathClass::TempOrInstaller &&
                mcls != DetectionFilter::PathClass::Unknown &&
                mcls != DetectionFilter::PathClass::Unmapped)
                continue;
            std::wstring modCn = DetectionFilter::GetSignerCommonNameUpperCached(module.path);

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





        if (DetectionFilter::IsTrustedDir(cls) && !packed) {






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


    uintptr_t maxModuleEnd = 0;
    for (const auto& m : modules)
        if (m.end > maxModuleEnd) maxModuleEnd = m.end;
    constexpr uintptr_t kMinScan   = 2ULL * 1024 * 1024 * 1024;
    constexpr uintptr_t kHeadroom  = 512ULL * 1024 * 1024;
    const uintptr_t kScanLimit = (maxModuleEnd + kHeadroom > kMinScan)
                                 ? (maxModuleEnd + kHeadroom) : kMinScan;

    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi = {};
    std::unordered_set<uintptr_t> seenAllocBases;
    size_t paceCounter = 0;
    while (address < kScanLimit &&
           VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        MaybePaceIteration(paceCounter, 48);
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
    size_t paceCounter = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            MaybePaceIteration(paceCounter, 64);
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


struct ExpectedMsysRuntimeProfile {
    bool valid = false;
    DWORD autoloadRva = 0;
    DWORD autoloadSize = 0;
};

static std::wstring QueryModuleVersionString(const std::vector<BYTE>& data,
                                             WORD language, WORD codepage,
                                             const wchar_t* key) {
    wchar_t block[128] = {};
    swprintf_s(block, L"\\StringFileInfo\\%04x%04x\\%s", language, codepage, key);
    LPVOID value = nullptr;
    UINT length = 0;
    if (VerQueryValueW(const_cast<BYTE*>(data.data()), block, &value, &length) &&
        value && length > 1)
        return reinterpret_cast<const wchar_t*>(value);
    return {};
}

static ExpectedMsysRuntimeProfile AnalyzeExpectedMsysRuntime(const std::wstring& path) {
    ExpectedMsysRuntimeProfile profile;
    if (ToUpperInvariant(BaseNameFromPath(path)) != L"MSYS-2.0.DLL")
        return profile;

    const std::wstring pathUpper = ToUpperInvariant(path);
    const bool expectedInstallPath =
        DetectionFilter::ClassifyPath(path) == DetectionFilter::PathClass::ProgramFiles ||
        pathUpper.find(L"\\MSYS64\\USR\\BIN\\MSYS-2.0.DLL") != std::wstring::npos;
    if (!expectedInstallPath)
        return profile;

    DWORD ignored = 0;
    DWORD versionSize = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!versionSize)
        return profile;
    std::vector<BYTE> versionData(versionSize);
    if (!GetFileVersionInfoW(path.c_str(), 0, versionSize, versionData.data()))
        return profile;

    struct Translation { WORD language; WORD codepage; };
    Translation* translations = nullptr;
    UINT translationBytes = 0;
    std::vector<Translation> candidates;
    if (VerQueryValueW(versionData.data(), L"\\VarFileInfo\\Translation",
                       reinterpret_cast<LPVOID*>(&translations), &translationBytes) &&
        translations && translationBytes >= sizeof(Translation)) {
        size_t count = translationBytes / sizeof(Translation);
        for (size_t i = 0; i < count && i < 8; ++i)
            candidates.push_back(translations[i]);
    }
    candidates.push_back({ 0x0409, 0x04B0 });
    candidates.push_back({ 0x0409, 0x04E4 });

    std::wstring company, product, original;
    for (const auto& candidate : candidates) {
        if (company.empty())
            company = QueryModuleVersionString(versionData, candidate.language,
                                               candidate.codepage, L"CompanyName");
        if (product.empty())
            product = QueryModuleVersionString(versionData, candidate.language,
                                               candidate.codepage, L"ProductName");
        if (original.empty())
            original = QueryModuleVersionString(versionData, candidate.language,
                                                candidate.codepage, L"OriginalFilename");
    }
    if (ToUpperInvariant(company).find(L"RED HAT") == std::wstring::npos ||
        ToUpperInvariant(product).find(L"MSYS2") == std::wstring::npos ||
        ToUpperInvariant(original) != L"MSYS-2.0.DLL")
        return profile;

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return profile;
    BYTE headers[4096] = {};
    DWORD read = 0;
    bool readOk = ReadFile(file, headers, sizeof(headers), &read, nullptr) != FALSE;
    CloseHandle(file);
    if (!readOk || read < sizeof(IMAGE_DOS_HEADER))
        return profile;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return profile;
    size_t peOffset = static_cast<size_t>(dos->e_lfanew);
    if (peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > read ||
        *reinterpret_cast<const DWORD*>(headers + peOffset) != IMAGE_NT_SIGNATURE)
        return profile;

    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        headers + peOffset + sizeof(DWORD));
    size_t sectionTable = peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                          fileHeader->SizeOfOptionalHeader;
    bool sawAutoload = false;
    static const char* badNames[] = {
        "packed", "themida", ".vmp", "protect", "petite", "upx", ".ndata", "sforce", nullptr
    };
    for (WORD i = 0; i < fileHeader->NumberOfSections && i < 96; ++i) {
        size_t offset = sectionTable + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (offset + sizeof(IMAGE_SECTION_HEADER) > read)
            return ExpectedMsysRuntimeProfile{};
        const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(headers + offset);
        char name[9] = {};
        memcpy(name, section->Name, 8);
        for (int n = 0; n < 8 && name[n]; ++n)
            if (static_cast<unsigned char>(name[n]) > 127)
                return ExpectedMsysRuntimeProfile{};
        char lower[9] = {};
        for (int n = 0; n < 8; ++n)
            lower[n] = static_cast<char>(tolower(static_cast<unsigned char>(name[n])));
        for (int n = 0; badNames[n]; ++n)
            if (strstr(lower, badNames[n]))
                return ExpectedMsysRuntimeProfile{};

        const bool writableExecutable =
            (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (!writableExecutable)
            continue;
        if (strncmp(lower, ".autoloa", 8) != 0)
            return ExpectedMsysRuntimeProfile{};
        profile.autoloadRva = section->VirtualAddress;
        profile.autoloadSize = (std::max)(section->Misc.VirtualSize, section->SizeOfRawData);
        sawAutoload = profile.autoloadSize != 0;
    }
    profile.valid = sawAutoload;
    return profile;
}

static void ScanLoadedModuleAnomalies(HANDLE , const std::string& processName,
                                      const std::vector<ModuleRange>& modules,
                                      std::vector<ScannerUI::EmulatorFinding>& out) {
    for (const auto& mod : modules) {
        if (mod.path.empty())
            continue;

        if (DetectionFilter::IsTrustedSignedCached(mod.path))
            continue;

        DetectionFilter::EfiPeInfo pe = DetectionFilter::AnalyzeEfiPe(mod.path);
        if (!pe.valid)
            continue;
        const ExpectedMsysRuntimeProfile msysProfile = AnalyzeExpectedMsysRuntime(mod.path);

        std::string modName = WideToUtf8(BaseNameFromPath(mod.path));


        if (DetectionFilter::CheckPeChecksumMismatch(mod.path, pe.storedChecksum)) {
            std::string detail = "Modulo com checksum PE diferente do disco: " + modName +
                                 " | checksum armazenado != calculado | indicador de patching binario";
            if (out.size() < ScanLimits::kMaxSysmemFindings)
                out.push_back({ processName, kTagModulePatch,
                                HexAddress(mod.begin), detail, "HIGH" });
            continue;
        }


        if (pe.badSections && !msysProfile.valid) {
            std::string detail = "Modulo com secoes de packer/protecao: " + modName +
                                 " | secoes anomalas detectadas (obfuscator/packer)";
            if (out.size() < ScanLimits::kMaxSysmemFindings)
                out.push_back({ processName, kTagModuleAnomaly,
                                HexAddress(mod.begin), detail, "HIGH" });
        }
    }
}


static SystemHandleSnapshot g_systemHandleSnapshot;
static bool g_systemHandleSnapshotFetched = false;

void ResetSystemHandleSnapshot() {
    g_systemHandleSnapshotFetched = false;
    g_systemHandleSnapshot = SystemHandleSnapshot{};
}

const SystemHandleSnapshot& GetSystemHandleSnapshot() {
    if (g_systemHandleSnapshotFetched)
        return g_systemHandleSnapshot;
    g_systemHandleSnapshotFetched = true;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto querySystem = ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    if (!querySystem)
        return g_systemHandleSnapshot;

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
        return g_systemHandleSnapshot;

    g_systemHandleSnapshot.buffer = std::move(buf);
    g_systemHandleSnapshot.ok = true;
    return g_systemHandleSnapshot;
}


static void ScanSuspiciousHandlesInProcess(DWORD pid, const std::string& procName,
                                           std::vector<ScannerUI::EmulatorFinding>& out) {
    constexpr DWORD kInjectCombo = PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION;

    const SystemHandleSnapshot& snapshot = GetSystemHandleSnapshot();
    if (!snapshot.ok)
        return;


    HANDLE targetProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!targetProc)
        return;

    const auto* info = snapshot.Info();
    std::unordered_set<std::string> seen;

    size_t paceCounter = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        MaybePaceIteration(paceCounter, 4096);
        const auto& h = info->Handles[i];
        if ((DWORD)h.UniqueProcessId != pid)
            continue;

        if ((h.GrantedAccess & kInjectCombo) != kInjectCombo)
            continue;


        HANDLE dup = nullptr;
        if (!DuplicateHandle(targetProc, (HANDLE)(ULONG_PTR)h.HandleValue,
                             GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;
        DWORD targetPid = GetProcessId(dup);
        CloseHandle(dup);

        if (targetPid == 0 || targetPid == pid)
            continue;


        std::wstring targetPath = ProcessFullPathW(targetPid);
        if (targetPath.empty() || !IsHdPlayerProcess(BaseNameFromPath(targetPath)))
            continue;


        std::string key = std::to_string(targetPid) + ":" +
                          std::to_string(h.GrantedAccess);
        if (!seen.insert(key).second)
            continue;

        std::ostringstream detail;
        detail << "Handle de injecao detectado: pid=" << pid
               << " possui handle no HD-Player.exe pid=" << targetPid
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



        if (DetectionFilter::IsTrustedSignedCached(mod.path))
            continue;




        BYTE modHdr[4096] = {}; SIZE_T mhg = 0;
        ReadProcessMemory(process, (LPCVOID)mod.begin, modHdr, sizeof(modHdr), &mhg);
        bool isGfxModule = DetectionFilter::ExportsGraphicsSymbol(modHdr, mhg, mod.begin);

        std::wstring file = BaseNameFromPath(mod.path);
        const ExpectedMsysRuntimeProfile msysProfile = AnalyzeExpectedMsysRuntime(mod.path);
        bool flaggedThisMod = false;
        uintptr_t addr = mod.begin;
        size_t paceCounter = 0;
        while (addr < mod.end && !flaggedThisMod) {
            MaybePaceIteration(paceCounter, 48);
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
                break;
            if (mbi.State == MEM_COMMIT && IsWriteExecuteProtection(mbi.Protect) &&
                mbi.RegionSize >= 4096) {
                const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                const uintptr_t autoloadBegin = mod.begin + msysProfile.autoloadRva;
                const uintptr_t autoloadEnd = autoloadBegin + msysProfile.autoloadSize;
                if (msysProfile.valid && regionBase >= autoloadBegin && regionBase < autoloadEnd) {
                    uintptr_t next = regionBase + mbi.RegionSize;
                    if (next <= addr) break;
                    addr = next;
                    continue;
                }
                uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
                bool isGfxHookTarget = gfxHookDests && allocBase && gfxHookDests->count(allocBase) > 0;


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


static bool QueryMappedImagePath(HANDLE process, PVOID address, std::wstring& path) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueryVirtMem = ntdll ? reinterpret_cast<NtQueryVirtualMemoryFn>(
        GetProcAddress(ntdll, "NtQueryVirtualMemory")) : nullptr;
    if (!NtQueryVirtMem)
        return false;

    constexpr size_t kBufSize = (MAX_PATH * 4 + 32) * sizeof(wchar_t);
    alignas(8) BYTE nameBuf[kBufSize] = {};
    SIZE_T retLen = 0;
    if (NtQueryVirtMem(process, address, 2, nameBuf, kBufSize, &retLen) < 0)
        return false;

    USHORT strLen = *reinterpret_cast<const USHORT*>(nameBuf);
    PWSTR bufPtr = nullptr;
    memcpy(&bufPtr, nameBuf + 8, sizeof(PWSTR));
    const uintptr_t bufferBegin = reinterpret_cast<uintptr_t>(nameBuf);
    const uintptr_t bufferEnd = bufferBegin + kBufSize;
    const uintptr_t textBegin = reinterpret_cast<uintptr_t>(bufPtr);
    if (!bufPtr || strLen == 0 || (strLen % sizeof(wchar_t)) != 0 ||
        textBegin < bufferBegin || textBegin + strLen > bufferEnd)
        return false;

    std::wstring devicePath(bufPtr, strLen / sizeof(wchar_t));
    path = DevicePathToDosPath(devicePath);
    if (path.empty())
        path = std::move(devicePath);
    return !path.empty();
}

static void ScanHiddenMappedDlls(HANDLE process, const std::string& procName,
                                  const std::vector<ModuleRange>& modules,
                                  std::vector<ScannerUI::EmulatorFinding>& out,
                                  const std::unordered_set<uintptr_t>* activeThreadBases = nullptr) {

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
    size_t paceCounter = 0;

    while (addr < 0x00007FFFFFFEFFFF && out.size() < ScanLimits::kMaxSysmemFindings) {
        MaybePaceIteration(paceCounter, 48);
        SIZE_T ret = VirtualQueryEx(process, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (!ret) break;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;

        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ||
            !IsExecutableProtection(mbi.Protect)) continue;

        uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
        if (!seenAlloc.insert(allocBase).second) continue;
        const bool hasPeHeader = DetectionFilter::HasPEHeader(process, mbi.AllocationBase);
        const bool hasActiveThread = activeThreadBases && activeThreadBases->count(allocBase) > 0;
        const bool writeExec = IsWriteExecuteProtection(mbi.Protect);
        if (knownBases.count(allocBase)) continue;


        std::wstring dosPath;
        if (!QueryMappedImagePath(process, mbi.AllocationBase, dosPath)) {

            if (!hasPeHeader || (!hasActiveThread && !writeExec))
                continue;
            std::string detail = "MEM_IMAGE executavel fora da lista de modulos, sem backing resolvido"
                                 " | base=" + HexAddress(allocBase) +
                                 " | thread=" + (hasActiveThread ? std::string("yes") : std::string("no")) +
                                 " | protect=" + ProtectionToString(mbi.Protect);
            AddEmulatorFinding(out, procName, kTagManualMapping, allocBase, detail, "HIGH");
            continue;
        }



        std::wstring dosUp = ToUpperInvariant(dosPath);

        if (knownPaths.count(dosUp)) continue;

        const bool backingExists = FileExistsW(dosPath);
        const bool trustedBacking = backingExists &&
            DetectionFilter::IsTrustedSignedCached(dosPath);
        if (trustedBacking)
            continue;

        DetectionFilter::PathClass pathClass = DetectionFilter::ClassifyPath(dosPath);
        const bool suspiciousPath =
            pathClass == DetectionFilter::PathClass::TempOrInstaller ||
            pathClass == DetectionFilter::PathClass::UserProfile ||
            pathClass == DetectionFilter::PathClass::Removable ||
            pathClass == DetectionFilter::PathClass::Unmapped ||
            pathClass == DetectionFilter::PathClass::Unknown;
        if (!hasPeHeader && !hasActiveThread)
            continue;
        if (backingExists && !suspiciousPath && !hasActiveThread && !writeExec)
            continue;

        std::string detail = "Imagem executavel mapeada do disco fora da lista de modulos: " +
                             WideToUtf8(dosPath) + " | base=" + HexAddress(allocBase) +
                             " | backing=" + (backingExists ? std::string("present") : std::string("missing")) +
                             " | thread=" + (hasActiveThread ? std::string("yes") : std::string("no")) +
                             " | protect=" + ProtectionToString(mbi.Protect);
        const std::string severity = (!backingExists || hasActiveThread || writeExec) ? "HIGH" : "MEDIUM";
        AddEmulatorFinding(out, procName, kTagManualMapping, allocBase, detail, severity);
    }
}


static void ScanProcessImageBacking(HANDLE process, const std::string& procName,
                                    const std::wstring& executablePath,
                                    const std::vector<ModuleRange>& modules,
                                    std::vector<ScannerUI::EmulatorFinding>& out) {
    if (executablePath.empty() || modules.empty())
        return;

    const std::wstring expected = ToUpperInvariant(executablePath);
    const ModuleRange* mainImage = nullptr;
    for (const auto& module : modules) {
        if (ToUpperInvariant(module.path) == expected) {
            mainImage = &module;
            break;
        }
    }
    if (!mainImage)
        return;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(mainImage->begin),
                       &mbi, sizeof(mbi)) != sizeof(mbi))
        return;

    std::wstring backingPath;
    const bool hasBacking = QueryMappedImagePath(process, mbi.AllocationBase, backingPath);
    const bool privateImage = mbi.Type != MEM_IMAGE;
    const bool pathMismatch = hasBacking && ToUpperInvariant(backingPath) != expected;
    const bool missingBacking = hasBacking && !FileExistsW(backingPath);
    if (!privateImage && !pathMismatch && !missingBacking)
        return;

    const bool trustedAlternate = hasBacking && FileExistsW(backingPath) &&
                                  DetectionFilter::IsTrustedSignedCached(backingPath);
    if (!privateImage && pathMismatch && trustedAlternate && !missingBacking)
        return;

    std::string memoryType = mbi.Type == MEM_IMAGE ? "MEM_IMAGE" :
                             mbi.Type == MEM_PRIVATE ? "MEM_PRIVATE" : "MEM_MAPPED";
    std::string detail = "Process image backing inconsistente"
                         " | expected=" + WideToUtf8(executablePath) +
                         " | mapped=" + (hasBacking ? WideToUtf8(backingPath) : std::string("unresolved")) +
                         " | memory_type=" + memoryType +
                         " | protect=" + ProtectionToString(mbi.Protect);
    AddEmulatorFinding(out, procName, ScanTag::Hollowing, mainImage->begin, detail, "HIGH");
}

static void ScanPrivateExecutableWorkingSet(HANDLE process, const std::string& procName,
                                             const std::vector<ModuleRange>& modules,
                                             std::vector<ScannerUI::EmulatorFinding>& out) {

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


    if (!QueryWorkingSetEx(process, entries.data(), (DWORD)(entries.size() * sizeof(WSExEntry))))
        return;

    std::unordered_set<uintptr_t> reported;
    for (const auto& e : entries) {

        bool valid = (e.VirtualAttributes & 1) != 0;
        if (!valid) continue;

        uintptr_t pageBase = (uintptr_t)e.VirtualAddress;

        MEMORY_BASIC_INFORMATION mbi2 = {};
        if (VirtualQueryEx(process, e.VirtualAddress, &mbi2, sizeof(mbi2)) != sizeof(mbi2)) continue;
        uintptr_t allocBase = (uintptr_t)mbi2.AllocationBase;
        if (!reported.insert(allocBase).second) continue;


        if (DetectionFilter::HasPEHeader(process, e.VirtualAddress)) {
            std::string detail = "Working set: pagina executavel privada com PE header | addr=" +
                                 HexAddress(pageBase) + " | alloc=" + HexAddress(allocBase) +
                                 " | indica DLL manualmente mapeada (header nao apagado)";
            AddEmulatorFinding(out, procName, kTagManualMapping, allocBase, detail, "HIGH");
        }
    }
}


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


    std::unordered_set<DWORD> toolhelpTids;
    if (!CollectToolhelpThreadIdsForPid(pid, toolhelpTids))
        return;

    HANDLE prevThread = nullptr;
    HANDLE nextThread = nullptr;
    constexpr DWORD kThreadAccess = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;




    std::unordered_map<DWORD, HiddenThreadCandidate> suspectDkomThreads;

    while (NtGetNextThread(process, prevThread, kThreadAccess, 0, 0, &nextThread) >= 0) {
        if (prevThread) CloseHandle(prevThread);
        prevThread = nextThread;

        DWORD tid = GetThreadId(nextThread);


        HiddenThreadCandidate* dkomCandidate = nullptr;
        if (tid && !toolhelpTids.count(tid)) {
            HiddenThreadCandidate& candidate = suspectDkomThreads[tid];
            candidate.tid = tid;
            dkomCandidate = &candidate;
        }


        PVOID startAddr = nullptr;
        if (queryThread(nextThread, 9, &startAddr, sizeof(startAddr), nullptr) < 0 || !startAddr)
            continue;

        uintptr_t start = (uintptr_t)startAddr;
        if (dkomCandidate) {
            dkomCandidate->start = start;
            dkomCandidate->hasStart = true;
        }
        if (AddressInsideModule(start, modules)) {

            BYTE prolog[16] = {}; SIZE_T pg = 0;
            if (!ReadProcessMemory(process, (LPCVOID)start, prolog, sizeof(prolog), &pg) || pg < 5)
                continue;

            bool hasJmp = (prolog[0] == 0xE9 || (prolog[0] == 0xFF && prolog[1] == 0x25) ||
                           (prolog[0] == 0x48 && prolog[1] == 0xB8 && pg >= 12 &&
                            prolog[10] == 0xFF && prolog[11] == 0xE0));
            if (!hasJmp) continue;


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



            if (out.size() >= ScanLimits::kMaxSysmemFindings) continue;
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(process, (LPCVOID)start, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;

            bool privateMem  = (mbi.Type == MEM_PRIVATE);
            bool hasPeHeader = privateMem && DetectionFilter::HasPEHeader(process, mbi.BaseAddress);
            double entropy   = DetectionFilter::ProcessRegionEntropy(
                process, mbi.BaseAddress, (size_t)mbi.RegionSize);


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

static bool IsHdPlayerHandleContext(const std::wstring& objectName) {




    std::wstring objectUpper = ToUpperInvariant(objectName);
    return objectUpper.find(L"HD-PLAYER.EXE") != std::wstring::npos ||
           objectUpper.find(L"HD-PLAYER") != std::wstring::npos;
}

static bool IsHdPlayerHandleContext(const SecurityHandleEvent& ev) {
    return IsHdPlayerHandleContext(ev.objectName);
}

static bool TryParseHexMask(const std::wstring& text, DWORD& mask) {
    mask = 0;
    if (text.empty())
        return false;
    wchar_t* end = nullptr;
    unsigned long value = wcstoul(text.c_str(), &end, 0);
    if (end == text.c_str())
        return false;
    mask = static_cast<DWORD>(value);
    return true;
}

static bool IsProcessOrThreadObject(const std::wstring& objectType) {
    const std::wstring type = UpperTrimW(objectType);
    return type == L"PROCESS" || type == L"THREAD";
}

static bool IsHdPlayerHighRiskAccess(const std::wstring& objectType,
                                     const std::wstring& accessMask) {
    DWORD mask = 0;
    if (!TryParseHexMask(accessMask, mask))
        return false;

    constexpr DWORD kMinInterestingMask = 0x000000ff;
    constexpr DWORD kMaxFocusedMask     = 0x0001ffff;
    if (mask < kMinInterestingMask || mask > kMaxFocusedMask)
        return false;

    const std::wstring type = UpperTrimW(objectType);
    constexpr DWORD kControlRights = WRITE_DAC | WRITE_OWNER | DELETE;
    if (type == L"PROCESS") {
        constexpr DWORD kProcessInjectionRights =
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
            PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME;
        return (mask & (kProcessInjectionRights | kControlRights)) != 0;
    }

    if (type == L"THREAD") {
        constexpr DWORD kThreadControlRights =
            THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT |
            THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN |
            THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION;
        return (mask & (kThreadControlRights | kControlRights)) != 0;
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
                        bool hdPlayerOpenHandle =
                            ev.eventId == 4656 &&
                            IsHdPlayerHandleContext(ev) &&
                            IsProcessOrThreadObject(ev.objectType) &&
                            IsHdPlayerHighRiskAccess(ev.objectType, ev.accessMask);
                        if (ev.handleId != L"-" && ev.processId != L"-" &&
                            (ev.eventId == 4658 || hdPlayerOpenHandle))
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
    std::unordered_set<std::string> reportedSignature;
    size_t emitted = 0;

    for (const auto& ev : events) {
        std::wstring key = ev.processId + L":" + ev.handleId;
        if (ev.eventId == 4656) {
            if (!IsHdPlayerHandleContext(ev) ||
                !IsProcessOrThreadObject(ev.objectType) ||
                !IsHdPlayerHighRiskAccess(ev.objectType, ev.accessMask)) {
                continue;
            }
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
        bool focusedHdPlayerHandle =
            IsHdPlayerHandleContext(ev) ||
            IsHdPlayerHandleContext(open.objectName);
        if (!focusedHdPlayerHandle ||
            !IsProcessOrThreadObject(open.objectType) ||
            !IsHdPlayerHighRiskAccess(open.objectType, open.accessMask)) {
            openHandles.erase(it);
            continue;
        }
        if (ev.time > open.time) {
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



                const std::string signature = source + "|" + objectType + "|" + access;
                if (!reportedSignature.insert(signature).second) {
                    openHandles.erase(it);
                    continue;
                }

                std::string detail =
                    "handle de " + objectType +
                    " com acesso alto foi fechado apos " + FormatHandleDuration(ev.time - open.time) +
                    " | opened=" + FormatLocalFileTime(open.fileTime) +
                    " | closed=" + FormatLocalFileTime(ev.fileTime) +
                    " | source=" + source +
                    " | object=" + target +
                    " | type=" + objectType +
                    " | access=" + access +
                    " | handle=" + WideToUtf8(ev.handleId);
                detail += " | evidence=Security 4656->4658, HD-Player, mask 0xff..0x1ffff";

                AddEmulatorFinding(out, source, "INTERNAL DETECTADO",
                                   0, detail, "HIGH");
                if (++emitted >= 80 || out.size() >= ScanLimits::kMaxSysmemFindings)
                    break;
            }
        }
        openHandles.erase(it);
    }
}

static std::string FindCleanerTokenAscii(const uint8_t* data, size_t len) {
    if (!data || len == 0)
        return {};

    std::string hay;
    hay.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = data[i];
        hay.push_back((c >= 0x20 && c <= 0x7e) ? static_cast<char>(tolower(c)) : ' ');
    }

    static const char* kTokens[] = {
        "prefetch", "hd-player.exe", "hd-player", "bam", "usn", "journal",
        "eventlog", "wevtutil", "clear-eventlog", "fsutil usn",
        "pcasvc", "dps", "diagtrack", "sysmain", "shimcache",
        "amcache", "cleaner", "clean", "clear", "delete", "sdelete",
        "journaldelete", "deletejournal", "handle", "hook", "stream",
        nullptr
    };
    for (int i = 0; kTokens[i]; ++i) {
        if (hay.find(kTokens[i]) != std::string::npos)
            return kTokens[i];
    }
    return {};
}

static void ScanHdPlayerLowWritableRange(HANDLE process, const std::string& procName,
                                         std::vector<ScannerUI::EmulatorFinding>& out) {
    constexpr uintptr_t kScanStart = 0x000000ff;
    constexpr uintptr_t kScanEnd   = 0x0001ffff;
    constexpr SIZE_T kMaxRead = 32 * 1024;

    uintptr_t addr = kScanStart;
    std::unordered_set<uintptr_t> seenAllocBases;
    std::vector<uint8_t> buffer(kMaxRead);

    while (addr < kScanEnd && out.size() < ScanLimits::kMaxSysmemFindings) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;

        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t next = base + mbi.RegionSize;
        if (next <= addr)
            break;
        addr = next;

        uintptr_t regionEnd = next < kScanEnd ? next : kScanEnd;
        if (regionEnd <= kScanStart)
            continue;

        if (mbi.State != MEM_COMMIT)
            continue;
        if (!IsWritableOrWriteExecuteProtection(mbi.Protect))
            continue;

        uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        if (!seenAllocBases.insert(allocBase).second)
            continue;

        uintptr_t readBase = base < kScanStart ? kScanStart : base;
        SIZE_T toRead = static_cast<SIZE_T>(regionEnd - readBase);
        if (toRead > kMaxRead)
            toRead = kMaxRead;
        if (toRead < 8)
            continue;

        SIZE_T got = 0;
        bool readable = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(readBase),
                                          buffer.data(), toRead, &got) && got >= 8;
        std::string token = readable ? FindCleanerTokenAscii(buffer.data(), got) : std::string();

        bool writeExec = IsWriteExecuteProtection(mbi.Protect);
        if (!writeExec && token.empty())
            continue;

        std::string detail = "HD-Player low memory range 0xff..0x1ffff";
        detail += " | region=" + HexAddress(base) + "-" + HexAddress(regionEnd);
        detail += " | alloc=" + HexAddress(allocBase);
        detail += " | protect=" + ProtectionToString(mbi.Protect);
        detail += " | readable=" + std::string(readable ? "yes" : "no");
        if (!token.empty())
            detail += " | cleaner_or_hook_string=" + token;

        AddEmulatorFinding(out, procName,
                           writeExec ? kTagMemoryInject : kTagMemoryProtect,
                           allocBase, detail,
                           writeExec || !token.empty() ? "HIGH" : "MEDIUM");
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

        std::wstring nameW(name.begin(), name.end());
        std::wstring exePathW = ProcessFullPathW(pid);



        bool isEmuRuntime = DetectionFilter::IsKnownEmulatorRuntime(nameW) &&
                            DetectionFilter::IsTrustedSignedCached(exePathW) &&
                            DetectionFilter::IsTrustedDir(DetectionFilter::ClassifyPath(exePathW));
        std::vector<ModuleRange> modules;
        if (CollectProcessModules(process, modules)) {
            auto threadBases = CollectThreadAllocBases(pid, process, modules);


            auto gfxDests = CollectGfxHookDestBases(process, modules);
            const std::unordered_set<uintptr_t>* pGfxDests = gfxDests.empty() ? nullptr : &gfxDests;

            ScanUnsignedModules(process, nameWithPid, modules, installDir, exePathW, findings);
            ScanExecutablePrivateMemory(process, nameWithPid, modules, findings, &threadBases,
                                        isEmuRuntime, true, true, pGfxDests);
            ScanThreadStartAddresses(pid, nameWithPid, process, modules, findings,
                                     isEmuRuntime, true, true, pGfxDests);
            if (IsHdPlayerProcess(nameW))
                ScanHdPlayerLowWritableRange(process, nameWithPid, findings);

            ScanHiddenMappedDlls(process, nameWithPid, modules, findings, &threadBases);
            ScanPrivateExecutableWorkingSet(process, nameWithPid, modules, findings);
            ScanAnomalousModuleProtections(process, nameWithPid, modules, findings, pGfxDests);
            ScanLoadedModuleAnomalies(process, nameWithPid, modules, findings);
            ScanHiddenThreadsViaKernel(pid, nameWithPid, process, modules, findings, isEmuRuntime, pGfxDests);
        }

        CloseHandle(process);
    }

    CollectEmulatorHandleLifetimeFindings(findings);

    std::vector<ScannerUI::EmulatorFinding> merged;
    std::unordered_map<std::string, size_t> byTarget;
    merged.reserve(findings.size());
    for (const auto& finding : findings) {
        const std::string key = finding.process + "\n" + finding.type + "\n" + finding.address;
        auto it = byTarget.find(key);
        if (it == byTarget.end()) {
            byTarget.emplace(key, merged.size());
            merged.push_back(finding);
            continue;
        }

        auto& existing = merged[it->second];
        if (DetectionFilter::SeverityRank(finding.severity) <
            DetectionFilter::SeverityRank(existing.severity))
            existing.severity = finding.severity;
        if (existing.detail.find(finding.detail) == std::string::npos)
            existing.detail += " | " + finding.detail;
    }
    return merged;
}



struct SyscallStubResult {
    int totalStubs   = 0;
    int classicStubs = 0;
    int simpleStubs  = 0;
    int hellsGate    = 0;
    int sw1Stubs     = 0;
    int tartarusGate = 0;
};

static SyscallStubResult CountSyscallStubs(const uint8_t* buf, size_t sz)
{
    SyscallStubResult r;
    if (sz < 8) return r;

    for (size_t i = 0; i + 7 < sz; ++i) {

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

    uintptr_t ntdllBegin = 0, ntdllEnd = 0;
    for (const auto& m : modules) {
        if (ToUpperInvariant(BaseNameFromPath(m.path)) == L"NTDLL.DLL") {
            ntdllBegin = m.begin;
            ntdllEnd   = m.end;
            break;
        }
    }


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
    size_t paceCounter = 0;

    while (addr < kSyscallScanLimit && out.size() < ScanLimits::kMaxSyscallDetections) {
        MaybePaceIteration(paceCounter, 48);
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


        uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        if (!seenAllocBases.insert(allocBase).second) continue;

        SIZE_T toRead = mbi.RegionSize < kMaxRead ? mbi.RegionSize : kMaxRead;
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, mbi.BaseAddress, buf.data(), toRead, &got) || got < 8)
            continue;

        SyscallStubResult stubs = CountSyscallStubs(buf.data(), got);
        if (stubs.totalStubs == 0) continue;

        bool isRwx = IsWriteExecuteProtection(mbi.Protect);









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


static void ScanSuspiciousStringsInMemory(
    HANDLE process, const std::string& procName,
    const std::vector<ModuleRange>& modules,
    std::vector<ScannerUI::EmulatorFinding>& out)
{
    struct Token { const char* str; const char* sev; };
    static const Token kTokens[] = {

        { "reflectiveloader",     "HIGH" },
        { "system.windows.forms", "HIGH" },
        { "system.reflection",    "HIGH" },
        { "shellcode",            "HIGH" },

        { "dllinjection",         "HIGH" },
        { "injectdll",            "HIGH" },
        { "reflective",           "HIGH" },
        { "manualmap",            "HIGH" },
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
    size_t paceCounter = 0;

    while (addr < kLimit && out.size() < ScanLimits::kMaxSysmemFindings) {
        MaybePaceIteration(paceCounter, 48);
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


static void EvaluateSuspiciousProcessHeuristics(DWORD pid, const std::wstring& rawExeName,
                                                const std::wstring& fullPath, bool signedOk,
                                                DetectionFilter::PathClass cls,
                                                std::vector<ScannerUI::EmulatorFinding>& out);

std::vector<ScannerUI::EmulatorFinding> CollectSystemMemoryFindings(
    std::string& status, std::vector<ScannerUI::EmulatorFinding>& suspiciousProcessFindings) {
    std::vector<ScannerUI::EmulatorFinding> findings;
    DWORD ownPid = GetCurrentProcessId();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        status = "Snapshot failed";
        return findings;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    size_t paceCounter = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (findings.size() >= ScanLimits::kMaxSysmemFindings)
                break;
            DWORD pid = entry.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == ownPid)
                continue;









            std::wstring imagePath = ProcessFullPathW(pid);
            DetectionFilter::PathClass cls = imagePath.empty()
                ? DetectionFilter::PathClass::Unknown
                : DetectionFilter::ClassifyPath(imagePath);
            bool signedOk = !imagePath.empty() && DetectionFilter::IsTrustedSignedCached(imagePath);
            EvaluateSuspiciousProcessHeuristics(pid, entry.szExeFile, imagePath, signedOk, cls,
                                                 suspiciousProcessFindings);

            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                continue;

            bool systemTrustedProcess = cls == DetectionFilter::PathClass::SystemTrusted;


            bool programFilesSigned = (cls == DetectionFilter::PathClass::ProgramFiles) && signedOk;

            DWORD64 procScanStart = GetTickCount64();
            std::string procName = WideToUtf8(entry.szExeFile) + " [" + std::to_string(pid) + "]";
            std::vector<ModuleRange> modules;
            if (CollectProcessModules(process, modules)) {
                std::vector<ScannerUI::EmulatorFinding> perProcess;
                auto threadBases = CollectThreadAllocBases(pid, process, modules);


                bool isEmuRuntime = DetectionFilter::IsKnownEmulatorRuntime(entry.szExeFile) &&
                                    DetectionFilter::IsTrustedSignedCached(imagePath) &&
                                    DetectionFilter::IsTrustedDir(DetectionFilter::ClassifyPath(imagePath));



                auto gfxDests = CollectGfxHookDestBases(process, modules);
                const std::unordered_set<uintptr_t>* pGfxDests = gfxDests.empty() ? nullptr : &gfxDests;

                ScanExecutablePrivateMemory(process, procName, modules, perProcess, &threadBases, isEmuRuntime, true, true, pGfxDests);
                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanProcessImageBacking(process, procName, imagePath, modules, perProcess);
                }
                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanHiddenMappedDlls(process, procName, modules, perProcess, &threadBases);
                }


                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanThreadStartAddresses(pid, procName, process, modules, perProcess, isEmuRuntime, true, true, pGfxDests);
                }



                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanAnomalousModuleProtections(process, procName, modules, perProcess, pGfxDests);
                }

                if (GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanLoadedModuleAnomalies(process, procName, modules, perProcess);
                }



                bool suspectedInjection = !perProcess.empty();
                bool deepScanGate    = !systemTrustedProcess || suspectedInjection;
                bool deepCostlyGate  = (!systemTrustedProcess && !programFilesSigned) || suspectedInjection;
                if (suspectedInjection &&
                    GetTickCount64() - procScanStart < ScanLimits::kProcessScanTimeoutMs) {
                    ScanHiddenThreadsViaKernel(pid, procName, process, modules, perProcess,
                                               isEmuRuntime, pGfxDests);
                }

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

                    if (f.severity == "MEDIUM")
                        f.detail = "[SUSPEITO] " + f.detail;
                    findings.push_back(std::move(f));
                }
            }
            CloseHandle(process);
            MaybePaceIteration(paceCounter, 6);
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


std::vector<ScannerUI::EmulatorFinding> CollectDkomAnomalies() {
    std::vector<ScannerUI::EmulatorFinding> findings;

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



                {

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


                            if (ntCnt > 200) continue;
                            auto it = th32ThreadCounts.find(pid);
                            DWORD th32Cnt = (it != th32ThreadCounts.end()) ? it->second : 0;



                            if (ntCnt > th32Cnt + 3)
                                candidatePids.insert(pid);
                        }



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

    return findings;
}


static void EvaluateSuspiciousProcessHeuristics(DWORD pid, const std::wstring& rawExeName,
                                                const std::wstring& fullPath, bool signedOk,
                                                DetectionFilter::PathClass cls,
                                                std::vector<ScannerUI::EmulatorFinding>& out) {
    bool nameMatch = HasSuspiciousProcessToken(rawExeName);
    bool tempOrInstallerPath = cls == DetectionFilter::PathClass::TempOrInstaller;
    bool userProfilePath = cls == DetectionFilter::PathClass::UserProfile;

    if (nameMatch) {
        ScannerUI::EmulatorFinding f;
        f.process = WideToUtf8(rawExeName);
        f.type = kTagMapper;
        f.address = "PID:" + std::to_string(pid);
        f.detail = "name=blacklisted | signed=" + std::string(signedOk ? "yes" : "no") +
                   " | path=" + WideToUtf8(fullPath.empty() ? L"unknown" : fullPath);
        f.severity = "HIGH";
        out.push_back(f);
        return;
    }

    if (!signedOk && !fullPath.empty() && tempOrInstallerPath &&
        !IsKnownDeveloperToolProcess(rawExeName)) {
        double entropy = DetectionFilter::FileEntropySample(fullPath);
        bool packed = entropy >= DetectionFilter::kPackedEntropy;
        if (!packed)
            return;
        ScannerUI::EmulatorFinding f;
        f.process = WideToUtf8(rawExeName);
        f.type = kTagMapper;
        f.address = "PID:" + std::to_string(pid);
        f.detail = "unsigned packed process in temp/installer path | entropy=" +
                   DetectionFilter::EntropyToStr(entropy) +
                   " | path=" + WideToUtf8(fullPath);
        f.severity = "MEDIUM";
        out.push_back(f);
    } else if (!signedOk && !fullPath.empty() && userProfilePath &&
               !IsBenignUserLaunchPath(fullPath) &&
               !IsKnownDeveloperToolProcess(rawExeName)) {
        double entropy = DetectionFilter::FileEntropySample(fullPath);
        bool packed = entropy >= DetectionFilter::kPackedEntropy;
        if (!packed)
            return;
        ScannerUI::EmulatorFinding f;
        f.process = WideToUtf8(rawExeName);
        f.type = kTagMapper;
        f.address = "PID:" + std::to_string(pid);
        f.detail = "unsigned packed process in user profile path | entropy=" +
                   DetectionFilter::EntropyToStr(entropy) +
                   " | path=" + WideToUtf8(fullPath);
        f.severity = "MEDIUM";
        out.push_back(f);
    }
}
