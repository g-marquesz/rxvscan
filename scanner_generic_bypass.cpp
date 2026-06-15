#include "scanner_core.h"

static void AddGenericBypassFinding(std::vector<ScannerUI::GenericBypassFinding>& out,
                                    const std::string& type,
                                    const std::string& process,
                                    const std::string& target,
                                    const std::string& detail,
                                    const std::string& severity = "HIGH",
                                    const FILETIME* eventTime = nullptr) {
    if (out.size() >= 160)
        return;

    FILETIME nowFt = {};
    if (eventTime)
        nowFt = *eventTime;
    else
        GetSystemTimeAsFileTime(&nowFt);

    ScannerUI::GenericBypassFinding finding;
    FileTimeToLocalStrings(nowFt, finding.date, finding.time);
    finding.type = type;
    finding.process = process;
    finding.target = target;
    finding.detail = detail;
    finding.severity = severity;
    out.push_back(finding);
}

static bool HasSuspiciousProcessWriteAccess(DWORD access) {
    constexpr DWORD suspicious =
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME;
    return (access & suspicious) != 0 || (access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS;
}

static void CollectHdPlayerExternalHandles(std::vector<ScannerUI::GenericBypassFinding>& out) {
    std::vector<DWORD> targetPids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (ToUpperInvariant(entry.szExeFile) == L"HD-PLAYER.EXE")
                    targetPids.push_back(entry.th32ProcessID);
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    if (targetPids.empty())
        return;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto querySystem = ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    if (!querySystem)
        return;

    ULONG size = 1 << 20;
    std::vector<BYTE> buffer(size);
    ULONG needed = 0;
    LONG status = querySystem(64, buffer.data(), size, &needed);
    while (status == (LONG)0xC0000004L || status == (LONG)0xC0000023L) {
        size = needed > size ? needed + (1 << 16) : size * 2;
        buffer.assign(size, 0);
        status = querySystem(64, buffer.data(), size, &needed);
    }
    if (status < 0)
        return;

    auto* info = reinterpret_cast<SystemHandleInformationEx*>(buffer.data());
    std::unordered_set<std::string> seen;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles && out.size() < 160; ++i) {
        const auto& handle = info->Handles[i];
        DWORD sourcePid = (DWORD)handle.UniqueProcessId;
        if (sourcePid == GetCurrentProcessId() || !HasSuspiciousProcessWriteAccess(handle.GrantedAccess))
            continue;

        HANDLE sourceProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
        if (!sourceProcess)
            continue;

        HANDLE duplicated = nullptr;
        BOOL ok = DuplicateHandle(sourceProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(),
                                  &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS);
        CloseHandle(sourceProcess);
        if (!ok || !duplicated)
            continue;

        DWORD targetPid = GetProcessId(duplicated);
        CloseHandle(duplicated);
        if (targetPid == 0 || std::find(targetPids.begin(), targetPids.end(), targetPid) == targetPids.end())
            continue;
        if (targetPid == sourcePid)
            continue;



        std::wstring sourcePathW = ProcessFullPathW(sourcePid);
        if (!sourcePathW.empty()) {
            // Emulator-name match alone is not a trust signal — a malicious process can be
            // renamed to a known emulator binary (e.g. MEMU.EXE) from any folder. Only
            // exempt when the executable is also signed and in a trusted directory.
            DetectionFilter::PathClass sourceClass = DetectionFilter::ClassifyPath(sourcePathW);
            if (DetectionFilter::IsTrustedSignedCached(sourcePathW) &&
                DetectionFilter::IsTrustedDir(sourceClass))
                continue;
        }

        std::ostringstream key;
        key << sourcePid << ":" << targetPid << ":" << std::hex << handle.GrantedAccess;
        if (!seen.insert(key.str()).second)
            continue;

        std::ostringstream detail;
        detail << "handle externo no HD-Player detectado: pid="
               << sourcePid << " -> " << targetPid << ", access=0x"
               << std::hex << std::uppercase << handle.GrantedAccess;
        AddGenericBypassFinding(out, ScanTag::Handle, ProcessPathByPid(sourcePid), ProcessPathByPid(targetPid), detail.str(), "HIGH");
    }
}

// ─── helpers shared by new detection functions ────────────────────────────────

static std::wstring ExpandEnvPathW(const std::wstring& value) {
    if (value.empty())
        return value;
    wchar_t expanded[4096] = {};
    DWORD n = ExpandEnvironmentStringsW(value.c_str(), expanded, (DWORD)std::size(expanded));
    if (n == 0 || n >= std::size(expanded))
        return value;
    return expanded;
}

static bool IsBroadOrWritableAvExclusion(const std::wstring& rawPath) {
    std::wstring expanded = ExpandEnvPathW(rawPath);
    std::wstring up = ToUpperInvariant(expanded);
    if (up.empty())
        return false;

    if (up.find(L"*") != std::wstring::npos || up == L"C:\\" || up == L"C:" ||
        up == L"\\" || up == L"%SYSTEMDRIVE%\\" || up == L"%SYSTEMDRIVE%")
        return true;

    static const wchar_t* riskyTokens[] = {
        L"\\USERS\\", L"\\APPDATA\\", L"\\TEMP", L"\\TMP",
        L"\\DOWNLOADS", L"\\DESKTOP", L"\\PROGRAMDATA\\",
        L"\\PUBLIC\\", L"\\DOCUMENTS", nullptr
    };
    for (const wchar_t** token = riskyTokens; *token; ++token) {
        if (up.find(*token) != std::wstring::npos)
            return true;
    }

    DWORD attrs = GetFileAttributesW(expanded.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring RegValueToPathString(const wchar_t* valueName, DWORD type,
                                         const std::vector<BYTE>& data, DWORD dataSize) {
    if (valueName && valueName[0] != L'\0')
        return valueName;

    if ((type == REG_SZ || type == REG_EXPAND_SZ) && dataSize >= sizeof(wchar_t)) {
        const wchar_t* text = reinterpret_cast<const wchar_t*>(data.data());
        size_t chars = dataSize / sizeof(wchar_t);
        if (chars > 0 && text[chars - 1] == L'\0')
            --chars;
        return std::wstring(text, text + chars);
    }

    return {};
}

static void CollectDefenderPathExclusionsFromKey(
    std::vector<ScannerUI::GenericBypassFinding>& out,
    HKEY root,
    const wchar_t* subkey,
    const char* source,
    std::unordered_set<std::wstring>& seen) {

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return;

    for (DWORD i = 0; out.size() < ScanLimits::kMaxBypassFindings; ++i) {
        wchar_t valueName[2048] = {};
        DWORD nameLen = (DWORD)std::size(valueName);
        DWORD type = 0;
        DWORD dataSize = 4096;
        std::vector<BYTE> data(dataSize);
        LONG rc = RegEnumValueW(hKey, i, valueName, &nameLen, nullptr, &type, data.data(), &dataSize);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_MORE_DATA) {
            data.assign(dataSize + sizeof(wchar_t), 0);
            nameLen = (DWORD)std::size(valueName);
            rc = RegEnumValueW(hKey, i, valueName, &nameLen, nullptr, &type, data.data(), &dataSize);
        }
        if (rc != ERROR_SUCCESS)
            continue;

        std::wstring raw = RegValueToPathString(valueName, type, data, dataSize);
        if (raw.empty())
            continue;

        std::wstring expanded = ExpandEnvPathW(raw);
        std::wstring key = ToUpperInvariant(expanded.empty() ? raw : expanded);
        if (!seen.insert(key).second)
            continue;

        bool risky = IsBroadOrWritableAvExclusion(raw);
        std::string target = WideToUtf8(expanded.empty() ? raw : expanded);
        std::string detail = std::string("Microsoft Defender path exclusion detected")
            + " | source=" + source
            + " | path=" + target;
        if (expanded != raw)
            detail += " | raw=" + WideToUtf8(raw);

        AddGenericBypassFinding(out, ScanTag::AvExclusion, "Microsoft Defender",
                                target, detail, risky ? "HIGH" : "MEDIUM");
    }

    RegCloseKey(hKey);
}

static void CollectAntivirusExclusionFindings(std::vector<ScannerUI::GenericBypassFinding>& out) {
    std::unordered_set<std::wstring> seen;
    CollectDefenderPathExclusionsFromKey(
        out, HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        "local", seen);
    CollectDefenderPathExclusionsFromKey(
        out, HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        "policy", seen);
}

static bool DefenderActionLooksLikeRemoval(const std::wstring& action, int eventId) {
    std::wstring up = ToUpperInvariant(action);
    if (up.find(L"REMOVE") != std::wstring::npos ||
        up.find(L"REMOVED") != std::wstring::npos ||
        up.find(L"QUARANTINE") != std::wstring::npos ||
        up.find(L"CLEAN") != std::wstring::npos ||
        up.find(L"DELETE") != std::wstring::npos)
        return true;
    return eventId == 1117 && !action.empty();
}

static std::wstring FirstDefenderPathFromEvent(const std::wstring& xml) {
    std::wstring path = ExtractSysmonData(xml, L"Path");
    if (!path.empty())
        return path;
    path = ExtractSysmonData(xml, L"Resources");
    if (!path.empty())
        return path;
    return ExtractSysmonData(xml, L"Detection Source");
}

static void CollectAntivirusRemovalFindings(std::vector<ScannerUI::GenericBypassFinding>& out) {
    const wchar_t* channel = L"Microsoft-Windows-Windows Defender/Operational";
    const wchar_t* query =
        L"*[System[(EventID=1006 or EventID=1007 or EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119)]]";
    EVT_HANDLE result = EvtQuery(nullptr, channel, query,
                                 EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!result)
        return;

    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);
    std::unordered_set<std::string> seen;
    constexpr DWORD kBatch = 12;
    EVT_HANDLE handles[kBatch] = {};
    DWORD returned = 0;
    size_t scanned = 0;
    bool reachedBoot = false;

    while (!reachedBoot && scanned < 1200 && out.size() < ScanLimits::kMaxBypassFindings &&
           EvtNext(result, kBatch, handles, ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            ++scanned;
            std::wstring xml;
            if (RenderEventXml(handles[i], xml)) {
                FILETIME eventTime = {};
                std::wstring systemTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
                if (SysmonSystemTimeToFileTime(systemTime, eventTime)) {
                    if (FileTimeToU64(eventTime) < bootValue) {
                        reachedBoot = true;
                    } else {
                        std::wstring idText = ExtractXmlTag(xml, L"EventID");
                        int eventId = idText.empty() ? 0 : _wtoi(idText.c_str());
                        std::wstring path = FirstDefenderPathFromEvent(xml);
                        std::wstring action = ExtractSysmonData(xml, L"Action Name");
                        std::wstring threat = ExtractSysmonData(xml, L"Threat Name");
                        std::wstring process = ExtractSysmonData(xml, L"Process Name");

                        if (!path.empty() && DefenderActionLooksLikeRemoval(action, eventId)) {
                            std::string pathUtf8 = WideToUtf8(path);
                            std::string key = std::to_string(eventId) + "|" + pathUtf8 + "|" + WideToUtf8(action);
                            if (seen.insert(key).second) {
                                std::string detail = "Microsoft Defender removed or quarantined item"
                                    " | action=" + (action.empty() ? "-" : WideToUtf8(action)) +
                                    " | threat=" + (threat.empty() ? "-" : WideToUtf8(threat)) +
                                    " | path=" + pathUtf8;
                                if (!process.empty())
                                    detail += " | process=" + WideToUtf8(process);

                                AddGenericBypassFinding(out, ScanTag::AvRemoval, "Microsoft Defender",
                                                        pathUtf8, detail, "MEDIUM", &eventTime);
                            }
                        }
                    }
                }
            }
            EvtClose(handles[i]);
            handles[i] = nullptr;
        }
    }

    EvtClose(result);
}

static bool IsExecProtect(DWORD protect) {
    DWORD base = protect & 0xff;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static bool IsAddrInModules(uintptr_t addr, const std::vector<ModuleRange>& modules) {
    for (const auto& m : modules)
        if (addr >= m.begin && addr < m.end)
            return true;
    return false;
}

// Follow a JMP chain in remote process memory, returning the final destination address.
// Supports: E9 rel32, FF 25 [rip+disp32], 48 B8 imm64 FF E0, 68 imm32 C3.
static uintptr_t FollowJmpChain(HANDLE process, uintptr_t addr, int maxHops = 7) {
    for (int hop = 0; hop < maxHops; ++hop) {
        BYTE buf[16] = {};
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, (LPCVOID)addr, buf, sizeof(buf), &got) || got < 5)
            return addr;
        if (buf[0] == 0xE9) {  // JMP rel32
            INT32 rel = *reinterpret_cast<const INT32*>(buf + 1);
            addr = addr + 5 + (uintptr_t)(intptr_t)rel;
            continue;
        }
        if (buf[0] == 0xFF && buf[1] == 0x25 && got >= 6) {  // JMP [rip+disp32]
            INT32 disp = *reinterpret_cast<const INT32*>(buf + 2);
            uintptr_t slot = addr + 6 + (uintptr_t)(intptr_t)disp;
            uintptr_t target = 0;
            SIZE_T r = 0;
            if (!ReadProcessMemory(process, (LPCVOID)slot, &target, sizeof(target), &r) || r < 8)
                return addr;
            addr = target;
            continue;
        }
        if (buf[0] == 0x48 && buf[1] == 0xB8 && got >= 12 &&
            buf[10] == 0xFF && buf[11] == 0xE0) {  // MOV RAX,imm64; JMP RAX
            addr = *reinterpret_cast<const uintptr_t*>(buf + 2);
            continue;
        }
        if (buf[0] == 0x68 && got >= 6 && buf[5] == 0xC3) {  // PUSH imm32; RET
            DWORD imm = *reinterpret_cast<const DWORD*>(buf + 1);
            addr = (uintptr_t)imm;
            continue;
        }
        return addr;
    }
    return addr;
}

static bool IsJmpHookPattern(const BYTE* b, size_t len) {
    if (len < 5) return false;
    if (b[0] == 0xE9) return true;
    if (b[0] == 0xFF && b[1] == 0x25 && len >= 6) return true;
    if (b[0] == 0x48 && b[1] == 0xB8 && len >= 12 && b[10] == 0xFF && b[11] == 0xE0) return true;
    if (b[0] == 0x68 && len >= 6 && b[5] == 0xC3) return true;
    return false;
}

// Content-based check: does this remote module export any graphics API symbol?
// Reads the first 4096 bytes of the module and parses its export directory.
// NO name/path check — cheats can use any name or path.
static bool IsGraphicsHookCandidate(HANDLE process, uintptr_t moduleBase) {
    BYTE header[4096] = {};
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, (LPCVOID)moduleBase, header, sizeof(header), &got) || got < 0x40)
        return false;
    return DetectionFilter::ExportsGraphicsSymbol(header, got, moduleBase);
}

// ─── Graphics hook destination collector ─────────────────────────────────────
// Scans graphics API exports in all modules of a single process for JMP hooks.
// Returns the AllocationBase of every hook destination that lands outside a
// trusted signed module. Used to cross-reference injected threads/memory so that
// THREAD_INJECT and MEMORY_INJECT findings can be tagged as confirmed chams.
std::unordered_set<uintptr_t> CollectGfxHookDestBases(HANDLE process,
                                                       const std::vector<ModuleRange>& modules) {
    std::unordered_set<uintptr_t> destBases;

    static const char* kGfxFuncs[] = {
        "wglSwapBuffers", "glDrawElements", "glDrawArrays", "glDepthFunc",
        "eglSwapBuffers", "SwapBuffers", "D3D11CreateDevice",
        "D3D11CreateDeviceAndSwapChain", "CreateDXGIFactory",
        "CreateDXGIFactory1", "CreateDXGIFactory2",
        "vkQueuePresentKHR", "wglGetProcAddress", "glGetProcAddress",
        nullptr
    };

    for (const auto& module : modules) {
        if (module.path.empty()) continue;
        if (!IsGraphicsHookCandidate(process, module.begin)) continue;

        BYTE hdr[4096] = {};
        SIZE_T hg = 0;
        if (!ReadProcessMemory(process, (LPCVOID)module.begin, hdr, sizeof(hdr), &hg) || hg < 0x40)
            continue;
        LONG peOff = *reinterpret_cast<const LONG*>(hdr + 0x3C);
        if (peOff <= 0 || (SIZE_T)peOff + 24 > hg) continue;

        WORD machine  = *reinterpret_cast<const WORD*>(hdr + peOff + 4);
        bool is64     = (machine == 0x8664);
        WORD optSize  = *reinterpret_cast<const WORD*>(hdr + peOff + 20);
        DWORD optOff  = (DWORD)peOff + 24;
        DWORD expDirRva = 0;
        if (is64 && optOff + 112 <= hg)
            expDirRva = *reinterpret_cast<const DWORD*>(hdr + optOff + 96);
        else if (!is64 && optOff + 96 <= hg)
            expDirRva = *reinterpret_cast<const DWORD*>(hdr + optOff + 80);
        if (expDirRva == 0) continue;

        BYTE expBuf[4096] = {};
        SIZE_T eg = 0;
        uintptr_t expAddr = module.begin + expDirRva;
        if (!ReadProcessMemory(process, (LPCVOID)expAddr, expBuf, sizeof(expBuf), &eg) || eg < 40)
            continue;

        DWORD numFuncs = *reinterpret_cast<const DWORD*>(expBuf + 20);
        DWORD numNames = *reinterpret_cast<const DWORD*>(expBuf + 24);
        DWORD addrRvaBase = *reinterpret_cast<const DWORD*>(expBuf + 28);
        DWORD nameRvaBase = *reinterpret_cast<const DWORD*>(expBuf + 32);
        DWORD ordRvaBase  = *reinterpret_cast<const DWORD*>(expBuf + 36);
        if (numNames == 0 || numNames > 65536 || numFuncs > 65536) continue;

        std::vector<DWORD> funcRvas(numFuncs);
        std::vector<DWORD> nameRvas(numNames);
        std::vector<WORD>  ordinals(numNames);
        SIZE_T r = 0;
        ReadProcessMemory(process, (LPCVOID)(module.begin + addrRvaBase),
                          funcRvas.data(), funcRvas.size() * 4, &r);
        ReadProcessMemory(process, (LPCVOID)(module.begin + nameRvaBase),
                          nameRvas.data(), nameRvas.size() * 4, &r);
        ReadProcessMemory(process, (LPCVOID)(module.begin + ordRvaBase),
                          ordinals.data(), ordinals.size() * 2, &r);

        for (DWORD ni = 0; ni < numNames; ++ni) {
            BYTE nameBuf[128] = {};
            SIZE_T nr = 0;
            ReadProcessMemory(process, (LPCVOID)(module.begin + nameRvas[ni]),
                              nameBuf, sizeof(nameBuf) - 1, &nr);
            if (nr == 0) continue;
            const char* fnName = reinterpret_cast<const char*>(nameBuf);

            bool isGfxFunc = false;
            for (int k = 0; kGfxFuncs[k]; ++k)
                if (strcmp(fnName, kGfxFuncs[k]) == 0) { isGfxFunc = true; break; }
            if (!isGfxFunc) continue;

            WORD ord = (ni < ordinals.size()) ? ordinals[ni] : (WORD)ni;
            if (ord >= funcRvas.size()) continue;
            DWORD funcRva = funcRvas[ord];
            if (funcRva == 0) continue;

            uintptr_t funcAddr = module.begin + funcRva;
            BYTE prolog[16] = {};
            SIZE_T pg = 0;
            if (!ReadProcessMemory(process, (LPCVOID)funcAddr, prolog, sizeof(prolog), &pg) || pg < 5)
                continue;
            if (!IsJmpHookPattern(prolog, pg)) continue;

            uintptr_t chainEnd = FollowJmpChain(process, funcAddr);

            // Ignore destinations that land inside a trusted signed module
            for (const auto& m : modules) {
                if (chainEnd >= m.begin && chainEnd < m.end) {
                    if (DetectionFilter::IsTrustedSignedCached(m.path)) {
                        BYTE dh[4096] = {}; SIZE_T dg = 0;
                        ReadProcessMemory(process, (LPCVOID)m.begin, dh, sizeof(dh), &dg);
                        if (DetectionFilter::ExportsGraphicsSymbol(dh, dg, m.begin))
                            goto nextFunc; // legitimate overlay layering
                    }
                    break;
                }
            }
            {
                MEMORY_BASIC_INFORMATION mbi2 = {};
                if (VirtualQueryEx(process, (LPCVOID)chainEnd, &mbi2, sizeof(mbi2)) == sizeof(mbi2)) {
                    uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi2.AllocationBase);
                    if (allocBase) destBases.insert(allocBase);
                }
            }
            nextFunc:;
        }
    }
    return destBases;
}

// ─── Full content-based graphics inline hook scanner ─────────────────────────
// Replaces the old name-based GfxHook detection. Checks EVERY module in every
// emulator process; no module is skipped based on its name or path.
static void CollectGraphicsHookFindings(std::vector<ScannerUI::GenericBypassFinding>& out) {
    std::vector<DWORD> pids = FindEmulatorProcesses();
    size_t gfxCount = 0;

    for (DWORD pid : pids) {
        if (gfxCount >= ScanLimits::kMaxGfxHookFindings) break;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) continue;

        std::string procPath = ProcessPathByPid(pid);
        std::vector<ModuleRange> modules;
        if (!CollectProcessModules(process, modules)) { CloseHandle(process); continue; }

        for (const auto& module : modules) {
            if (gfxCount >= ScanLimits::kMaxGfxHookFindings) break;
            if (module.path.empty()) continue;
            if (!IsGraphicsHookCandidate(process, module.begin)) continue;

            std::wstring modName = BaseNameFromPath(module.path);
            bool modSigned = DetectionFilter::IsTrustedSignedCached(module.path);

            // Re-read header to parse export directory in-memory
            BYTE hdr[4096] = {};
            SIZE_T hg = 0;
            if (!ReadProcessMemory(process, (LPCVOID)module.begin, hdr, sizeof(hdr), &hg) || hg < 0x40)
                continue;
            LONG peOff = *reinterpret_cast<const LONG*>(hdr + 0x3C);
            if (peOff <= 0 || (SIZE_T)peOff + 24 > hg) continue;

            WORD machine = *reinterpret_cast<const WORD*>(hdr + peOff + 4);
            bool is64 = (machine == 0x8664);
            WORD optSize = *reinterpret_cast<const WORD*>(hdr + peOff + 20);
            DWORD optOff = (DWORD)peOff + 24;
            DWORD expDirRva = 0;
            if (is64 && optOff + 112 <= hg)
                expDirRva = *reinterpret_cast<const DWORD*>(hdr + optOff + 96);
            else if (!is64 && optOff + 96 <= hg)
                expDirRva = *reinterpret_cast<const DWORD*>(hdr + optOff + 80);
            if (expDirRva == 0) continue;

            // Read export directory from remote memory
            BYTE expBuf[4096] = {};
            SIZE_T eg = 0;
            uintptr_t expAddr = module.begin + expDirRva;
            if (!ReadProcessMemory(process, (LPCVOID)expAddr, expBuf, sizeof(expBuf), &eg) || eg < 40)
                continue;

            DWORD numFuncs = *reinterpret_cast<const DWORD*>(expBuf + 20);
            DWORD numNames = *reinterpret_cast<const DWORD*>(expBuf + 24);
            DWORD addrRvaBase = *reinterpret_cast<const DWORD*>(expBuf + 28);
            DWORD nameRvaBase = *reinterpret_cast<const DWORD*>(expBuf + 32);
            DWORD ordRvaBase  = *reinterpret_cast<const DWORD*>(expBuf + 36);
            if (numNames == 0 || numNames > 65536 || numFuncs > 65536) continue;

            std::vector<DWORD> funcRvas(numFuncs);
            std::vector<DWORD> nameRvas(numNames);
            std::vector<WORD>  ordinals(numNames);
            SIZE_T r = 0;
            ReadProcessMemory(process, (LPCVOID)(module.begin + addrRvaBase),
                              funcRvas.data(), funcRvas.size() * 4, &r);
            ReadProcessMemory(process, (LPCVOID)(module.begin + nameRvaBase),
                              nameRvas.data(), nameRvas.size() * 4, &r);
            ReadProcessMemory(process, (LPCVOID)(module.begin + ordRvaBase),
                              ordinals.data(), ordinals.size() * 2, &r);

            static const char* kGfxFuncs[] = {
                "wglSwapBuffers", "glDrawElements", "glDrawArrays", "glDepthFunc",
                "eglSwapBuffers", "SwapBuffers", "D3D11CreateDevice",
                "D3D11CreateDeviceAndSwapChain", "CreateDXGIFactory",
                "CreateDXGIFactory1", "CreateDXGIFactory2",
                "vkQueuePresentKHR", "wglGetProcAddress", "glGetProcAddress",
                nullptr
            };

            for (DWORD ni = 0; ni < numNames && gfxCount < ScanLimits::kMaxGfxHookFindings; ++ni) {
                BYTE nameBuf[128] = {};
                SIZE_T nr = 0;
                ReadProcessMemory(process, (LPCVOID)(module.begin + nameRvas[ni]),
                                  nameBuf, sizeof(nameBuf) - 1, &nr);
                if (nr == 0) continue;
                const char* fnName = reinterpret_cast<const char*>(nameBuf);

                bool isGfxFunc = false;
                for (int k = 0; kGfxFuncs[k]; ++k)
                    if (strcmp(fnName, kGfxFuncs[k]) == 0) { isGfxFunc = true; break; }
                if (!isGfxFunc) continue;

                WORD ord = (ni < ordinals.size()) ? ordinals[ni] : (WORD)ni;
                if (ord >= funcRvas.size()) continue;
                DWORD funcRva = funcRvas[ord];
                if (funcRva == 0) continue;

                uintptr_t funcAddr = module.begin + funcRva;
                BYTE prolog[16] = {};
                SIZE_T pg = 0;
                if (!ReadProcessMemory(process, (LPCVOID)funcAddr, prolog, sizeof(prolog), &pg) || pg < 5)
                    continue;
                if (!IsJmpHookPattern(prolog, pg)) continue;

                uintptr_t chainEnd = FollowJmpChain(process, funcAddr);

                // Allow chain that ends in a signed module which itself exports graphics symbols
                bool legitimateLayering = false;
                for (const auto& m : modules) {
                    if (chainEnd >= m.begin && chainEnd < m.end) {
                        if (m.path == module.path) { legitimateLayering = true; break; }
                        if (DetectionFilter::IsTrustedSignedCached(m.path)) {
                            BYTE dh[4096] = {}; SIZE_T dg = 0;
                            ReadProcessMemory(process, (LPCVOID)m.begin, dh, sizeof(dh), &dg);
                            if (DetectionFilter::ExportsGraphicsSymbol(dh, dg, m.begin))
                                legitimateLayering = true;
                        }
                        break;
                    }
                }
                if (legitimateLayering) continue;

                MEMORY_BASIC_INFORMATION mbi = {};
                bool shellcode = false;
                if (VirtualQueryEx(process, (LPCVOID)chainEnd, &mbi, sizeof(mbi)) == sizeof(mbi))
                    shellcode = (mbi.Type == MEM_PRIVATE) && !IsAddrInModules(chainEnd, modules);

                char funcBuf[32], chainBuf[32];
                snprintf(funcBuf,  sizeof(funcBuf),  "0x%llX", (unsigned long long)funcAddr);
                snprintf(chainBuf, sizeof(chainBuf), "0x%llX", (unsigned long long)chainEnd);

                std::string detail = "hook em funcao grafica: " + std::string(fnName) +
                                     " | modulo=" + WideToUtf8(modName) +
                                     " | signed=" + (modSigned ? "yes" : "no") +
                                     " | func=" + funcBuf + " -> chain_end=" + chainBuf +
                                     (shellcode ? " | SHELLCODE em memoria anonima" : " | redireciona fora do modulo");
                // Diagnostic annotation (informational only — not a trust signal)
                if (DetectionFilter::IsNamedLikeGraphicsRuntime(modName))
                    detail += " | nota: nome similar a runtime grafico";
                else if (DetectionFilter::IsNamedLikeOverlay(modName))
                    detail += " | nota: nome similar a overlay";

                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(module.path), detail, "HIGH");
                ++gfxCount;
            }
        }
        CloseHandle(process);
    }
}

// ─── NTDLL syscall stub integrity ────────────────────────────────────────────
// Reads ntdll.dll from disk and compares first 5 bytes of each Nt*/Zw* export
// against the in-memory version. Any mismatch on a valid stub = inline hook.
static void ScanNtdllStubIntegrity(std::vector<ScannerUI::GenericBypassFinding>& out) {
    wchar_t sysDir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sysDir, (UINT)std::size(sysDir))) return;
    std::wstring ntdllPath = std::wstring(sysDir) + L"\\ntdll.dll";

    HANDLE hFile = CreateFileW(ntdllPath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    constexpr DWORD kMaxRead = 4 * 1024 * 1024;
    std::vector<BYTE> disk(kMaxRead);
    DWORD rd = 0;
    ReadFile(hFile, disk.data(), kMaxRead, &rd, nullptr);
    CloseHandle(hFile);
    if (rd < 0x1000 || disk[0] != 'M' || disk[1] != 'Z') return;

    LONG peOff = *reinterpret_cast<const LONG*>(disk.data() + 0x3C);
    if (peOff <= 0 || (DWORD)peOff + 24 > rd) return;

    WORD machine = *reinterpret_cast<const WORD*>(disk.data() + peOff + 4);
    bool is64 = (machine == 0x8664);
    WORD optSize = *reinterpret_cast<const WORD*>(disk.data() + peOff + 20);
    DWORD optOff = (DWORD)peOff + 24;
    DWORD expDirRva = 0;
    if (is64 && optOff + 112 <= rd)
        expDirRva = *reinterpret_cast<const DWORD*>(disk.data() + optOff + 96);
    else if (!is64 && optOff + 96 <= rd)
        expDirRva = *reinterpret_cast<const DWORD*>(disk.data() + optOff + 80);
    if (expDirRva == 0) return;

    WORD numSec = *reinterpret_cast<const WORD*>(disk.data() + peOff + 6);
    if (numSec > 96) numSec = 96;
    DWORD secOff = (DWORD)peOff + 24 + optSize;

    auto rvaToOff = [&](DWORD rva) -> DWORD {
        for (WORD si = 0; si < numSec; ++si) {
            DWORD sh = secOff + si * 40;
            if (sh + 40 > rd) break;
            DWORD vAddr  = *reinterpret_cast<const DWORD*>(disk.data() + sh + 12);
            DWORD vSize  = *reinterpret_cast<const DWORD*>(disk.data() + sh + 8);
            DWORD rawOff = *reinterpret_cast<const DWORD*>(disk.data() + sh + 20);
            if (rva >= vAddr && rva < vAddr + vSize) {
                DWORD off = rawOff + (rva - vAddr);
                if (off < rd) return off;
            }
        }
        return 0;
    };

    DWORD expOff = rvaToOff(expDirRva);
    if (expOff + 40 > rd) return;

    DWORD numNames = *reinterpret_cast<const DWORD*>(disk.data() + expOff + 24);
    DWORD addrRva  = *reinterpret_cast<const DWORD*>(disk.data() + expOff + 28);
    DWORD nameRva  = *reinterpret_cast<const DWORD*>(disk.data() + expOff + 32);
    DWORD ordRva   = *reinterpret_cast<const DWORD*>(disk.data() + expOff + 36);
    if (numNames == 0 || numNames > 65536) return;

    DWORD addrOff = rvaToOff(addrRva);
    DWORD nameOff = rvaToOff(nameRva);
    DWORD ordOff  = rvaToOff(ordRva);
    if (!addrOff || !nameOff || !ordOff) return;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;
    uintptr_t inMemBase = (uintptr_t)hNtdll;

    int hookCount = 0;
    for (DWORD ni = 0; ni < numNames && hookCount < (int)ScanLimits::kMaxSyscallDetections; ++ni) {
        DWORD rnOff = nameOff + ni * 4;
        if (rnOff + 4 > rd) break;
        DWORD rnRva = *reinterpret_cast<const DWORD*>(disk.data() + rnOff);
        DWORD fnNameOff = rvaToOff(rnRva);
        if (!fnNameOff || fnNameOff >= rd) continue;

        const char* fnName = reinterpret_cast<const char*>(disk.data() + fnNameOff);
        if ((fnName[0] != 'N' || fnName[1] != 't') &&
            (fnName[0] != 'Z' || fnName[1] != 'w')) continue;

        DWORD ordEntOff = ordOff + ni * 2;
        if (ordEntOff + 2 > rd) continue;
        WORD ord = *reinterpret_cast<const WORD*>(disk.data() + ordEntOff);
        DWORD funcRvaOff = addrOff + ord * 4;
        if (funcRvaOff + 4 > rd) continue;
        DWORD funcRva = *reinterpret_cast<const DWORD*>(disk.data() + funcRvaOff);
        if (funcRva == 0) continue;

        DWORD diskFuncOff = rvaToOff(funcRva);
        if (!diskFuncOff || diskFuncOff + 16 > rd) continue;

        const BYTE* diskBytes = disk.data() + diskFuncOff;
        if (!DetectionFilter::IsValidSyscallStub(diskBytes, 16)) continue;

        uintptr_t inMemFunc = inMemBase + funcRva;
        BYTE memBytes[16] = {};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)inMemFunc, memBytes, 16, &got) || got < 5)
            continue;
        if (memcmp(diskBytes, memBytes, 5) == 0) continue;

        // Mismatch detected — follow the JMP chain to identify the hook destination.
        // AV/EDR products (Windows Defender, etc.) legitimately hook NTDLL stubs and
        // their hooks land in signed modules. Only report if the destination is in
        // anonymous memory or an unsigned DLL (characteristic of cheat hooks).
        uintptr_t hookTarget = inMemFunc;
        for (int hop = 0; hop < 5; ++hop) {
            BYTE hbuf[16] = {}; SIZE_T hr = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hookTarget, hbuf, sizeof(hbuf), &hr) || hr < 5) break;
            if (hbuf[0] == 0xE9) {
                INT32 rel = *reinterpret_cast<const INT32*>(hbuf+1);
                hookTarget = hookTarget + 5 + (uintptr_t)(intptr_t)rel; continue;
            }
            if (hbuf[0] == 0xFF && hbuf[1] == 0x25 && hr >= 6) {
                INT32 disp = *reinterpret_cast<const INT32*>(hbuf+2);
                uintptr_t slot = hookTarget + 6 + (uintptr_t)(intptr_t)disp;
                uintptr_t tgt = 0; SIZE_T sr2 = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slot, &tgt, sizeof(tgt), &sr2)) break;
                hookTarget = tgt; continue;
            }
            if (hbuf[0] == 0x48 && hbuf[1] == 0xB8 && hr >= 12 && hbuf[10] == 0xFF && hbuf[11] == 0xE0) {
                hookTarget = *reinterpret_cast<const uintptr_t*>(hbuf+2); continue;
            }
            break;
        }

        // Check if hook destination is inside a loaded, signed module (AV/EDR hook)
        {
            HMODULE lmods[512] = {}; DWORD lneeded = 0;
            if (EnumProcessModulesEx(GetCurrentProcess(), lmods, sizeof(lmods), &lneeded, LIST_MODULES_ALL)) {
                for (DWORD mi = 0; mi < lneeded / sizeof(HMODULE); ++mi) {
                    MODULEINFO minfo = {};
                    if (!GetModuleInformation(GetCurrentProcess(), lmods[mi], &minfo, sizeof(minfo))) continue;
                    uintptr_t modBase = (uintptr_t)minfo.lpBaseOfDll;
                    if (hookTarget < modBase || hookTarget >= modBase + minfo.SizeOfImage) continue;
                    wchar_t modPath[MAX_PATH] = {};
                    GetModuleFileNameExW(GetCurrentProcess(), lmods[mi], modPath, (DWORD)std::size(modPath));
                    if (DetectionFilter::IsTrustedSignedCached(modPath))
                        goto skip_ntdll_hook; // AV/EDR hook into signed module — not a cheat
                    break; // unsigned module at destination — fall through to report
                }
            }
        }

        {
            char diskHex[20] = {}, memHex[20] = {};
            for (int b = 0; b < 5; ++b) {
                snprintf(diskHex + b*3, 4, "%02X ", diskBytes[b]);
                snprintf(memHex  + b*3, 4, "%02X ", memBytes[b]);
            }
            std::ostringstream rvaStr;
            rvaStr << std::hex << std::uppercase << funcRva;
            char tgtBuf[32];
            snprintf(tgtBuf, sizeof(tgtBuf), "0x%llX", (unsigned long long)hookTarget);

            std::string detail = "ntdll hook: " + std::string(fnName) +
                                 " | disk=[" + diskHex + "] mem=[" + memHex + "]" +
                                 " | rva=0x" + rvaStr.str() +
                                 " | chain_end=" + tgtBuf;
            AddGenericBypassFinding(out, ScanTag::ThreadProtect, "ntdll.dll", std::string(fnName), detail, "HIGH");
            ++hookCount;
        }
        skip_ntdll_hook:;
    }
}

// ─── IAT hook detection ───────────────────────────────────────────────────────
// Scans critical function IAT entries in emulator processes. Flags any entry
// pointing outside all known modules (i.e. into anonymous memory).
static void ScanIatHooks(std::vector<ScannerUI::GenericBypassFinding>& out) {
    static const char* kCritical[] = {
        "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx",
        "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory",
        "ReadProcessMemory", "LoadLibraryA", "LoadLibraryW",
        "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtOpenProcess",
        nullptr
    };

    std::vector<DWORD> pids = FindEmulatorProcesses();
    std::unordered_set<std::string> seenIat;

    for (DWORD pid : pids) {
        if (out.size() >= ScanLimits::kMaxBypassFindings) break;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) continue;

        std::string procPath = ProcessPathByPid(pid);
        std::vector<ModuleRange> modules;
        if (!CollectProcessModules(process, modules)) { CloseHandle(process); continue; }

        int modChecked = 0;
        for (const auto& module : modules) {
            if (modChecked >= 10 || out.size() >= ScanLimits::kMaxBypassFindings) break;

            bool isMainExe = (modChecked == 0);
            bool isGfxMod  = false;
            if (!isMainExe) {
                BYTE hdr[4096] = {}; SIZE_T g = 0;
                ReadProcessMemory(process, (LPCVOID)module.begin, hdr, sizeof(hdr), &g);
                isGfxMod = DetectionFilter::ExportsGraphicsSymbol(hdr, g, module.begin);
            }
            ++modChecked;
            if (!isMainExe && !isGfxMod) continue;

            BYTE hdrBuf[4096] = {}; SIZE_T hg = 0;
            if (!ReadProcessMemory(process, (LPCVOID)module.begin, hdrBuf, sizeof(hdrBuf), &hg) || hg < 0x40)
                continue;
            if (hdrBuf[0] != 'M' || hdrBuf[1] != 'Z') continue;
            LONG peOff = *reinterpret_cast<const LONG*>(hdrBuf + 0x3C);
            if (peOff <= 0 || (SIZE_T)peOff + 24 > hg) continue;

            WORD machine = *reinterpret_cast<const WORD*>(hdrBuf + peOff + 4);
            bool is64 = (machine == 0x8664);
            DWORD optOff = (DWORD)peOff + 24;

            DWORD impRva = 0;
            if (is64 && optOff + 128 <= hg)
                impRva = *reinterpret_cast<const DWORD*>(hdrBuf + optOff + 104);
            else if (!is64 && optOff + 112 <= hg)
                impRva = *reinterpret_cast<const DWORD*>(hdrBuf + optOff + 88);
            if (impRva == 0) continue;

            BYTE impBuf[8192] = {}; SIZE_T ir = 0;
            ReadProcessMemory(process, (LPCVOID)(module.begin + impRva), impBuf, sizeof(impBuf), &ir);

            for (size_t descOff = 0; descOff + 20 <= ir; descOff += 20) {
                DWORD origFirstThunk = *reinterpret_cast<const DWORD*>(impBuf + descOff + 0);
                DWORD firstThunk     = *reinterpret_cast<const DWORD*>(impBuf + descOff + 16);
                if (firstThunk == 0 && origFirstThunk == 0) break;

                uintptr_t iatBase = module.begin + firstThunk;
                uintptr_t intBase = module.begin + origFirstThunk;
                size_t entrySize = is64 ? 8 : 4;

                for (size_t ei = 0; ei < 512; ++ei) {
                    BYTE intBuf[8] = {}; SIZE_T itr = 0;
                    ReadProcessMemory(process, (LPCVOID)(intBase + ei * entrySize), intBuf, entrySize, &itr);
                    if (itr < entrySize) break;

                    uint64_t intVal = is64 ? *reinterpret_cast<const uint64_t*>(intBuf)
                                           : *reinterpret_cast<const uint32_t*>(intBuf);
                    if (intVal == 0) break;
                    if (is64  && (intVal & (1ULL << 63))) continue;
                    if (!is64 && (intVal & (1ULL << 31))) continue;

                    DWORD hintNameRva = (DWORD)(intVal & 0x7FFFFFFF);
                    BYTE nameBuf[128] = {}; SIZE_T nr = 0;
                    ReadProcessMemory(process, (LPCVOID)(module.begin + hintNameRva + 2),
                                      nameBuf, sizeof(nameBuf) - 1, &nr);
                    if (nr == 0) continue;
                    const char* importName = reinterpret_cast<const char*>(nameBuf);

                    bool isCritical = false;
                    for (int k = 0; kCritical[k]; ++k)
                        if (strcmp(importName, kCritical[k]) == 0) { isCritical = true; break; }
                    if (!isCritical) continue;

                    BYTE iatBuf[8] = {}; SIZE_T iatr = 0;
                    ReadProcessMemory(process, (LPCVOID)(iatBase + ei * entrySize), iatBuf, entrySize, &iatr);
                    if (iatr < entrySize) continue;

                    uintptr_t resolved = is64 ? *reinterpret_cast<const uint64_t*>(iatBuf)
                                              : *reinterpret_cast<const uint32_t*>(iatBuf);
                    if (resolved == 0 || IsAddrInModules(resolved, modules)) continue;

                    std::string key = std::to_string(pid) + ":" + std::to_string(module.begin) + ":" + std::to_string(ei);
                    if (!seenIat.insert(key).second) continue;

                    char addrBuf[32];
                    snprintf(addrBuf, sizeof(addrBuf), "0x%llX", (unsigned long long)resolved);
                    std::string detail = "IAT hook: " + std::string(importName) +
                                         " em " + WideToUtf8(BaseNameFromPath(module.path)) +
                                         " -> addr anonimo " + addrBuf;
                    AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                           WideToUtf8(module.path), detail, "HIGH");
                }
            }
        }
        CloseHandle(process);
    }
}

// ─── Vulkan implicit/explicit layer detection ─────────────────────────────────
// Checks registry paths for Vulkan layers with unsigned or suspicious DLLs.
// Unsigned Vulkan layers are a common chams injection vector.
static void ScanVulkanLayers(std::vector<ScannerUI::GenericBypassFinding>& out) {
    struct RegSpec { HKEY root; const wchar_t* path; bool isUser; };
    static const RegSpec kSpecs[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers",             false },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Khronos\\Vulkan\\ExplicitLayers",             false },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers",             true  },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Khronos\\Vulkan\\ImplicitLayers",false },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Khronos\\Vulkan\\ExplicitLayers",false },
    };

    for (const auto& spec : kSpecs) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(spec.root, spec.path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        DWORD idx = 0;
        wchar_t valueName[MAX_PATH * 2] = {};
        DWORD nameLen = (DWORD)std::size(valueName);
        DWORD valType = 0, valData = 0, dataLen = sizeof(valData);

        while (RegEnumValueW(hKey, idx++, valueName, &nameLen, nullptr,
                             &valType, (LPBYTE)&valData, &dataLen) == ERROR_SUCCESS) {
            nameLen = (DWORD)std::size(valueName);
            dataLen = sizeof(valData);

            std::wstring manifestPath = valueName;
            HANDLE hMf = CreateFileW(manifestPath.c_str(), GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
            if (hMf == INVALID_HANDLE_VALUE) continue;
            char jsonBuf[4096] = {}; DWORD jr = 0;
            ReadFile(hMf, jsonBuf, sizeof(jsonBuf) - 1, &jr, nullptr);
            CloseHandle(hMf);
            if (jr == 0) continue;

            const char* p = strstr(jsonBuf, "\"library_path\"");
            if (!p) continue;
            p += 14;
            while (*p == ' ' || *p == ':' || *p == '\t') ++p;
            if (*p != '"') continue; ++p;
            const char* end = strchr(p, '"');
            if (!end || end == p) continue;

            std::string libA(p, (size_t)(end - p));
            std::wstring libW(libA.begin(), libA.end());
            if (libA[0] != '/' && libA[0] != '\\' && (libA.size() < 2 || libA[1] != ':')) {
                std::wstring dir = manifestPath;
                size_t sl = dir.find_last_of(L"\\/");
                if (sl != std::wstring::npos) dir = dir.substr(0, sl + 1);
                libW = dir + libW;
            }

            bool isSigned = DetectionFilter::IsTrustedSignedCached(libW);
            DetectionFilter::PathClass cls = DetectionFilter::ClassifyPath(libW);
            // For signed layers: only Temp paths are truly suspicious.
            // HKCU, ProgramData, and ProgramFiles are all used legitimately by
            // OBS Studio, NVIDIA GeForce Experience, and other capture software.
            bool suspPathForSigned = cls == DetectionFilter::PathClass::TempOrInstaller;

            std::string severity;
            if (!isSigned)
                severity = "HIGH";       // unsigned layer = always report
            else if (suspPathForSigned)
                severity = "MEDIUM";     // signed but in Temp = unusual
            else
                severity = "FLAG";       // signed + normal path (incl. HKCU) → skip

            if (severity == "FLAG") continue;

            std::string detail = "Vulkan layer suspeito: " + WideToUtf8(manifestPath) +
                                  " | dll=" + WideToUtf8(libW) +
                                  " | signed=" + (isSigned ? "yes" : "no") +
                                  " | hkcu=" + (spec.isUser ? "yes" : "no");
            AddGenericBypassFinding(out, ScanTag::GfxHook, "-", WideToUtf8(libW), detail, severity);
        }
        RegCloseKey(hKey);
    }
}

// ─── D3D11/DXGI VTable integrity ─────────────────────────────────────────────
// Scans the .rdata section of graphics modules in emulator processes for
// pointer-sized values that redirect outside the module into executable memory.
// Identifies VTable overwrites without needing to instantiate COM objects.
static void ScanDxgiVtableIntegrity(std::vector<ScannerUI::GenericBypassFinding>& out) {
    std::vector<DWORD> pids = FindEmulatorProcesses();
    size_t vtCount = 0;

    for (DWORD pid : pids) {
        if (vtCount >= ScanLimits::kMaxGfxHookFindings) break;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) continue;

        std::string procPath = ProcessPathByPid(pid);
        std::vector<ModuleRange> modules;
        if (!CollectProcessModules(process, modules)) { CloseHandle(process); continue; }

        for (const auto& module : modules) {
            if (vtCount >= ScanLimits::kMaxGfxHookFindings) break;
            if (module.path.empty()) continue;

            BYTE hdr[4096] = {}; SIZE_T hg = 0;
            ReadProcessMemory(process, (LPCVOID)module.begin, hdr, sizeof(hdr), &hg);
            if (!DetectionFilter::ExportsGraphicsSymbol(hdr, hg, module.begin)) continue;
            if (hg < 0x40 || hdr[0] != 'M' || hdr[1] != 'Z') continue;

            LONG peOff = *reinterpret_cast<const LONG*>(hdr + 0x3C);
            if (peOff <= 0 || (SIZE_T)peOff + 24 > hg) continue;
            WORD numSec  = *reinterpret_cast<const WORD*>(hdr + peOff + 6);
            if (numSec > 96) numSec = 96;
            WORD optSize = *reinterpret_cast<const WORD*>(hdr + peOff + 20);
            WORD machine = *reinterpret_cast<const WORD*>(hdr + peOff + 4);
            bool is64 = (machine == 0x8664);
            DWORD secOff = (DWORD)peOff + 24 + optSize;

            for (WORD si = 0; si < numSec && vtCount < ScanLimits::kMaxGfxHookFindings; ++si) {
                DWORD sHdr = secOff + si * 40;
                if (sHdr + 40 > hg) break;
                char secName[9] = {}; memcpy(secName, hdr + sHdr, 8);
                if (strncmp(secName, ".rdata", 6) != 0) continue;

                DWORD vAddr = *reinterpret_cast<const DWORD*>(hdr + sHdr + 12);
                DWORD vSize = *reinterpret_cast<const DWORD*>(hdr + sHdr + 8);
                if (vSize > 2 * 1024 * 1024) vSize = 2 * 1024 * 1024;

                uintptr_t secBase = module.begin + vAddr;
                constexpr size_t kChunk = 65536;
                std::vector<BYTE> chunk(kChunk);

                for (DWORD off = 0; off < vSize && vtCount < ScanLimits::kMaxGfxHookFindings; off += (DWORD)kChunk) {
                    size_t toRead = (vSize - off) < kChunk ? (size_t)(vSize - off) : kChunk;
                    SIZE_T rd2 = 0;
                    if (!ReadProcessMemory(process, (LPCVOID)(secBase + off), chunk.data(), toRead, &rd2) || rd2 == 0)
                        break;

                    size_t stride = is64 ? 8 : 4;
                    bool foundInChunk = false;
                    for (size_t pos = 0; pos + stride <= rd2 && !foundInChunk; pos += stride) {
                        uintptr_t ptr = is64 ? *reinterpret_cast<const uint64_t*>(chunk.data() + pos)
                                              : *reinterpret_cast<const uint32_t*>(chunk.data() + pos);
                        if (ptr < 0x10000) continue;
                        if (ptr >= module.begin && ptr < module.end) continue;

                        bool inSignedMod = false;
                        for (const auto& m : modules) {
                            if (ptr >= m.begin && ptr < m.end) {
                                if (DetectionFilter::IsTrustedSignedCached(m.path))
                                    inSignedMod = true;
                                break;
                            }
                        }
                        if (inSignedMod) continue;

                        MEMORY_BASIC_INFORMATION mbi = {};
                        if (VirtualQueryEx(process, (LPCVOID)ptr, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
                        if (mbi.State != MEM_COMMIT || !IsExecProtect(mbi.Protect)) continue;

                        char entryBuf[32], tgtBuf[32];
                        snprintf(entryBuf, sizeof(entryBuf), "0x%llX", (unsigned long long)(secBase + off + pos));
                        snprintf(tgtBuf,   sizeof(tgtBuf),   "0x%llX", (unsigned long long)ptr);
                        std::string detail = "VTable/RDATA pointer redireciona fora do modulo: " +
                                             WideToUtf8(BaseNameFromPath(module.path)) +
                                             " | entry=" + entryBuf + " -> " + tgtBuf +
                                             " | mem=" + (mbi.Type == MEM_PRIVATE ? "anonima" : "mapeada");
                        AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                               WideToUtf8(module.path), detail, "HIGH");
                        ++vtCount;
                        foundInChunk = true;
                    }
                }
            }
        }
        CloseHandle(process);
    }
}

// ─── Duplicate / sideloaded graphics modules ─────────────────────────────────
// Splits canonical graphics DLLs in two policy classes:
//
//   STRICT: Windows-shipped DLLs that should NEVER be redistributed alongside
//           a third-party executable. ANY copy outside System32/SysWOW64/WinSxS
//           is treated as DLL search-order hijack regardless of signature.
//             opengl32.dll, glu32.dll, d3d9.dll, d3d10.dll, d3d11.dll,
//             d3d12.dll, dxgi.dll, d2d1.dll, dwrite.dll
//
//   BUNDLED: DLLs the Microsoft redistribution license permits applications to
//            ship in their own install dir (ANGLE, D3DCompiler, SwiftShader,
//            Vulkan loader). Every modern Android emulator (BlueStacks, MEmu,
//            LDPlayer, Nox, MuMu) bundles these. Only flag if UNSIGNED, or if
//            the publisher differs from the host .exe AND the DLL is in the
//            exe directory.
//
// Same-publisher exemption: any side-by-side DLL signed by the same publisher
// as the hosting executable is treated as vendor-shipped and skipped.
static bool DupGfxIsSystemPath(const std::wstring& path) {
    const auto& r = DetectionFilter::Roots();
    std::wstring up = DetectionFilter::UpperW(path);
    return DetectionFilter::PathIsUnder(up, r.system32) ||
           DetectionFilter::PathIsUnder(up, r.syswow64) ||
           DetectionFilter::PathIsUnder(up, r.winsxs);
}

static bool DupGfxSamePublisherAsExe(const std::wstring& dllPath,
                                     const std::wstring& exePath) {
    // Hardened: requires both binaries to be genuinely Authenticode-trusted and to
    // share the same signer CN *and* root CA — a forged-CN/untrusted DLL placed next
    // to a legit exe no longer inherits the vendor exemption.
    return DetectionFilter::SamePublisherTrusted(dllPath, exePath);
}

static void ScanDuplicateGraphicsModules(std::vector<ScannerUI::GenericBypassFinding>& out) {
    static const wchar_t* kStrictGfxDlls[] = {
        L"OPENGL32.DLL", L"GLU32.DLL",
        L"D3D9.DLL", L"D3D10.DLL", L"D3D11.DLL", L"D3D12.DLL",
        L"DXGI.DLL", L"D2D1.DLL", L"DWRITE.DLL",
        // Classic "phantom DLL" / search-order hijack targets. These are pure
        // Windows DLLs that ship ONLY in System32/SysWOW64 and are never legitimately
        // redistributed in an application directory. A side-by-side copy is the
        // textbook DLL-search-order hijack used to gain code execution in a trusted
        // process (proxying exports to the real System32 DLL).
        L"VERSION.DLL", L"DWMAPI.DLL", L"UXTHEME.DLL",
        L"CRYPTBASE.DLL", L"PROPSYS.DLL", L"UALAPI.DLL",
        L"PROFAPI.DLL", L"SECUR32.DLL", L"WTSAPI32.DLL",
        nullptr
    };
    static const wchar_t* kBundledGfxDlls[] = {
        L"LIBEGL.DLL", L"LIBGLESV2.DLL",
        L"D3DCOMPILER_43.DLL", L"D3DCOMPILER_46.DLL", L"D3DCOMPILER_47.DLL",
        L"VK_SWIFTSHADER.DLL", L"LIBVK_SWIFTSHADER.DLL",
        L"SWIFTSHADER_LIBEGL.DLL", L"SWIFTSHADER_LIBGLESV2.DLL",
        L"VULKAN-1.DLL", L"OPENGL32SW.DLL",
        nullptr
    };

    auto matchList = [](const std::wstring& upName, const wchar_t** list) -> bool {
        for (int i = 0; list[i]; ++i) if (upName == list[i]) return true;
        return false;
    };

    std::vector<DWORD> pids = FindEmulatorProcesses();
    for (DWORD pid : pids) {
        if (out.size() >= ScanLimits::kMaxBypassFindings) break;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) continue;

        std::string  procPath  = ProcessPathByPid(pid);
        std::wstring exePathW  = ProcessFullPathW(pid);
        std::wstring exeDir    = ProcessImageDirW(process);
        std::wstring exeDirUp  = DetectionFilter::UpperW(exeDir);
        std::vector<ModuleRange> modules;
        if (!CollectProcessModules(process, modules)) { CloseHandle(process); continue; }

        std::unordered_map<std::wstring, std::vector<const ModuleRange*>> byName;
        for (const auto& m : modules) {
            if (m.path.empty()) continue;
            std::wstring upName = DetectionFilter::UpperW(BaseNameFromPath(m.path));
            byName[upName].push_back(&m);
        }

        for (const auto& kv : byName) {
            const std::wstring& upName = kv.first;
            bool strict  = matchList(upName, kStrictGfxDlls);
            bool bundled = !strict && matchList(upName, kBundledGfxDlls);
            if (!strict && !bundled) continue;

            // (a) Same name loaded more than once. Require evidence of a
            // hijack — at least one copy must be either unsigned or located
            // outside trusted roots (System32/Program Files). Two signed
            // copies in trusted dirs (rare WinSxS redirect) → skip.
            if (kv.second.size() > 1) {
                bool suspect = false;
                for (const auto* m : kv.second) {
                    bool sgn = DetectionFilter::IsTrustedSignedCached(m->path);
                    auto cls = DetectionFilter::ClassifyPath(m->path);
                    if (!sgn || !DetectionFilter::IsTrustedDir(cls)) { suspect = true; break; }
                }
                if (!suspect) continue;

                std::string paths;
                for (size_t i = 0; i < kv.second.size(); ++i) {
                    if (i) paths += " ; ";
                    paths += WideToUtf8(kv.second[i]->path);
                }
                std::string detail = "DLL do Windows duplicada: " + WideToUtf8(upName) +
                                     " carregada " + std::to_string(kv.second.size()) +
                                     "x | paths=" + paths;
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(upName), detail, "HIGH");
                if (out.size() >= ScanLimits::kMaxBypassFindings) break;
                continue;
            }

            // (b) Single copy, but loaded from outside System32/SysWOW64/WinSxS.
            const ModuleRange* m = kv.second.front();
            if (DupGfxIsSystemPath(m->path)) continue;

            bool sideBySide = !exeDirUp.empty() &&
                DetectionFilter::PathIsUnder(DetectionFilter::UpperW(m->path), exeDirUp);
            bool signedMod  = DetectionFilter::IsTrustedSignedCached(m->path);
            bool samePub    = signedMod && DupGfxSamePublisherAsExe(m->path, exePathW);

            // Same-publisher signed DLL → vendor-shipped, always allowed.
            if (samePub) continue;

            // BUNDLED list policy: signed DLLs anywhere are allowed (these are
            // commonly redistributed by countless apps). Only unsigned copies
            // are flagged.
            if (bundled && signedMod) continue;
            if (bundled && !signedMod) {
                std::string detail = std::string("DLL grafica bundled NAO assinada: ") +
                                     WideToUtf8(upName) +
                                     " | path=" + WideToUtf8(m->path) +
                                     (sideBySide ? " | lado-a-lado com o exe" : "");
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(m->path), detail, "HIGH");
                if (out.size() >= ScanLimits::kMaxBypassFindings) break;
                continue;
            }

            // STRICT list policy: ANY copy outside System32/SysWOW64/WinSxS
            // is suspect. HIGH if side-by-side or unsigned; MEDIUM otherwise.
            std::string detail = std::string("DLL do Windows fora do System32 (search-order hijack): ") +
                                 WideToUtf8(upName) +
                                 " | path=" + WideToUtf8(m->path) +
                                 " | signed=" + (signedMod ? "yes" : "no") +
                                 (sideBySide ? " | LADO A LADO COM O EXE (DLL hijack)" : "");
            std::string sev = (sideBySide || !signedMod) ? "HIGH" : "MEDIUM";
            AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                    WideToUtf8(m->path), detail, sev);
            if (out.size() >= ScanLimits::kMaxBypassFindings) break;
        }

        // (c) Strict gfx DLL file present in the exe dir but not loaded yet.
        // Bundled list is skipped here — emulators legitimately ship those.
        if (!exeDir.empty()) {
            for (int i = 0; kStrictGfxDlls[i]; ++i) {
                if (out.size() >= ScanLimits::kMaxBypassFindings) break;
                std::wstring candidate = exeDir + L"\\" + kStrictGfxDlls[i];
                if (!FileExistsW(candidate)) continue;

                std::wstring up = DetectionFilter::UpperW(kStrictGfxDlls[i]);
                auto it = byName.find(up);
                if (it != byName.end()) {
                    bool already = false;
                    for (const auto* m : it->second) {
                        if (DetectionFilter::UpperW(m->path) ==
                            DetectionFilter::UpperW(candidate)) { already = true; break; }
                    }
                    if (already) continue;
                }

                bool signedFile = DetectionFilter::IsTrustedSignedCached(candidate);
                bool samePub    = signedFile && DupGfxSamePublisherAsExe(candidate, exePathW);
                if (samePub) continue;

                std::string detail = "arquivo grafico do Windows lado-a-lado com o exe (DLL hijack preparado): " +
                                     WideToUtf8(kStrictGfxDlls[i]) +
                                     " | path=" + WideToUtf8(candidate) +
                                     " | signed=" + (signedFile ? "yes" : "no");
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(candidate), detail,
                                        signedFile ? "MEDIUM" : "HIGH");
            }
        }

        CloseHandle(process);
    }
}

// ─── Graphics strings in anonymous executable memory ─────────────────────────
// Scans MEM_PRIVATE executable regions OUTSIDE all loaded modules for ASCII
// identifiers that indicate the region is a chams/overlay loader resolving
// OpenGL/WGL/EGL/D3D entry points by name.
//
// Anti-FP design:
//   • Skip regions <4 KB (too small to host a loader) and >4 MB (V8/Skia/CEF
//     JIT heaps used by Chromium-based emulator UIs).
//   • Classify the region with three independent signals computed in ONE
//     pass: distinctNeedleCount, loaderEvidence (full DLL filename like
//     "opengl32.dll"), jitEvidence (V8/Chromium/SwiftShader/ANGLE markers).
//   • Skip immediately if jitEvidence>0 — Chromium JIT pages legitimately
//     embed gl* symbol tables for proc resolution.
//   • Require (loaderEvidence AND distinctNeedles>=2) for HIGH. Without a
//     full DLL filename present, require distinctNeedles>=4 for MEDIUM.
//     This combination is essentially never produced incidentally.
struct GfxRegionScore {
    int  distinctNeedles = 0;
    bool loaderEvidence  = false;   // full DLL filename present
    bool jitEvidence     = false;   // V8/Chromium/SwiftShader/ANGLE/Skia marker
    const char* firstMatch = nullptr;
};

static GfxRegionScore ClassifyGfxRegion(const BYTE* buf, size_t len) {
    GfxRegionScore s;
    if (len < 8) return s;

    // Loader-evidence needles: only triggered by code that calls
    // LoadLibraryA("opengl32.dll") or stores the filename in a string table.
    // Chromium JIT does not contain these literal filenames.
    static const char* kLoaderNeedles[] = {
        "opengl32.dll", "OPENGL32.DLL", "Opengl32.dll",
        "d3d9.dll", "D3D9.DLL",
        "d3d11.dll", "D3D11.DLL",
        "d3d12.dll", "D3D12.DLL",
        "dxgi.dll", "DXGI.DLL",
        "vulkan-1.dll", "VULKAN-1.DLL",
        nullptr
    };

    // Function-name needles: distinct match counter. A real loader/cham
    // typically resolves several of these; JIT pages may have one or two by
    // coincidence (e.g. an exported symbol name) but not many.
    static const char* kFuncNeedles[] = {
        "wglMakeCurrent", "wglSwapBuffers", "wglGetProcAddress",
        "wglCreateContext", "wglDeleteContext", "wglShareLists",
        "glDrawElements", "glDrawArrays", "glDrawRangeElements",
        "glClearColor", "glDepthFunc", "glDepthMask",
        "glColorMask", "glPolygonMode", "glStencilFunc", "glBlendFunc",
        "glBindTexture", "glTexImage2D", "glUseProgram", "glCreateShader",
        "glShaderSource", "glCompileShader", "glUniformMatrix4fv",
        "glBindFramebuffer", "glBindBuffer", "glVertexAttribPointer",
        "eglMakeCurrent", "eglSwapBuffers", "eglGetProcAddress",
        "eglCreateContext", "eglDestroyContext",
        "Direct3DCreate9", "D3D11CreateDevice", "CreateDXGIFactory",
        "vkQueuePresentKHR", "vkCmdDraw", "vkAcquireNextImageKHR",
        nullptr
    };

    // JIT/Chromium/SwiftShader markers. Any single occurrence vetoes the
    // region as JIT-origin even if it also contains gfx needles.
    static const char* kJitNeedles[] = {
        "v8::", "V8 ", "V8_", "Isolate", "IsolateData",
        "crashpad", "Crashpad", "CRASHPAD",
        "chrome_elf", "chrome.dll", "libcef", "cef_", "CefMain",
        "blink::", "mojo::", "Skia", "SkBitmap", "SkSurface",
        "RegExpMacroAssembler", "TurboFan", "Ignition", "Wasm",
        "SwiftShader", "swiftshader",
        "ANGLE", "ANGLEPlatform", "ANGLERender",
        "node::", "JitCode", "CodeStub", "WebAssembly",
        nullptr
    };

    auto containsAny = [&](const char* const* list, int& firstHitIdx) -> int {
        int hits = 0;
        firstHitIdx = -1;
        for (int k = 0; list[k]; ++k) {
            const char* n = list[k];
            size_t nlen = strlen(n);
            if (nlen > len) continue;
            bool found = false;
            for (size_t i = 0; i + nlen <= len; ++i) {
                if (buf[i] != (BYTE)n[0]) continue;
                if (memcmp(buf + i, n, nlen) == 0) { found = true; break; }
            }
            if (found) {
                ++hits;
                if (firstHitIdx < 0) firstHitIdx = k;
            }
        }
        return hits;
    };

    int jitFirst = -1;
    if (containsAny(kJitNeedles, jitFirst) > 0) {
        s.jitEvidence = true;
        return s;  // JIT veto — short-circuit, no further classification needed
    }

    int loadFirst = -1;
    int loadHits = containsAny(kLoaderNeedles, loadFirst);
    if (loadHits > 0) {
        s.loaderEvidence = true;
        s.firstMatch = kLoaderNeedles[loadFirst];
    }

    int funcFirst = -1;
    int funcHits = containsAny(kFuncNeedles, funcFirst);
    s.distinctNeedles = funcHits;
    if (!s.firstMatch && funcFirst >= 0)
        s.firstMatch = kFuncNeedles[funcFirst];

    return s;
}

// Determines if the host process is Chromium-based (HD-Player UI, CEF apps,
// Electron etc.). Used to raise the gfx-needle threshold further, since
// Chromium ships gl symbol tables in many places besides JIT.
static bool ProcessHostsChromiumRuntime(const std::vector<ModuleRange>& modules) {
    for (const auto& m : modules) {
        if (m.path.empty()) continue;
        std::wstring up = DetectionFilter::UpperW(BaseNameFromPath(m.path));
        if (up == L"CHROME.DLL" || up == L"CHROME_ELF.DLL" ||
            up == L"LIBCEF.DLL" || up == L"CEF.DLL" ||
            up == L"V8.DLL"     || up == L"V8_LIBBASE.DLL" ||
            up == L"NODE.DLL"   || up.find(L"ELECTRON") != std::wstring::npos)
            return true;
    }
    return false;
}

static void ScanGraphicsStringsInAnonMemory(std::vector<ScannerUI::GenericBypassFinding>& out) {
    std::vector<DWORD> pids = FindEmulatorProcesses();
    size_t reported = 0;

    for (DWORD pid : pids) {
        if (reported >= ScanLimits::kMaxGfxHookFindings) break;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) continue;

        std::string procPath = ProcessPathByPid(pid);
        std::vector<ModuleRange> modules;
        if (!CollectProcessModules(process, modules)) { CloseHandle(process); continue; }

        bool chromium = ProcessHostsChromiumRuntime(modules);
        // Chromium-host processes raise the bar: still require loaderEvidence
        // AND at least 3 distinct function needles to flag.
        const int kMinNeedlesWithLoader    = chromium ? 3 : 2;
        const int kMinNeedlesWithoutLoader = chromium ? 99 : 4;  // effectively off in chromium

        // Region size band: chams loaders are tiny; anything outside this
        // band is almost certainly not a loader.
        constexpr SIZE_T kMinRegion = 4 * 1024;        // skip <4 KB
        constexpr SIZE_T kMaxRegion = 4 * 1024 * 1024; // skip >4 MB (JIT heaps)

        uintptr_t maxModEnd = 0;
        for (const auto& m : modules) if (m.end > maxModEnd) maxModEnd = m.end;
        constexpr uintptr_t kMinScan  = 2ULL * 1024 * 1024 * 1024;
        constexpr uintptr_t kHeadroom = 512ULL * 1024 * 1024;
        const uintptr_t kLimit = (maxModEnd + kHeadroom > kMinScan)
                                 ? (maxModEnd + kHeadroom) : kMinScan;

        uintptr_t addr = 0x10000;
        MEMORY_BASIC_INFORMATION mbi = {};
        std::unordered_set<uintptr_t> seenAlloc;

        while (addr < kLimit && reported < ScanLimits::kMaxGfxHookFindings &&
               VirtualQueryEx(process, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;

            bool commit  = (mbi.State == MEM_COMMIT);
            bool privexe = (mbi.Type == MEM_PRIVATE) && IsExecProtect(mbi.Protect);
            bool inMod   = IsAddrInModules((uintptr_t)mbi.BaseAddress, modules);
            bool inBand  = (mbi.RegionSize >= kMinRegion && mbi.RegionSize <= kMaxRegion);

            if (commit && privexe && !inMod && inBand) {
                uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
                if (seenAlloc.insert(allocBase).second) {
                    constexpr SIZE_T kChunk = 64 * 1024;
                    constexpr SIZE_T kMax   = 256 * 1024;
                    SIZE_T toScan = mbi.RegionSize < kMax ? (SIZE_T)mbi.RegionSize : kMax;
                    std::vector<BYTE> buf(toScan);
                    SIZE_T total = 0;
                    for (SIZE_T off = 0; off < toScan; off += kChunk) {
                        SIZE_T want = (toScan - off) < kChunk ? (toScan - off) : kChunk;
                        SIZE_T got = 0;
                        if (!ReadProcessMemory(process,
                                               (LPCVOID)((uintptr_t)mbi.BaseAddress + off),
                                               buf.data() + off, want, &got) || got == 0)
                            break;
                        total += got;
                        if (got < want) break;
                    }
                    if (total >= 8) {
                        GfxRegionScore s = ClassifyGfxRegion(buf.data(), total);
                        // JIT veto already returns short-circuit; if jitEvidence
                        // is set, skip without flagging.
                        bool flagHigh = !s.jitEvidence && s.loaderEvidence &&
                                        s.distinctNeedles >= kMinNeedlesWithLoader;
                        bool flagMed  = !s.jitEvidence && !s.loaderEvidence &&
                                        s.distinctNeedles >= kMinNeedlesWithoutLoader;
                        if (flagHigh || flagMed) {
                            char addrBuf[32];
                            snprintf(addrBuf, sizeof(addrBuf), "0x%llX",
                                     (unsigned long long)(uintptr_t)mbi.BaseAddress);
                            std::string detail =
                                std::string("loader grafico em memoria anonima fora de modulo")
                                + " | base=" + addrBuf
                                + " | size=" + std::to_string((unsigned long long)mbi.RegionSize)
                                + " | loader_dll=" + (s.loaderEvidence ? "yes" : "no")
                                + " | funcs=" + std::to_string(s.distinctNeedles)
                                + " | first=\"" + (s.firstMatch ? s.firstMatch : "?") + "\"";
                            AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                                    addrBuf, detail,
                                                    flagHigh ? "HIGH" : "MEDIUM");
                            ++reported;
                        }
                    }
                }
            }
            addr = next;
        }
        CloseHandle(process);
    }
}

// ─── Threads whose start region contains graphics strings ────────────────────
// Same scoring engine as the anon-memory scan, plus thread-description filter
// to skip JIT/renderer/compositor/crashpad worker threads by name.
static bool ThreadNameLooksLikeJit(HANDLE thread) {
    using GetThreadDescriptionFn = HRESULT (WINAPI*)(HANDLE, PWSTR*);
    static auto fn = []() {
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        return k ? reinterpret_cast<GetThreadDescriptionFn>(
            GetProcAddress(k, "GetThreadDescription")) : nullptr;
    }();
    if (!fn) return false;

    PWSTR desc = nullptr;
    if (FAILED(fn(thread, &desc)) || !desc) return false;
    std::wstring d = DetectionFilter::UpperW(desc);
    LocalFree(desc);

    static const wchar_t* kJitWords[] = {
        L"JIT", L"V8", L"WASM", L"CHROME", L"CEF", L"BLINK", L"SKIA",
        L"COMPOSITOR", L"RASTER", L"RENDERER", L"GPU", L"ANGLE",
        L"SWIFTSHADER", L"CRASHPAD", L"COMPILER", L"OPTIMIZ", L"IGNITION",
        L"TURBOFAN", L"GARBAGE", L"WORKER", L"BACKGROUND",
        nullptr
    };
    for (int i = 0; kJitWords[i]; ++i)
        if (d.find(kJitWords[i]) != std::wstring::npos) return true;
    return false;
}

static void ScanThreadsWithGraphicsContext(std::vector<ScannerUI::GenericBypassFinding>& out) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto queryThread = ntdll ? reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread")) : nullptr;
    if (!queryThread) return;

    std::vector<DWORD> pids = FindEmulatorProcesses();
    size_t reported = 0;

    for (DWORD pid : pids) {
        if (reported >= ScanLimits::kMaxGfxHookFindings) break;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process)
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) continue;

        std::string procPath = ProcessPathByPid(pid);
        std::vector<ModuleRange> modules;
        if (!CollectProcessModules(process, modules)) { CloseHandle(process); continue; }

        bool chromium = ProcessHostsChromiumRuntime(modules);
        const int kMinNeedlesWithLoader    = chromium ? 3 : 2;
        const int kMinNeedlesWithoutLoader = chromium ? 99 : 4;

        constexpr SIZE_T kMinRegion = 4 * 1024;
        constexpr SIZE_T kMaxRegion = 4 * 1024 * 1024;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) { CloseHandle(process); continue; }

        std::unordered_set<uintptr_t> seenRegion;
        THREADENTRY32 te = {}; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (reported >= ScanLimits::kMaxGfxHookFindings) break;
                if (te.th32OwnerProcessID != pid) continue;

                HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!thread)
                    thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (!thread) continue;

                if (ThreadNameLooksLikeJit(thread)) { CloseHandle(thread); continue; }

                PVOID start = nullptr;
                LONG st = queryThread(thread, 9, &start, sizeof(start), nullptr);
                CloseHandle(thread);
                if (st < 0 || !start) continue;

                uintptr_t startAddr = (uintptr_t)start;
                if (IsAddrInModules(startAddr, modules)) continue;

                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQueryEx(process, start, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
                if (mbi.State != MEM_COMMIT || !IsExecProtect(mbi.Protect)) continue;
                if (mbi.RegionSize < kMinRegion || mbi.RegionSize > kMaxRegion) continue;

                uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
                if (!seenRegion.insert(allocBase).second) continue;

                constexpr SIZE_T kChunk = 64 * 1024;
                constexpr SIZE_T kMax   = 128 * 1024;
                SIZE_T toScan = mbi.RegionSize < kMax ? (SIZE_T)mbi.RegionSize : kMax;
                std::vector<BYTE> buf(toScan);
                SIZE_T total = 0;
                for (SIZE_T off = 0; off < toScan; off += kChunk) {
                    SIZE_T want = (toScan - off) < kChunk ? (toScan - off) : kChunk;
                    SIZE_T got = 0;
                    if (!ReadProcessMemory(process,
                                           (LPCVOID)((uintptr_t)mbi.BaseAddress + off),
                                           buf.data() + off, want, &got) || got == 0)
                        break;
                    total += got;
                    if (got < want) break;
                }
                if (total < 8) continue;

                GfxRegionScore s = ClassifyGfxRegion(buf.data(), total);
                bool flagHigh = !s.jitEvidence && s.loaderEvidence &&
                                s.distinctNeedles >= kMinNeedlesWithLoader;
                bool flagMed  = !s.jitEvidence && !s.loaderEvidence &&
                                s.distinctNeedles >= kMinNeedlesWithoutLoader;
                if (!flagHigh && !flagMed) continue;

                char addrBuf[32], startBuf[32];
                snprintf(addrBuf,  sizeof(addrBuf),  "0x%llX", (unsigned long long)allocBase);
                snprintf(startBuf, sizeof(startBuf), "0x%llX", (unsigned long long)startAddr);
                std::string detail =
                    std::string("thread fora de modulo em loader grafico anonimo")
                    + " | tid=" + std::to_string(te.th32ThreadID)
                    + " | start=" + startBuf
                    + " | region=" + addrBuf
                    + " | loader_dll=" + (s.loaderEvidence ? "yes" : "no")
                    + " | funcs=" + std::to_string(s.distinctNeedles)
                    + " | first=\"" + (s.firstMatch ? s.firstMatch : "?") + "\"";
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        startBuf, detail,
                                        flagHigh ? "HIGH" : "MEDIUM");
                ++reported;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        CloseHandle(process);
    }
}

// --- Per-event-ID handlers returning true if a finding was produced ---

static bool HandleSysmonServiceEvent(int id, const std::wstring& xml,
                                     std::string& type, std::string& detail) {
    if (id == 4) {
        std::wstring state = ToUpperInvariant(ExtractSysmonData(xml, L"State"));
        if (state.find(L"STOP") != std::wstring::npos) {
            type = ScanTag::Sysmon;
            detail = "servico do sysmon parado detectado";
            return true;
        }
    } else if (id == 16) {
        type = ScanTag::Sysmon;
        detail = "mudanca de configuracao do sysmon detectada";
        return true;
    }
    return false;
}

static bool HandleLogClearEvent(int id, const std::wstring& xml,
                                std::string& type, std::string& detail) {
    if (id == 104 || id == 1102) {
        type = ScanTag::EventLog;
        detail = "limpeza/modificacao do event log detectada";
        return true;
    }
    if (id == 1) {
        std::wstring cmd = ToUpperInvariant(ExtractSysmonData(xml, L"CommandLine"));
        bool wevtClear = cmd.find(L"WEVTUTIL") != std::wstring::npos &&
                         (cmd.find(L" CL ") != std::wstring::npos ||
                          cmd.find(L"CLEAR-LOG") != std::wstring::npos ||
                          cmd.find(L" CL\"") != std::wstring::npos);
        if (wevtClear || cmd.find(L"CLEAR-EVENTLOG") != std::wstring::npos) {
            type = ScanTag::EventLog;
            detail = "comando de limpeza de log detectado";
            return true;
        }
    }
    return false;
}

static bool HandleCheatDomainEvent(const std::wstring& xml,
                                   std::string& type, std::string& detail) {
    std::wstring dns = ToUpperInvariant(ExtractSysmonData(xml, L"QueryName"));
    for (int di = 0; DetectionFilter::kCheatDomains[di]; ++di) {
        const wchar_t* d = DetectionFilter::kCheatDomains[di];
        // Only flag actual DNS queries — not command line arguments.
        // Command line matching causes false positives when browsers, text editors,
        // or security research tools reference these domains in arguments.
        if (dns.find(d) != std::wstring::npos) {
            type = ScanTag::CheatDomain;
            detail = "cheat service domain detected: " + WideToUtf8(d);
            return true;
        }
    }
    return false;
}

static bool HandleRemoteThreadEvent(const std::wstring& xml,
                                    std::string& type, std::string& detail,
                                    std::string& outSeverity) {
    std::wstring src    = ExtractSysmonData(xml, L"SourceImage");
    std::wstring tgt    = ExtractSysmonData(xml, L"TargetImage");
    std::wstring srcUp  = ToUpperInvariant(src);
    std::wstring tgtUp  = ToUpperInvariant(tgt);
    static const std::unordered_set<std::wstring> kIgnoreSrc = {
        L"CSRSS.EXE", L"WERFAULT.EXE", L"WERFAULTSECURE.EXE",
        L"SVCHOST.EXE", L"LSASS.EXE", L"SERVICES.EXE"
    };
    // Known system process targets: game clients and anti-cheats (e.g. Roblox Hyperion)
    // legitimately inject threads into these for crash reporting, telemetry, and hooks.
    // Allow if source is Authenticode-signed, regardless of install directory.
    static const std::unordered_set<std::wstring> kTrustedSystemTargets = {
        L"SVCHOST.EXE", L"WINLOGON.EXE", L"LSASS.EXE",
        L"SERVICES.EXE", L"CSRSS.EXE", L"WININIT.EXE", L"SMSS.EXE"
    };
    std::wstring srcBase = ToUpperInvariant(BaseNameFromPath(src));
    std::wstring tgtBase = ToUpperInvariant(BaseNameFromPath(tgt));
    bool srcSigned = DetectionFilter::IsTrustedSignedCached(src);
    bool ignore = kIgnoreSrc.count(srcBase) > 0
               || (srcSigned && DetectionFilter::IsTrustedDir(DetectionFilter::ClassifyPath(src)))
               || (srcSigned && kTrustedSystemTargets.count(tgtBase) > 0);
    if (!ignore && !srcUp.empty() && srcUp != tgtUp) {
        bool tgtSigned = DetectionFilter::IsTrustedSignedCached(tgt);
        type   = ScanTag::RemoteThread;
        detail = "CreateRemoteThread: src=" + WideToUtf8(BaseNameFromPath(src)) +
                 " -> tgt=" + WideToUtf8(BaseNameFromPath(tgt));
        // Severity based on cryptographic identity, not path:
        // Both signed → legitimate overlay/hook between identified software (FLAG).
        // Unsigned source → real injection threat (HIGH).
        outSeverity = (srcSigned && tgtSigned) ? "FLAG" : "HIGH";
        return true;
    }
    return false;
}

static bool HandleProcessAccessEvent(const std::wstring& xml,
                                     std::string& type, std::string& detail) {
    std::wstring src    = ExtractSysmonData(xml, L"SourceImage");
    std::wstring tgtAll = ExtractSysmonData(xml, L"TargetImage");
    std::string  acc    = WideToUtf8(ExtractSysmonData(xml, L"GrantedAccess"));
    if (ToUpperInvariant(tgtAll).find(L"HD-PLAYER.EXE") != std::wstring::npos)
        return false; // handled by direct HD-Player path below
    bool vmWrite = (acc == "0x28" || acc == "0x38" || acc == "0x1FFFFF" ||
                    acc == "0x143A" || acc == "0x1F0FFF");
    if (!vmWrite) return false;
    auto srcCls = DetectionFilter::ClassifyPath(src);
    bool srcSigned = DetectionFilter::IsTrustedSignedCached(src);
    // Emulator-name match alone is not a trust signal — only exempt when the source
    // executable is also signed and located in a trusted directory.
    bool ignore = srcSigned && (DetectionFilter::IsTrustedDir(srcCls) ||
                                 srcCls == DetectionFilter::PathClass::ProgramFiles);
    if (!ignore) {
        type   = ScanTag::ProcAccess;
        detail = "cross-process write access: src=" + WideToUtf8(BaseNameFromPath(src)) +
                 " tgt=" + WideToUtf8(BaseNameFromPath(tgtAll)) + " access=" + acc;
        return true;
    }
    return false;
}

static bool HandleExplorerParentEvent(const std::wstring& xml,
                                      std::string& type, std::string& detail) {
    std::wstring image = ToUpperInvariant(BaseNameFromPath(ExtractSysmonData(xml, L"Image")));
    if (image != L"EXPLORER.EXE") return false;
    std::wstring parent = ToUpperInvariant(BaseNameFromPath(ExtractSysmonData(xml, L"ParentImage")));
    static const std::unordered_set<std::wstring> kNormalParents = {
        L"USERINIT.EXE", L"EXPLORER.EXE", L"WININIT.EXE", L"WINLOGON.EXE", L"SVCHOST.EXE", L""
    };
    if (kNormalParents.find(parent) == kNormalParents.end()) {
        type   = ScanTag::Explorer;
        detail = "explorer iniciado por pai incomum: " + WideToUtf8(parent);
        return true;
    }
    return false;
}

static void CollectGenericBypassEventLogs(std::vector<ScannerUI::GenericBypassFinding>& out) {
    struct QuerySpec { const wchar_t* channel; const wchar_t* query; };
    static const QuerySpec specs[] = {
        { L"Microsoft-Windows-Sysmon/Operational",
          L"*[System[(EventID=4 or EventID=16 or EventID=1 or EventID=8 or EventID=10 or EventID=22)]]" },
        { L"System",
          L"*[System[(EventID=7035 or EventID=7036 or EventID=7040 or EventID=104)]]" },
        { L"Security",
          L"*[System[(EventID=1102)]]" },
        { L"Microsoft-Windows-DNS-Client/Operational",
          L"*[System[(EventID=3008 or EventID=3009 or EventID=3010 or EventID=3020)]]" },
    };

    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);
    constexpr DWORD kBatch = 10;

    for (const auto& spec : specs) {
        EVT_HANDLE result = EvtQuery(nullptr, spec.channel, spec.query,
                                     EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!result) continue;

        EVT_HANDLE handles[kBatch] = {};
        DWORD returned = 0;
        bool reachedBoot = false;

        while (!reachedBoot &&
               EvtNext(result, kBatch, handles, ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
            for (DWORD i = 0; i < returned; ++i) {
                std::wstring xml;
                if (!RenderEventXml(handles[i], xml)) {
                    EvtClose(handles[i]); handles[i] = nullptr;
                    continue;
                }

                FILETIME eventTime = {};
                std::wstring sysTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
                if (SysmonSystemTimeToFileTime(sysTime, eventTime) &&
                    FileTimeToU64(eventTime) < bootValue) {
                    reachedBoot = true;
                    EvtClose(handles[i]); handles[i] = nullptr;
                    break;
                }

                int id = _wtoi(ExtractXmlTag(xml, L"EventID").c_str());
                bool hit = false;
                std::string type, detail;
                std::string evtSeverity = "HIGH";  // default; overridden per-handler

                // Dispatch to per-event-ID handlers
                if (!hit) hit = HandleSysmonServiceEvent(id, xml, type, detail);
                if (!hit) hit = HandleLogClearEvent(id, xml, type, detail);
                if (!hit) hit = HandleCheatDomainEvent(xml, type, detail);
                if (!hit && id == 8)  hit = HandleRemoteThreadEvent(xml, type, detail, evtSeverity);
                if (!hit && id == 10) hit = HandleProcessAccessEvent(xml, type, detail);
                if (!hit && id == 1)  hit = HandleExplorerParentEvent(xml, type, detail);

                // Direct HD-Player access via EventID 10 (emits finding directly)
                if (id == 10 && !hit) {
                    std::string target = WideToUtf8(ExtractSysmonData(xml, L"TargetImage"));
                    std::string access = WideToUtf8(ExtractSysmonData(xml, L"GrantedAccess"));
                    std::wstring tgtUp = ToUpperInvariant(ExtractSysmonData(xml, L"TargetImage"));
                    if (tgtUp.find(L"HD-PLAYER.EXE") != std::wstring::npos &&
                        (access == "0x20" || access == "0x28" || access == "0x38" ||
                         access == "0x1FFFFF" || access == "0x143A" || access == "0x1F0FFF")) {
                        std::wstring src = ExtractSysmonData(xml, L"SourceImage");
                        // Emulator-name match alone is not a trust signal — only exempt when
                        // the source executable is also signed and in a trusted directory.
                        bool ignore = DetectionFilter::IsTrustedSignedCached(src) &&
                                      DetectionFilter::IsTrustedDir(DetectionFilter::ClassifyPath(src));
                        if (!ignore)
                            AddGenericBypassFinding(out, ScanTag::Handle, WideToUtf8(src), target,
                                                    "handle suspeito no HD-Player detectado: access=" + access,
                                                    "HIGH", &eventTime);
                    }
                }

                if (hit) {
                    std::string process = FirstNonEmptyUtf8({
                        ExtractSysmonData(xml, L"Image"),
                        ExtractSysmonData(xml, L"SourceImage"),
                        ExtractSysmonData(xml, L"ProcessName")
                    });
                    // Use handler-provided severity when available (e.g. REMOTETHREAD
                    // sets FLAG for both-signed interactions), otherwise apply defaults.
                    std::string finalSev = evtSeverity;
                    if (type == ScanTag::CheatDomain) finalSev = "MEDIUM";
                    AddGenericBypassFinding(out, type, process, "-", detail,
                                            finalSev, &eventTime);
                }

                EvtClose(handles[i]); handles[i] = nullptr;
            }
        }
        EvtClose(result);
    }
}

// Enumerate \\.\pipe\* and flag pipes with cheat-related names.
static void CollectSuspiciousNamedPipes(std::vector<ScannerUI::GenericBypassFinding>& out) {
    static const char* kPipeTokens[] = {
        "CHEAT", "BYPASS", "INJECT", "HWID", "SPOOF", "MAPPER",
        "RING0", "ROOTKIT", "PHANTOM",
        // "LOADER" removed — too generic: matches .NET Assembly Loader, MSBuild, Unity, etc.
        // "GHOST" removed — too generic: matches Symantec Ghost, enterprise backup tools.
        // Replaced with cheat-specific compound variants:
        "RING0LOADER", "KLOADER", "HACKLOADER", "CHEATLOADER",
        "DLLGHOST", "PROCESSGHOST",
        "MHYPROTECT", "EAC_", "VANGUARD", "BATTLEYE",
        nullptr
    };
    // Windows system pipes that legitimately contain blacklisted tokens as substrings.
    // "epmapper" → "MAPPER" (RPC Endpoint Mapper, created by RPCSS).
    static const std::unordered_set<std::string> kSafeSystemPipes = {
        "EPMAPPER",  // RPC Endpoint Mapper (RPCSS — used by COM/DCOM/.NET/VS)
        "LSARPC",    // Local Security Authority RPC
        "SAMR",      // Security Account Manager remote
        "NTSVCS",    // NT Services
        "SVCCTL",    // Service Control Manager
        "WINREG",    // Remote Registry
        "WKSSVC",    // Workstation Service
        "SRVSVC",    // Server Service
    };

    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do {
        std::string nameUp = fd.cFileName;
        std::transform(nameUp.begin(), nameUp.end(), nameUp.begin(),
                       [](unsigned char c) { return (unsigned char)toupper(c); });
        if (kSafeSystemPipes.count(nameUp) > 0)
            continue;
        for (int i = 0; kPipeTokens[i]; ++i) {
            if (nameUp.find(kPipeTokens[i]) != std::string::npos) {
                AddGenericBypassFinding(out, ScanTag::NamedPipe, "-",
                    std::string("\\\\.\\pipe\\") + fd.cFileName,
                    "suspicious named pipe detected: " + std::string(fd.cFileName),
                    "MEDIUM");
                break;
            }
        }
    } while (FindNextFileA(h, &fd) && out.size() < 160);

    FindClose(h);
}

// WSAPROTOCOL_INFOW forward declaration to avoid including ws2spi.h which conflicts with windows.h
#ifndef WSAPROTOCOL_LEN
#define WSAPROTOCOL_LEN  255
struct WSAPROTOCOL_INFOW_COMPAT {
    DWORD   dwServiceFlags1;
    DWORD   dwServiceFlags2;
    DWORD   dwServiceFlags3;
    DWORD   dwServiceFlags4;
    DWORD   dwProviderFlags;
    GUID    ProviderId;
    DWORD   dwCatalogEntryId;
    DWORD   ProtocolChain[8];   // WSAPROTOCOLCHAIN is 4+8*4 = 36 bytes but we just need the entry
    int     iVersion;
    int     iAddressFamily;
    int     iMaxSockAddr;
    int     iMinSockAddr;
    int     iSocketType;
    int     iProtocol;
    int     iProtocolMaxOffset;
    int     iNetworkByteOrder;
    int     iSecurityScheme;
    DWORD   dwMessageSize;
    DWORD   dwProviderReserved;
    wchar_t szProtocol[WSAPROTOCOL_LEN + 1];
};
using WSCEnumProtocolsFn    = int  (WINAPI*)(LPINT, WSAPROTOCOL_INFOW_COMPAT*, LPDWORD, LPINT);
using WSCGetProviderPathFn  = int  (WINAPI*)(LPGUID, WCHAR*, LPINT, LPINT);
#endif

// Check Winsock LSP chain for non-Microsoft providers (hijack indicator).
// Uses GetProcAddress to avoid header conflicts with ws2spi.h.
static void CollectLspFindings(std::vector<ScannerUI::GenericBypassFinding>& out) {
    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryW(L"ws2_32.dll");
    if (!ws2) return;

    auto WSCEnum    = reinterpret_cast<WSCEnumProtocolsFn>(GetProcAddress(ws2, "WSCEnumProtocols"));
    auto WSCGetPath = reinterpret_cast<WSCGetProviderPathFn>(GetProcAddress(ws2, "WSCGetProviderPath"));
    if (!WSCEnum)
        return;

    DWORD bufLen = 0;
    int err = 0;
    WSCEnum(nullptr, nullptr, &bufLen, &err);
    if (bufLen == 0)
        return;

    std::vector<uint8_t> buf(bufLen);
    auto* proto = reinterpret_cast<WSAPROTOCOL_INFOW_COMPAT*>(buf.data());
    int count = WSCEnum(nullptr, proto, &bufLen, &err);
    if (count <= 0)
        return;

    for (int i = 0; i < count; ++i) {
        const auto& p = proto[i];

        // Primary filter: cryptographic — resolve the provider DLL path via the
        // provider GUID and verify Authenticode + location. This correctly exempts
        // legitimate Windows features like "Hyper-V RAW" and "AF_UNIX" (WSL) whose
        // backing DLLs are Microsoft-signed in System32, regardless of protocol name.
        if (WSCGetPath) {
            WCHAR dllBuf[MAX_PATH * 2] = {};
            INT   dllLen = (INT)std::size(dllBuf);
            INT   wsaErr = 0;
            GUID  guid   = p.ProviderId;
            if (WSCGetPath(&guid, dllBuf, &dllLen, &wsaErr) == 0) {
                wchar_t expanded[MAX_PATH * 2] = {};
                ExpandEnvironmentStringsW(dllBuf, expanded, (DWORD)std::size(expanded));
                std::wstring dllPath = expanded;
                auto cls = DetectionFilter::ClassifyPath(dllPath);
                if (cls == DetectionFilter::PathClass::SystemTrusted &&
                    DetectionFilter::IsTrustedSignedCached(dllPath))
                    continue;  // Microsoft-signed DLL in System32 → legitimate Windows LSP
            }
        }

        // Fallback name-based filter (when WSCGetProviderPath unavailable or fails).
        std::wstring provNameUp = DetectionFilter::UpperW(std::wstring(p.szProtocol));
        if (provNameUp.find(L"MICROSOFT") != std::wstring::npos ||
            provNameUp.find(L"MSWSOCK")   != std::wstring::npos ||
            provNameUp.find(L"RSVP")      != std::wstring::npos ||
            provNameUp.find(L"MSAFD")     != std::wstring::npos)
            continue;

        std::string detail = "non-Microsoft LSP detected: \"" + WideToUtf8(p.szProtocol) + "\"";
        detail += " | catalog_entry=" + std::to_string(p.dwCatalogEntryId);
        AddGenericBypassFinding(out, ScanTag::Lsp, "-", WideToUtf8(p.szProtocol), detail, "MEDIUM");
        if (out.size() >= 160)
            break;
    }
}

std::vector<ScannerUI::GenericBypassFinding> CollectGenericBypassFindings(std::string& status) {
    std::vector<ScannerUI::GenericBypassFinding> findings;
    ScanNtdllStubIntegrity(findings);        // NTDLL hook detection (internal)
    CollectHdPlayerExternalHandles(findings);
    CollectGraphicsHookFindings(findings);   // content-based, no name/path filter
    ScanIatHooks(findings);                  // IAT hook in emulator processes
    ScanVulkanLayers(findings);              // Vulkan implicit layer abuse
    ScanDxgiVtableIntegrity(findings);       // D3D/DXGI VTable overwrite
    ScanDuplicateGraphicsModules(findings);  // duplicated/sideloaded opengl32/d3d9/dxgi/...
    ScanGraphicsStringsInAnonMemory(findings); // chams loader em RWX privado fora de modulo
    ScanThreadsWithGraphicsContext(findings);  // threads cujo start carrega strings de OpenGL/WGL
    CollectSuspiciousNamedPipes(findings);
    CollectLspFindings(findings);
    CollectAntivirusExclusionFindings(findings);
    CollectAntivirusRemovalFindings(findings);
    CollectGenericBypassEventLogs(findings);

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        int ra = DetectionFilter::SeverityRank(a.severity);
        int rb = DetectionFilter::SeverityRank(b.severity);
        if (ra != rb) return ra < rb;
        if (a.date != b.date) return a.date > b.date;
        return a.time > b.time;
    });
    status = findings.empty() ? "No generic bypass indicators" : "Review indicators";

    return findings;
}
