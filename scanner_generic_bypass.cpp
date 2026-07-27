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

// Richer overload carrying rule/confidence/evidence metadata for detectors that classify
// destinations by trust tier (signed vs unsigned vs unresolved) rather than a flat severity.
static void AddGenericBypassFinding(std::vector<ScannerUI::GenericBypassFinding>& out,
                                    const std::string& type,
                                    const std::string& process,
                                    const std::string& target,
                                    const std::string& detail,
                                    const std::string& severity,
                                    const std::string& ruleId,
                                    const std::string& confidence,
                                    const std::string& evidenceState,
                                    const std::string& source = "scanner_generic_bypass",
                                    const FILETIME* eventTime = nullptr) {
    if (out.size() >= ScanLimits::kMaxBypassFindings)
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
    finding.ruleId = ruleId;
    finding.confidence = confidence;
    finding.evidenceState = evidenceState;
    finding.source = source;
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

    const SystemHandleSnapshot& handleSnapshot = GetSystemHandleSnapshot();
    if (!handleSnapshot.ok)
        return;

    const auto* info = handleSnapshot.Info();
    std::unordered_set<std::string> seen;
    size_t paceCounter = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles && out.size() < 160; ++i) {
        MaybePaceIteration(paceCounter, 4096);
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

static bool IsWildcardOrRootAvExclusion(const std::wstring& up) {
    return up.find(L"*") != std::wstring::npos || up == L"C:\\" || up == L"C:" ||
           up == L"\\" || up == L"%SYSTEMDRIVE%\\" || up == L"%SYSTEMDRIVE%";
}

static bool IsWritablePathTokenAvExclusion(const std::wstring& up) {
    static const wchar_t* riskyTokens[] = {
        L"\\USERS\\", L"\\APPDATA\\", L"\\TEMP", L"\\TMP",
        L"\\DOWNLOADS", L"\\DESKTOP", L"\\PROGRAMDATA\\",
        L"\\PUBLIC\\", L"\\DOCUMENTS", nullptr
    };
    for (const wchar_t** token = riskyTokens; *token; ++token)
        if (up.find(*token) != std::wstring::npos) return true;
    return false;
}

// Samples up to kMaxSample .exe files directly under `dir` (and its \bin, \x64, \x86
// subfolders, if present) and returns true as soon as one is genuinely Authenticode/
// catalog signed (reuses IsTrustedSignedCached — real WinVerifyTrust chain validation,
// not a name/path heuristic). This excuses the EXCLUSION as pointing at a currently
// installed, verifiably-signed piece of software; it does not excuse any other
// individual unsigned file that may also live in that folder (those remain subject to
// every other scanner in the codebase).
static bool DirectoryHasTrustedSignedExecutable(const std::wstring& dir) {
    static const wchar_t* kSubdirs[] = { L"", L"\\bin", L"\\x64", L"\\x86", nullptr };
    constexpr int kMaxSample = 40;
    int sampled = 0;
    for (int si = 0; kSubdirs[si] && sampled < kMaxSample; ++si) {
        std::wstring probeDir = dir + kSubdirs[si];
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW((probeDir + L"\\*.exe").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (++sampled > kMaxSample) break;
            if (DetectionFilter::IsTrustedSignedCached(probeDir + L"\\" + fd.cFileName)) {
                FindClose(h);
                return true;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return false;
}

enum class AvExclusionRisk {
    BroadOrRoot, WritableUnsigned, WritableSignedVendor,
    OtherUnsigned, OtherSignedVendor, Nonexistent
};

static AvExclusionRisk ClassifyAvExclusionTarget(const std::wstring& rawPath, std::wstring& expandedOut) {
    std::wstring expanded = ExpandEnvPathW(rawPath);
    expandedOut = expanded;
    std::wstring up = ToUpperInvariant(expanded);
    if (up.empty() || IsWildcardOrRootAvExclusion(up))
        return AvExclusionRisk::BroadOrRoot;

    bool writable = IsWritablePathTokenAvExclusion(up);
    DWORD attrs = GetFileAttributesW(expanded.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return AvExclusionRisk::Nonexistent;

    bool hasTrustedContent = (attrs & FILE_ATTRIBUTE_DIRECTORY)
        ? DirectoryHasTrustedSignedExecutable(expanded)
        : DetectionFilter::IsTrustedSignedCached(expanded);

    if (writable)
        return hasTrustedContent ? AvExclusionRisk::WritableSignedVendor : AvExclusionRisk::WritableUnsigned;
    return hasTrustedContent ? AvExclusionRisk::OtherSignedVendor : AvExclusionRisk::OtherUnsigned;
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

        std::wstring expandedForClass;
        AvExclusionRisk risk = ClassifyAvExclusionTarget(raw, expandedForClass);
        std::string target = WideToUtf8(expanded.empty() ? raw : expanded);
        std::string detail = std::string("Microsoft Defender path exclusion detected")
            + " | source=" + source
            + " | path=" + target;
        if (expanded != raw)
            detail += " | raw=" + WideToUtf8(raw);

        std::string sev, conf, evState, ruleId;
        switch (risk) {
        case AvExclusionRisk::BroadOrRoot:
            sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
            ruleId = "AV.EXCLUSION.WILDCARD_OR_ROOT";
            break;
        case AvExclusionRisk::WritableUnsigned:
            sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
            ruleId = "AV.EXCLUSION.WRITABLE_PATH_UNVERIFIED";
            break;
        case AvExclusionRisk::WritableSignedVendor:
            sev = "MEDIUM"; conf = "MEDIUM"; evState = "TRUSTED_THIRD_PARTY";
            ruleId = "AV.EXCLUSION.WRITABLE_PATH_SIGNED_VENDOR";
            detail += " | conteudo assinado encontrado - ainda em pasta gravavel pelo usuario";
            break;
        case AvExclusionRisk::OtherUnsigned:
            sev = "MEDIUM"; conf = "MEDIUM"; evState = "REVIEW";
            ruleId = "AV.EXCLUSION.PATH_UNVERIFIED";
            break;
        case AvExclusionRisk::OtherSignedVendor:
            sev = "FLAG"; conf = "HIGH"; evState = "TRUSTED_THIRD_PARTY";
            ruleId = "AV.EXCLUSION.PATH_SIGNED_VENDOR";
            detail += " | conteudo assinado verificado (provavel software legitimo)";
            break;
        case AvExclusionRisk::Nonexistent:
            sev = "MEDIUM"; conf = "LOW"; evState = "INCONCLUSIVE";
            ruleId = "AV.EXCLUSION.PATH_NOT_FOUND";
            detail += " | caminho nao existe atualmente (regra obsoleta ou pre-configurada)";
            break;
        }

        AddGenericBypassFinding(out, ScanTag::AvExclusion, "Microsoft Defender",
                                target, detail, sev, ruleId, conf, evState);
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
// ─── Hook-destination trust classification ────────────────────────────────────
// Shared trust tiering used by CollectGraphicsHookFindings and ScanDxgiVtableIntegrity
// (ScanIatHooks calls DetectionFilter::ResolveModuleTrustAtAddress directly since it has
// no "does the destination itself export a graphics symbol" concept). A destination is
// only ever fully suppressed (LayeredTrustedGfx) when it lands back in the same module,
// or in a module that is BOTH signed AND itself exports a graphics symbol — otherwise it
// is still reported, just at a severity/confidence reflecting the partial trust evidence.
enum class HookDestTrust { LayeredTrustedGfx, SignedNonGfx, Unsigned, Unresolved };

struct HookDestVerdict {
    HookDestTrust trust = HookDestTrust::Unresolved;
    std::wstring  resolvedPath;
};

static HookDestVerdict ClassifyHookDestination(HANDLE process, uintptr_t destAddr,
                                               const std::vector<ModuleRange>& modules,
                                               const std::wstring& sourceModulePath) {
    HookDestVerdict v;
    for (const auto& m : modules) {
        if (destAddr < m.begin || destAddr >= m.end) continue;
        v.resolvedPath = m.path;
        if (!sourceModulePath.empty() && m.path == sourceModulePath) {
            v.trust = HookDestTrust::LayeredTrustedGfx;  // self-referential thunk
            return v;
        }
        if (DetectionFilter::IsTrustedSignedCached(m.path)) {
            BYTE dh[4096] = {}; SIZE_T dg = 0;
            ReadProcessMemory(process, (LPCVOID)m.begin, dh, sizeof(dh), &dg);
            v.trust = DetectionFilter::ExportsGraphicsSymbol(dh, dg, m.begin)
                      ? HookDestTrust::LayeredTrustedGfx : HookDestTrust::SignedNonGfx;
        } else {
            v.trust = HookDestTrust::Unsigned;
        }
        return v;
    }
    // Not in the (possibly stale) module snapshot — resolve live.
    auto resolved = DetectionFilter::ResolveModuleTrustAtAddress(process, destAddr);
    v.resolvedPath = resolved.path;
    if (!resolved.resolved) { v.trust = HookDestTrust::Unresolved; return v; }
    if (!resolved.signedTrusted) { v.trust = HookDestTrust::Unsigned; return v; }
    v.trust = resolved.exportsGraphics ? HookDestTrust::LayeredTrustedGfx : HookDestTrust::SignedNonGfx;
    return v;
}

// Maps a trust tier to (severity, ruleId, confidence, evidenceState). Callers must skip
// emission entirely on LayeredTrustedGfx — the only tier backed by both cryptographic
// trust AND content evidence.
static void SeverityForHookDest(HookDestTrust t, const char* ruleFamily,
                                std::string& sev, std::string& ruleId,
                                std::string& conf, std::string& evState) {
    switch (t) {
    case HookDestTrust::SignedNonGfx:
        sev = "FLAG"; conf = "MEDIUM"; evState = "TRUSTED_THIRD_PARTY";
        ruleId = std::string(ruleFamily) + ".SIGNED_NONGFX_DEST";
        break;
    case HookDestTrust::Unsigned:
        sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
        ruleId = std::string(ruleFamily) + ".UNSIGNED_DEST";
        break;
    case HookDestTrust::Unresolved:
    default:
        sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
        ruleId = std::string(ruleFamily) + ".ANON_DEST";
        break;
    }
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
        "glDrawRangeElements", "glBindTexture", "glUseProgram", "glUniform4f",
        "glUniform4fv", "glEnable", "glDisable", "glBlendFunc", "glStencilFunc",
        "glPolygonMode", "eglSwapBuffers", "eglMakeCurrent", "eglGetProcAddress",
        "SwapBuffers", "D3D11CreateDevice",
        "D3D11CreateDeviceAndSwapChain", "CreateDXGIFactory",
        "CreateDXGIFactory1", "CreateDXGIFactory2",
        "vkQueuePresentKHR", "vkCmdDraw", "vkCmdDrawIndexed",
        "vkCreateGraphicsPipelines", "wglGetProcAddress", "glGetProcAddress",
        nullptr
    };

    for (const auto& module : modules) {
        if (module.path.empty()) continue;

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
                "glDrawRangeElements", "glBindTexture", "glUseProgram", "glUniform4f",
                "glUniform4fv", "glEnable", "glDisable", "glBlendFunc", "glStencilFunc",
                "glPolygonMode", "eglSwapBuffers", "eglMakeCurrent", "eglGetProcAddress",
                "SwapBuffers", "D3D11CreateDevice",
                "D3D11CreateDeviceAndSwapChain", "CreateDXGIFactory",
                "CreateDXGIFactory1", "CreateDXGIFactory2",
                "vkQueuePresentKHR", "vkCmdDraw", "vkCmdDrawIndexed",
                "vkCreateGraphicsPipelines", "wglGetProcAddress", "glGetProcAddress",
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

                HookDestVerdict destV = ClassifyHookDestination(process, chainEnd, modules, module.path);
                if (destV.trust == HookDestTrust::LayeredTrustedGfx) continue; // legitimate layering

                char funcBuf[32], chainBuf[32];
                snprintf(funcBuf,  sizeof(funcBuf),  "0x%llX", (unsigned long long)funcAddr);
                snprintf(chainBuf, sizeof(chainBuf), "0x%llX", (unsigned long long)chainEnd);

                std::string sev, ruleId, conf, evState;
                SeverityForHookDest(destV.trust, "GFX.HOOK", sev, ruleId, conf, evState);

                std::string detail = "hook em funcao grafica: " + std::string(fnName) +
                                     " | modulo=" + WideToUtf8(modName) +
                                     " | signed=" + (modSigned ? "yes" : "no") +
                                     " | func=" + funcBuf + " -> chain_end=" + chainBuf +
                                     " | destino=" + (destV.trust == HookDestTrust::Unresolved
                                          ? "memoria anonima/sem arquivo mapeado"
                                          : WideToUtf8(destV.resolvedPath) +
                                            (destV.trust == HookDestTrust::SignedNonGfx
                                             ? " (assinado, sem exports graficos - possivel shim de overlay/captura)"
                                             : " (nao assinado)"));
                // Diagnostic annotation (informational only — not a trust signal)
                if (DetectionFilter::IsNamedLikeGraphicsRuntime(modName))
                    detail += " | nota: nome similar a runtime grafico";
                else if (DetectionFilter::IsNamedLikeOverlay(modName))
                    detail += " | nota: nome similar a overlay";

                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(module.path), detail, sev, ruleId, conf, evState);
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
            AddGenericBypassFinding(out, ScanTag::ThreadProtect, "ntdll.dll", std::string(fnName), detail,
                                    "HIGH", "NTDLL.HOOK.UNSIGNED_OR_UNRESOLVED_DEST", "HIGH", "SUSPICIOUS");
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

                    // Outside the (possibly stale) module snapshot — resolve live before deciding
                    // trust. A late-loaded or manually-mapped-but-signed DLL is common for
                    // legitimate overlay/anti-cheat/RGB software hooking exactly these APIs
                    // (CreateRemoteThread, VirtualAlloc*, WriteProcessMemory...); "outside the
                    // snapshot" alone is not equivalent to shellcode.
                    auto destTrust = DetectionFilter::ResolveModuleTrustAtAddress(process, resolved);

                    std::string key = std::to_string(pid) + ":" + std::to_string(module.begin) + ":" + std::to_string(ei);
                    if (!seenIat.insert(key).second) continue;

                    char addrBuf[32];
                    snprintf(addrBuf, sizeof(addrBuf), "0x%llX", (unsigned long long)resolved);
                    std::string detail = "IAT hook: " + std::string(importName) +
                                         " em " + WideToUtf8(BaseNameFromPath(module.path)) +
                                         " -> addr " + addrBuf;

                    std::string sev, conf, evState, ruleId;
                    if (destTrust.resolved && destTrust.signedTrusted) {
                        sev = "FLAG"; conf = "MEDIUM"; evState = "TRUSTED_THIRD_PARTY";
                        ruleId = "GFX.IAT.SIGNED_UNLISTED_DEST";
                        detail += " | destino assinado, fora do snapshot de modulos: " + WideToUtf8(destTrust.path);
                    } else if (destTrust.resolved) {
                        sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
                        ruleId = "GFX.IAT.UNSIGNED_DEST";
                        detail += " | destino NAO assinado: " + WideToUtf8(destTrust.path);
                    } else {
                        sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
                        ruleId = "GFX.IAT.ANON_DEST";
                        detail += " | destino em memoria anonima (sem arquivo mapeado)";
                    }
                    AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                           WideToUtf8(module.path), detail, sev, ruleId, conf, evState);
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

                        MEMORY_BASIC_INFORMATION mbi = {};
                        if (VirtualQueryEx(process, (LPCVOID)ptr, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
                        if (mbi.State != MEM_COMMIT || !IsExecProtect(mbi.Protect)) continue;

                        HookDestVerdict destV = ClassifyHookDestination(process, ptr, modules, module.path);
                        if (destV.trust == HookDestTrust::LayeredTrustedGfx) continue;

                        std::string sev, ruleId, conf, evState;
                        SeverityForHookDest(destV.trust, "GFX.VTABLE", sev, ruleId, conf, evState);

                        char entryBuf[32], tgtBuf[32];
                        snprintf(entryBuf, sizeof(entryBuf), "0x%llX", (unsigned long long)(secBase + off + pos));
                        snprintf(tgtBuf,   sizeof(tgtBuf),   "0x%llX", (unsigned long long)ptr);
                        std::string detail = "VTable/RDATA pointer redireciona fora do modulo: " +
                                             WideToUtf8(BaseNameFromPath(module.path)) +
                                             " | entry=" + entryBuf + " -> " + tgtBuf +
                                             " | mem=" + (mbi.Type == MEM_PRIVATE ? "anonima" : "mapeada") +
                                             (destV.trust == HookDestTrust::SignedNonGfx
                                              ? " | destino assinado sem exports graficos: " + WideToUtf8(destV.resolvedPath)
                                              : "");
                        AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                               WideToUtf8(module.path), detail, sev, ruleId, conf, evState);
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
                bool anyUnsigned = false;
                bool anySignedUntrustedDir = false;
                for (const auto* m : kv.second) {
                    bool sgn = DetectionFilter::IsTrustedSignedCached(m->path);
                    auto cls = DetectionFilter::ClassifyPath(m->path);
                    if (!sgn) anyUnsigned = true;
                    else if (!DetectionFilter::IsTrustedDir(cls)) anySignedUntrustedDir = true;
                }
                if (!anyUnsigned && !anySignedUntrustedDir) continue;

                std::string paths;
                for (size_t i = 0; i < kv.second.size(); ++i) {
                    if (i) paths += " ; ";
                    paths += WideToUtf8(kv.second[i]->path);
                }
                std::string detail = "DLL do Windows duplicada: " + WideToUtf8(upName) +
                                     " carregada " + std::to_string(kv.second.size()) +
                                     "x | paths=" + paths;
                std::string sev     = anyUnsigned ? "HIGH"       : "MEDIUM";
                std::string conf    = anyUnsigned ? "HIGH"       : "MEDIUM";
                std::string evState = anyUnsigned ? "SUSPICIOUS" : "REVIEW";
                std::string ruleId  = anyUnsigned ? "GFX.DUPLICATE.MULTILOAD_UNSIGNED"
                                                   : "GFX.DUPLICATE.MULTILOAD_SIGNED_UNTRUSTED_DIR";
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(upName), detail, sev, ruleId, conf, evState);
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
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath, WideToUtf8(m->path), detail,
                                        "HIGH", "GFX.DUPLICATE.BUNDLED_UNSIGNED", "HIGH", "SUSPICIOUS");
                if (out.size() >= ScanLimits::kMaxBypassFindings) break;
                continue;
            }

            // STRICT list policy: any copy outside System32/SysWOW64/WinSxS is suspect.
            //   - Unsigned                                      -> HIGH  (real hijack risk)
            //   - Signed + side-by-side + SAME publisher as exe  -> already exempted above (samePub)
            //   - Signed + side-by-side + DIFFERENT publisher    -> MEDIUM (plausible legit
            //         third-party DLL-proxy tool; still a genuine hijack technique, so not
            //         downgraded further even though signed)
            //   - Signed, NOT side-by-side                       -> MEDIUM
            std::string detail = std::string("DLL do Windows fora do System32 (search-order hijack): ") +
                                 WideToUtf8(upName) +
                                 " | path=" + WideToUtf8(m->path) +
                                 " | signed=" + (signedMod ? "yes" : "no") +
                                 (sideBySide ? " | LADO A LADO COM O EXE (DLL hijack)" : "");
            std::string sev     = !signedMod ? "HIGH" : "MEDIUM";
            std::string conf    = !signedMod ? "HIGH" : "MEDIUM";
            std::string evState = !signedMod ? "SUSPICIOUS" : "REVIEW";
            std::string ruleId  = !signedMod ? "GFX.DUPLICATE.STRICT_UNSIGNED"
                                 : (sideBySide ? "GFX.DUPLICATE.STRICT_SIGNED_THIRDPARTY_SIDEBYSIDE"
                                                : "GFX.DUPLICATE.STRICT_SIGNED_ELSEWHERE");
            AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                    WideToUtf8(m->path), detail, sev, ruleId, conf, evState);
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
                std::string sev     = signedFile ? "MEDIUM" : "HIGH";
                std::string conf    = signedFile ? "MEDIUM" : "HIGH";
                std::string evState = signedFile ? "REVIEW" : "SUSPICIOUS";
                std::string ruleId  = signedFile ? "GFX.DUPLICATE.STAGED_SIGNED" : "GFX.DUPLICATE.STAGED_UNSIGNED";
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        WideToUtf8(candidate), detail, sev, ruleId, conf, evState);
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

        // Cross-reference: if this exact allocation is ALSO a confirmed JMP-hook destination
        // on a graphics API export (same collector wired into scanner_processes.cpp's
        // injection scanners), the string-based classification below is corroborated by an
        // independent structural signal and can stay at full severity. Without corroboration,
        // string-only matches are downgraded: legitimate DLL-injection overlay tools resolve
        // gl*/wgl*/d3d* symbols by name from a small anonymous stub by design — this looks
        // identical to a cheat loader on strings alone.
        auto gfxHookDests = CollectGfxHookDestBases(process, modules);

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
                            bool corroborated = !gfxHookDests.empty() && gfxHookDests.count(allocBase) > 0;
                            char addrBuf[32];
                            snprintf(addrBuf, sizeof(addrBuf), "0x%llX",
                                     (unsigned long long)(uintptr_t)mbi.BaseAddress);
                            std::string detail =
                                std::string("loader grafico em memoria anonima fora de modulo")
                                + " | base=" + addrBuf
                                + " | size=" + std::to_string((unsigned long long)mbi.RegionSize)
                                + " | loader_dll=" + (s.loaderEvidence ? "yes" : "no")
                                + " | funcs=" + std::to_string(s.distinctNeedles)
                                + " | first=\"" + (s.firstMatch ? s.firstMatch : "?") + "\""
                                + (corroborated ? " | CONFIRMADO: destino de hook grafico" : "");

                            std::string sev, conf, evState, ruleId;
                            if (corroborated) {
                                sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
                                ruleId = "GFX.ANONMEM.CONFIRMED_HOOK_DEST";
                            } else if (flagHigh) {
                                sev = "MEDIUM"; conf = "MEDIUM"; evState = "REVIEW";
                                ruleId = "GFX.ANONMEM.LOADER_STRINGS_ONLY";
                            } else {
                                sev = "MEDIUM"; conf = "LOW"; evState = "INCONCLUSIVE";
                                ruleId = "GFX.ANONMEM.NEEDLES_ONLY";
                            }
                            AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                                    addrBuf, detail, sev, ruleId, conf, evState);
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

        // See ScanGraphicsStringsInAnonMemory for rationale: corroborate string-only
        // classification against confirmed graphics-hook destinations before trusting it
        // at full severity.
        auto gfxHookDests = CollectGfxHookDestBases(process, modules);

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

                bool corroborated = !gfxHookDests.empty() && gfxHookDests.count(allocBase) > 0;
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
                    + " | first=\"" + (s.firstMatch ? s.firstMatch : "?") + "\""
                    + (corroborated ? " | CONFIRMADO: destino de hook grafico" : "");

                std::string sev, conf, evState, ruleId;
                if (corroborated) {
                    sev = "HIGH"; conf = "HIGH"; evState = "SUSPICIOUS";
                    ruleId = "GFX.ANONMEM.CONFIRMED_HOOK_DEST";
                } else if (flagHigh) {
                    sev = "MEDIUM"; conf = "MEDIUM"; evState = "REVIEW";
                    ruleId = "GFX.ANONMEM.LOADER_STRINGS_ONLY";
                } else {
                    sev = "MEDIUM"; conf = "LOW"; evState = "INCONCLUSIVE";
                    ruleId = "GFX.ANONMEM.NEEDLES_ONLY";
                }
                AddGenericBypassFinding(out, ScanTag::GfxHook, procPath,
                                        startBuf, detail, sev, ruleId, conf, evState);
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

struct SysmonStructuralRecord {
    ULONGLONG time = 0;
    ULONGLONG recordId = 0;
    FILETIME fileTime = {};
    int eventId = 0;
    std::wstring state;
};

static void CollectSysmonAvailabilityGaps(std::vector<ScannerUI::GenericBypassFinding>& out) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return;

    SC_HANDLE service = OpenServiceW(scm, L"Sysmon64", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service)
        service = OpenServiceW(scm, L"Sysmon", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        CloseServiceHandle(scm);
        return;
    }

    SERVICE_STATUS_PROCESS serviceStatus = {};
    DWORD needed = 0;
    bool running = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                        reinterpret_cast<LPBYTE>(&serviceStatus),
                                        sizeof(serviceStatus), &needed) &&
                   serviceStatus.dwCurrentState == SERVICE_RUNNING;
    if (!running) {
        AddGenericBypassFinding(out, ScanTag::Sysmon, "Sysmon service",
                                "Sysmon Operational",
                                "gap de telemetria: servico do Sysmon existe, mas nao esta em execucao",
                                "HIGH", "SYSMON.SERVICE_NOT_RUNNING", "HIGH", "SUSPICIOUS",
                                "Service Control Manager");
    }

    DWORD configBytes = 0;
    QueryServiceConfigW(service, nullptr, 0, &configBytes);
    if (configBytes > 0) {
        std::vector<BYTE> buffer(configBytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (QueryServiceConfigW(service, config, configBytes, &configBytes) &&
            config->dwStartType == SERVICE_DISABLED) {
            AddGenericBypassFinding(out, ScanTag::Sysmon, "Sysmon service",
                                    "Sysmon Operational",
                                    "gap de telemetria: servico do Sysmon esta desabilitado",
                                    "HIGH", "SYSMON.SERVICE_DISABLED", "HIGH", "SUSPICIOUS",
                                    "Service Control Manager");
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

static bool SysmonStateContains(const std::wstring& state, const wchar_t* token) {
    return ToUpperInvariant(state).find(token) != std::wstring::npos;
}

static void CollectSysmonStructuralGaps(std::vector<ScannerUI::GenericBypassFinding>& out) {
    constexpr const wchar_t* kChannel = L"Microsoft-Windows-Sysmon/Operational";
    EVT_HANDLE query = EvtQuery(nullptr, kChannel, L"*",
                                EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query)
        return;

    const ULONGLONG boot = FileTimeToU64(GetBootFileTime());
    std::vector<SysmonStructuralRecord> records;
    records.reserve(2048);
    EVT_HANDLE events[32] = {};
    DWORD returned = 0;
    bool reachedBoot = false;

    while (!reachedBoot && records.size() < 8192 &&
           EvtNext(query, (DWORD)std::size(events), events,
                   ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            std::wstring xml;
            bool rendered = RenderEventXml(events[i], xml);
            EvtClose(events[i]);
            events[i] = nullptr;
            if (!rendered)
                continue;

            FILETIME eventTime = {};
            std::wstring systemTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
            if (!SysmonSystemTimeToFileTime(systemTime, eventTime))
                continue;
            ULONGLONG eventValue = FileTimeToU64(eventTime);
            if (eventValue < boot) {
                reachedBoot = true;
                break;
            }

            std::wstring recordText = ExtractXmlTag(xml, L"EventRecordID");
            wchar_t* end = nullptr;
            ULONGLONG recordId = _wcstoui64(recordText.c_str(), &end, 10);
            if (recordText.empty() || end == recordText.c_str())
                continue;

            SysmonStructuralRecord record;
            record.time = eventValue;
            record.recordId = recordId;
            record.fileTime = eventTime;
            record.eventId = _wtoi(ExtractXmlTag(xml, L"EventID").c_str());
            if (record.eventId == 4)
                record.state = ExtractSysmonData(xml, L"State");
            records.push_back(std::move(record));
        }
    }
    EvtClose(query);

    if (records.size() < 2)
        return;
    std::reverse(records.begin(), records.end());

    size_t emitted = 0;
    ULONGLONG stoppedAt = 0;
    FILETIME stoppedFileTime = {};
    for (size_t i = 0; i < records.size() && emitted < 12; ++i) {
        const auto& current = records[i];
        if (i > 0) {
            const auto& previous = records[i - 1];
            if (current.recordId > previous.recordId + 1) {
                ULONGLONG missing = current.recordId - previous.recordId - 1;
                std::string detail =
                    "gap estrutural no Sysmon: EventRecordID " + std::to_string(previous.recordId) +
                    " -> " + std::to_string(current.recordId) +
                    " | registros_ausentes=" + std::to_string(missing);
                AddGenericBypassFinding(out, ScanTag::Sysmon, "Sysmon64.exe",
                                        WideToUtf8(kChannel), detail, "HIGH",
                                        "SYSMON.RECORD_ID_GAP", "HIGH", "SUSPICIOUS",
                                        "Sysmon Operational", &current.fileTime);
                ++emitted;
            }
        }

        if (current.eventId != 4)
            continue;
        const bool stopped = SysmonStateContains(current.state, L"STOP") ||
                             SysmonStateContains(current.state, L"PARAD") ||
                             SysmonStateContains(current.state, L"INTERROMP");
        const bool started = SysmonStateContains(current.state, L"START") ||
                             SysmonStateContains(current.state, L"RUNNING") ||
                             SysmonStateContains(current.state, L"INICIAD") ||
                             SysmonStateContains(current.state, L"EXECUCAO");
        if (stopped) {
            stoppedAt = current.time;
            stoppedFileTime = current.fileTime;
        } else if (started && stoppedAt != 0 && current.time > stoppedAt) {
            ULONGLONG gapSeconds = (current.time - stoppedAt) / 10000000ULL;
            if (gapSeconds >= 2) {
                std::string detail = "gap de telemetria do Sysmon entre stop/start | duracao=" +
                                     std::to_string(gapSeconds) + "s";
                AddGenericBypassFinding(out, ScanTag::Sysmon, "Sysmon64.exe",
                                        WideToUtf8(kChannel), detail, "HIGH",
                                        "SYSMON.SERVICE_GAP", "HIGH", "SUSPICIOUS",
                                        "Sysmon Event 4", &stoppedFileTime);
                ++emitted;
            }
            stoppedAt = 0;
            stoppedFileTime = {};
        }
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
    CollectSysmonAvailabilityGaps(findings);
    CollectSysmonStructuralGaps(findings);

    // Backstop for detectors intentionally left out of scope for this precision pass
    // (named pipes, LSP, event-log/sysmon handlers, AV removal, HD-Player external
    // handles) — mirrors the fallback convention in scanner_files.cpp. Only fills
    // fields left empty by the detector, so it's a no-op for everything above.
    for (auto& finding : findings) {
        if (finding.ruleId.empty())
            finding.ruleId = "GENERIC_BYPASS." + finding.type;
        if (finding.source.empty())
            finding.source = "scanner_generic_bypass";
        if (finding.confidence.empty())
            finding.confidence = (finding.severity == "HIGH") ? "MEDIUM" : "LOW";
        if (finding.evidenceState.empty())
            finding.evidenceState = (finding.severity == "HIGH") ? "SUSPICIOUS" : "REVIEW";
    }

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
