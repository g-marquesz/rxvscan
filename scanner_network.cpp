// Remote-port listener detector (anti-panel-remoto).
// Layered defense: enumerate sockets → canonicalize path → path-mimicry →
// trust pin by root thumbprint → interpreter unwrap (PEB read) → SCM map
// for svchost family → parent chain → firewall + tunnel cross-check → classify.

// Winsock2 must be visible before windows.h (pulled in by scanner_core.h).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "scanner_core.h"

#include <netfw.h>
#include <oleauto.h>
#include <mscat.h>
#include <fwpmu.h>
#include <setupapi.h>
#include <devguid.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "setupapi.lib")

namespace {

// ─── Pinned root CA thumbprints (SHA-1, lowercase as GetSignerRootThumbprint returns) ───
// Microsoft Root Certificate Authority 2010 (signs most modern Windows binaries).
constexpr const char* kMsRoot2010 = "3b1efd3a66ea28b16697394703a72ca340a05bd5";
// Microsoft Root Certificate Authority 2011.
constexpr const char* kMsRoot2011 = "8f43288ad272f3103b6fb1428485ea3014c0bcfe";

// ─── Catalog hash lookup ────────────────────────────────────────────────
// Direct query against the Windows Security Catalog Database. Returns true
// when the file's cryptographic hash is registered in any installed catalog,
// meaning Windows itself vouches for these exact bytes. Survives revocation-
// cache failures that break WinVerifyTrust's catalog provider (the root cause
// of spoolsv.exe appearing UNSIGNED on PCs with stale CRL state).
//
// Path-agnostic by design: the lookup key is the file hash, not the location.
// An attacker copying a legitimate binary to a malicious path can not benefit,
// because Rule 1 (mimicry) rejects system-binary basenames outside System32
// BEFORE this check runs. An attacker shipping different bytes can not benefit
// either, because the catalog is Microsoft-signed and only Microsoft hashes
// land there.
bool IsCatalogHashSigned(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING,
                                FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    auto tryAlgo = [&](LPCWSTR algo) -> bool {
        HCATADMIN hAdmin = nullptr;
        if (!CryptCATAdminAcquireContext2(&hAdmin, nullptr, algo, nullptr, 0))
            return false;
        DWORD hashSz = 0;
        CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &hashSz, nullptr, 0);
        if (hashSz == 0) { CryptCATAdminReleaseContext(hAdmin, 0); return false; }
        std::vector<BYTE> hash(hashSz);
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &hashSz,
                                                   hash.data(), 0)) {
            CryptCATAdminReleaseContext(hAdmin, 0);
            return false;
        }
        HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash.data(),
                                                         hashSz, 0, nullptr);
        bool found = (hCat != nullptr);
        if (hCat) CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
        CryptCATAdminReleaseContext(hAdmin, 0);
        return found;
    };

    bool ok = tryAlgo(BCRYPT_SHA256_ALGORITHM);
    if (!ok) {
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        ok = tryAlgo(BCRYPT_SHA1_ALGORITHM); // legacy catalogs
    }
    CloseHandle(hFile);
    return ok;
}

std::unordered_map<std::wstring, bool> g_catCache;
std::mutex g_catCacheMtx;

bool IsCatalogHashSignedCached(const std::wstring& path) {
    if (path.empty()) return false;
    {
        std::lock_guard<std::mutex> lk(g_catCacheMtx);
        auto it = g_catCache.find(path);
        if (it != g_catCache.end()) return it->second;
    }
    bool r = IsCatalogHashSigned(path);
    {
        std::lock_guard<std::mutex> lk(g_catCacheMtx);
        if (g_catCache.size() < 4096) g_catCache[path] = r;
    }
    return r;
}

// ─── Port classifications ───────────────────────────────────────────────
bool IsPanelPort(uint16_t port) {
    static const uint16_t kPanel[] = {1337, 3000, 4444, 5000, 5173, 6666, 6969, 7777,
                                       8000, 8080, 8081, 8888, 9000, 9090, 31337};
    for (uint16_t p : kPanel) if (p == port) return true;
    return false;
}

bool IsNoiseProtocolPort(uint16_t port) {
    static const uint16_t kNoise[] = {137, 138, 139, 5353, 5355, 1900, 3702, 5050};
    for (uint16_t p : kNoise) if (p == port) return true;
    return false;
}

// ─── String helpers ─────────────────────────────────────────────────────
std::wstring ToUpperW(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towupper((wint_t)c);
    return s;
}

std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                  nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring BaseNameUp(const std::wstring& path) {
    if (path.empty()) return {};
    auto pos = path.find_last_of(L"\\/");
    std::wstring name = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    return ToUpperW(name);
}

// ─── Basename categories ────────────────────────────────────────────────
bool IsInterpreterBasenameW(const std::wstring& up) {
    static const wchar_t* kList[] = {
        L"PYTHON.EXE", L"PYTHONW.EXE", L"NODE.EXE", L"RUBY.EXE", L"PERL.EXE",
        L"PHP.EXE", L"DOTNET.EXE", L"JAVA.EXE", L"JAVAW.EXE",
        L"POWERSHELL.EXE", L"PWSH.EXE", L"CMD.EXE",
        L"WSCRIPT.EXE", L"CSCRIPT.EXE", L"MSHTA.EXE",
        L"RUNDLL32.EXE", L"REGSVR32.EXE", L"HH.EXE", nullptr
    };
    for (int i = 0; kList[i]; ++i) if (up == kList[i]) return true;
    return false;
}

bool IsSystemImpersonationTarget(const std::wstring& up) {
    static const wchar_t* kList[] = {
        L"SVCHOST.EXE", L"SERVICES.EXE", L"LSASS.EXE", L"CSRSS.EXE",
        L"WINLOGON.EXE", L"SMSS.EXE", L"CONHOST.EXE", L"WININIT.EXE",
        L"DWM.EXE", L"TASKHOSTW.EXE", L"SPOOLSV.EXE", L"FONTDRVHOST.EXE",
        L"RUNTIMEBROKER.EXE", L"DLLHOST.EXE", L"MSMPENG.EXE", nullptr
    };
    for (int i = 0; kList[i]; ++i) if (up == kList[i]) return true;
    return false;
}

bool IsTunnelBasenameW(const std::wstring& up) {
    static const wchar_t* kList[] = {
        L"NGROK.EXE", L"CLOUDFLARED.EXE", L"FRPC.EXE", L"FRPS.EXE",
        L"LOCALTUNNEL.EXE", L"LT.EXE", L"NPS.EXE", L"SERVEO.EXE",
        L"PINGGY.EXE", L"BORE.EXE", nullptr
    };
    for (int i = 0; kList[i]; ++i) if (up == kList[i]) return true;
    return false;
}

// ─── Path classification ────────────────────────────────────────────────
std::string DetectPathMimicry(const std::wstring& path, const std::wstring& baseUp) {
    if (path.empty() || baseUp.empty()) return {};

    // Homoglyph / non-ASCII / RTL override / trailing whitespace.
    for (wchar_t c : baseUp) {
        if (c > 0x7F) return "homoglyph or non-ASCII in basename";
        if (c == 0x202E) return "RTL override character in basename";
    }
    auto dot = baseUp.find_last_of(L'.');
    if (dot != std::wstring::npos && dot > 0) {
        wchar_t prev = baseUp[dot - 1];
        if (prev == L' ' || prev == L'\t')
            return "trailing whitespace before extension";
    }

    // System basename outside canonical dirs.
    if (IsSystemImpersonationTarget(baseUp)) {
        auto sep = path.find_last_of(L"\\/");
        std::wstring dirUp = (sep == std::wstring::npos)
                                 ? std::wstring()
                                 : ToUpperW(path.substr(0, sep));
        wchar_t sysroot[MAX_PATH] = {};
        GetSystemWindowsDirectoryW(sysroot, MAX_PATH);
        std::wstring sysrootUp = ToUpperW(sysroot);
        std::wstring s32    = sysrootUp + L"\\SYSTEM32";
        std::wstring sw64   = sysrootUp + L"\\SYSWOW64";
        std::wstring winsxs = sysrootUp + L"\\WINSXS";
        bool canonical = (dirUp == s32) || (dirUp == sw64) ||
                         (!winsxs.empty() && dirUp.rfind(winsxs, 0) == 0);
        if (!canonical)
            return std::string("system-binary basename outside System32 (") +
                   ToUtf8(dirUp) + ")";
    }

    // Fake System32 nested inside user-writable tree.
    {
        std::wstring up = ToUpperW(path);
        bool inUserOrAppData =
            up.find(L"\\USERS\\")    != std::wstring::npos ||
            up.find(L"\\APPDATA\\")  != std::wstring::npos ||
            up.find(L"\\TEMP\\")     != std::wstring::npos;
        bool fakeSystem32 = up.find(L"\\SYSTEM32\\") != std::wstring::npos;
        if (inUserOrAppData && fakeSystem32)
            return "fake System32 inside user-writable tree";
    }
    return {};
}

bool IsUserWritablePath(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring up = ToUpperW(path);
    static const wchar_t* kMarkers[] = {
        L"\\USERS\\", L"\\APPDATA\\", L"\\TEMP\\", L"\\DOWNLOADS\\",
        L"\\DESKTOP\\", L"\\PUBLIC\\", L"\\PROGRAMDATA\\TEMP\\",
        L"\\WINDOWS\\TEMP\\", nullptr
    };
    for (int i = 0; kMarkers[i]; ++i)
        if (up.find(kMarkers[i]) != std::wstring::npos) return true;
    return false;
}

// ─── PEB read for remote command line (anti-interpreter-impersonation) ──
// x64-only offsets. The project is x64-only per build documentation.
struct ProcessBasicInfoX64 {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
};
typedef LONG (NTAPI* PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

bool ReadRemoteCommandLine(DWORD pid, std::wstring& out) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) return false;
    static auto pNtQip = (PFN_NtQueryInformationProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!pNtQip) { CloseHandle(h); return false; }

    ProcessBasicInfoX64 pbi{};
    ULONG retLen = 0;
    if (pNtQip(h, 0 /* ProcessBasicInformation */,
               &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress) {
        CloseHandle(h);
        return false;
    }

    PVOID userParams = nullptr;
    SIZE_T br = 0;
    // PEB.ProcessParameters at offset 0x20 on x64.
    if (!ReadProcessMemory(h, (BYTE*)pbi.PebBaseAddress + 0x20,
                           &userParams, sizeof(userParams), &br) || !userParams) {
        CloseHandle(h);
        return false;
    }

    // RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) at 0x70 on x64:
    //   USHORT Length      @ +0x70
    //   USHORT MaximumLen  @ +0x72
    //   PWSTR  Buffer      @ +0x78 (after 4-byte padding)
    USHORT cmdLen = 0;
    PVOID  cmdBuf = nullptr;
    if (!ReadProcessMemory(h, (BYTE*)userParams + 0x70,
                           &cmdLen, sizeof(USHORT), &br) ||
        !ReadProcessMemory(h, (BYTE*)userParams + 0x78,
                           &cmdBuf, sizeof(PVOID), &br) ||
        !cmdBuf || cmdLen == 0 || cmdLen > 0x4000) {
        CloseHandle(h);
        return false;
    }
    std::wstring buffer(cmdLen / sizeof(wchar_t), L'\0');
    if (!ReadProcessMemory(h, cmdBuf, buffer.data(), cmdLen, &br)) {
        CloseHandle(h);
        return false;
    }
    out = std::move(buffer);
    CloseHandle(h);
    return true;
}

// Parse the first non-flag argument that looks like a script/module file.
std::wstring ParseInterpreterScript(const std::wstring& cmdline) {
    auto skipSpaces = [](const std::wstring& s, size_t i) {
        while (i < s.size() && (s[i] == L' ' || s[i] == L'\t')) ++i;
        return i;
    };
    auto nextToken = [](const std::wstring& s, size_t& i) {
        std::wstring tok;
        bool inQuote = false;
        while (i < s.size()) {
            wchar_t c = s[i];
            if (c == L'"') { inQuote = !inQuote; ++i; continue; }
            if (!inQuote && (c == L' ' || c == L'\t')) break;
            tok.push_back(c);
            ++i;
        }
        return tok;
    };

    size_t i = 0;
    i = skipSpaces(cmdline, i);
    (void)nextToken(cmdline, i); // skip interpreter exe

    while (i < cmdline.size()) {
        i = skipSpaces(cmdline, i);
        if (i >= cmdline.size()) break;
        std::wstring tok = nextToken(cmdline, i);
        if (tok.empty()) continue;
        if (tok[0] == L'-' || tok[0] == L'/') continue;
        auto comma = tok.find(L','); // rundll32 "path,Entry"
        if (comma != std::wstring::npos) tok = tok.substr(0, comma);
        return tok;
    }
    return {};
}

bool CmdlineContainsListener(const std::wstring& cmd) {
    std::wstring up = ToUpperW(cmd);
    static const wchar_t* kSig[] = {
        L"HTTPLISTENER", L"TCPLISTENER", L"NET.SOCKETS",
        L"PREFIXES.ADD", L"HTTP.SERVER", L"WEBSOCKETS.SERVE",
        L" NCAT ", L"NCAT.EXE", L"NCAT -L", L" NC -L", L"NC.EXE -L",
        L"SOCKET.IO", L" FLASK ", L"FLASK RUN", L"FASTAPI",
        L" EXPRESS ", L"SOCKETSERVER", nullptr
    };
    for (int i = 0; kSig[i]; ++i)
        if (up.find(kSig[i]) != std::wstring::npos) return true;
    return false;
}

// ─── Process snapshot + parent chain ────────────────────────────────────
std::unordered_map<DWORD, std::pair<DWORD, std::wstring>> SnapshotProcesses() {
    std::unordered_map<DWORD, std::pair<DWORD, std::wstring>> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            out[pe.th32ProcessID] = { pe.th32ParentProcessID, pe.szExeFile };
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::string BuildParentChain(DWORD pid,
                              const std::unordered_map<DWORD, std::pair<DWORD, std::wstring>>& snap) {
    std::string out;
    DWORD cur = pid;
    int depth = 0;
    while (cur != 0 && depth < 6) {
        auto it = snap.find(cur);
        if (it == snap.end()) break;
        if (!out.empty()) out = ToUtf8(it->second.second) + "->" + out;
        else out = ToUtf8(it->second.second);
        cur = it->second.first;
        ++depth;
    }
    return out;
}

std::string FindRunningTunnel(const std::unordered_map<DWORD, std::pair<DWORD, std::wstring>>& snap) {
    for (const auto& kv : snap) {
        std::wstring up = ToUpperW(kv.second.second);
        if (IsTunnelBasenameW(up)) return ToUtf8(kv.second.second);
    }
    return {};
}

// ─── SCM lookup: PID → service host name(s) ─────────────────────────────
std::unordered_map<DWORD, std::string> BuildSvchostPidToServiceMap(std::string& note) {
    std::unordered_map<DWORD, std::string> out;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { note = "scm unavailable"; return out; }

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
    if (bytesNeeded == 0) { CloseServiceHandle(scm); return out; }

    std::vector<BYTE> buf(bytesNeeded);
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO,
                              SERVICE_WIN32, SERVICE_STATE_ALL,
                              buf.data(), bytesNeeded,
                              &bytesNeeded, &count, &resume, nullptr)) {
        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            DWORD pid = arr[i].ServiceStatusProcess.dwProcessId;
            if (pid == 0) continue;
            std::string name = arr[i].lpServiceName
                                   ? ToUtf8(std::wstring(arr[i].lpServiceName))
                                   : std::string("?");
            auto it = out.find(pid);
            if (it == out.end()) out[pid] = name;
            else it->second += "," + name;
        }
    }
    CloseServiceHandle(scm);
    return out;
}

// ─── Firewall: map { uppercase exe path → rule label } for enabled inbound allows ──
std::unordered_map<std::wstring, std::string>
BuildFirewallInboundAllowMap(std::string& note) {
    std::unordered_map<std::wstring, std::string> out;

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool needUninit = SUCCEEDED(hrInit) && hrInit != S_FALSE;

    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), (void**)&policy);
    if (FAILED(hr) || !policy) {
        if (needUninit) CoUninitialize();
        note = "firewall lookup unavailable";
        return out;
    }

    INetFwRules* rules = nullptr;
    if (SUCCEEDED(policy->get_Rules(&rules)) && rules) {
        IUnknown* unk = nullptr;
        if (SUCCEEDED(rules->get__NewEnum(&unk)) && unk) {
            IEnumVARIANT* enumv = nullptr;
            if (SUCCEEDED(unk->QueryInterface(__uuidof(IEnumVARIANT),
                                              (void**)&enumv)) && enumv) {
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (enumv->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    INetFwRule* rule = nullptr;
                    if (V_VT(&v) == VT_DISPATCH && V_DISPATCH(&v))
                        V_DISPATCH(&v)->QueryInterface(__uuidof(INetFwRule),
                                                       (void**)&rule);
                    VariantClear(&v);
                    if (!rule) continue;

                    VARIANT_BOOL          enabled = VARIANT_FALSE;
                    NET_FW_RULE_DIRECTION dir     = NET_FW_RULE_DIR_IN;
                    NET_FW_ACTION         action  = NET_FW_ACTION_BLOCK;
                    rule->get_Enabled(&enabled);
                    rule->get_Direction(&dir);
                    rule->get_Action(&action);

                    if (enabled == VARIANT_TRUE &&
                        dir == NET_FW_RULE_DIR_IN &&
                        action == NET_FW_ACTION_ALLOW) {
                        BSTR app  = nullptr;
                        BSTR name = nullptr;
                        rule->get_ApplicationName(&app);
                        rule->get_Name(&name);
                        if (app && SysStringLen(app) > 0) {
                            std::wstring p =
                                ToUpperW(std::wstring(app, SysStringLen(app)));
                            std::string label = "INBOUND ALLOW ";
                            label += (name && SysStringLen(name) > 0)
                                         ? ToUtf8(std::wstring(name, SysStringLen(name)))
                                         : std::string("<unnamed>");
                            out.emplace(std::move(p), std::move(label));
                        }
                        if (app)  SysFreeString(app);
                        if (name) SysFreeString(name);
                    }
                    rule->Release();
                }
                enumv->Release();
            }
            unk->Release();
        }
        rules->Release();
    }
    policy->Release();
    if (needUninit) CoUninitialize();
    return out;
}

// ─── Path resolution ────────────────────────────────────────────────────
std::wstring CanonicalizeFinalPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD len = MAX_PATH * 2;
    if (!QueryFullProcessImageNameW(h, 0, buf, &len)) {
        CloseHandle(h);
        return {};
    }
    CloseHandle(h);
    return std::wstring(buf, len);
}

// ─── Address formatting ─────────────────────────────────────────────────
bool IsLoopbackV4(DWORD net) {
    // 127.0.0.0/8 — first byte in network order.
    return (net & 0xFFu) == 127u;
}
bool IsAnyV4(DWORD net) { return net == 0; }

bool IsLoopbackV6(const IN6_ADDR& a) {
    static const uint8_t lb[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return memcmp(&a, lb, 16) == 0;
}
bool IsAnyV6(const IN6_ADDR& a) {
    static const uint8_t any[16] = {0};
    return memcmp(&a, any, 16) == 0;
}

std::string FormatV4(DWORD net) {
    IN_ADDR ia;
    ia.S_un.S_addr = net;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));
    return buf;
}
std::string FormatV6(const IN6_ADDR& a) {
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return buf;
}

// ─── Listener record ────────────────────────────────────────────────────
struct Listener {
    std::string protocol;
    uint16_t    port;
    std::string bindAddr;
    DWORD       pid;
    bool        loopback;
    bool        anyBind;
};

void EnumTcpV4(std::vector<Listener>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (!size) return;
    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& row = t->table[i];
        Listener L;
        L.protocol = "TCP";
        L.port     = ntohs(static_cast<u_short>(row.dwLocalPort));
        L.pid      = row.dwOwningPid;
        L.bindAddr = FormatV4(row.dwLocalAddr);
        L.loopback = IsLoopbackV4(row.dwLocalAddr);
        L.anyBind  = IsAnyV4(row.dwLocalAddr);
        out.push_back(L);
    }
}

void EnumTcpV6(std::vector<Listener>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6,
                        TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (!size) return;
    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& row = t->table[i];
        Listener L;
        L.protocol = "TCP6";
        L.port     = ntohs(static_cast<u_short>(row.dwLocalPort));
        L.pid      = row.dwOwningPid;
        IN6_ADDR a;
        memcpy(&a, row.ucLocalAddr, 16);
        L.bindAddr = FormatV6(a);
        L.loopback = IsLoopbackV6(a);
        L.anyBind  = IsAnyV6(a);
        out.push_back(L);
    }
}

void EnumUdpV4(std::vector<Listener>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (!size) return;
    std::vector<BYTE> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& row = t->table[i];
        Listener L;
        L.protocol = "UDP";
        L.port     = ntohs(static_cast<u_short>(row.dwLocalPort));
        L.pid      = row.dwOwningPid;
        L.bindAddr = FormatV4(row.dwLocalAddr);
        L.loopback = IsLoopbackV4(row.dwLocalAddr);
        L.anyBind  = IsAnyV4(row.dwLocalAddr);
        out.push_back(L);
    }
}

void EnumUdpV6(std::vector<Listener>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (!size) return;
    std::vector<BYTE> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;
    auto* t = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buf.data());
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const auto& row = t->table[i];
        Listener L;
        L.protocol = "UDP6";
        L.port     = ntohs(static_cast<u_short>(row.dwLocalPort));
        L.pid      = row.dwOwningPid;
        IN6_ADDR a;
        memcpy(&a, row.ucLocalAddr, 16);
        L.bindAddr = FormatV6(a);
        L.loopback = IsLoopbackV6(a);
        L.anyBind  = IsAnyV6(a);
        out.push_back(L);
    }
}

} // anonymous namespace

// ─── Public entry point ─────────────────────────────────────────────────
std::vector<ScannerUI::RemotePortFinding>
CollectRemotePortFindings(std::string& status) {
    std::vector<ScannerUI::RemotePortFinding> findings;

    {
        std::lock_guard<std::mutex> lk(g_catCacheMtx);
        g_catCache.clear();
    }

    std::vector<Listener> listeners;
    EnumTcpV4(listeners);
    EnumTcpV6(listeners);
    EnumUdpV4(listeners);
    EnumUdpV6(listeners);

    auto procSnap = SnapshotProcesses();

    std::string fwNote;
    auto fwMap = BuildFirewallInboundAllowMap(fwNote);

    std::string scmNote;
    auto svcMap = BuildSvchostPidToServiceMap(scmNote);

    std::string tunnelBasename = FindRunningTunnel(procSnap);

    std::unordered_set<std::string> seen;

    for (const auto& L : listeners) {
        if (L.pid == 0 || L.pid == 4) continue;

        // UDP is noisy. Only consider UDP entries on panel-range ports.
        if ((L.protocol == "UDP" || L.protocol == "UDP6") && !IsPanelPort(L.port))
            continue;

        std::string key = std::to_string(L.pid) + "|" + L.protocol + "|" +
                          std::to_string(L.port) + "|" + L.bindAddr;
        if (!seen.insert(key).second) continue;

        std::wstring fullPath = CanonicalizeFinalPath(L.pid);
        if (fullPath.empty()) fullPath = ProcessFullPathW(L.pid);

        std::wstring baseUp   = BaseNameUp(fullPath);
        std::string  baseUtf8 = ToUtf8(baseUp);

        bool isInterpreter   = IsInterpreterBasenameW(baseUp);
        bool isSvchostFamily = (baseUp == L"SVCHOST.EXE"      ||
                                baseUp == L"DLLHOST.EXE"      ||
                                baseUp == L"RUNTIMEBROKER.EXE"||
                                baseUp == L"TASKHOSTW.EXE"    ||
                                baseUp == L"RUNDLL32.EXE");

        // Skip well-known noise protocol ports owned by a registered service host.
        if (IsNoiseProtocolPort(L.port) && isSvchostFamily && svcMap.count(L.pid))
            continue;

        // Layer 1: path mimicry — instant HIGH if matched.
        std::string mimicryReason = DetectPathMimicry(fullPath, baseUp);

        // Authenticode + root thumbprint.
        DetectionFilter::VerifiedSignerIdentity ident =
            DetectionFilter::GetVerifiedSignerIdentityCached(fullPath);

        bool msPinned = ident.trusted &&
                        (ident.rootThumb == kMsRoot2010 ||
                         ident.rootThumb == kMsRoot2011);

        std::string signerLabel;
        if (ident.trusted) {
            std::string cn = ToUtf8(ident.cnUpper);
            std::string thumb8 = ident.rootThumb.size() >= 8
                                     ? ident.rootThumb.substr(0, 8)
                                     : ident.rootThumb;
            signerLabel = cn.empty() ? std::string("SIGNED") : cn;
            if (!thumb8.empty()) signerLabel += " (" + thumb8 + ")";
            if (msPinned)        signerLabel += " [MS-ROOT]";
        } else {
            signerLabel = "UNSIGNED";
        }

        // Cryptographic trust composition. Both paths are pure-signature:
        //   ident.trusted  — WinVerifyTrust (embedded or catalog) end-to-end OK.
        //   catalogSigned  — file hash present in Windows Catalog Database
        //                    (raw lookup, survives revocation-cache failures).
        // No path / name / folder / size heuristic participates in this gate.
        bool catalogSigned  = IsCatalogHashSignedCached(fullPath);
        bool effectiveTrust = ident.trusted || catalogSigned;
        if (!ident.trusted && catalogSigned)
            signerLabel = "SIGNED [CATALOG-HASH]";

        // Layer 2: SCM check for svchost family.
        std::string svcHost;
        bool svchostMissingService = false;
        if (isSvchostFamily) {
            auto it = svcMap.find(L.pid);
            if (it == svcMap.end()) {
                if (baseUp == L"SVCHOST.EXE") svchostMissingService = true;
            } else {
                svcHost = it->second;
            }
        }

        // Layer 3: interpreter unwrap.
        std::wstring cmdline;
        std::wstring scriptPath;
        bool inlineLolbin       = false;
        bool scriptUserWritable = false;
        bool scriptUnsigned     = false;
        bool cmdlineReadable    = false;

        if (isInterpreter) {
            if (ReadRemoteCommandLine(L.pid, cmdline)) {
                cmdlineReadable = true;
                if (CmdlineContainsListener(cmdline)) inlineLolbin = true;
                scriptPath = ParseInterpreterScript(cmdline);
                if (!scriptPath.empty()) {
                    DWORD attrs = GetFileAttributesW(scriptPath.c_str());
                    if (attrs == INVALID_FILE_ATTRIBUTES) {
                        scriptPath.clear();
                    } else {
                        scriptUserWritable = IsUserWritablePath(scriptPath);
                        scriptUnsigned = !DetectionFilter::IsTrustedSignedCached(scriptPath);
                    }
                }
            }
        }

        // Layer 4: parent chain.
        std::string parentChain = BuildParentChain(L.pid, procSnap);

        // Layer 5: firewall / tunnel.
        std::string fwRule;
        {
            auto it = fwMap.find(ToUpperW(fullPath));
            if (it != fwMap.end()) fwRule = it->second;
        }
        std::string tunnel;
        if (!tunnelBasename.empty() && L.loopback && IsPanelPort(L.port))
            tunnel = tunnelBasename;

        std::string scriptOrHost;
        if (!svcHost.empty())          scriptOrHost = "svc:" + svcHost;
        else if (!scriptPath.empty())  scriptOrHost = ToUtf8(scriptPath);
        else if (isInterpreter && cmdlineReadable) {
            std::string c = ToUtf8(cmdline);
            if (c.size() > 160) c = c.substr(0, 160) + "...";
            scriptOrHost = c;
        } else if (isInterpreter) {
            scriptOrHost = "<unreadable cmdline>";
        }

        // ── CLASSIFICATION (first match wins) ──────────────────────────
        std::string severity;
        std::string reason;
        auto setIf = [&](const char* sev, std::string why) {
            if (severity.empty()) { severity = sev; reason = std::move(why); }
        };

        if (!mimicryReason.empty())
            setIf("HIGH", "impersonation: " + mimicryReason);

        if (svchostMissingService)
            setIf("HIGH", "svchost listener with no SCM-registered service host");

        if (isInterpreter && scriptUnsigned && scriptUserWritable && !L.loopback)
            setIf("HIGH", "interpreter listener: unsigned user-writable script on LAN-reachable bind");

        if (isInterpreter && inlineLolbin && !L.loopback)
            setIf("HIGH", "inline interpreter network listener (LOLBin) on LAN-reachable bind");
        if (isInterpreter && inlineLolbin && L.loopback)
            setIf("MEDIUM", "inline interpreter network listener (LOLBin) on loopback");

        if (!fwRule.empty() && IsUserWritablePath(fullPath) &&
            !L.loopback && IsPanelPort(L.port))
            setIf("HIGH", "user-installed firewall allow for non-system binary on panel port");

        if (!tunnel.empty())
            setIf("HIGH", "loopback panel-port listener exposed via " + tunnel);

        if (!effectiveTrust && !L.loopback && !isInterpreter)
            setIf("HIGH", "unsigned process listening on LAN-reachable interface");

        if (ident.trusted && !msPinned && !L.loopback &&
            IsPanelPort(L.port) && IsUserWritablePath(fullPath))
            setIf("HIGH", "signed-but-unverified publisher on panel port (LAN-bound, user-writable path)");

        if (isInterpreter && L.loopback && scriptUserWritable && scriptUnsigned)
            setIf("MEDIUM", "interpreter listening on loopback from user-writable script");

        if (!L.loopback && IsUserWritablePath(fullPath) && !effectiveTrust)
            setIf("MEDIUM", "LAN listener from staging directory");

        if (L.loopback && !effectiveTrust && !isInterpreter)
            setIf("FLAG", "loopback unsigned listener (informational)");

        if (severity.empty()) continue;

        ScannerUI::RemotePortFinding f;
        f.protocol      = L.protocol;
        f.port          = std::to_string(L.port);
        f.bindAddress   = L.bindAddr;
        f.pid           = std::to_string(L.pid);
        f.process       = baseUtf8;
        f.path          = ToUtf8(fullPath);
        f.signer        = signerLabel;
        f.parentChain   = parentChain;
        f.scriptOrHost  = scriptOrHost;
        f.firewallRule  = fwRule;
        f.tunnelPeer    = tunnel;
        f.reason        = reason;
        f.severity      = severity;

        std::string detail;
        detail += "pid=" + f.pid + " ";
        detail += "path=" + f.path + " ";
        if (!parentChain.empty()) detail += "parent=" + parentChain + " ";
        if (cmdlineReadable && !cmdline.empty()) {
            std::string c = ToUtf8(cmdline);
            if (c.size() > 240) c = c.substr(0, 240) + "...";
            detail += "cmd=\"" + c + "\" ";
        }
        if (!svcHost.empty()) detail += "service=" + svcHost + " ";
        if (!fwRule.empty())  detail += "fw=" + fwRule + " ";
        if (!tunnel.empty())  detail += "tunnel=" + tunnel + " ";
        f.detail = std::move(detail);

        findings.push_back(std::move(f));
    }

    bool anyHigh = false;
    for (const auto& f : findings) {
        if (f.severity == "HIGH") { anyHigh = true; break; }
    }
    if (findings.empty())     status = "OK";
    else if (anyHigh)         status = "DETECTED";
    else                      status = "REVIEW";

    if (!fwNote.empty())  status += " (" + fwNote + ")";
    if (!scmNote.empty()) status += " (" + scmNote + ")";

    return findings;
}

// ─── WFP stream/datagram callout detection ──────────────────────────────────
// Enumerates callouts registered at TCP stream and UDP datagram layers via the
// WFP management API. A callout at FWPM_LAYER_STREAM_V4/V6 has the ability to
// inspect, modify, inject into, or truncate TCP stream data — the primary
// mechanism used by kernel-level cheats to interfere with anti-cheat traffic.

static std::string GuidToHexStr(const GUID& g) {
    char buf[40];
    snprintf(buf, sizeof(buf),
             "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
             g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

static bool GuidEq(const GUID& a, const GUID& b) {
    return memcmp(&a, &b, sizeof(GUID)) == 0;
}

static const char* WfpTcpLayerName(const GUID& layerKey) {
    if (GuidEq(layerKey, FWPM_LAYER_STREAM_V4))        return "STREAM_V4";
    if (GuidEq(layerKey, FWPM_LAYER_STREAM_V6))        return "STREAM_V6";
    if (GuidEq(layerKey, FWPM_LAYER_DATAGRAM_DATA_V4)) return "DATAGRAM_V4";
    if (GuidEq(layerKey, FWPM_LAYER_DATAGRAM_DATA_V6)) return "DATAGRAM_V6";
    if (GuidEq(layerKey, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4)) return "ALE_FLOW_ESTABLISHED_V4";
    if (GuidEq(layerKey, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6)) return "ALE_FLOW_ESTABLISHED_V6";
    if (GuidEq(layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4))     return "ALE_AUTH_CONNECT_V4";
    if (GuidEq(layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6))     return "ALE_AUTH_CONNECT_V6";
    if (GuidEq(layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4)) return "ALE_AUTH_RECV_ACCEPT_V4";
    if (GuidEq(layerKey, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)) return "ALE_AUTH_RECV_ACCEPT_V6";
    if (GuidEq(layerKey, FWPM_LAYER_OUTBOUND_TRANSPORT_V4))   return "OUTBOUND_TRANSPORT_V4";
    if (GuidEq(layerKey, FWPM_LAYER_OUTBOUND_TRANSPORT_V6))   return "OUTBOUND_TRANSPORT_V6";
    if (GuidEq(layerKey, FWPM_LAYER_INBOUND_TRANSPORT_V4))    return "INBOUND_TRANSPORT_V4";
    if (GuidEq(layerKey, FWPM_LAYER_INBOUND_TRANSPORT_V6))    return "INBOUND_TRANSPORT_V6";
    return nullptr;
}

static std::wstring ResolveWfpServiceDriverPath(const std::wstring& serviceName) {
    if (serviceName.empty())
        return {};

    std::wstring svcKey = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
    HKEY hSvc = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, svcKey.c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, &hSvc) != ERROR_SUCCESS)
        return {};

    wchar_t imgBuf[MAX_PATH * 4] = {};
    DWORD sz = sizeof(imgBuf), type = 0;
    std::wstring driverPath;
    if (RegQueryValueExW(hSvc, L"ImagePath", nullptr, &type,
                         reinterpret_cast<LPBYTE>(imgBuf), &sz) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        wchar_t expanded[MAX_PATH * 4] = {};
        if (type == REG_EXPAND_SZ)
            ExpandEnvironmentStringsW(imgBuf, expanded, static_cast<DWORD>(std::size(expanded)));
        else
            wcscpy_s(expanded, imgBuf);
        driverPath = expanded;
        if (driverPath.rfind(L"\\SystemRoot\\", 0) == 0) {
            wchar_t windowsDir[MAX_PATH] = {};
            GetWindowsDirectoryW(windowsDir, static_cast<UINT>(std::size(windowsDir)));
            driverPath = std::wstring(windowsDir) + L"\\" + driverPath.substr(12);
        }
        else if (driverPath.rfind(L"\\??\\", 0) == 0)
            driverPath = driverPath.substr(4);

        // Service ImagePath values commonly include arguments (for example,
        // svchost.exe -k LocalServiceNoNetworkFirewall). Verify the executable,
        // not the complete command line.
        while (!driverPath.empty() && iswspace(driverPath.front()))
            driverPath.erase(driverPath.begin());
        if (!driverPath.empty() && driverPath.front() == L'"') {
            size_t closingQuote = driverPath.find(L'"', 1);
            if (closingQuote != std::wstring::npos)
                driverPath = driverPath.substr(1, closingQuote - 1);
        } else {
            std::wstring upper = ToUpperInvariant(driverPath);
            size_t exeEnd = upper.find(L".EXE");
            size_t sysEnd = upper.find(L".SYS");
            size_t imageEnd = std::wstring::npos;
            if (exeEnd != std::wstring::npos)
                imageEnd = exeEnd + 4;
            if (sysEnd != std::wstring::npos)
                imageEnd = imageEnd == std::wstring::npos
                    ? sysEnd + 4
                    : (std::min)(imageEnd, sysEnd + 4);
            if (imageEnd != std::wstring::npos)
                driverPath.resize(imageEnd);
        }
    }
    RegCloseKey(hSvc);
    return driverPath;
}

static bool IsKnownWindowsWfpServiceImage(const std::wstring& serviceName,
                                          const std::wstring& imagePath) {
    const std::wstring serviceUpper = ToUpperInvariant(serviceName);
    const std::wstring imageUpper = ToUpperInvariant(BaseNameFromPath(imagePath));
    return ((serviceUpper == L"MPSSVC" || serviceUpper == L"BFE") &&
            imageUpper == L"SVCHOST.EXE") ||
           (serviceUpper == L"NDU" && imageUpper == L"NDU.SYS");
}

static bool HasMicrosoftWfpMetadata(const std::string& providerName,
                                    const std::string& sublayerName) {
    std::string metadata = providerName + " " + sublayerName;
    std::transform(metadata.begin(), metadata.end(), metadata.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return metadata.find("MICROSOFT") != std::string::npos ||
           metadata.find("@BFE.DLL,") != std::string::npos;
}

static bool IsWfpDriverPathHighRisk(const std::wstring& path) {
    if (path.empty())
        return false;
    auto cls = DetectionFilter::ClassifyPath(path);
    return cls == DetectionFilter::PathClass::TempOrInstaller ||
           cls == DetectionFilter::PathClass::UserProfile ||
           cls == DetectionFilter::PathClass::Removable ||
           cls == DetectionFilter::PathClass::Unmapped;
}

static const char* WfpActionName(FWP_ACTION_TYPE type) {
    switch (type) {
    case FWP_ACTION_CALLOUT_TERMINATING: return "CALLOUT_TERMINATING";
    case FWP_ACTION_CALLOUT_INSPECTION:  return "CALLOUT_INSPECTION";
    case FWP_ACTION_CALLOUT_UNKNOWN:     return "CALLOUT_UNKNOWN";
    case FWP_ACTION_BLOCK:               return "BLOCK";
    case FWP_ACTION_PERMIT:              return "PERMIT";
    default:                             return "OTHER";
    }
}

struct TcpLoopbackAttempt {
    bool established = false;
    bool sentAll = false;
    bool receivedAll = false;
    bool contentMatch = false;
    size_t receivedBytes = 0;
};

static TcpLoopbackAttempt RunTcpLoopbackAttempt() {
    TcpLoopbackAttempt result;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return result;

    DWORD timeoutMs = 2500;
    setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
    setsockopt(listener, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(listener, 1) == SOCKET_ERROR) {
        closesocket(listener);
        return result;
    }

    int addressLen = sizeof(address);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &addressLen) == SOCKET_ERROR) {
        closesocket(listener);
        return result;
    }

    constexpr size_t kPayloadSize = 256 * 1024;
    std::vector<uint8_t> payload(kPayloadSize);
    uint32_t state = 0x6D2B79F5u;
    for (size_t i = 0; i < payload.size(); ++i) {
        state = state * 1664525u + 1013904223u;
        payload[i] = static_cast<uint8_t>(state >> 24);
    }

    std::vector<uint8_t> received;
    std::thread server([&]() {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listener, &readSet);
        timeval wait = {};
        wait.tv_sec = 3;
        if (select(0, &readSet, nullptr, nullptr, &wait) <= 0)
            return;
        SOCKET peer = accept(listener, nullptr, nullptr);
        if (peer == INVALID_SOCKET)
            return;
        setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        std::array<uint8_t, 8192> buffer = {};
        while (received.size() < payload.size()) {
            int count = recv(peer, reinterpret_cast<char*>(buffer.data()),
                             static_cast<int>(buffer.size()), 0);
            if (count <= 0)
                break;
            received.insert(received.end(), buffer.begin(), buffer.begin() + count);
        }
        closesocket(peer);
    });

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client != INVALID_SOCKET) {
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        if (connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
            result.established = true;
            size_t sent = 0;
            while (sent < payload.size()) {
                int count = send(client,
                                 reinterpret_cast<const char*>(payload.data() + sent),
                                 static_cast<int>(std::min<size_t>(8192, payload.size() - sent)),
                                 0);
                if (count <= 0)
                    break;
                sent += static_cast<size_t>(count);
            }
            result.sentAll = sent == payload.size();
            shutdown(client, SD_SEND);
        }
        closesocket(client);
    }

    server.join();
    closesocket(listener);

    result.receivedBytes = received.size();
    result.receivedAll = received.size() == payload.size();
    result.contentMatch = result.receivedAll &&
                          memcmp(received.data(), payload.data(), payload.size()) == 0;
    return result;
}

static void AppendTcpLoopbackIntegrityFinding(
    std::vector<ScannerUI::GenericBypassFinding>& findings,
    const std::string& date,
    const std::string& timeStr) {
    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return;

    int established = 0;
    int completed = 0;
    int truncated = 0;
    size_t minimumReceived = SIZE_MAX;
    for (int attempt = 0; attempt < 3; ++attempt) {
        TcpLoopbackAttempt sample = RunTcpLoopbackAttempt();
        if (sample.established)
            ++established;
        if (sample.sentAll && sample.contentMatch)
            ++completed;
        if (sample.established && sample.sentAll && !sample.contentMatch) {
            ++truncated;
            minimumReceived = (std::min)(minimumReceived, sample.receivedBytes);
        }
    }
    WSACleanup();

    if (truncated < 2)
        return;

    ScannerUI::GenericBypassFinding finding;
    finding.date = date;
    finding.time = timeStr;
    finding.type = "TCP_STREAM_INTEGRITY";
    finding.process = "rxvscan-selftest";
    finding.target = "127.0.0.1";
    finding.severity = truncated == 3 ? "HIGH" : "MEDIUM";
    finding.ruleId = "NET.TCP.LOOPBACK_TRUNCATION";
    finding.source = "controlled Winsock loopback test";
    finding.confidence = truncated == 3 ? "HIGH" : "MEDIUM";
    finding.evidenceState = "SUSPICIOUS";
    finding.detail =
        "attempts=3 established=" + std::to_string(established) +
        " completed=" + std::to_string(completed) +
        " truncated_or_modified=" + std::to_string(truncated);
    if (minimumReceived != SIZE_MAX)
        finding.detail += " minimum_received=" + std::to_string(minimumReceived) +
                          "/262144";
    findings.push_back(std::move(finding));
}

static std::wstring SetupApiStringProperty(HDEVINFO devices,
                                           SP_DEVINFO_DATA& device,
                                           DWORD property) {
    wchar_t buffer[1024] = {};
    DWORD type = 0, required = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(
            devices, &device, property, &type,
            reinterpret_cast<PBYTE>(buffer), sizeof(buffer), &required))
        return {};
    return buffer;
}

static void AppendNdisNetworkServiceFindings(
    std::vector<ScannerUI::GenericBypassFinding>& findings,
    const std::string& date,
    const std::string& timeStr) {
    HDEVINFO devices = SetupDiGetClassDevsW(
        &GUID_DEVCLASS_NETSERVICE, nullptr, nullptr, DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE)
        return;

    std::unordered_set<std::wstring> seenServices;
    for (DWORD index = 0;; ++index) {
        SP_DEVINFO_DATA device = {};
        device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(devices, index, &device)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        std::wstring service =
            SetupApiStringProperty(devices, device, SPDRP_SERVICE);
        if (service.empty() ||
            !seenServices.insert(ToUpperInvariant(service)).second)
            continue;

        std::wstring path = ResolveWfpServiceDriverPath(service);
        if (path.empty() ||
            GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;

        auto identity = DetectionFilter::GetVerifiedSignerIdentityCached(path);
        const bool microsoft =
            identity.trusted && identity.cnUpper.compare(0, 9, L"MICROSOFT") == 0;
        if (microsoft)
            continue;

        std::wstring display =
            SetupApiStringProperty(devices, device, SPDRP_FRIENDLYNAME);
        if (display.empty())
            display = SetupApiStringProperty(devices, device, SPDRP_DEVICEDESC);

        const bool highRiskPath = IsWfpDriverPathHighRisk(path);
        ScannerUI::GenericBypassFinding finding;
        finding.date = date;
        finding.time = timeStr;
        finding.type = "NDIS_NETWORK_SERVICE";
        finding.process = WideToUtf8(BaseNameFromPath(path));
        finding.target = display.empty() ? WideToUtf8(service) : WideToUtf8(display);
        finding.ruleId = "NET.NDIS.REGISTERED_SERVICE";
        finding.source = "SetupAPI NetService";
        if (!identity.trusted && highRiskPath) {
            finding.severity = "HIGH";
            finding.confidence = "HIGH";
            finding.evidenceState = "SUSPICIOUS";
        } else if (!identity.trusted) {
            finding.severity = "MEDIUM";
            finding.confidence = "MEDIUM";
            finding.evidenceState = "REVIEW";
        } else {
            continue;
        }
        finding.detail =
            "service=" + WideToUtf8(service) +
            " trusted=" + (identity.trusted ? std::string("yes") : std::string("no")) +
            " path=" + WideToUtf8(path);
        if (!identity.cnUpper.empty())
            finding.detail += " signer=\"" + WideToUtf8(identity.cnUpper) + "\"";
        findings.push_back(std::move(finding));
    }
    SetupDiDestroyDeviceInfoList(devices);
}

std::vector<ScannerUI::GenericBypassFinding>
CollectWfpStreamFilterFindings(std::string& status) {
    std::vector<ScannerUI::GenericBypassFinding> findings;

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    HANDLE engine = nullptr;
    if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine) != ERROR_SUCCESS) {
        status = "REVIEW (WFP unavailable)";
        return findings;
    }

    HANDLE enumH = nullptr;
    bool enumerationWorked = false;
    if (FwpmFilterCreateEnumHandle0(engine, nullptr, &enumH) == ERROR_SUCCESS) {
        enumerationWorked = true;
        for (;;) {
            FWPM_FILTER0** batch = nullptr;
            UINT32 n = 0;
            DWORD ret = FwpmFilterEnum0(engine, enumH, 128, &batch, &n);
            if (ret != ERROR_SUCCESS || n == 0) {
                if (batch) FwpmFreeMemory0((void**)&batch);
                break;
            }

            for (UINT32 i = 0; i < n; ++i) {
                const FWPM_FILTER0* filter = batch[i];
                const char* layerName = WfpTcpLayerName(filter->layerKey);
                if (!layerName) continue;

                const bool usesCallout =
                    (filter->action.type & FWP_ACTION_FLAG_CALLOUT) != 0;
                if (!usesCallout)
                    continue;

                FWPM_CALLOUT0* callout = nullptr;
                if (FwpmCalloutGetByKey0(engine, &filter->action.calloutKey, &callout) != ERROR_SUCCESS ||
                    !callout)
                    continue;

                std::wstring serviceName;
                std::string providerName;
                const GUID* providerKey = callout->providerKey
                    ? callout->providerKey
                    : filter->providerKey;
                if (providerKey) {
                    FWPM_PROVIDER0* prov = nullptr;
                    if (FwpmProviderGetByKey0(engine, providerKey, &prov) == ERROR_SUCCESS && prov) {
                        if (prov->displayData.name)
                            providerName = WideToUtf8(prov->displayData.name);
                        if (prov->serviceName)
                            serviceName = prov->serviceName;
                        FwpmFreeMemory0((void**)&prov);
                    }
                }
                if (providerName.empty() && callout->displayData.name)
                    providerName = WideToUtf8(callout->displayData.name);

                std::string sublayerName;
                FWPM_SUBLAYER0* sublayer = nullptr;
                if (FwpmSubLayerGetByKey0(engine, &filter->subLayerKey, &sublayer) == ERROR_SUCCESS &&
                    sublayer) {
                    if (sublayer->displayData.name)
                        sublayerName = WideToUtf8(sublayer->displayData.name);
                    FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
                }

                std::wstring driverPath = ResolveWfpServiceDriverPath(serviceName);
                bool pathExists = !driverPath.empty() &&
                                  GetFileAttributesW(driverPath.c_str()) != INVALID_FILE_ATTRIBUTES;
                bool trusted = false;
                bool microsoft = false;
                std::wstring signer;
                if (pathExists) {
                    auto identity = DetectionFilter::GetVerifiedSignerIdentityCached(driverPath);
                    trusted = identity.trusted;
                    signer = identity.cnUpper;
                    microsoft = trusted && signer.compare(0, 9, L"MICROSOFT") == 0;
                }

                const bool persistent =
                    (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) != 0;
                const bool bootTime =
                    (filter->flags & FWPM_FILTER_FLAG_BOOTTIME) != 0;
                const bool highRiskPath = IsWfpDriverPathHighRisk(driverPath);
                std::string providerUpper = providerName;
                std::transform(providerUpper.begin(), providerUpper.end(), providerUpper.begin(),
                               [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
                const bool microsoftBuiltinWithoutService =
                    driverPath.empty() && serviceName.empty() &&
                    providerUpper.find("MICROSOFT") != std::string::npos;
                const bool microsoftBuiltinService =
                    IsKnownWindowsWfpServiceImage(serviceName, driverPath) &&
                    HasMicrosoftWfpMetadata(providerName, sublayerName);

                std::string severity;
                std::string confidence;
                std::string evidenceState;
                if (microsoftBuiltinWithoutService || microsoftBuiltinService) {
                    FwpmFreeMemory0(reinterpret_cast<void**>(&callout));
                    continue;
                } else if (pathExists && !trusted && (highRiskPath || bootTime)) {
                    severity = "HIGH";
                    confidence = "HIGH";
                    evidenceState = "SUSPICIOUS";
                } else if (pathExists && !trusted) {
                    severity = "MEDIUM";
                    confidence = "MEDIUM";
                    evidenceState = "REVIEW";
                } else if (!pathExists || driverPath.empty()) {
                    severity = "FLAG";
                    confidence = "LOW";
                    evidenceState = "INCONCLUSIVE";
                } else if (trusted && !microsoft) {
                    // Signed VPN, endpoint-security and firewall filters are normal
                    // inventory, not bypass evidence.
                    FwpmFreeMemory0(reinterpret_cast<void**>(&callout));
                    continue;
                } else {
                    FwpmFreeMemory0(reinterpret_cast<void**>(&callout));
                    continue;
                }

                std::string itemLabel;
                if (!driverPath.empty()) {
                    std::wstring base = BaseNameFromPath(driverPath);
                    itemLabel = WideToUtf8(base);
                } else if (!serviceName.empty()) {
                    itemLabel = WideToUtf8(serviceName);
                } else if (!providerName.empty()) {
                    itemLabel = providerName;
                } else {
                    itemLabel = GuidToHexStr(filter->action.calloutKey);
                }

                ScannerUI::GenericBypassFinding finding;
                finding.date = date;
                finding.time = timeStr;
                finding.type = "WFP_ACTIVE_FILTER";
                finding.target = layerName;
                finding.severity = severity;
                finding.process = itemLabel;
                finding.ruleId = "NET.WFP.ACTIVE_CALLOUT";
                finding.source = "Windows Filtering Platform";
                finding.confidence = confidence;
                finding.evidenceState = evidenceState;
                finding.detail =
                    "filter=" + GuidToHexStr(filter->filterKey) +
                    " callout=" + GuidToHexStr(filter->action.calloutKey) +
                    " action=" + WfpActionName(filter->action.type) +
                    " persistent=" + (persistent ? std::string("yes") : std::string("no")) +
                    " boot_time=" + (bootTime ? std::string("yes") : std::string("no")) +
                    " trusted=" + (trusted ? std::string("yes") : std::string("no"));
                if (!providerName.empty())
                    finding.detail += " provider=\"" + providerName + "\"";
                if (!sublayerName.empty())
                    finding.detail += " sublayer=\"" + sublayerName + "\"";
                if (!serviceName.empty())
                    finding.detail += " service=" + WideToUtf8(serviceName);
                if (!driverPath.empty())
                    finding.detail += " path=" + WideToUtf8(driverPath);
                if (!signer.empty())
                    finding.detail += " signer=\"" + WideToUtf8(signer) + "\"";
                findings.push_back(std::move(finding));

                FwpmFreeMemory0(reinterpret_cast<void**>(&callout));
            }
            FwpmFreeMemory0((void**)&batch);
            if (n < 128) break;
        }
        FwpmFilterDestroyEnumHandle0(engine, enumH);
    }

    FwpmEngineClose0(engine);
    AppendNdisNetworkServiceFindings(findings, date, timeStr);
    AppendTcpLoopbackIntegrityFinding(findings, date, timeStr);

    bool anyHigh = false;
    for (const auto& f : findings)
        if (f.severity == "HIGH") { anyHigh = true; break; }
    if (!enumerationWorked)
        status = "REVIEW (WFP filter enumeration failed)";
    else
        status = findings.empty() ? "OK" : (anyHigh ? "DETECTED" : "REVIEW");
    return findings;
}
