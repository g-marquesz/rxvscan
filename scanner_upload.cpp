#include "scanner_upload.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <sstream>
#include <ctime>

#pragma comment(lib, "winhttp.lib")

namespace ScannerUpload {

namespace {

// Embedded PIN storage - replaced at binary level by the web downloader.
// NOT const/constexpr so the compiler emits a writeable symbol in .data
// that can be patched at the binary level after compilation.
// The web server searches for "RXV0000000" in the .exe and writes the 6-char
// PIN starting at offset 3 (after "RXV"). Remaining bytes stay as zeroes.
// Total size: 32 bytes. Format: RXV + 6-char PIN + 23 null bytes.
static char kEmbeddedPinStorage[32] = "RXV00000000000000000000000000";

// Embedded endpoint storage - replaced at binary level by the web downloader.
// The web server searches for "RXVEP" in the .exe and writes the endpoint URL
// starting at offset 5 (after "RXVEP"). Total size: 128 bytes.
// Format: RXVEP + up to 123-char URL (null-terminated).
// NOTE: cannot use string literal with embedded \x00 (MSVC C2117).
//       brace-init fills remaining bytes with zero automatically.
static char kEmbeddedEndpointStorage[128] = { 'R', 'X', 'V', 'E', 'P' };

std::string ReadEmbeddedPin() {
    // Check if the placeholder was replaced (first bytes after "RXV" are non-zero)
    if (kEmbeddedPinStorage[3] == '0' && kEmbeddedPinStorage[4] == '0') {
        return ""; // not replaced
    }
    std::string pin(kEmbeddedPinStorage + 3, 6);
    auto nullPos = pin.find('\0');
    if (nullPos != std::string::npos) pin.resize(nullPos);
    return pin;
}

std::string ReadEmbeddedEndpoint() {
    // Check if the endpoint was patched (byte after "RXVEP" must be non-null)
    if (kEmbeddedEndpointStorage[5] == '\0') {
        return ""; // not patched
    }
    // Read null-terminated string starting at offset 5 (after "RXVEP")
    std::string ep(kEmbeddedEndpointStorage + 5, 123);
    auto nullPos = ep.find('\0');
    if (nullPos != std::string::npos) ep.resize(nullPos);
    return ep;
}

constexpr wchar_t kRegPath[] = L"SOFTWARE\\rxvscan\\Upload";
constexpr wchar_t kRegApiKey[] = L"ApiKey";
constexpr wchar_t kRegEndpoint[] = L"Endpoint";

std::wstring ReadRegString(HKEY hKey, const wchar_t* name) {
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(hKey, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS) return L"";
    if (type != REG_SZ && type != REG_EXPAND_SZ) return L"";
    if (bytes == 0) return L"";
    std::wstring out(bytes / sizeof(wchar_t), L'\0');
    if (RegQueryValueExW(hKey, name, nullptr, &type,
                         reinterpret_cast<LPBYTE>(out.data()), &bytes) != ERROR_SUCCESS) {
        return L"";
    }
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

void AppendEscapedJson(std::string& out, const std::string& s) {
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04X", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
}

void AppendField(std::string& out, const char* key, const std::string& value, bool& first) {
    if (!first) out.push_back(',');
    first = false;
    out.push_back('"'); out += key; out += "\":";
    AppendEscapedJson(out, value);
}

std::string Utf16ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        out.data(), needed, nullptr, nullptr);
    return out;
}

std::string GetHostnameUtf8() {
    wchar_t buf[256];
    DWORD sz = 256;
    if (!GetComputerNameW(buf, &sz)) return {};
    return Utf16ToUtf8(std::wstring(buf, sz));
}

std::string IsoTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

template <typename T, typename F>
void EmitFindingArray(std::string& out, const char* panel,
                      const std::vector<T>& items, F&& fields) {
    if (items.empty()) return;
    out.push_back(',');
    out.push_back('"'); out += panel; out += "\":[";
    bool firstItem = true;
    for (const auto& it : items) {
        if (!firstItem) out.push_back(',');
        firstItem = false;
        out.push_back('{');
        bool first = true;
        fields(it, [&](const char* k, const std::string& v) {
            AppendField(out, k, v, first);
        });
        out.push_back('}');
    }
    out.push_back(']');
}

bool ParseUrl(const std::wstring& url, std::wstring& host, INTERNET_PORT& port,
              std::wstring& path, bool& https) {
    URL_COMPONENTSW u{};
    u.dwStructSize = sizeof(u);
    wchar_t hostBuf[256] = {};
    wchar_t pathBuf[2048] = {};
    u.lpszHostName = hostBuf;       u.dwHostNameLength = 256;
    u.lpszUrlPath  = pathBuf;       u.dwUrlPathLength  = 2048;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &u)) return false;
    host  = hostBuf;
    path  = pathBuf[0] ? pathBuf : L"/";
    port  = u.nPort;
    https = (u.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

void WritePendingFile(const std::string& json) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t dir[64];
    std::swprintf(dir, 64, L"Z:\\rxvscan_%04u%02u%02u_%02u%02u%02u",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    CreateDirectoryW(dir, nullptr);
    std::wstring path = std::wstring(dir) + L"\\upload_pending.json";
    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) f.write(json.data(), static_cast<std::streamsize>(json.size()));
}

} // namespace

Config LoadConfigFromRegistry() {
    Config cfg;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        cfg.apiKey   = ReadRegString(hKey, kRegApiKey);
        cfg.endpoint = ReadRegString(hKey, kRegEndpoint);
        RegCloseKey(hKey);
    }
    // Fallback: if no API key in registry, try embedded PIN
    if (cfg.apiKey.empty()) {
        std::string embeddedPin = ReadEmbeddedPin();
        if (!embeddedPin.empty()) {
            cfg.apiKey.assign(embeddedPin.begin(), embeddedPin.end());
        }
    }
    // Fallback: if no endpoint in registry, try embedded endpoint (patched at download)
    if (cfg.endpoint.empty()) {
        std::string embeddedEndpoint = ReadEmbeddedEndpoint();
        if (!embeddedEndpoint.empty()) {
            cfg.endpoint.assign(embeddedEndpoint.begin(), embeddedEndpoint.end());
        } else {
            cfg.endpoint = L"https://rxvteam.com/api/scans";
        }
    }
    cfg.valid = !cfg.apiKey.empty() && !cfg.endpoint.empty();
    return cfg;
}

bool SaveConfigToRegistry(const Config& cfg) {
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegPath, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) return false;
    LONG r1 = RegSetValueExW(hKey, kRegApiKey, 0, REG_SZ,
                             reinterpret_cast<const BYTE*>(cfg.apiKey.c_str()),
                             static_cast<DWORD>((cfg.apiKey.size() + 1) * sizeof(wchar_t)));
    LONG r2 = RegSetValueExW(hKey, kRegEndpoint, 0, REG_SZ,
                             reinterpret_cast<const BYTE*>(cfg.endpoint.c_str()),
                             static_cast<DWORD>((cfg.endpoint.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS;
}

std::string BuildScanJson(const ScannerUI::ScanData& data,
                          const std::string& clientScanId,
                          const std::string& startedAt,
                          const std::string& status,
                          const std::string& stage,
                          float progress) {
    std::string out;
    out.reserve(64 * 1024);
    out.push_back('{');
    bool first = true;
    AppendField(out, "clientScanId", clientScanId, first);
    AppendField(out, "startedAt", startedAt, first);
    AppendField(out, "status", status, first);
    AppendField(out, "stage", stage, first);
    if (!first) out.push_back(',');
    first = false;
    out += "\"progress\":";
    char progressBuf[32];
    std::snprintf(progressBuf, sizeof(progressBuf), "%.4f",
                  progress < 0.0f ? 0.0f : progress > 1.0f ? 1.0f : progress);
    out += progressBuf;
    AppendField(out, "scannerVersion", data.version, first);
    AppendField(out, "hostname", GetHostnameUtf8(), first);
    AppendField(out, "hwid", data.hwid, first);
    AppendField(out, "biosMode", data.biosMode, first);
    AppendField(out, "osVersion", data.osVersion, first);
    AppendField(out, "device", data.device, first);
    AppendField(out, "finishedAt", IsoTimestamp(), first);

    EmitFindingArray(out, "emulator", data.emulatorFindings,
        [](const ScannerUI::EmulatorFinding& f, auto add) {
            add("process", f.process); add("type", f.type); add("address", f.address);
            add("detail", f.detail);   add("severity", f.severity);
        });

    EmitFindingArray(out, "systemMemory", data.systemMemoryFindings,
        [](const ScannerUI::EmulatorFinding& f, auto add) {
            add("process", f.process); add("type", f.type); add("address", f.address);
            add("detail", f.detail);   add("severity", f.severity);
        });

    EmitFindingArray(out, "genericBypass", data.genericBypass,
        [](const ScannerUI::GenericBypassFinding& f, auto add) {
            add("date", f.date); add("time", f.time); add("type", f.type);
            add("process", f.process); add("target", f.target); add("detail", f.detail);
            add("severity", f.severity); add("ruleId", f.ruleId); add("source", f.source);
            add("confidence", f.confidence); add("evidenceState", f.evidenceState);
        });

    EmitFindingArray(out, "streamMod", data.streamModFindings,
        [](const ScannerUI::StreamModFinding& f, auto add) {
            add("type", f.type); add("process", f.process); add("target", f.target);
            add("detail", f.detail); add("severity", f.severity);
        });

    EmitFindingArray(out, "remotePort", data.remotePortFindings,
        [](const ScannerUI::RemotePortFinding& f, auto add) {
            add("protocol", f.protocol); add("port", f.port); add("bindAddress", f.bindAddress);
            add("pid", f.pid); add("process", f.process); add("path", f.path);
            add("signer", f.signer); add("parentChain", f.parentChain);
            add("scriptOrHost", f.scriptOrHost); add("firewallRule", f.firewallRule);
            add("tunnelPeer", f.tunnelPeer); add("reason", f.reason);
            add("detail", f.detail); add("severity", f.severity);
        });

    EmitFindingArray(out, "efi", data.efiCheats,
        [](const ScannerUI::EfiCheatFinding& f, auto add) {
            add("date", f.date); add("time", f.time); add("severity", f.severity);
            add("path", f.path); add("reason", f.reason); add("detail", f.detail);
            add("ruleId", f.ruleId); add("source", f.source);
            add("confidence", f.confidence); add("evidenceState", f.evidenceState);
        });

    EmitFindingArray(out, "kernelDrivers", data.kernelDrivers,
        [](const ScannerUI::KernelDriverFinding& f, auto add) {
            add("date", f.date); add("time", f.time); add("severity", f.severity);
            add("path", f.path); add("reason", f.reason); add("detail", f.detail);
        });

    EmitFindingArray(out, "registry", data.registryFindings,
        [](const ScannerUI::RegistryFinding& f, auto add) {
            add("date", f.date); add("time", f.time); add("severity", f.severity);
            add("key", f.key); add("value", f.value); add("data", f.data);
            add("reason", f.reason); add("detail", f.detail);
        });

    EmitFindingArray(out, "clsid", data.clsidFindings,
        [](const ScannerUI::ClsidFinding& f, auto add) {
            add("date", f.date); add("time", f.time); add("severity", f.severity);
            add("clsid", f.clsid); add("friendlyName", f.friendlyName);
            add("hivePath", f.hivePath); add("serverType", f.serverType);
            add("serverPath", f.serverPath); add("reason", f.reason); add("detail", f.detail);
        });

    EmitFindingArray(out, "driverIntegrity", data.driverIntegrity,
        [](const ScannerUI::DriverIntegrityFinding& f, auto add) {
            add("date", f.date); add("time", f.time); add("severity", f.severity);
            add("driverName", f.driverName); add("path", f.path); add("sha256", f.sha256);
            add("signerName", f.signerName); add("reason", f.reason);
            add("detail", f.detail); add("verdict", f.verdict);
        });

    EmitFindingArray(out, "kernelAnomalies", data.kernelAnomalies,
        [](const ScannerUI::KernelAnomalyFinding& f, auto add) {
            add("severity", f.severity); add("type", f.type);
            add("driverName", f.driverName); add("path", f.path);
            add("reason", f.reason); add("detail", f.detail);
        });

    out.push_back('}');
    return out;
}

bool PostScanResults(const ScannerUI::ScanData& data,
                     const Config& cfg,
                     const std::string& clientScanId,
                     const std::string& startedAt,
                     const std::string& status,
                     const std::string& stage,
                     float progress,
                     bool persistOnFailure,
                     std::string& outError) {
    std::string body = BuildScanJson(data, clientScanId, startedAt, status, stage, progress);

    std::wstring host, path;
    INTERNET_PORT port = 0;
    bool https = false;
    if (!ParseUrl(cfg.endpoint, host, port, path, https)) {
        outError = "invalid endpoint URL";
        if (persistOnFailure) WritePendingFile(body);
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"rxvscan/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        outError = "WinHttpOpen failed";
        if (persistOnFailure) WritePendingFile(body);
        return false;
    }

    DWORD timeout = persistOnFailure ? 10000 : 3500;
    WinHttpSetTimeouts(hSession, timeout, timeout, timeout, timeout);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        outError = "WinHttpConnect failed";
        WinHttpCloseHandle(hSession);
        if (persistOnFailure) WritePendingFile(body);
        return false;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        outError = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        if (persistOnFailure) WritePendingFile(body);
        return false;
    }

    std::wstring headers = L"Content-Type: application/json\r\nX-Api-Key: " + cfg.apiKey;

    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(),
        static_cast<DWORD>(-1L), const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
    bool success = false;
    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
        if (status >= 200 && status < 300) {
            success = true;
        } else {
            char codebuf[32];
            std::snprintf(codebuf, sizeof(codebuf), "HTTP %lu", status);
            outError = codebuf;
        }
    } else {
        outError = "WinHttpSendRequest failed";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (!success && persistOnFailure) WritePendingFile(body);
    return success;
}

namespace {

// extrai valor string de um campo JSON top-level: "key":"...". Naive, sem decodificar
// escapes complexos — basta pros campos curtos do endpoint /api/blacklist/check.
std::string ExtractJsonStringField(const std::string& body, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t i = body.find(needle);
    if (i == std::string::npos) return "";
    i = body.find(':', i + needle.size());
    if (i == std::string::npos) return "";
    ++i;
    while (i < body.size() && (body[i] == ' ' || body[i] == '\t')) ++i;
    if (i >= body.size() || body[i] != '"') return "";
    ++i;
    std::string out;
    while (i < body.size() && body[i] != '"') {
        if (body[i] == '\\' && i + 1 < body.size()) {
            char esc = body[i + 1];
            switch (esc) {
                case 'n': out.push_back('\n'); break;
                case 't': out.push_back('\t'); break;
                case 'r': out.push_back('\r'); break;
                case '\\': out.push_back('\\'); break;
                case '"': out.push_back('"'); break;
                case '/': out.push_back('/'); break;
                default: out.push_back(esc); break;
            }
            i += 2;
        } else {
            out.push_back(body[i++]);
        }
    }
    return out;
}

bool JsonBoolFieldTrue(const std::string& body, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t i = body.find(needle);
    if (i == std::string::npos) return false;
    i = body.find(':', i + needle.size());
    if (i == std::string::npos) return false;
    ++i;
    while (i < body.size() && (body[i] == ' ' || body[i] == '\t')) ++i;
    return body.compare(i, 4, "true") == 0;
}

} // namespace

BlacklistHit CheckHwidBlacklist(const std::string& hwidUtf8) {
    BlacklistHit hit;
    if (hwidUtf8.empty() || hwidUtf8 == "TPM2_PUBLIC_HASH_UNAVAILABLE") {
        hit.error = "no_hwid";
        return hit;
    }

    Config cfg = LoadConfigFromRegistry();
    if (!cfg.valid) {
        hit.error = "no_config";
        return hit;
    }

    std::wstring host, path;
    INTERNET_PORT port = 0;
    bool https = false;
    if (!ParseUrl(cfg.endpoint, host, port, path, https)) {
        hit.error = "invalid_endpoint";
        return hit;
    }

    // mantém apenas host+porta+esquema do endpoint configurado e troca o path
    // pra /api/blacklist/check?hwid=... — assim continua funcionando mesmo se
    // o endpoint apontar pra /api/scans.
    std::wstring whwid(hwidUtf8.begin(), hwidUtf8.end());
    std::wstring checkPath = L"/api/blacklist/check?hwid=" + whwid;

    HINTERNET hSession = WinHttpOpen(L"rxvscan/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { hit.error = "WinHttpOpen"; return hit; }
    WinHttpSetTimeouts(hSession, 4000, 4000, 4000, 4000);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        hit.error = "WinHttpConnect"; return hit;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", checkPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        hit.error = "WinHttpOpenRequest"; return hit;
    }

    std::wstring headers = L"X-Api-Key: " + cfg.apiKey;
    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(),
        static_cast<DWORD>(-1L),
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    std::string body;
    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            std::string chunk(avail, '\0');
            DWORD readBytes = 0;
            if (!WinHttpReadData(hRequest, chunk.data(), avail, &readBytes)) break;
            chunk.resize(readBytes);
            body += chunk;
            if (body.size() > 64 * 1024) break;
        }

        if (status >= 200 && status < 300) {
            hit.blacklisted = JsonBoolFieldTrue(body, "blacklisted");
            if (hit.blacklisted) {
                hit.exposedId = ExtractJsonStringField(body, "exposedId");
                hit.title     = ExtractJsonStringField(body, "title");
                hit.summary   = ExtractJsonStringField(body, "summary");
                hit.severity  = ExtractJsonStringField(body, "severity");
                hit.createdAt = ExtractJsonStringField(body, "createdAt");
            }
        } else {
            char codebuf[32];
            std::snprintf(codebuf, sizeof(codebuf), "HTTP %lu", status);
            hit.error = codebuf;
        }
    } else {
        hit.error = "WinHttpSendRequest";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return hit;
}

bool TryUploadSnapshot(const ScannerUI::ScanData& data,
                       const std::string& clientScanId,
                       const std::string& startedAt,
                       const std::string& status,
                       const std::string& stage,
                       float progress,
                       bool persistOnFailure,
                       std::string& outMessage) {
    Config cfg = LoadConfigFromRegistry();
    if (!cfg.valid) {
        outMessage = "upload skipped: no API key/endpoint configured";
        return false;
    }
    std::string err;
    if (PostScanResults(data, cfg, clientScanId, startedAt, status, stage,
                        progress, persistOnFailure, err)) {
        outMessage = status == "complete" ? "upload OK" : "live snapshot OK";
        return true;
    }
    outMessage = "upload failed: " + err;
    if (persistOnFailure) outMessage += " (saved upload_pending.json)";
    return false;
}

}
