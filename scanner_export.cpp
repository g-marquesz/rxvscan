#include "scanner_core.h"

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

// Returns the last path component (filename), wide version.
static std::wstring BaseNameW(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? path : path.substr(p + 1);
}

// Builds a unique destination path in samplesDir for a given source basename.
// Adds _2, _3, ... suffix before the extension if the name is already taken.
static std::wstring UniqueSamplePath(const std::wstring& samplesDir,
                                     const std::string& severity,
                                     const std::wstring& srcBasename) {
    std::wstring prefix = Utf8ToWide(severity) + L"_" + srcBasename;
    std::wstring candidate = samplesDir + L"\\" + prefix;
    if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES)
        return candidate;
    // Collision — insert suffix before extension
    size_t dot = prefix.rfind(L'.');
    std::wstring stem = (dot == std::wstring::npos) ? prefix : prefix.substr(0, dot);
    std::wstring ext  = (dot == std::wstring::npos) ? L""    : prefix.substr(dot);
    for (int i = 2; i < 1000; ++i) {
        candidate = samplesDir + L"\\" + stem + L"_" + std::to_wstring(i) + ext;
        if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES)
            return candidate;
    }
    return candidate; // fallback (very unlikely)
}

// Tries to copy srcPath (UTF-8) to samplesDir. Returns true on success.
static bool CopyFileTo(const std::string& srcPathUtf8,
                       const std::string& severity,
                       const std::wstring& samplesDir) {
    if (srcPathUtf8.empty()) return false;
    std::wstring src = Utf8ToWide(srcPathUtf8);
    if (GetFileAttributesW(src.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    std::wstring basename = BaseNameW(src);
    if (basename.empty()) return false;
    std::wstring dst = UniqueSamplePath(samplesDir, severity, basename);
    return CopyFileW(src.c_str(), dst.c_str(), FALSE) != 0;
}

// Dumps the first 512 bytes of PhysicalDrive0 to samplesDir\PhysicalDrive0_MBR.bin.
static void DumpMbrSector(const std::wstring& samplesDir) {
    HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    uint8_t sector[512] = {};
    DWORD rd = 0;
    bool ok = ReadFile(h, sector, 512, &rd, nullptr) && rd == 512;
    CloseHandle(h);
    if (!ok) return;
    std::wstring outPath = samplesDir + L"\\PhysicalDrive0_MBR.bin";
    HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(hOut, sector, 512, &written, nullptr);
    CloseHandle(hOut);
}

// ── Report text helpers ───────────────────────────────────────────────────────

static void WriteSep(std::ofstream& f) {
    f << "================================================================================\n";
}

static void WriteSection(std::ofstream& f, const std::string& title, const std::string& status) {
    f << "\n[" << title << "] " << status << "\n";
    f << "--------------------------------------------------------------------------------\n";
}

static void WriteReport(const ScannerUI::ScanData& d, const std::wstring& outDir) {
    std::wstring path = outDir + L"\\report.txt";
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) return;

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char ts[32] = {};
    snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    WriteSep(f);
    f << "RXVScan Report\n";
    f << "Scan Date : " << ts << "\n";
    f << "Device    : " << d.device << "\n";
    f << "OS        : " << d.osVersion << "\n";
    f << "HWID      : " << d.hwid << "\n";
    WriteSep(f);

    // EFI Cheat Detect
    WriteSection(f, "EFI CHEAT DETECT", d.efiCheatStatus);
    if (d.efiCheats.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.efiCheats) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    Path:   " << x.path << "\n";
        f << "    Reason: " << x.reason << "\n";
        f << "    Detail: " << x.detail << "\n";
        if (!x.ruleId.empty()) f << "    Rule: " << x.ruleId << "\n";
        if (!x.source.empty()) f << "    Source: " << x.source << "\n";
        if (!x.confidence.empty()) f << "    Confidence: " << x.confidence << "\n";
        if (!x.evidenceState.empty()) f << "    Evidence: " << x.evidenceState << "\n";
        f << "\n";
    }

    // Driver Integrity
    WriteSection(f, "DRIVER INTEGRITY", d.driverIntegrityStatus);
    if (d.driverIntegrity.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.driverIntegrity) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    Driver: " << x.driverName << "\n";
        f << "    Path:   " << x.path << "\n";
        f << "    Reason: " << x.reason << "\n";
        f << "    Detail: " << x.detail << "\n";
        if (!x.verdict.empty()) f << "    Verdict: " << x.verdict << "\n";
        f << "\n";
    }

    // Kernel Drivers
    WriteSection(f, "KERNEL DRIVERS", d.kernelDriverStatus);
    if (d.kernelDrivers.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.kernelDrivers) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    Path:   " << x.path << "\n";
        f << "    Reason: " << x.reason << "\n";
        f << "    Detail: " << x.detail << "\n\n";
    }

    // Kernel Anomalies
    WriteSection(f, "KERNEL ANOMALIES", d.kernelAnomalyStatus);
    if (d.kernelAnomalies.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.kernelAnomalies) {
        f << "  [" << x.severity << "] " << x.type << "\n";
        f << "    Driver: " << x.driverName << "\n";
        f << "    Path:   " << x.path << "\n";
        f << "    Reason: " << x.reason << "\n";
        f << "    Detail: " << x.detail << "\n\n";
    }

    // Registry Persistence
    WriteSection(f, "REGISTRY PERSISTENCE", d.registryStatus);
    if (d.registryFindings.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.registryFindings) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    Key:    " << x.key << "\n";
        f << "    Value:  " << x.value << "\n";
        f << "    Data:   " << x.data << "\n";
        f << "    Reason: " << x.reason << "\n\n";
    }

    // CLSID Hijack
    WriteSection(f, "CLSID HIJACK", d.clsidStatus);
    if (d.clsidFindings.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.clsidFindings) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    CLSID:  " << x.clsid << " (" << x.friendlyName << ")\n";
        f << "    Server: " << x.serverPath << "\n";
        f << "    Reason: " << x.reason << "\n\n";
    }

    // Generic Bypass
    WriteSection(f, "GENERIC BYPASS", d.genericBypassStatus);
    if (d.genericBypass.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.genericBypass) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    Type:    " << x.type << "\n";
        f << "    Process: " << x.process << "\n";
        f << "    Target:  " << x.target << "\n";
        f << "    Detail:  " << x.detail << "\n";
        if (!x.ruleId.empty()) f << "    Rule: " << x.ruleId << "\n";
        if (!x.source.empty()) f << "    Source: " << x.source << "\n";
        if (!x.confidence.empty()) f << "    Confidence: " << x.confidence << "\n";
        if (!x.evidenceState.empty()) f << "    Evidence: " << x.evidenceState << "\n";
        f << "\n";
    }

    // Stream Mods
    WriteSection(f, "STREAM MODS", d.streamModStatus);
    if (d.streamModFindings.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.streamModFindings) {
        f << "  [" << x.severity << "] " << x.type << "\n";
        f << "    Process: " << x.process << "\n";
        f << "    Target:  " << x.target << "\n";
        f << "    Detail:  " << x.detail << "\n\n";
    }

    // Remote Ports
    WriteSection(f, "REMOTE PORTS", d.remotePortStatus);
    if (d.remotePortFindings.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.remotePortFindings) {
        f << "  [" << x.severity << "] " << x.protocol << ":" << x.port << "\n";
        f << "    Process: " << x.process << " (" << x.path << ")\n";
        f << "    Reason:  " << x.reason << "\n";
        f << "    Detail:  " << x.detail << "\n\n";
    }

    // Timeline
    WriteSection(f, "TIMELINE CORRELATION", d.timelineStatus);
    if (d.timelineFindings.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.timelineFindings) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    Path:   " << x.path << "\n";
        f << "    Reason: " << x.reason << "\n";
        f << "    Detail: " << x.detail << "\n\n";
    }

    // BAM
    WriteSection(f, "BAM DETECTIONS", "");
    if (d.bam.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.bam) {
        f << "  " << x.date << " " << x.time;
        if (x.suspicious) f << " [SUSPICIOUS]";
        f << "\n";
        f << "    Path:   " << x.path << "\n";
        f << "    Reason: " << x.reason << "\n\n";
    }

    // Prefetch
    WriteSection(f, "PREFETCH", "");
    if (d.prefetch.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.prefetch) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    File: " << x.file << "\n";
        if (!x.note.empty()) f << "    Note: " << x.note << "\n";
        f << "\n";
    }

    // USN Anomalies
    WriteSection(f, "USN ANOMALIES", d.usnAnomalyStatus);
    if (d.usnAnomalies.empty()) { f << "  (none)\n"; }
    for (const auto& x : d.usnAnomalies) {
        f << "  [" << x.severity << "] " << x.date << " " << x.time << "\n";
        f << "    File: " << x.file << "\n";
        if (!x.note.empty()) f << "    Note: " << x.note << "\n";
        f << "\n";
    }

    WriteSep(f);
    f << "End of report.\n";
}

// ── Main export function ──────────────────────────────────────────────────────

void ExportScanReportToZ(ScannerUI::ScanData& data) {
    // Only export if Z:\ is accessible
    if (GetFileAttributesW(L"Z:\\") == INVALID_FILE_ATTRIBUTES)
        return;

    // Build timestamped directory name
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t dirName[64] = {};
    swprintf_s(dirName, L"Z:\\rxvscan_%04d%02d%02d_%02d%02d%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::wstring outDir = dirName;
    std::wstring samplesDir = outDir + L"\\samples";

    if (!CreateDirectoryW(outDir.c_str(), nullptr)) return;
    CreateDirectoryW(samplesDir.c_str(), nullptr);

    char dirUtf8[256] = {};
    WideCharToMultiByte(CP_UTF8, 0, outDir.c_str(), -1, dirUtf8, sizeof(dirUtf8), nullptr, nullptr);

    data.terminalLog.push_back(std::string("[EXPORT] Exportando para ") + dirUtf8);

    // 1. Write text report
    WriteReport(data, outDir);

    // 2. Copy suspicious files to samples/
    int copied = 0;

    // All EFI findings (regardless of suspicious flag — user wants to inspect them)
    for (const auto& x : data.efiCheats) {
        // Skip MBR/NVRAM virtual paths — they have no real file to copy
        if (x.path.find("PhysicalDrive") != std::string::npos) continue;
        if (x.path.find("NVRAM::") != std::string::npos) continue;
        if (CopyFileTo(x.path, x.severity, samplesDir)) ++copied;
    }

    // Suspicious driver integrity findings
    for (const auto& x : data.driverIntegrity) {
        if (x.suspicious && CopyFileTo(x.path, x.severity, samplesDir)) ++copied;
    }

    // Suspicious kernel drivers
    for (const auto& x : data.kernelDrivers) {
        if (x.suspicious && CopyFileTo(x.path, x.severity, samplesDir)) ++copied;
    }

    // Suspicious timeline correlations
    for (const auto& x : data.timelineFindings) {
        if (x.suspicious && CopyFileTo(x.path, x.severity, samplesDir)) ++copied;
    }

    // Suspicious BAM entries
    for (const auto& x : data.bam) {
        if (x.suspicious && CopyFileTo(x.path, "", samplesDir)) ++copied;
    }

    // Prefetch entries with HIGH/MEDIUM severity
    for (const auto& x : data.prefetch) {
        if ((x.severity == "HIGH" || x.severity == "MEDIUM") &&
            CopyFileTo(x.file, x.severity, samplesDir)) ++copied;
    }

    // 3. Dump MBR sector 0 if any EFI finding mentions a physical drive
    bool hasMbrFinding = false;
    for (const auto& x : data.efiCheats)
        if (x.path.find("PhysicalDrive") != std::string::npos) { hasMbrFinding = true; break; }
    if (hasMbrFinding)
        DumpMbrSector(samplesDir);

    data.terminalLog.push_back("[EXPORT] " + std::to_string(copied) + " arquivo(s) copiado(s) para samples\\");
    data.terminalLog.push_back(std::string("[EXPORT] Concluido: ") + dirUtf8);
}
