#include "scanner_core.h"
#include "scanner_upload.h"

void AppendTerminalLine(ScannerUI::ScanData& data, const std::string& line);

static std::mutex g_scanOptionMutex;          // serializa comandos de terminal
static std::atomic_bool g_scanRunning = false; // previne scan concorrente sem bloquear UI

void RunTerminalCommandAsync(const std::string& command, ScannerUI::ScanData& data, std::mutex& dataMutex) {
    std::lock_guard<std::mutex> scanLock(g_scanOptionMutex);
    std::string normalized = ToLowerAscii(TrimAscii(command));
    if (normalized == "xv!pg1") {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.activePage = 1;
        AppendTerminalLine(data, "> page 1 opened: scanner");
        return;
    }

    if (normalized == "xv!pg2") {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.activePage = 2;
        AppendTerminalLine(data, "> page 2 opened: EFI Cheat Detect");
        return;
    }

    if (normalized == "run!pg2") {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            if (data.efiCheatStatus == "Loading") return;
            data.efiCheatStatus = "Loading";
            data.efiCheats.clear();
            AppendTerminalLine(data, "> EFI scan started");
        }
        std::string efiStatus;
        auto efiFindings = CollectEfiCheatFindings(efiStatus);
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.efiCheats      = std::move(efiFindings);
            data.efiCheatStatus = efiStatus;
            AppendTerminalLine(data, "> EFI cheat detect loaded");
        }
        return;
    }

    if (normalized == "xv!pg3") {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.activePage = 3;
        AppendTerminalLine(data, "> page 3 opened: Driver & Kernel Integrity");
        return;
    }

    if (normalized == "run!pg3") {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            if (data.driverIntegrityStatus == "Loading" || data.kernelDriverStatus == "Loading") return;
            data.driverIntegrityStatus = "Loading";
            data.kernelDriverStatus = "Loading";
            data.driverIntegrity.clear();
            data.kernelDrivers.clear();
            AppendTerminalLine(data, "> driver and kernel integrity scan started");
        }
        std::string integrityStatus;
        auto integrityFindings = CollectDriverIntegrityFindings(integrityStatus);
        std::string kernelStatus;
        auto kernelFindings = CollectKernelDriverFindings(kernelStatus);
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.driverIntegrity       = std::move(integrityFindings);
            data.driverIntegrityStatus = integrityStatus;
            data.kernelDrivers         = std::move(kernelFindings);
            data.kernelDriverStatus    = kernelStatus;
            AppendTerminalLine(data, "> driver and kernel integrity scan loaded");
        }
        return;
    }

    if (normalized == "xv!pg5") {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.activePage = 3;
        AppendTerminalLine(data, "> page 5 redirected: unified Driver & Kernel Integrity");
        return;
    }

    std::string message;
    ExportUsnCsvForCommand(command, message);
    std::lock_guard<std::mutex> lock(dataMutex);
    AppendTerminalLine(data, "> " + message);
}

static void ScanThrottlePause() {
    Sleep(g_scanSlow.load() ? 180 : 25);
}

static std::string ScanUtcTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string NewClientScanId() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[96];
    std::snprintf(buf, sizeof(buf), "%04u%02u%02u-%02u%02u%02u-%lu-%llu",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                  GetCurrentProcessId(), static_cast<unsigned long long>(GetTickCount64()));
    return buf;
}

static void PublishLiveSnapshot(ScannerUI::ScanData& data,
                                std::mutex& dataMutex,
                                const std::string& clientScanId,
                                const std::string& startedAt,
                                const std::string& status,
                                const std::string& stage,
                                float progress,
                                bool persistOnFailure = false) {
    ScannerUI::ScanData snapshot;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        snapshot = data;
    }
    if (progress < 0.0f) progress = snapshot.scanProgress;
    std::string ignoredMessage;
    ScannerUpload::TryUploadSnapshot(snapshot, clientScanId, startedAt, status,
                                     stage, progress, persistOnFailure, ignoredMessage);
}

void AppendTerminalLine(ScannerUI::ScanData& data, const std::string& line) {
    data.terminalLog.push_back(line);
    if (data.terminalLog.size() > 200)
        data.terminalLog.erase(data.terminalLog.begin());
    data.terminalNotif = (int)data.terminalLog.size();
}

void RunScannerAsync(ScannerUI::ScanData& data, std::mutex& dataMutex) {
    bool expected = false;
    if (!g_scanRunning.compare_exchange_strong(expected, true))
        return;
    DetectionFilter::ClearSignatureCache();
    DetectionFilter::ClearPublisherCache();
    DetectionFilter::ClearIdentityCache();
    const std::string clientScanId = NewClientScanId();
    const std::string startedAt = ScanUtcTimestamp();
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.scanProgress = 0.02f;
        data.currentStage = "Inicializando scanner";
        data.speedScan = "starting";
        data.services = CollectServiceStatuses();
        data.bam.clear();
        data.prefetch.clear();
        data.prefetchHits = 0;
        data.sysmonStatus = "Loading";
        data.sysmonEvents.clear();
        data.sysmonDerivedReady = false;
        data.emulatorChecking = true;
        data.emulatorResult = "Checking emulator integrity";
        data.emulatorStatus = "Loading";
        data.emulatorOpenedAt = "-";
        data.emulatorFindings.clear();
        data.genericBypassStatus = "Loading";
        data.genericBypass.clear();
        data.streamModStatus = "Loading";
        data.streamModFindings.clear();
        data.remotePortStatus = "Loading";
        data.remotePortFindings.clear();
        data.systemMemoryStatus = "Loading";
        data.systemMemoryFindings.clear();
        data.efiCheatStatus = "Waiting";
        data.efiCheats.clear();
        data.driverIntegrityStatus = "Waiting";
        data.driverIntegrity.clear();
        data.kernelDriverStatus = "Waiting";
        data.kernelDrivers.clear();
        data.registryStatus = "Waiting";
        data.registryFindings.clear();
        data.clsidStatus = "Waiting";
        data.clsidFindings.clear();
        data.clsidPendingCleanIdx = -1;
        data.clsidCleanConfirmed  = false;
        AppendTerminalLine(data, "> scanner started");
    }
    PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                        "running", "Inicializando scanner", 0.02f);

    // Checa HWID contra a blacklist de exposeds publicada no site.
    // Falha de rede / sem config é silenciosa: blacklist é um bônus, não um requisito.
    {
        std::string hwidCopy;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            hwidCopy = data.hwid;
        }
        ScannerUpload::BlacklistHit hit = ScannerUpload::CheckHwidBlacklist(hwidCopy);
        if (hit.blacklisted) {
            ScannerUI::GenericBypassFinding f;
            std::string now = ScanUtcTimestamp(); // YYYY-MM-DDTHH:MM:SSZ
            f.date = now.substr(0, 10);
            f.time = now.size() >= 19 ? now.substr(11, 8) : "";
            f.type = "HWID_BLACKLIST";
            f.process = "rxvscan";
            f.target = hwidCopy;
            std::string detail = hit.title;
            if (!hit.summary.empty()) {
                if (!detail.empty()) detail += " — ";
                detail += hit.summary;
            }
            if (!hit.exposedId.empty()) {
                detail += " (exposed=" + hit.exposedId + ")";
            }
            f.detail = detail;
            std::string sev = hit.severity;
            for (auto& c : sev) c = static_cast<char>(::toupper(static_cast<unsigned char>(c)));
            f.severity = (sev == "CRITICAL" || sev == "HIGH") ? "HIGH"
                       : (sev == "LOW") ? "FLAG" : "HIGH";
            f.ruleId = "exposed.hwid";
            f.source = "rxvteam.blacklist";
            f.confidence = "HIGH";
            f.evidenceState = "CONFIRMED";

            std::lock_guard<std::mutex> lock(dataMutex);
            data.genericBypass.push_back(std::move(f));
            AppendTerminalLine(data,
                std::string("> HWID na blacklist da comunidade: ") + hit.title);
        } else if (!hit.error.empty() && hit.error != "no_config" && hit.error != "no_hwid") {
            std::lock_guard<std::mutex> lock(dataMutex);
            AppendTerminalLine(data,
                std::string("> blacklist check skipped: ") + hit.error);
        }
    }

    try {

    ScanThrottlePause();
    ScannerUI::ScanData systemOverview;
    CollectSystemOverview(systemOverview);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.boot = systemOverview.boot;
        data.explorer = systemOverview.explorer;
        data.biosVersion = systemOverview.biosVersion;
        data.biosMode = systemOverview.biosMode;
        data.osVersion = systemOverview.osVersion;
        data.device = systemOverview.device;
        data.pagefile = systemOverview.pagefile;
        data.sysType = systemOverview.sysType;
        data.scanProgress = 0.12f;
        data.currentStage = "Coletando informacoes do sistema";
        AppendTerminalLine(data, "> system info loaded");
    }
    PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                        "running", "Informacoes do sistema", 0.12f);

    ScanThrottlePause();
    std::string sysmonStatus;
    auto sysmonEvents = CollectSysmonEvents(sysmonStatus);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.sysmonEvents = std::move(sysmonEvents);
        data.sysmonDerivedReady = false;
        data.sysmonStatus = sysmonStatus;
        data.scanProgress = 0.26f;
        data.currentStage = "Lendo eventos do Sysmon";
        AppendTerminalLine(data, "> Sysmon events loaded");
    }

    ScanThrottlePause();
    auto bam = CollectBamDetections();
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.bam = std::move(bam);
        data.scanProgress = 0.48f;
        data.currentStage = "Analisando historico de execucao (BAM)";
        AppendTerminalLine(data, "> BAM detections loaded");
    }

    ScanThrottlePause();
    {
        // USN Journal integrity: detect anti-forensic manipulation of the journal itself
        std::string usnStatus, usnDrive;
        auto usnAnomalies = CollectUsnJournalIntegrityFindings(usnStatus, usnDrive);
        // Change-journal based detection: .pf created (execution confirmed) but deleted (anti-forensic)
        auto prefetch  = CollectHiddenPrefetchDetections();
        // Integrity checks: registry, reparse point, mass deletion, SysMain service
        auto prefInteg = CollectPrefetchIntegrityFindings();
        // Integrity findings go first — tampering indicators take priority in the list
        prefInteg.insert(prefInteg.end(), prefetch.begin(), prefetch.end());
        std::lock_guard<std::mutex> lock(dataMutex);
        data.prefetch       = std::move(prefInteg);
        data.prefetchHits   = (int)data.prefetch.size();
        data.usnAnomalies   = std::move(usnAnomalies);
        data.usnStatus      = std::move(usnStatus);
        data.usnDrive       = std::move(usnDrive);
        data.usnAnomalyStatus = data.usnAnomalies.empty() ? "OK" : "ANOMALY";
        data.scanProgress   = 0.72f;
        data.currentStage = "Verificando Prefetch e USN Journal";
        AppendTerminalLine(data, "> Prefetch/USN comparison loaded");
    }
    PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                        "running", "Prefetch e USN Journal", 0.72f);

    // P5 — Timeline correlation (BAM × Prefetch × USN)
    ScanThrottlePause();
    {
        std::string timelineStatus;
        std::vector<ScannerUI::BamEntry> bamCopy;
        std::vector<ScannerUI::PrefetchHit> prefetchCopy;
        std::vector<ScannerUI::SysmonEvent> sysmonCopy;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            bamCopy      = data.bam;
            prefetchCopy = data.prefetch;
            sysmonCopy   = data.sysmonEvents;
            data.timelineStatus = "Loading";
        }
        auto timelineFindings = CollectTimelineCorrelationFindings(bamCopy, prefetchCopy, sysmonCopy, timelineStatus);
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.timelineFindings = std::move(timelineFindings);
            data.timelineStatus   = timelineStatus;
            AppendTerminalLine(data, "> timeline correlation loaded");
        }
    }

    ScanThrottlePause();
    auto emulatorRuntime = CollectEmulatorRuntimeInfo();
    auto emulatorFindings = CollectEmulatorIntegrityFindings();
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.emulatorFindings = std::move(emulatorFindings);
        data.emulatorChecking = false;
        data.emulatorOpenedAt = emulatorRuntime.openedAt;
        if (!data.emulatorFindings.empty()) {
            data.emulatorStatus = "DETECTED";
            data.emulatorResult = "Review unsigned modules, injected memory or external thread starts";
        } else if (!emulatorRuntime.hdPlayerOpen) {
            data.emulatorStatus = "CLOSED";
            data.emulatorResult = "HD-Player.exe is closed";
        } else {
            data.emulatorStatus = "OK";
            data.emulatorResult = "HD-Player.exe is open and clean";
        }
        data.scanProgress = 0.84f;
        data.currentStage = "Checando integridade do emulador";
        AppendTerminalLine(data, "> emulator integrity loaded");
    }
    PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                        "running", "Integridade do emulador", 0.84f);

    ScanThrottlePause();
    std::string sysmemStatus;
    auto sysmemFindings = CollectSystemMemoryFindings(sysmemStatus);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.systemMemoryFindings = std::move(sysmemFindings);
        data.systemMemoryStatus = sysmemStatus;
        data.scanProgress = 0.93f;
        data.currentStage = "Analisando memoria do sistema";
        AppendTerminalLine(data, "> system memory scan loaded");
    }

    ScanThrottlePause();
    std::string suspProcStatus;
    auto suspProcFindings = CollectSuspiciousProcesses(suspProcStatus);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        for (auto& f : suspProcFindings)
            data.systemMemoryFindings.push_back(f);
        AppendTerminalLine(data, "> suspicious process scan loaded");
    }

    ScanThrottlePause();
    std::string genericBypassStatus;
    auto genericBypass = CollectGenericBypassFindings(genericBypassStatus);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.genericBypass = std::move(genericBypass);
        data.genericBypassStatus = genericBypassStatus;
        data.scanProgress = 0.95f;
        data.currentStage = "Procurando bypass e injecoes";
        AppendTerminalLine(data, "> generic bypass loaded");
    }
    PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                        "running", "Bypass e memoria", 0.95f);

    ScanThrottlePause();
    std::string streamModStatus;
    auto streamModFindings = CollectStreamModFindings(streamModStatus);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.streamModFindings = std::move(streamModFindings);
        data.streamModStatus   = streamModStatus;
        data.scanProgress = 0.965f;
        data.currentStage = "Verificando modificacoes de stream";
        AppendTerminalLine(data, "> stream mod scan loaded");
    }

    ScanThrottlePause();
    {
        std::string wfpStatus;
        auto wfpFindings = CollectWfpStreamFilterFindings(wfpStatus);
        std::lock_guard<std::mutex> lock(dataMutex);
        for (auto& f : wfpFindings)
            data.genericBypass.push_back(std::move(f));
        if (!wfpFindings.empty()) {
            bool anyHigh = false;
            for (const auto& f : data.genericBypass)
                if (f.severity == "HIGH") { anyHigh = true; break; }
            data.genericBypassStatus = anyHigh ? "DETECTED" : "REVIEW";
        } else if (wfpStatus.rfind("REVIEW", 0) == 0 &&
                   data.genericBypassStatus == "OK") {
            data.genericBypassStatus = wfpStatus;
        }
        AppendTerminalLine(data, "> WFP stream filter scan loaded");
    }

    ScanThrottlePause();
    {
        std::string remotePortStatus;
        auto remotePortFindings = CollectRemotePortFindings(remotePortStatus);
        std::lock_guard<std::mutex> lock(dataMutex);
        data.remotePortFindings = std::move(remotePortFindings);
        data.remotePortStatus   = remotePortStatus;
        data.scanProgress       = 0.975f;
        data.currentStage = "Checando portas remotas e rede";
        AppendTerminalLine(data, "> remote port listener scan loaded");
    }
    PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                        "running", "Portas remotas e rede", 0.975f);

    ScanThrottlePause();
    {
        std::string registryStatus;
        auto registryFindings = CollectRegistryPersistenceFindings(registryStatus);
        std::lock_guard<std::mutex> lock(dataMutex);
        data.registryFindings = std::move(registryFindings);
        data.registryStatus   = registryStatus;
        data.scanProgress     = 0.985f;
        data.currentStage = "Verificando persistencia no registro";
        AppendTerminalLine(data, "> registry persistence scan loaded");
    }

    ScanThrottlePause();
    {
        std::string clsidStatus;
        auto clsidFindings = CollectClsidHijackFindings(clsidStatus);
        std::lock_guard<std::mutex> lock(dataMutex);
        data.clsidFindings = std::move(clsidFindings);
        data.clsidStatus   = clsidStatus;
        data.scanProgress  = 0.993f;
        data.currentStage = "Verificando CLSID hijacks";
        AppendTerminalLine(data, "> CLSID hijack scan loaded");
    }

    std::string kernelAnomalyStatus;
    auto kernelAnomalies = CollectKernelAnomalies(kernelAnomalyStatus);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.kernelAnomalies = std::move(kernelAnomalies);
        data.kernelAnomalyStatus = kernelAnomalyStatus;
        data.scanProgress = 1.0f;
        data.currentStage = "Analise concluida";
        data.speedScan = "normal";
        AppendTerminalLine(data, "> kernel anomalies scan loaded");
        AppendTerminalLine(data, "> page 1 scan finished");
        AppendTerminalLine(data, "> use xv!pg2, xv!pg3 or xv!pg5 to load one extra option");
    }
    ExportScanReportToZ(data);

    {
        ScannerUI::ScanData snapshot;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            snapshot = data;
        }
        std::string uploadMsg;
        ScannerUpload::TryUploadSnapshot(snapshot, clientScanId, startedAt,
                                         "complete", "Scan concluido", 1.0f,
                                         true, uploadMsg);
        std::lock_guard<std::mutex> lock(dataMutex);
        AppendTerminalLine(data, std::string("> ") + uploadMsg);
    }

    } catch (const std::exception& ex) {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.speedScan = "error";
            data.currentStage = "Falha durante o scan";
            AppendTerminalLine(data, std::string("> scan crashed: ") + ex.what());
        }
        PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                            "error", "Falha durante o scan", -1.0f, true);
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.speedScan = "error";
            data.currentStage = "Falha durante o scan";
            AppendTerminalLine(data, "> scan crashed: unknown exception");
        }
        PublishLiveSnapshot(data, dataMutex, clientScanId, startedAt,
                            "error", "Falha durante o scan", -1.0f, true);
    }
    g_scanFinished = true;
    g_scanRunning = false;
}
