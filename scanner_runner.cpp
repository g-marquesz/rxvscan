#include "scanner_core.h"
#include "embedded_driver.h"
#include "rtcore64_driver.h"

void AppendTerminalLine(ScannerUI::ScanData& data, const std::string& line);

static std::mutex g_scanOptionMutex;
static std::atomic_bool g_scanRunning = false;

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

    if (normalized == "run!pg4") {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            if (data.deepScanStatus == "Loading") return;
            data.deepScanStatus = "Loading";
            data.deepScanFindings.clear();
            AppendTerminalLine(data, "> deep scan started");
        }
        std::string deepScanStatus;
        auto deepScanFindings = CollectDeepScanFindings(deepScanStatus);
        bool xvLoaded = false;
        bool rtcoreLoaded = false;
        std::string xvStatus;
        {
            XvKernelDriver xv;
            xvLoaded = xv.Load();
            xvStatus = xv.Status();

            RTCoreDriver rtcore;
            if (rtcore.Load(L"")) {
                rtcoreLoaded = true;
                auto virtualFindings = rtcore.VerifyKernelVirtualIntegrity();
                auto physicalFindings = rtcore.VerifyKernelIntegrity();
                virtualFindings.insert(virtualFindings.end(),
                                       physicalFindings.begin(), physicalFindings.end());
                for (const auto& kernel : virtualFindings) {
                    ScannerUI::DeepScanFinding finding;
                    finding.type = "KRTSCAN";
                    finding.process = kernel.driverName;
                    finding.target = kernel.path;
                    finding.detail = kernel.reason + " | " + kernel.detail;
                    finding.severity = kernel.severity;
                    deepScanFindings.push_back(std::move(finding));
                }

                auto hiddenProcesses = rtcore.FindHiddenProcesses();
                for (const auto& hidden : hiddenProcesses) {
                    std::ostringstream address;
                    address << std::uppercase << std::hex << hidden.eprocessVirtual;
                    ScannerUI::DeepScanFinding finding;
                    finding.type = "DKOM";
                    finding.process = hidden.imageFileName;
                    finding.target = "PID:" + std::to_string(hidden.pid);
                    finding.detail = hidden.reason + " | eprocess_va=0x" + address.str();
                    finding.severity = "HIGH";
                    deepScanFindings.push_back(std::move(finding));
                }

                rtcore.Unload();
                if (!virtualFindings.empty() || !physicalFindings.empty() ||
                    !hiddenProcesses.empty())
                    deepScanStatus = "DETECTED";
            }
        }
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.deepScanFindings = std::move(deepScanFindings);
            data.deepScanStatus   = deepScanStatus;
            AppendTerminalLine(data, xvLoaded
                ? "> xvscreen kernel backend loaded and unloaded"
                : "> xvscreen kernel backend unavailable: " + xvStatus);
            AppendTerminalLine(data, rtcoreLoaded
                ? "> RTCore64 read-only virtual/physical kernel verification completed and unloaded"
                : "> RTCore64 unavailable; user-mode deep scan completed");
            AppendTerminalLine(data, "> deep scan loaded");
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
    switch (static_cast<ScanTier>(g_scanTier.load())) {
        case ScanTier::Overloaded: Sleep(180); break;
        case ScanTier::Busy:       Sleep(80);  break;
        default:                   Sleep(25);  break;
    }
}

void MaybePaceIteration(size_t& counter, size_t everyN) {
    if (everyN == 0 || (++counter % everyN) != 0)
        return;
    switch (static_cast<ScanTier>(g_scanTier.load())) {
        case ScanTier::Overloaded: Sleep(3);    break;
        case ScanTier::Busy:       Sleep(1);    break;
        default:                   Sleep(0);    break;
    }
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
    ResetSystemHandleSnapshot();
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
        data.deepScanStatus = "Waiting";
        data.deepScanFindings.clear();
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

        std::string usnStatus, usnDrive;
        auto usnAnomalies = CollectUsnJournalIntegrityFindings(usnStatus, usnDrive);

        auto prefetch  = CollectHiddenPrefetchDetections();

        auto prefInteg = CollectPrefetchIntegrityFindings();

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
    bool xvKernelLoaded = false;
    bool emulatorKernelLoaded = false;
    std::string xvKernelStatus;
    {
        XvKernelDriver xv;
        xvKernelLoaded = xv.Load();
        xvKernelStatus = xv.Status();

        RTCoreDriver rtcore;
        if (rtcore.Load(L"")) {
            emulatorKernelLoaded = true;
            auto kernelFindings = rtcore.VerifyKernelVirtualIntegrity();
            for (const auto& kernel : kernelFindings) {
                ScannerUI::EmulatorFinding finding;
                finding.process = kernel.driverName.empty() ? "Kernel" : kernel.driverName;
                finding.type = ScanTag::MemoryProtect;
                finding.address = kernel.path.empty() ? "kernel" : kernel.path;
                finding.detail = "Kernel backend detectou interferencia nas APIs de memoria/thread"
                                 " | " + kernel.reason + " | " + kernel.detail;
                finding.severity = kernel.severity;
                emulatorFindings.push_back(std::move(finding));
            }
            rtcore.Unload();
        }
    }
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
        AppendTerminalLine(data, xvKernelLoaded
            ? "> xvscreen kernel backend loaded and unloaded"
            : "> xvscreen kernel backend unavailable: " + xvKernelStatus);
        AppendTerminalLine(data, emulatorKernelLoaded
            ? "> RTCore64 kernel attestation completed and driver unloaded"
            : "> RTCore64 backend unavailable; memory/thread scan completed");
        AppendTerminalLine(data, "> emulator integrity loaded");
    }

    ScanThrottlePause();
    std::string sysmemStatus;
    std::vector<ScannerUI::EmulatorFinding> suspiciousProcessFindings;
    auto sysmemFindings = CollectSystemMemoryFindings(sysmemStatus, suspiciousProcessFindings);
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        data.systemMemoryFindings = std::move(sysmemFindings);
        data.systemMemoryStatus = sysmemStatus;
        data.scanProgress = 0.93f;
        data.currentStage = "Analisando memoria do sistema";
        AppendTerminalLine(data, "> system memory scan loaded");
    }

    ScanThrottlePause();
    {



        std::lock_guard<std::mutex> lock(dataMutex);
        for (auto& f : suspiciousProcessFindings)
            data.systemMemoryFindings.push_back(f);
        AppendTerminalLine(data, "> suspicious process scan loaded");
    }

    ScanThrottlePause();
    {


        auto dkomFindings = CollectDkomAnomalies();
        std::lock_guard<std::mutex> lock(dataMutex);
        for (auto& f : dkomFindings)
            data.systemMemoryFindings.push_back(f);
        AppendTerminalLine(data, "> DKOM cross-check loaded");
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
        bool clsidHigh = false;
        for (const auto& clsid : clsidFindings) {
            ScannerUI::GenericBypassFinding finding;
            finding.date = clsid.date;
            finding.time = clsid.time;
            finding.type = clsid.serverType == "Hidden" ? "CLSID_HIDDEN" :
                           clsid.serverType == "Deleted" ? "CLSID_DELETED" :
                                                           "CLSID_DEVIATION";
            const bool hasServerPath = clsid.serverType != "Hidden" &&
                                       clsid.serverType != "Deleted" &&
                                       !clsid.serverPath.empty() && clsid.serverPath != "-";
            finding.process = hasServerPath ? clsid.serverPath : clsid.hivePath;
            finding.target = clsid.clsid;
            finding.detail = clsid.reason + " | server_type=" + clsid.serverType +
                             " | server=" + clsid.serverPath + " | " + clsid.detail;
            finding.severity = clsid.severity;
            finding.ruleId = "REG.COM.CLSID_" + finding.type;
            finding.source = clsid.serverType == "Deleted" ? "Sysmon registry telemetry" :
                                                               "Registry cross-view";
            finding.confidence = clsid.serverType == "Hidden" ? "HIGH" : "MEDIUM";
            finding.evidenceState = clsid.serverType == "Hidden" ? "SUSPICIOUS" : "REVIEW";
            clsidHigh |= clsid.severity == "HIGH";
            data.genericBypass.push_back(std::move(finding));
        }
        if (!clsidFindings.empty())
            data.genericBypassStatus = clsidHigh ? "DETECTED" : "REVIEW";
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

    } catch (const std::exception& ex) {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.speedScan = "error";
            data.currentStage = "Falha durante o scan";
            AppendTerminalLine(data, std::string("> scan crashed: ") + ex.what());
        }
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            data.speedScan = "error";
            data.currentStage = "Falha durante o scan";
            AppendTerminalLine(data, "> scan crashed: unknown exception");
        }
    }
    g_scanFinished = true;
    g_scanRunning = false;
}
