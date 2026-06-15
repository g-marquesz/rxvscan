#include "scanner_core.h"

std::wstring ExtractXmlTag(const std::wstring& xml, const std::wstring& tag) {
    std::wstring open = L"<" + tag + L">";
    std::wstring close = L"</" + tag + L">";
    size_t begin = xml.find(open);
    if (begin == std::wstring::npos)
        return {};
    begin += open.size();
    size_t end = xml.find(close, begin);
    if (end == std::wstring::npos)
        return {};
    return xml.substr(begin, end - begin);
}

std::wstring ExtractXmlAttribute(const std::wstring& xml, const std::wstring& marker, const std::wstring& attr) {
    size_t markerPos = xml.find(marker);
    if (markerPos == std::wstring::npos)
        return {};

    std::wstring needle = attr + L"=\"";
    size_t begin = xml.find(needle, markerPos);
    wchar_t quote = L'"';
    if (begin == std::wstring::npos) {
        needle = attr + L"='";
        begin = xml.find(needle, markerPos);
        quote = L'\'';
    }
    if (begin == std::wstring::npos)
        return {};

    begin += needle.size();
    size_t end = xml.find(quote, begin);
    if (end == std::wstring::npos)
        return {};
    return xml.substr(begin, end - begin);
}

std::wstring ExtractSysmonData(const std::wstring& xml, const std::wstring& name) {
    std::wstring marker = L"<Data Name='" + name + L"'>";
    size_t begin = xml.find(marker);
    if (begin == std::wstring::npos) {
        marker = L"<Data Name=\"" + name + L"\">";
        begin = xml.find(marker);
    }
    if (begin == std::wstring::npos)
        return {};

    begin += marker.size();
    size_t end = xml.find(L"</Data>", begin);
    if (end == std::wstring::npos)
        return {};
    return xml.substr(begin, end - begin);
}

static std::string SysmonEventType(int id) {
    switch (id) {
    case 1: return "Process Create";
    case 6: return "Driver Loaded";
    case 7: return "Image Loaded";
    case 8: return "CreateRemoteThread";
    case 10: return "Process Access";
    case 13: return "Registry Value Set";
    case 22: return "DNS Query";
    default: return "Sysmon Event";
    }
}

static void SysmonTimeToLocalStrings(const std::wstring& systemTime, std::string& date, std::string& time) {
    FILETIME ft = {};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (swscanf_s(systemTime.c_str(), L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) == 6) {
        SYSTEMTIME utc = {};
        utc.wYear = (WORD)year;
        utc.wMonth = (WORD)month;
        utc.wDay = (WORD)day;
        utc.wHour = (WORD)hour;
        utc.wMinute = (WORD)minute;
        utc.wSecond = (WORD)second;

        if (SystemTimeToFileTime(&utc, &ft)) {
            FileTimeToLocalStrings(ft, date, time);
            return;
        }
    }

    date = "--/--/----";
    time = "--:--:--";
}

bool SysmonSystemTimeToFileTime(const std::wstring& systemTime, FILETIME& out) {
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (swscanf_s(systemTime.c_str(), L"%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) == 6) {
        SYSTEMTIME utc = {};
        utc.wYear = (WORD)year;
        utc.wMonth = (WORD)month;
        utc.wDay = (WORD)day;
        utc.wHour = (WORD)hour;
        utc.wMinute = (WORD)minute;
        utc.wSecond = (WORD)second;

        return SystemTimeToFileTime(&utc, &out) != FALSE;
    }
    return false;
}

std::string FirstNonEmptyUtf8(std::initializer_list<std::wstring> values) {
    for (const auto& value : values) {
        if (!value.empty())
            return WideToUtf8(value);
    }
    return "-";
}

static ScannerUI::SysmonEvent ParseSysmonEventXml(const std::wstring& xml) {
    ScannerUI::SysmonEvent event;
    std::wstring idText = ExtractXmlTag(xml, L"EventID");
    event.eventId = idText.empty() ? 0 : _wtoi(idText.c_str());
    event.type = SysmonEventType(event.eventId);
    SysmonTimeToLocalStrings(ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime"), event.date, event.time);

    std::wstring image = ExtractSysmonData(xml, L"Image");
    std::wstring targetImage = ExtractSysmonData(xml, L"TargetImage");
    std::wstring sourceImage = ExtractSysmonData(xml, L"SourceImage");
    event.process = FirstNonEmptyUtf8({ image, sourceImage, targetImage });
    event.sourceProcess = WideToUtf8(sourceImage);
    event.targetProcess = WideToUtf8(targetImage);
    event.access = WideToUtf8(ExtractSysmonData(xml, L"GrantedAccess"));
    event.callTrace = WideToUtf8(ExtractSysmonData(xml, L"CallTrace"));
    event.parentProcess = WideToUtf8(ExtractSysmonData(xml, L"ParentImage"));
    event.commandLine = WideToUtf8(ExtractSysmonData(xml, L"CommandLine"));
    event.user = WideToUtf8(ExtractSysmonData(xml, L"User"));
    event.currentDirectory = WideToUtf8(ExtractSysmonData(xml, L"CurrentDirectory"));
    event.imageLoaded = WideToUtf8(ExtractSysmonData(xml, L"ImageLoaded"));
    event.registryObject = WideToUtf8(ExtractSysmonData(xml, L"TargetObject"));
    event.queryName = WideToUtf8(ExtractSysmonData(xml, L"QueryName"));
    event.startAddress = WideToUtf8(ExtractSysmonData(xml, L"StartAddress"));

    switch (event.eventId) {
    case 1:
        event.detail = "Image: " + FirstNonEmptyUtf8({ image }) +
                       " | Parent: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"ParentImage") }) +
                       " | Cmd: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"CommandLine") });
        break;
    case 6:
        event.detail = "Driver: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"ImageLoaded") }) +
                       " | Signature: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"SignatureStatus") });
        break;
    case 7:
        event.detail = "ImageLoaded: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"ImageLoaded") });
        break;
    case 8:
        event.detail = "Target: " + FirstNonEmptyUtf8({ targetImage }) + " | Start: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"StartAddress") });
        break;
    case 10:
        event.process = event.sourceProcess.empty() ? event.process : event.sourceProcess;
        event.detail = "Source: " + FirstNonEmptyUtf8({ sourceImage }) +
                       " -> Target: " + FirstNonEmptyUtf8({ targetImage }) +
                       " | Access: " + (event.access.empty() ? "-" : event.access);
        break;
    case 13:
        event.detail = "Registry: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"TargetObject") });
        break;
    case 22:
        event.detail = "Query: " + FirstNonEmptyUtf8({ ExtractSysmonData(xml, L"QueryName") });
        break;
    default:
        event.detail = "Raw Sysmon event";
        break;
    }

    return event;
}

bool RenderEventXml(EVT_HANDLE eventHandle, std::wstring& out) {
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;
    if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bufferUsed == 0)
            return false;
    }

    std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount))
        return false;

    out.assign(buffer.data());
    return true;
}

std::vector<ScannerUI::SysmonEvent> CollectSysmonEvents(std::string& status) {
    std::vector<ScannerUI::SysmonEvent> events;
    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);
    const wchar_t* channel = L"Microsoft-Windows-Sysmon/Operational";
    const wchar_t* query = L"*[System[(EventID=10 or EventID=7 or EventID=8 or EventID=6 or EventID=22 or EventID=13 or EventID=1)]]";

    EVT_HANDLE result = EvtQuery(nullptr, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!result) {
        status = "Sysmon unavailable";
        return events;
    }

    constexpr DWORD kBatch = 12;
    EVT_HANDLE handles[kBatch] = {};
    DWORD returned = 0;
    bool reachedBoot = false;
    while (!reachedBoot && EvtNext(result, kBatch, handles, ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            std::wstring xml;
            if (RenderEventXml(handles[i], xml)) {
                FILETIME eventTime = {};
                std::wstring systemTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
                if (SysmonSystemTimeToFileTime(systemTime, eventTime)) {
                    if (FileTimeToU64(eventTime) < bootValue) {
                        reachedBoot = true;
                    } else {
                        events.push_back(ParseSysmonEventXml(xml));
                    }
                }
            }
            EvtClose(handles[i]);
            handles[i] = nullptr;
            if (reachedBoot)
                break;
        }
    }

    EvtClose(result);
    status = events.empty() ? "No matching Sysmon events after boot" : "Loaded after boot";
    return events;
}

static std::wstring ServiceDisplayName(SC_HANDLE scm, const std::wstring& serviceName) {
    SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_CONFIG);
    if (!service)
        return serviceName;

    DWORD needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &needed);
    std::wstring display = serviceName;
    if (needed > 0) {
        std::vector<BYTE> buffer(needed);
        auto cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (QueryServiceConfigW(service, cfg, needed, &needed) && cfg->lpDisplayName)
            display = cfg->lpDisplayName;
    }
    CloseServiceHandle(service);
    return display;
}

static bool QueryServiceRunning(SC_HANDLE scm, const std::wstring& serviceName, DWORD& pid) {
    pid = 0;
    SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!service)
        return false;

    SERVICE_STATUS_PROCESS status = {};
    DWORD needed = 0;
    bool running = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                        reinterpret_cast<LPBYTE>(&status),
                                        sizeof(status), &needed) &&
                   status.dwCurrentState == SERVICE_RUNNING;
    pid = status.dwProcessId;
    CloseServiceHandle(service);
    return running;
}

static std::wstring ResolveServiceName(SC_HANDLE scm, std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        SC_HANDLE service = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
        if (service) {
            CloseServiceHandle(service);
            return name;
        }
    }
    return names.size() > 0 ? *names.begin() : L"";
}

static bool TextMatchesAnyLabel(const std::wstring& text, const std::vector<std::wstring>& labels) {
    std::wstring upper = ToUpperInvariant(text);
    for (const auto& label : labels) {
        if (!label.empty() && upper.find(ToUpperInvariant(label)) != std::wstring::npos)
            return true;
    }
    return false;
}

static bool IsTpm2AvailableNow() {
    TBS_CONTEXT_PARAMS2 params = {};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;

    TBS_HCONTEXT context = nullptr;
    TBS_RESULT result = Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&params), &context);
    if (result != TBS_SUCCESS)
        return false;

    Tbsip_Context_Close(context);
    return true;
}

static bool ServiceRestartedAfterBoot(const std::vector<std::wstring>& labels) {
    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);
    constexpr ULONGLONG kBootGrace = 5ULL * 60ULL * 10000000ULL;

    EVT_HANDLE result = EvtQuery(nullptr, L"System",
        L"*[System[Provider[@Name='Service Control Manager'] and (EventID=7036)]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!result)
        return false;

    bool sawRunning = false;
    bool restarted = false;
    bool reachedBoot = false;
    EVT_HANDLE handles[16] = {};
    DWORD returned = 0;
    while (!restarted && !reachedBoot && EvtNext(result, (DWORD)std::size(handles), handles, ScanLimits::kEvtNextTimeoutMs, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            std::wstring xml;
            bool ok = RenderEventXml(handles[i], xml);
            EvtClose(handles[i]);
            handles[i] = nullptr;
            if (!ok)
                continue;

            std::wstring systemTime = ExtractXmlAttribute(xml, L"<TimeCreated", L"SystemTime");
            FILETIME eventTime = {};
            if (!SysmonSystemTimeToFileTime(systemTime, eventTime))
                continue;

            ULONGLONG eventValue = FileTimeToU64(eventTime);
            if (eventValue < bootValue) {
                reachedBoot = true;
                continue;
            }
            if (eventValue < bootValue + kBootGrace)
                continue;

            std::wstring service = ExtractSysmonData(xml, L"param1");
            if (!TextMatchesAnyLabel(service, labels))
                continue;

            std::wstring state = ToUpperInvariant(ExtractSysmonData(xml, L"param2"));
            bool running = state.find(L"RUNNING") != std::wstring::npos ||
                           state.find(L"STARTED") != std::wstring::npos ||
                           state.find(L"EXECU") != std::wstring::npos ||
                           state.find(L"INICI") != std::wstring::npos;
            bool stopped = state.find(L"STOPPED") != std::wstring::npos ||
                           state.find(L"PARAD") != std::wstring::npos;

            if (running)
                sawRunning = true;
            else if (stopped && sawRunning) {
                restarted = true;
                break;
            }
        }
    }

    EvtClose(result);
    return restarted;
}

std::vector<ScannerUI::ServiceStatus> CollectServiceStatuses() {
    struct WantedService {
        const char* label;
        std::initializer_list<const wchar_t*> names;
    };

    static const WantedService wanted[] = {
        { "PcaSvc",    { L"PcaSvc" } },
        { "DPS",       { L"DPS" } },
        { "DiagTrack", { L"DiagTrack" } },
        { "SysMain",   { L"SysMain" } },
        { "Sysmon",    { L"Sysmon64", L"Sysmon" } },
        { "EventLog",  { L"EventLog" } },
        { "PlugPlay",  { L"PlugPlay" } },
        { "TPM 2.0",   { L"TBS" } },
    };

    std::vector<ScannerUI::ServiceStatus> out;

    {
        bool sb = IsSecureBootEnabled();
        out.push_back({ "SecureBoot", sb, false,
            sb ? "Secure Boot ativo (variavel UEFI/registro)"
               : "Secure Boot desativado ou sistema sem UEFI" });
    }
    {
        bool iommu = IsIommuEnabled();
        out.push_back({ "IOMMU", iommu, false,
            iommu ? "IOMMU ativo (tabela ACPI DMAR/IVRS presente)"
                  : "Nenhuma tabela ACPI DMAR/IVRS encontrada - VT-d/AMD-Vi desativado ou nao suportado" });
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        for (const auto& item : wanted)
            out.push_back({ item.label, false, false, "Service Control Manager unavailable" });
        return out;
    }

    for (const auto& item : wanted) {
        std::wstring serviceName = ResolveServiceName(scm, item.names);
        DWORD pid = 0;
        bool running = !serviceName.empty() && QueryServiceRunning(scm, serviceName, pid);
        std::wstring display = serviceName.empty() ? L"" : ServiceDisplayName(scm, serviceName);
        std::vector<std::wstring> labels = { serviceName, display, std::wstring(item.label, item.label + strlen(item.label)) };

        if (std::string(item.label) == "TPM 2.0") {
            bool tpmReady = IsTpm2AvailableNow();
            std::string note;
            if (tpmReady) {
                note = "TPM 2.0 available (TBS service can be stopped while idle)";
            } else {
                // Check if the board is Intel X99 — that platform has no native TPM 2.0 support.
                // Read BaseBoardProduct and SystemProductName from the BIOS registry key.
                bool isX99 = false;
                {
                    HKEY hBios = nullptr;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                      L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                                      0, KEY_READ, &hBios) == ERROR_SUCCESS) {
                        const wchar_t* kFields[] = { L"BaseBoardProduct", L"SystemProductName", nullptr };
                        for (int fi = 0; kFields[fi] && !isX99; ++fi) {
                            wchar_t buf[256] = {};
                            DWORD sz = sizeof(buf), tp = 0;
                            if (RegQueryValueExW(hBios, kFields[fi], nullptr, &tp,
                                                 (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                                std::wstring up = ToUpperInvariant(std::wstring(buf));
                                if (up.find(L"X99") != std::wstring::npos)
                                    isX99 = true;
                            }
                        }
                        RegCloseKey(hBios);
                    }
                }
                note = isX99
                    ? "TPM 2.0 nao disponivel — plataforma Intel X99 nao possui suporte nativo a TPM 2.0"
                    : "TPM 2.0 unavailable through TBS";
            }
            if (!serviceName.empty())
                note += " | service=" + WideToUtf8(serviceName);
            if (pid != 0)
                note += " | pid=" + std::to_string(pid);
            out.push_back({ item.label, tpmReady, false, note });
            continue;
        }

        bool restarted = running && ServiceRestartedAfterBoot(labels);

        std::string note = running ? "Service running" : "Service stopped";
        if (running && restarted)
            note = "Service stopped and started again after boot";
        if (!serviceName.empty())
            note += " | service=" + WideToUtf8(serviceName);
        if (pid != 0)
            note += " | pid=" + std::to_string(pid);

        out.push_back({ item.label, running, restarted, note });
    }

    CloseServiceHandle(scm);
    return out;

}
