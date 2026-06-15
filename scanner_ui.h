









#pragma once

#include "imgui.h"
#include <algorithm>
#include <cmath>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

namespace ScannerUI {

inline constexpr float kTitleBarH = 52.0f;
inline constexpr float kOuterPad  = 2.0f;
inline constexpr float kSidebarW  = 350.0f;
inline constexpr float kBodyGap   = 0.0f;
inline constexpr float kTerminalH = 52.0f;
inline constexpr float kTerminalExpandedH = 210.0f;
inline constexpr float kStatusH   = 30.0f;
inline constexpr float kLoadingHoldSeconds  = 1.65f;
inline constexpr float kLoadingMorphSeconds = 0.90f;




struct ServiceStatus {
    std::string name;
    bool ok = false;
    bool restarted = false;
    std::string note;
};

struct BamEntry {
    std::string date;
    std::string time;
    std::string path;
    std::string reason;
    std::string detail;
    std::string pathClass;
    bool suspicious = false;
};

struct PrefetchHit {
    std::string date;
    std::string time;
    std::string severity;
    std::string alias;
    std::string file;
    std::string note;
};

struct EmulatorFinding {
    std::string process;
    std::string type;
    std::string address;
    std::string detail;
    std::string severity;
};

struct GenericBypassFinding {
    std::string date;
    std::string time;
    std::string type;
    std::string process;
    std::string target;
    std::string detail;
    std::string severity;
    std::string ruleId;
    std::string source;
    std::string confidence;
    std::string evidenceState;
};

struct StreamModFinding {
    std::string type;      // CAPTURE_EXCLUDE, OBS_PLUGIN, VIRTUAL_DISPLAY, DWM_INJECT, DWM_HOOK, OVERLAY
    std::string process;
    std::string target;
    std::string detail;
    std::string severity;  // HIGH / MEDIUM / FLAG
};

struct RemotePortFinding {
    std::string protocol;       // TCP, TCP6, UDP, UDP6
    std::string port;
    std::string bindAddress;    // 0.0.0.0, 127.0.0.1, ::, LAN IP
    std::string pid;
    std::string process;        // basename
    std::string path;           // canonicalised path
    std::string signer;         // "UNSIGNED" or "<CN> <thumbprint8>"
    std::string parentChain;    // walked ancestry
    std::string scriptOrHost;   // interpreter script alvo / svchost service host
    std::string firewallRule;   // inbound allow rule name (empty if none)
    std::string tunnelPeer;     // ngrok/cloudflared/frpc basename if co-running
    std::string reason;         // short reason
    std::string detail;         // verbose dump (cmdline, etc.)
    std::string severity;       // HIGH / MEDIUM / FLAG
};

struct EfiCheatFinding {
    std::string date;
    std::string time;
    std::string severity;
    std::string path;
    std::string reason;
    std::string detail;
    std::string ruleId;
    std::string source;
    std::string confidence;
    std::string evidenceState;
    bool suspicious = false;
};

struct KernelDriverFinding {
    std::string date;
    std::string time;
    std::string severity;
    std::string path;
    std::string reason;
    std::string detail;
    bool        suspicious   = false;
    uintptr_t   loadAddress  = 0;
};

struct RegistryFinding {
    std::string date;
    std::string time;
    std::string severity;
    std::string key;
    std::string value;
    std::string data;
    std::string reason;
    std::string detail;
    bool suspicious = false;
};

struct ClsidFinding {
    std::string date;
    std::string time;
    std::string severity;        // "HIGH", "MEDIUM", "FLAG"
    std::string clsid;           // {XXXXXXXX-XXXX-...}
    std::string friendlyName;
    std::string hivePath;        // "HKCU", "HKCR"
    std::string serverType;      // "InprocServer32" | "LocalServer32"
    std::string serverPath;
    std::string reason;
    std::string detail;
    bool fileExists     = false;
    bool isSigned       = false;
    bool isHkcuOverride = false;
    bool canClean       = false;
    bool cleaned        = false;
};

struct TimelineCorrelationFinding {
    std::string date, time;
    std::string severity;
    std::string path;
    std::string reason;
    std::string detail;
    bool suspicious = false;
};

struct KernelAnomalyFinding {
    std::string severity;
    std::string type;
    std::string driverName;
    std::string path;
    std::string reason;
    std::string detail;
    uintptr_t   loadAddress = 0;
    uint32_t    loadedSize  = 0;
    bool        suspicious  = true;
};

struct DriverIntegrityFinding {
    std::string date, time;
    std::string severity;
    std::string driverName;
    std::string path;
    std::string sha256;
    std::string referenceSource;
    bool        hashMatch   = true;
    bool        signedOk    = false;
    bool        catalogOk   = false;
    std::string signerName;
    bool        hasHooks      = false;
    std::string hookedFunctions;
    bool        hasCallbackSurface = false;
    std::string callbackSurface;
    bool        checksumOk     = true;
    bool        hasOverlay     = false;
    bool        signerTrusted  = true;
    std::string reason;
    std::string detail;
    std::string logSource;
    bool        suspicious     = false;
    uintptr_t   loadAddress    = 0;
    uint32_t    loadedSize     = 0;
    int         maliciousScore   = 0;
    std::string verdict;
    bool        isCrashDumpDriver = false;
    // P1 — Certificate deep analysis
    bool        certSelfSigned      = false;
    bool        certEkuMismatch     = false;
    bool        certHomoglyphCn     = false;
    bool        certSerialDuplicate = false;
    int         certChainDepth      = 0;
    std::string certSerial;
    std::string certIssuerCN;
    // P2 — Import behavior fingerprinting
    bool        importInjectionCombo = false;
    bool        importDmaCombo       = false;
    bool        importPhysMemAccess  = false;
    bool        importIoctlSurface   = false;
    bool        importCountSuspect   = false;
    std::string impHash;
    // P3 — PE section deep analysis
    bool        missingRichHeader        = false;
    bool        nonStandardAlignment     = false;
    bool        codeEntropySpike         = false;
    bool        virtualRawRatioAnomalous = false;
    bool        stringObfuscation        = false;
    // P6 — BYOVD hash match
    bool        byovdHashMatch = false;
    // P8 — Anti-analysis patterns
    bool        hasRdtscCheck    = false;
    bool        hasCpuidVmCheck  = false;
    bool        hasPebDebugCheck = false;
};

struct SysmonEvent {
    std::string date;
    std::string time;
    int eventId = 0;
    std::string type;
    std::string process;
    std::string detail;
    std::string parentProcess;
    std::string commandLine;
    std::string user;
    std::string currentDirectory;
    std::string imageLoaded;
    std::string registryObject;
    std::string queryName;
    std::string startAddress;
    std::string sourceProcess;
    std::string targetProcess;
    std::string access;
    std::string callTrace;
};

struct ScanData {

    std::string title   = "RXVScan - developed by rarexv";
    std::string version = "v1.3";
    ImVec4 accentColor = ImVec4(0.24f, 0.26f, 0.30f, 1.00f);
    bool alwaysOnTop   = false;


    std::vector<ServiceStatus> services;


    std::string hwid;
    std::string hwidWarning;


    std::string boot, explorer, biosVersion, biosMode, osVersion;
    std::string device, pagefile, sysType;
    float inspectZoom = 1.20f;


    std::vector<BamEntry> bam;


    int          prefetchHits = 0;
    std::vector<PrefetchHit> prefetch;


    std::string usnStatus;
    std::string usnDrive;
    std::vector<PrefetchHit> usnAnomalies;
    std::string usnAnomalyStatus = "OK"; // "OK" or "ANOMALY"


    std::string sysmonStatus = "Waiting";
    std::vector<SysmonEvent> sysmonEvents;
    int sysmonEventFilter = 0;
    // Triage view state — see DrawSysmon redesign plan.
    int sysmonViewMode = 0;                 // 0 = Triage (novo), 1 = Flat (legado)
    int sysmonExpandedIdx = -1;             // indice do row expandido inline, -1 = nenhum
    int sysmonTimeBucket = -1;              // minuto-do-dia selecionado, -1 = nenhum
    char sysmonProcessFilter[160] = {};     // basename, exact match
    bool sysmonDerivedReady = false;
    std::vector<uint32_t> sysmonEventMinute;   // paralelo a sysmonEvents (HH*60+MM)
    std::vector<uint8_t>  sysmonEventSeverity; // paralelo: 0=green, 1=yellow, 2=red
    char sysmonTextFilter[160] = {};
    char sysmonAccessFilter[64] = {};
    char sysmonSourceFilter[160] = {};
    char sysmonTargetFilter[160] = {};
    char sysmonCallTraceFilter[220] = {};
    char sysmonParentFilter[160] = {};
    char sysmonCommandFilter[220] = {};
    char sysmonImageFilter[180] = {};
    char sysmonUserFilter[120] = {};
    char sysmonRegistryFilter[220] = {};
    char sysmonDnsFilter[180] = {};
    char sysmonStartFilter[80] = {};


    bool  emulatorChecking = true;
    float emulatorProgress = 0.55f;
    std::string emulatorResult;
    std::string emulatorStatus = "Waiting";
    std::string emulatorOpenedAt = "-";
    std::vector<EmulatorFinding> emulatorFindings;


    std::string systemMemoryStatus = "Waiting";
    std::vector<EmulatorFinding> systemMemoryFindings;


    std::string genericBypassStatus = "Waiting";
    std::vector<GenericBypassFinding> genericBypass;

    std::string streamModStatus = "Waiting";
    std::vector<StreamModFinding> streamModFindings;

    std::string remotePortStatus = "Waiting";
    std::vector<RemotePortFinding> remotePortFindings;


    int activePage = 1;
    std::string efiCheatStatus = "Waiting";
    std::vector<EfiCheatFinding> efiCheats;


    std::string driverIntegrityStatus = "Waiting";
    std::vector<DriverIntegrityFinding> driverIntegrity;


    std::string kernelDriverStatus = "Waiting";
    std::vector<KernelDriverFinding> kernelDrivers;

    std::string kernelAnomalyStatus = "Waiting";
    std::vector<KernelAnomalyFinding> kernelAnomalies;


    std::string registryStatus = "Waiting";
    std::vector<RegistryFinding> registryFindings;

    std::string clsidStatus = "Waiting";
    std::vector<ClsidFinding> clsidFindings;
    int  clsidPendingCleanIdx  = -1;
    bool clsidCleanConfirmed   = false;

    char efiFilter[128]   = {};
    int  efiSevFilter     = 0;


    char drvIntFilter[128] = {};
    int  drvIntSevFilter   = 0;


    char kdrvFilter[128]  = {};
    int  kdrvSevFilter    = 0;


    char bamFilter[128]   = {};
    int  bamReasonFilter  = 0;


    char bypassFilter[128] = {};
    int  bypassTypeFilter  = 0;


    char memFilter[128]   = {};
    int  memSevFilter     = 0;
    int  memTypeFilter    = 0;

    // P5 — Timeline correlation
    std::string timelineStatus = "Waiting";
    std::vector<TimelineCorrelationFinding> timelineFindings;
    char timelineFilter[128] = {};

    std::vector<std::string> terminalLog;
    int  terminalNotif = 1;
    bool terminalExpanded = false;
    char terminalInput[160] = {};
    std::string pendingCommand;


    bool debugMode = false;

    void* logoTexture = nullptr;  // ID3D11ShaderResourceView* cast to void*
    void* generalIconTexture = nullptr;
    void* efiIconTexture = nullptr;
    void* emuIconTexture = nullptr;
    void* winScanIconTexture = nullptr;
    void* kernelScanIconTexture = nullptr;
    void* sysmonIconTexture = nullptr;

    int   cpu = 62, ram = 71, gpu = 45;
    std::string speedScan = "normal";
    float scanProgress = 0.58f;
    std::string elapsed = "00:00:32";
    std::string currentStage = "Inicializando scanner";
};




namespace col {
    inline const ImVec4 Bg        = ImVec4(0.009f, 0.010f, 0.012f, 1.00f);
    inline const ImVec4 BgTitle   = ImVec4(0.006f, 0.007f, 0.008f, 1.00f);
    inline const ImVec4 Panel     = ImVec4(0.015f, 0.016f, 0.019f, 1.00f);
    inline const ImVec4 PanelSoft = ImVec4(0.025f, 0.027f, 0.032f, 1.00f);
    inline const ImVec4 PanelLift = ImVec4(0.045f, 0.048f, 0.057f, 1.00f);
    inline const ImVec4 Header    = ImVec4(0.91f,  0.92f,  0.95f,  1.00f);
    inline const ImVec4 Text      = ImVec4(0.75f,  0.77f,  0.82f,  1.00f);
    inline const ImVec4 TextDim   = ImVec4(0.42f,  0.44f,  0.50f,  1.00f);
    inline const ImVec4 Green     = ImVec4(0.00f,  0.88f,  0.34f,  1.00f);
    inline const ImVec4 Red       = ImVec4(1.00f,  0.12f,  0.24f,  1.00f);
    inline const ImVec4 Yellow    = ImVec4(1.00f,  0.78f,  0.00f,  1.00f);
    inline const ImVec4 Sep       = ImVec4(0.095f, 0.101f, 0.119f, 1.00f);
    inline ImVec4 Accent          = ImVec4(0.24f,  0.26f,  0.30f,  1.00f);
    inline ImVec4 AccentDim       = ImVec4(0.09f,  0.10f,  0.12f,  1.00f);

    inline ImVec4 MakeAccentDim(const ImVec4& accent) {
        return ImVec4(accent.x * 0.38f, accent.y * 0.38f, accent.z * 0.39f, 1.00f);
    }

    inline void SetAccentColor(const ImVec4& accent) {
        Accent = ImVec4(std::clamp(accent.x, 0.0f, 1.0f),
                        std::clamp(accent.y, 0.0f, 1.0f),
                        std::clamp(accent.z, 0.0f, 1.0f),
                        1.00f);
        AccentDim = MakeAccentDim(Accent);
    }
}




inline void ApplyTheme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowPadding     = ImVec2(14, 11);
    s.FramePadding      = ImVec2(11, 7);
    s.ItemSpacing       = ImVec2(9, 8);
    s.ItemInnerSpacing  = ImVec2(8, 6);
    s.ScrollbarSize     = 9.0f;
    s.WindowBorderSize  = 0.0f;
    s.FrameBorderSize   = 0.0f;
    s.WindowRounding    = 0.0f;
    s.ChildRounding     = 5.0f;
    s.PopupRounding     = 5.0f;
    s.FrameRounding     = 5.0f;
    s.GrabRounding      = 4.0f;
    s.ScrollbarRounding = 5.0f;
    s.TabRounding       = 5.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]          = col::Bg;
    c[ImGuiCol_ChildBg]           = col::Panel;
    c[ImGuiCol_PopupBg]           = col::BgTitle;
    c[ImGuiCol_Text]              = col::Text;
    c[ImGuiCol_TextDisabled]      = col::TextDim;
    c[ImGuiCol_Separator]         = col::Sep;
    c[ImGuiCol_Border]            = col::Sep;
    c[ImGuiCol_FrameBg]           = col::PanelSoft;
    c[ImGuiCol_FrameBgHovered]    = ImVec4(0.045f, 0.048f, 0.057f, 1.00f);
    c[ImGuiCol_FrameBgActive]     = ImVec4(0.060f, 0.064f, 0.075f, 1.00f);
    c[ImGuiCol_Button]            = ImVec4(0.035f, 0.037f, 0.044f, 1.00f);
    c[ImGuiCol_ButtonHovered]     = ImVec4(0.065f, 0.069f, 0.081f, 1.00f);
    c[ImGuiCol_ButtonActive]      = ImVec4(0.085f, 0.090f, 0.105f, 1.00f);
    c[ImGuiCol_Header]            = ImVec4(0.040f, 0.043f, 0.051f, 1.00f);
    c[ImGuiCol_HeaderHovered]     = ImVec4(0.060f, 0.064f, 0.075f, 1.00f);
    c[ImGuiCol_HeaderActive]      = ImVec4(0.080f, 0.085f, 0.099f, 1.00f);
    c[ImGuiCol_TableRowBg]        = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_TableRowBgAlt]     = ImVec4(0.035f, 0.042f, 0.055f, 0.34f);
    c[ImGuiCol_ScrollbarBg]       = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab]     = ImVec4(0.22f, 0.24f, 0.29f, 0.80f);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.32f, 0.35f, 0.41f, 0.95f);
    c[ImGuiCol_PlotHistogram]     = col::Yellow;
    c[ImGuiCol_Tab]               = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabHovered]        = ImVec4(0.060f, 0.076f, 0.102f, 1.00f);
    c[ImGuiCol_TabActive]         = ImVec4(0.050f, 0.064f, 0.086f, 1.00f);
    c[ImGuiCol_TabUnfocused]      = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabUnfocusedActive]= ImVec4(0.050f, 0.064f, 0.086f, 1.00f);
}




namespace detail {

inline void DrawAnimatedTopicBorder(const ImVec2& pos, const ImVec2& size, ImGuiID seed);
inline bool FolderButton(const char* id);

inline std::string CompactPath(const std::string& path, size_t maxLen = 72) {
    if (path.size() <= maxLen)
        return path;

    size_t slash = path.find_last_of("\\/");
    std::string file = (slash == std::string::npos) ? path : path.substr(slash + 1);
    if (file.size() + 6 >= maxLen)
        return "..." + file.substr(file.size() - (maxLen - 3));

    size_t driveLen = (path.size() > 2 && path[1] == ':') ? 3 : 0;
    std::string prefix = driveLen ? path.substr(0, driveLen) : "";
    return prefix + "...\\" + file;
}

inline std::string CompactText(const std::string& text, size_t maxLen = 64) {
    if (text.size() <= maxLen)
        return text;
    if (maxLen <= 3)
        return text.substr(0, maxLen);
    return text.substr(0, maxLen - 3) + "...";
}

inline std::string FileNameFromPath(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

// Formats "ExeName.exe [1234]" → "ExeName.exe 1234"
// Used to build headline text: "MAPPER in Discord.exe 1234  0x00ABCDEF"
inline std::string FindingHeadline(const std::string& type,
                                   const std::string& process,
                                   const std::string& address) {
    // Strip brackets from "[PID]" → " PID"
    std::string proc = process;
    auto lb = proc.find(" [");
    auto rb = proc.rfind(']');
    if (lb != std::string::npos && rb != std::string::npos && rb > lb + 2)
        proc = proc.substr(0, lb) + " " + proc.substr(lb + 2, rb - lb - 2);
    return type + " in " + proc + "  " + address;
}

inline float MinFloat(float a, float b) {
    return a < b ? a : b;
}

inline float Saturate(float v) {
    return std::clamp(v, 0.0f, 1.0f);
}

inline float SmoothStep(float t) {
    t = Saturate(t);
    return t * t * (3.0f - 2.0f * t);
}

inline float SmootherStep(float t) {
    t = Saturate(t);
    return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
}

inline float Lerp(float a, float b, float t) {
    return a + (b - a) * t;
}

inline ImVec2 Lerp(const ImVec2& a, const ImVec2& b, float t) {
    return ImVec2(Lerp(a.x, b.x, t), Lerp(a.y, b.y, t));
}

inline ImU32 ColorAlpha(const ImVec4& color, float alpha) {
    return ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, Saturate(color.w * alpha)));
}

inline ImVec4 Mix(const ImVec4& a, const ImVec4& b, float t) {
    t = Saturate(t);
    return ImVec4(Lerp(a.x, b.x, t), Lerp(a.y, b.y, t), Lerp(a.z, b.z, t), Lerp(a.w, b.w, t));
}

inline void DrawAppBackground(ImDrawList* dl, const ImVec2& min, const ImVec2& max) {
    dl->AddRectFilled(min, max, ImGui::GetColorU32(col::Bg));
    dl->AddRect(min, max, ColorAlpha(col::Header, 0.075f), 0.0f, 0, 1.0f);
}

inline void WrappedValue(const char* label, const std::string& value, ImVec4 color = col::Header) {
    ImGui::TextColored(col::TextDim, "%s", label);
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
    ImGui::TextColored(color, "%s", value.empty() ? "-" : value.c_str());
    ImGui::PopTextWrapPos();
}

inline void CopyableValue(const std::string& value, ImVec4 color = col::Header) {
    ImGui::TextColored(color, "%s", value.empty() ? "-" : value.c_str());
    if (!value.empty() && value != "-" && ImGui::IsItemHovered()) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::SetTooltip("Click to copy: %s", value.c_str());
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            ImGui::SetClipboardText(value.c_str());
    }
}

inline void ProcessLink(const char* label, const std::string& path, const char* id) {
    std::string file = FileNameFromPath(path);
    if (file.empty())
        file = "-";

    ImGui::TextColored(col::TextDim, "%s", label);
    ImGui::TextColored(col::Header, "%s", file.c_str());
    if (ImGui::IsItemHovered() && !path.empty())
        ImGui::SetTooltip("%s", path.c_str());

    if (!path.empty() && path != "-") {
        ImGui::SameLine();
        ImGui::PushID(id);
        if (FolderButton("##open-process-path")) {
            std::string cmd = "explorer /select,\"" + path + "\"";
            system(cmd.c_str());
        }
        ImGui::PopID();
    }
}

inline void BeginPanel(const char* id, const char* title, float height = 0.0f) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::Panel);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 11));
    ImGui::BeginChild(id, ImVec2(0, height), true);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 panelMin = ImGui::GetWindowPos();
    ImVec2 panelMax(panelMin.x + ImGui::GetWindowWidth(), panelMin.y + ImGui::GetWindowHeight());
    dl->AddRectFilled(panelMin, ImVec2(panelMax.x, panelMin.y + 32.0f),
                      ColorAlpha(col::PanelLift, 0.30f), 5.0f,
                      ImDrawFlags_RoundCornersTop);
    dl->AddLine(ImVec2(panelMin.x + 14.0f, panelMin.y + 31.0f),
                ImVec2(panelMax.x - 14.0f, panelMin.y + 31.0f),
                ColorAlpha(col::Header, 0.055f), 1.0f);

    ImGui::PushStyleColor(ImGuiCol_Text, col::Header);
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();
    ImGui::Dummy(ImVec2(0, 5));
}

inline void EndPanel() {
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

inline ImVec2 BorderPoint(const ImVec2& pos, const ImVec2& size, float distance) {
    float w = size.x;
    float h = size.y;
    float perimeter = (w + h) * 2.0f;
    while (distance < 0.0f) distance += perimeter;
    while (distance >= perimeter) distance -= perimeter;

    if (distance < w)
        return ImVec2(pos.x + distance, pos.y);
    distance -= w;
    if (distance < h)
        return ImVec2(pos.x + w, pos.y + distance);
    distance -= h;
    if (distance < w)
        return ImVec2(pos.x + w - distance, pos.y + h);
    distance -= w;
    return ImVec2(pos.x, pos.y + h - distance);
}

inline void DrawAnimatedScannerBorder(const ImVec2& pos, const ImVec2& size) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRect(pos, ImVec2(pos.x + size.x, pos.y + size.y),
                ColorAlpha(col::Header, 0.055f), 0.0f, 0, 1.0f);
    dl->AddLine(pos, ImVec2(pos.x + size.x, pos.y),
                ColorAlpha(col::Accent, 0.22f), 1.0f);
}

inline const ImVec4 LoadOnyx       = ImVec4(0.010f, 0.011f, 0.013f, 1.00f);
inline const ImVec4 LoadOnyxSoft   = ImVec4(0.025f, 0.026f, 0.030f, 1.00f);
inline const ImVec4 LoadOnyxRaised = ImVec4(0.042f, 0.043f, 0.049f, 1.00f);
inline const ImVec4 LoadWhite      = ImVec4(0.94f,  0.95f,  0.96f,  1.00f);
inline const ImVec4 LoadMuted      = ImVec4(0.56f,  0.58f,  0.62f,  1.00f);
inline const ImVec4 LoadLine       = ImVec4(0.24f,  0.25f,  0.28f,  1.00f);

inline void DrawLoadingSpinner(ImDrawList* dl, const ImVec2& center, float radius,
                               float thickness, float alpha) {
    if (alpha <= 0.0f)
        return;

    constexpr float pi = 3.14159265358979323846f;
    const int segments = 58;
    const float now = (float)ImGui::GetTime();
    const float start = now * 3.15f;
    const float arc = pi * 1.32f;
    const float pulse = 0.5f + 0.5f * std::sin(now * 3.4f);

    dl->AddCircleFilled(center, radius + 18.0f, ColorAlpha(LoadWhite, alpha * 0.035f), 72);
    dl->AddCircle(center, radius + 10.0f, ColorAlpha(LoadWhite, alpha * 0.105f), 72, 1.0f);
    dl->AddCircle(center, radius, ColorAlpha(LoadLine, alpha * 0.94f), 72, thickness);

    for (int i = 0; i < segments; ++i) {
        float t0 = (float)i / (float)segments;
        float t1 = (float)(i + 1) / (float)segments;
        float a0 = start + t0 * arc;
        float a1 = start + t1 * arc;
        float tail = SmoothStep(t1);
        ImVec2 p0(center.x + std::cos(a0) * radius, center.y + std::sin(a0) * radius);
        ImVec2 p1(center.x + std::cos(a1) * radius, center.y + std::sin(a1) * radius);
        dl->AddLine(p0, p1, ColorAlpha(LoadWhite, alpha * (0.12f + tail * 0.84f)),
                    thickness + tail * 0.8f);
    }

    float scanY = center.y + std::sin(now * 2.6f) * radius * 0.42f;
    dl->AddLine(ImVec2(center.x - radius * 0.50f, scanY),
                ImVec2(center.x + radius * 0.50f, scanY),
                ColorAlpha(LoadWhite, alpha * (0.34f + pulse * 0.18f)), 1.2f);
    dl->AddCircleFilled(center, 3.2f, ColorAlpha(LoadWhite, alpha * (0.55f + pulse * 0.18f)), 20);
}

inline void DrawLoadingCorners(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                               float length, float alpha) {
    if (alpha <= 0.0f)
        return;

    ImU32 col = ColorAlpha(LoadWhite, alpha);
    float thickness = 1.0f;
    dl->AddLine(min, ImVec2(min.x + length, min.y), col, thickness);
    dl->AddLine(min, ImVec2(min.x, min.y + length), col, thickness);

    dl->AddLine(ImVec2(max.x, min.y), ImVec2(max.x - length, min.y), col, thickness);
    dl->AddLine(ImVec2(max.x, min.y), ImVec2(max.x, min.y + length), col, thickness);

    dl->AddLine(ImVec2(max.x, max.y), ImVec2(max.x - length, max.y), col, thickness);
    dl->AddLine(ImVec2(max.x, max.y), ImVec2(max.x, max.y - length), col, thickness);

    dl->AddLine(ImVec2(min.x, max.y), ImVec2(min.x + length, max.y), col, thickness);
    dl->AddLine(ImVec2(min.x, max.y), ImVec2(min.x, max.y - length), col, thickness);
}

inline void DrawLoadingBorderSweep(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                                   float elapsed, float alpha) {
    if (alpha <= 0.0f)
        return;

    ImVec2 size(max.x - min.x, max.y - min.y);
    float perimeter = (size.x + size.y) * 2.0f;
    if (perimeter <= 0.0f)
        return;

    ImVec2 insetMin(min.x + 1.0f, min.y + 1.0f);
    ImVec2 insetSize(size.x - 2.0f, size.y - 2.0f);
    float head = (float)std::fmod(elapsed * 320.0f, perimeter);
    float trail = MinFloat(230.0f, perimeter * 0.34f);
    const int steps = 44;

    ImVec2 prev = BorderPoint(insetMin, insetSize, head - trail);
    for (int i = 1; i <= steps; ++i) {
        float t = (float)i / (float)steps;
        ImVec2 cur = BorderPoint(insetMin, insetSize, head - trail + trail * t);
        float a = alpha * (0.12f + SmoothStep(t) * 0.88f);
        dl->AddLine(prev, cur, ColorAlpha(LoadWhite, a), 1.0f + t * 0.6f);
        prev = cur;
    }
}

inline void DrawLoadingCardShine(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                                 float elapsed, float alpha) {
    if (alpha <= 0.0f)
        return;

    float w = max.x - min.x;
    float h = max.y - min.y;
    if (w <= 1.0f || h <= 1.0f)
        return;

    float t = (float)std::fmod(elapsed * 0.38f, 1.0f);
    float x = Lerp(min.x - w * 0.45f, max.x + w * 0.18f, t);
    float band = MinFloat(86.0f, w * 0.22f);
    ImU32 transparent = ColorAlpha(LoadWhite, 0.0f);
    ImU32 glow = ColorAlpha(LoadWhite, alpha * 0.10f);
    dl->AddRectFilledMultiColor(ImVec2(x, min.y), ImVec2(x + band, max.y),
                                transparent, glow, glow, transparent);
}

inline void DrawLoadingTelemetryTicks(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                                      float elapsed, float alpha) {
    if (alpha <= 0.0f)
        return;

    float y = max.y - 36.0f;
    float left = min.x + 22.0f;
    float right = max.x - 22.0f;
    float width = right - left;
    if (width <= 0.0f)
        return;

    for (int i = 0; i < 10; ++i) {
        float t = (float)i / 9.0f;
        float pulse = 0.5f + 0.5f * std::sin(elapsed * 4.0f + i * 0.7f);
        float h = 3.0f + pulse * 5.0f;
        float x = left + width * t;
        dl->AddLine(ImVec2(x, y - h * 0.5f), ImVec2(x, y + h * 0.5f),
                    ColorAlpha(LoadWhite, alpha * (0.08f + pulse * 0.14f)), 1.0f);
    }
}

inline void DrawLoadingMicroGrid(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                                 float elapsed, float alpha) {
    if (alpha <= 0.0f)
        return;

    float spacing = 24.0f;
    float drift = (float)std::fmod(elapsed * 9.0f, spacing);
    ImU32 line = ColorAlpha(LoadWhite, alpha * 0.035f);
    ImU32 accentLine = ColorAlpha(LoadWhite, alpha * 0.060f);

    for (float x = min.x + drift; x <= max.x; x += spacing)
        dl->AddLine(ImVec2(x, min.y), ImVec2(x, max.y), line, 1.0f);

    for (float y = min.y + spacing - drift; y <= max.y; y += spacing)
        dl->AddLine(ImVec2(min.x, y), ImVec2(max.x, y), line, 1.0f);

    float sweepX = Lerp(min.x, max.x, (float)std::fmod(elapsed * 0.22f, 1.0f));
    dl->AddLine(ImVec2(sweepX, min.y + 12.0f), ImVec2(sweepX, max.y - 12.0f), accentLine, 1.2f);
}

inline void DrawLoadingSignalBars(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                                  float elapsed, float alpha) {
    if (alpha <= 0.0f)
        return;

    float width = max.x - min.x;
    float height = max.y - min.y;
    if (width <= 1.0f || height <= 1.0f)
        return;

    const int bars = 18;
    float slot = width / (float)bars;
    for (int i = 0; i < bars; ++i) {
        float pulse = 0.5f + 0.5f * std::sin(elapsed * 5.2f + (float)i * 0.57f);
        float barW = slot * 0.42f;
        float barH = Lerp(4.0f, height, pulse);
        float x = min.x + slot * (float)i + slot * 0.28f;
        float y = max.y - barH;
        ImVec4 c = (i % 5 == 0) ? LoadWhite : LoadMuted;
        dl->AddRectFilled(ImVec2(x, y), ImVec2(x + barW, max.y),
                          ColorAlpha(c, alpha * (0.08f + pulse * 0.18f)), 2.0f);
    }
}

inline void DrawLoadingBeam(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                            float elapsed, float alpha) {
    if (alpha <= 0.0f)
        return;

    float pad = MinFloat((max.x - min.x) * 0.15f, 16.0f);
    float y0 = min.y + pad;
    float y1 = max.y - pad;
    if (y1 <= y0)
        return;

    float t = (float)std::fmod(elapsed * 0.85f, 1.0f);
    float y = Lerp(y0, y1, t);
    ImVec2 left(min.x + pad, y);
    ImVec2 right(max.x - pad, y);

    dl->AddRectFilled(ImVec2(left.x, y - 7.0f), ImVec2(right.x, y + 7.0f),
                      ColorAlpha(LoadWhite, alpha * 0.045f), 3.0f);
    dl->AddLine(left, right, ColorAlpha(LoadWhite, alpha * 0.72f), 1.2f);
}

inline void DrawAnimatedTopicBorder(const ImVec2& pos, const ImVec2& size, ImGuiID seed) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 line = ImGui::GetColorU32(ImVec4(col::Accent.x, col::Accent.y, col::Accent.z, 0.32f));
    float perimeter = (size.x + size.y) * 2.0f;
    float offset = (float)(seed % 997) * 0.37f;
    float head = (float)std::fmod(ImGui::GetTime() * 190.0f + offset, perimeter);
    float trail = 160.0f;
    const int steps = 34;

    ImVec2 insetPos(pos.x + 1.0f, pos.y + 1.0f);
    ImVec2 insetSize(size.x - 2.0f, size.y - 2.0f);
    ImVec2 prev = BorderPoint(insetPos, insetSize, head - trail);
    for (int i = 1; i <= steps; ++i) {
        float t = (float)i / (float)steps;
        ImVec2 cur = BorderPoint(insetPos, insetSize, head - trail + trail * t);
        dl->AddLine(prev, cur, line, 1.0f);
        prev = cur;
    }
}

inline void DrawPillText(const char* text, const ImVec4& color, const ImVec4& bg) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 textSz = ImGui::CalcTextSize(text);
    ImVec2 sz(textSz.x + 16.0f, textSz.y + 6.0f);
    ImGui::InvisibleButton(text, sz);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 bgCol = ImGui::GetColorU32(bg);
    ImU32 lineCol = ImGui::GetColorU32(color);
    dl->AddRectFilled(p, ImVec2(p.x + sz.x, p.y + sz.y), bgCol, 4.0f);
    dl->AddRect(p, ImVec2(p.x + sz.x, p.y + sz.y),
                ColorAlpha(color, 0.34f), 4.0f);
    dl->AddCircleFilled(ImVec2(p.x + 8.0f, p.y + sz.y * 0.5f), 2.6f, lineCol);
    dl->AddText(ImVec2(p.x + 14.0f, p.y + 3.0f), ImGui::GetColorU32(col::Text), text);
}

inline void ServiceChip(const ServiceStatus& sv, int index) {
    ImVec4 color = sv.ok ? col::Green : col::Red;
    ImVec4 bg = sv.ok ? ImVec4(0.07f, 0.13f, 0.10f, 1.0f) : ImVec4(0.15f, 0.07f, 0.08f, 1.0f);
    std::string status = sv.ok ? "OK" : "STOPPED";
    if (sv.ok && sv.restarted) {
        color = col::Yellow;
        bg = ImVec4(0.15f, 0.12f, 0.05f, 1.0f);
        status = "RESTARTED";
    }
    std::string label = sv.name + "  " + status;
    ImGui::PushID(index);
    DrawPillText(label.c_str(), color, bg);
    ImGui::PopID();
}


inline void StatusGlyph(bool ok) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h  = ImGui::GetTextLineHeight();
    float s  = h * 0.55f;
    float cy = p.y + h * 0.5f;
    ImU32 c  = ok ? ImGui::GetColorU32(col::Green) : ImGui::GetColorU32(col::Red);
    if (ok) {
        dl->AddLine(ImVec2(p.x,            cy + s * 0.20f),
                    ImVec2(p.x + s * 0.38f, cy + s * 0.55f), c, 1.7f);
        dl->AddLine(ImVec2(p.x + s * 0.38f, cy + s * 0.55f),
                    ImVec2(p.x + s,         cy - s * 0.55f), c, 1.7f);
    } else {
        dl->AddLine(ImVec2(p.x,     cy - s * 0.5f), ImVec2(p.x + s, cy + s * 0.5f), c, 1.7f);
        dl->AddLine(ImVec2(p.x + s, cy - s * 0.5f), ImVec2(p.x,     cy + s * 0.5f), c, 1.7f);
    }
    ImGui::Dummy(ImVec2(s + 2.0f, h));
}


inline bool FolderButton(const char* id) {
    float h = ImGui::GetTextLineHeight();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 sz(h * 1.1f, h);
    bool clicked = ImGui::InvisibleButton(id, sz);
    bool hover   = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 c = hover ? ImGui::GetColorU32(col::Yellow) : ImGui::GetColorU32(col::TextDim);
    float x = p.x, y = p.y + h * 0.18f;
    float w = sz.x, bh = h * 0.62f;

    dl->AddRectFilled(ImVec2(x, y), ImVec2(x + w * 0.45f, y + bh * 0.3f), c, 1.0f);

    dl->AddRectFilled(ImVec2(x, y + bh * 0.18f), ImVec2(x + w, y + bh), c, 1.5f);
    return clicked;
}


inline void SeverityTag(const std::string& sev) {
    ImVec4 c = col::Yellow;
    if (sev == "HIGH" || sev == "CRITICAL") c = col::Red;
    else if (sev == "LOW")                  c = col::Green;
    ImGui::TextColored(c, "%s", sev.c_str());
}


inline void KeyValue(const char* key, const std::string& value) {
    ImGui::PushStyleColor(ImGuiCol_Text, col::TextDim);
    ImGui::TextUnformatted(key);
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 6);
    ImGui::TextColored(col::Text, "%s", value.c_str());
}

inline void KeyValueCell(const char* key, const std::string& value) {
    ImGui::BeginGroup();
    ImGui::TextColored(col::TextDim, "%s", key);
    std::string compact = CompactText(value, 42);
    ImGui::TextColored(col::Header, "%s", compact.c_str());
    if (compact != value && ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", value.c_str());
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    ImGui::EndGroup();
}

inline void ResultLine(const char* id, const ImVec4& accent, const char* left,
                       const char* main, const char* right = nullptr, float reserveRight = 0.0f) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x - reserveRight;
    if (w < 220.0f) w = ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetTextLineHeight() + 14.0f;
    ImGui::InvisibleButton(id, ImVec2(w, h));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    bool hovered = ImGui::IsItemHovered();
    if (hovered) {
        dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                          ColorAlpha(col::Header, 0.030f), 3.0f);
    }
    dl->AddLine(ImVec2(p.x, p.y + h - 1.0f), ImVec2(p.x + w, p.y + h - 1.0f),
                ColorAlpha(col::Header, 0.060f), 1.0f);
    dl->AddLine(ImVec2(p.x, p.y + 7.0f), ImVec2(p.x, p.y + h - 7.0f),
                ColorAlpha(accent, 0.76f), 1.2f);
    float mainX = p.x + 150.0f;
    float rightX = p.x + w - 14.0f;
    if (right)
        rightX -= ImGui::CalcTextSize(right).x;
    dl->AddText(ImVec2(p.x + 14.0f, p.y + 7.0f), ImGui::GetColorU32(col::TextDim), left);
    ImVec4 clip(mainX, p.y, rightX - 10.0f, p.y + h);
    dl->PushClipRect(ImVec2(clip.x, clip.y), ImVec2(clip.z, clip.w), true);
    dl->AddText(ImVec2(mainX, p.y + 7.0f), ImGui::GetColorU32(col::Text), main);
    dl->PopClipRect();
    if (right)
        dl->AddText(ImVec2(rightX, p.y + 7.0f), ImGui::GetColorU32(accent), right);
}

inline void StatusBadge(const char* text, const ImVec4& color) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 textSz = ImGui::CalcTextSize(text);
    ImVec2 sz(textSz.x + 18.0f, textSz.y + 7.0f);
    ImGui::InvisibleButton(text, sz);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 rectMax(p.x + sz.x, p.y + sz.y);
    ImVec4 bg = Mix(col::PanelSoft, color, 0.14f);
    dl->AddRectFilled(p, rectMax, ColorAlpha(bg, 0.90f), 4.0f);
    dl->AddRect(p, rectMax, ColorAlpha(color, 0.45f), 4.0f);
    dl->AddCircleFilled(ImVec2(p.x + 8.0f, p.y + sz.y * 0.5f), 2.2f, ColorAlpha(color, 0.92f), 12);
    dl->AddText(ImVec2(p.x + 14.0f, p.y + 3.5f), ImGui::GetColorU32(color), text);
}

inline bool ScanPageButton(const char* id, bool isLoading) {
    const char* label = isLoading ? "running" : "scan";
    std::string btnId = std::string(label) + id;
    if (isLoading) {
        float t          = (float)ImGui::GetTime();
        float pulse      = sinf(t * 3.0f) * 0.5f + 0.5f;
        float bright     = 0.055f + pulse * 0.025f;
        float textBright = 0.58f + pulse * 0.20f;
        ImGui::PushStyleColor(ImGuiCol_Button,
            ImVec4(bright, bright, bright + 0.01f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
            ImVec4(bright + 0.02f, bright + 0.02f, bright + 0.025f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,
            ImVec4(bright + 0.03f, bright + 0.03f, bright + 0.035f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text,
            ImVec4(textBright, textBright, textBright, 1.0f));
        int dots = (int)(t * 2.0f) % 4;
        std::string runLabel = "running" + std::string(dots, '.') + id;
        ImGui::Button(runLabel.c_str(), ImVec2(96.0f, 0));
        ImGui::PopStyleColor(4);
        return false;
    }
    ImGui::PushStyleColor(ImGuiCol_Button,
        ImVec4(col::Accent.x * 0.18f + col::PanelSoft.x * 0.82f,
               col::Accent.y * 0.18f + col::PanelSoft.y * 0.82f,
               col::Accent.z * 0.18f + col::PanelSoft.z * 0.82f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
        ImVec4(col::Accent.x * 0.28f + col::PanelLift.x * 0.72f,
               col::Accent.y * 0.28f + col::PanelLift.y * 0.72f,
               col::Accent.z * 0.28f + col::PanelLift.z * 0.72f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
        ImVec4(col::Accent.x * 0.36f + col::PanelLift.x * 0.64f,
               col::Accent.y * 0.36f + col::PanelLift.y * 0.64f,
               col::Accent.z * 0.36f + col::PanelLift.z * 0.64f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text,          col::Header);
    bool clicked = ImGui::Button(btnId.c_str(), ImVec2(96.0f, 0));
    ImGui::PopStyleColor(4);
    return clicked;
}

inline void TableHeaderText(const char* text) {
    ImGui::TextColored(col::TextDim, "%s", text);
}

inline void SectionTitle(const char* text) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 ts = ImGui::CalcTextSize(text);
    ImGui::TextColored(col::Header, "%s", text);
    dl->AddLine(ImVec2(p.x, p.y + ts.y + 6.0f),
                ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y + ts.y + 6.0f),
                ColorAlpha(col::Header, 0.070f), 1.0f);
    ImGui::Dummy(ImVec2(0.0f, 8.0f));
}

inline void DetectionHeaderBg() {
    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(col::PanelSoft));
}

inline ImGuiTableFlags DetectionTableFlags() {
    return ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
           ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX;
}

inline void BeginDetectionTableStyle() {
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(12.0f, 8.0f));
}

inline void EndDetectionTableStyle() {
    ImGui::PopStyleVar();
}

inline void SummaryCell(const char* id, const char* label, const std::string& value,
                        const ImVec4& valueColor = col::Header) {
    ImGui::PushID(id);
    ImGui::BeginGroup();
    ImGui::TextColored(col::TextDim, "%s", label);
    std::string compact = CompactText(value, 80);
    ImGui::TextColored(valueColor, "%s", compact.c_str());
    if (compact != value && ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", value.c_str());
    ImGui::Dummy(ImVec2(0.0f, 8.0f));
    ImGui::EndGroup();
    ImGui::PopID();
}

inline void ServiceCell(const ServiceStatus& sv, int index) {
    ImVec4 stateColor = sv.ok ? col::Green : col::Red;
    if (sv.ok && sv.restarted) {
        stateColor = col::Yellow;
    }
    const char* stateText = sv.ok ? (sv.restarted ? "RESTARTED" : "OK") : "STOPPED";

    ImGui::PushID(index);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float rowH = ImGui::GetTextLineHeight() * 2.0f + 12.0f;
    ImGui::InvisibleButton("##service-row", ImVec2(ImGui::GetContentRegionAvail().x, rowH));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (ImGui::IsItemHovered())
        dl->AddRectFilled(p, ImVec2(p.x + ImGui::GetItemRectSize().x, p.y + rowH),
                          ColorAlpha(col::Header, 0.026f), 3.0f);
    dl->AddCircleFilled(ImVec2(p.x + 7.0f, p.y + 14.0f), 3.0f, ColorAlpha(stateColor, 0.90f), 16);
    dl->AddText(ImVec2(p.x + 18.0f, p.y + 5.0f), ImGui::GetColorU32(col::Header), sv.name.c_str());
    dl->AddText(ImVec2(p.x + 18.0f, p.y + 23.0f), ImGui::GetColorU32(col::TextDim), stateText);
    if (!sv.note.empty() && ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", sv.note.c_str());
    ImGui::PopID();
}

inline ImVec4 StatusColor(const std::string& status, int count = 0) {
    if (status == "OK" || status == "CLEAN")
        return count > 0 ? col::Yellow : col::Green;
    if (status == "DETECTED" || status == "ANOMALY" ||
        status == "HIGH" || status == "CRITICAL")
        return col::Red;
    if (status == "REVIEW" || status == "CLOSED" || status == "Loading" || status == "MEDIUM" ||
        status == "FLAG" || count > 0)
        return col::Yellow;
    return col::TextDim;
}

inline void ProgressStrip(float progress, const ImVec4& color, float width = -1.0f) {
    progress = Saturate(progress);
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 sz(width > 0.0f ? width : ImGui::GetContentRegionAvail().x, 7.0f);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + sz.x, p.y + sz.y), ColorAlpha(col::Header, 0.060f), 4.0f);
    dl->AddRectFilled(p, ImVec2(p.x + sz.x * progress, p.y + sz.y), ColorAlpha(color, 0.92f), 4.0f);
    dl->AddRect(p, ImVec2(p.x + sz.x, p.y + sz.y), ColorAlpha(col::Header, 0.045f), 4.0f);
    ImGui::Dummy(sz);
}

inline bool DashboardStatCard(const char* id, const char* label, const std::string& value,
                              const char* detail, const ImVec4& accent) {
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = 92.0f;
    ImGui::InvisibleButton("##stat-card", ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    if (hovered)
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec4 bg = hovered ? Mix(col::PanelLift, accent, 0.045f) : col::PanelSoft;
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), ColorAlpha(bg, 0.72f), 6.0f);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h), ColorAlpha(col::Header, hovered ? 0.120f : 0.065f), 6.0f);
    dl->AddRectFilled(ImVec2(p.x, p.y), ImVec2(p.x + 3.0f, p.y + h), ColorAlpha(accent, 0.82f), 6.0f,
                      ImDrawFlags_RoundCornersLeft);
    dl->AddText(ImVec2(p.x + 16.0f, p.y + 12.0f), ImGui::GetColorU32(col::TextDim), label);
    dl->AddText(ImVec2(p.x + 16.0f, p.y + 34.0f), ImGui::GetColorU32(col::Header), value.c_str());
    dl->AddText(ImVec2(p.x + 16.0f, p.y + 62.0f), ImGui::GetColorU32(col::TextDim), detail);
    ImGui::PopID();
    return clicked;
}

inline void ModuleCard(ScanData& d, const char* id, int page, const char* title,
                       const std::string& status, int count, const char* description,
                       const char* runCommand = nullptr, float cardHeight = 118.0f) {
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = cardHeight;
    ImVec4 accent = StatusColor(status, count);
    bool active = d.activePage == page;
    ImGui::InvisibleButton("##module-card", ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    ImVec2 mouse = ImGui::GetMousePos();
    ImVec2 openMin(p.x + w - 96.0f, p.y + 12.0f);
    ImVec2 openMax(openMin.x + 80.0f, openMin.y + 26.0f);
    ImVec2 scanMin(p.x + w - 96.0f, p.y + 44.0f);
    ImVec2 scanMax(scanMin.x + 80.0f, scanMin.y + 26.0f);
    bool openHot = hovered && mouse.x >= openMin.x && mouse.x <= openMax.x &&
                   mouse.y >= openMin.y && mouse.y <= openMax.y;
    bool scanHot = hovered && runCommand && status != "Loading" &&
                   mouse.x >= scanMin.x && mouse.x <= scanMax.x &&
                   mouse.y >= scanMin.y && mouse.y <= scanMax.y;
    if (ImGui::IsItemClicked()) {
        if (scanHot)
            d.pendingCommand = runCommand;
        else
            d.activePage = page;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec4 bg = active ? Mix(col::PanelLift, col::Accent, 0.10f)
                       : (hovered ? Mix(col::PanelSoft, accent, 0.055f) : col::PanelSoft);
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), ColorAlpha(bg, 0.78f), 6.0f);
    dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                ColorAlpha(active ? col::Accent : col::Header, active ? 0.34f : 0.075f), 6.0f);
    dl->AddCircleFilled(ImVec2(p.x + 18.0f, p.y + 21.0f), 4.0f, ColorAlpha(accent, 0.95f), 16);
    dl->AddText(ImVec2(p.x + 32.0f, p.y + 12.0f), ImGui::GetColorU32(col::Header), title);
    dl->AddText(ImVec2(p.x + 16.0f, p.y + 43.0f), ImGui::GetColorU32(col::TextDim), description);

    std::string countText = std::to_string(count) + " findings";
    const float footerY = p.y + h - 30.0f;
    dl->AddText(ImVec2(p.x + 16.0f, footerY), ImGui::GetColorU32(col::Text), countText.c_str());
    ImVec2 badgeSize = ImGui::CalcTextSize(status.c_str());
    dl->AddText(ImVec2(p.x + w - badgeSize.x - 16.0f, footerY), ImGui::GetColorU32(accent), status.c_str());

    ImVec4 actionBg = openHot ? Mix(col::PanelLift, col::Accent, 0.22f) : Mix(col::PanelSoft, col::Accent, active ? 0.18f : 0.10f);
    dl->AddRectFilled(openMin, openMax, ColorAlpha(actionBg, 0.95f), 4.0f);
    dl->AddRect(openMin, openMax, ColorAlpha(active ? col::Accent : col::Header, active ? 0.42f : 0.10f), 4.0f);
    const char* openLabel = active ? "Aberto" : "Abrir";
    ImVec2 openText = ImGui::CalcTextSize(openLabel);
    dl->AddText(ImVec2(openMin.x + (80.0f - openText.x) * 0.5f, openMin.y + 5.0f),
                ImGui::GetColorU32(col::Header), openLabel);
    if (runCommand && status != "Loading") {
        ImVec4 scanBg = scanHot ? Mix(col::PanelLift, accent, 0.22f) : Mix(col::PanelSoft, accent, 0.10f);
        dl->AddRectFilled(scanMin, scanMax, ColorAlpha(scanBg, 0.95f), 4.0f);
        dl->AddRect(scanMin, scanMax, ColorAlpha(accent, 0.24f), 4.0f);
        ImVec2 scanText = ImGui::CalcTextSize("Scan");
        dl->AddText(ImVec2(scanMin.x + (80.0f - scanText.x) * 0.5f, scanMin.y + 5.0f),
                    ImGui::GetColorU32(col::Header), "Scan");
    }
    ImGui::PopID();
}

inline void EvidenceRow(const char* id, const char* source, const std::string& main,
                        const std::string& detail, const ImVec4& accent) {
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = 42.0f;
    ImGui::InvisibleButton("##evidence-row", ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (hovered)
        dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), ColorAlpha(col::Header, 0.026f), 4.0f);
    dl->AddLine(ImVec2(p.x, p.y + h - 1.0f), ImVec2(p.x + w, p.y + h - 1.0f),
                ColorAlpha(col::Header, 0.055f), 1.0f);
    dl->AddCircleFilled(ImVec2(p.x + 8.0f, p.y + 19.0f), 3.0f, ColorAlpha(accent, 0.92f), 16);
    dl->AddText(ImVec2(p.x + 20.0f, p.y + 6.0f), ImGui::GetColorU32(accent), source);
    dl->AddText(ImVec2(p.x + 104.0f, p.y + 6.0f), ImGui::GetColorU32(col::Header),
                CompactText(main, 58).c_str());
    dl->AddText(ImVec2(p.x + 104.0f, p.y + 24.0f), ImGui::GetColorU32(col::TextDim),
                CompactText(detail, 76).c_str());
    if (hovered && (main.size() > 58 || detail.size() > 76))
        ImGui::SetTooltip("%s\n%s", main.c_str(), detail.c_str());
    ImGui::PopID();
}

inline void BeginResultCard(const char* id, float height, const ImVec4& tint) {
    if (height < 92.0f)
        height = 92.0f;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(15, 12));
    ImGui::BeginChild(id, ImVec2(0, height), false, ImGuiWindowFlags_NoScrollbar);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetWindowPos();
    ImVec2 rectMax(p.x + ImGui::GetWindowWidth(), p.y + ImGui::GetWindowHeight());
    bool hovered = ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows);
    ImVec4 rowBg = hovered ? Mix(col::PanelSoft, tint, 0.08f) : col::PanelSoft;
    dl->AddRectFilled(p, rectMax, ColorAlpha(rowBg, hovered ? 0.72f : 0.42f), 5.0f);
    dl->AddRect(p, rectMax, ColorAlpha(col::Header, hovered ? 0.105f : 0.060f), 5.0f);
    dl->AddRectFilled(ImVec2(p.x, p.y), ImVec2(rectMax.x, p.y + 2.0f),
                      ColorAlpha(tint, 0.72f), 5.0f, ImDrawFlags_RoundCornersTop);
    dl->AddLine(ImVec2(p.x + 12.0f, rectMax.y - 1.0f), ImVec2(rectMax.x - 12.0f, rectMax.y - 1.0f),
                ColorAlpha(col::Header, 0.050f), 1.0f);
}

inline void EndResultCard() {
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

inline void BeginFlatResultRow(const char* id, float height) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 10.0f));
    ImGui::BeginChild(id, ImVec2(0.0f, height), false, ImGuiWindowFlags_NoScrollbar);
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows)) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 p = ImGui::GetWindowPos();
        dl->AddRectFilled(p, ImVec2(p.x + ImGui::GetWindowWidth(),
                                    p.y + ImGui::GetWindowHeight()),
                          ColorAlpha(col::Header, 0.018f), 3.0f);
    }
}

inline void EndFlatResultRow() {
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

inline void MiniMeter(const char* label, int value, const ImVec4& color) {
    ImGui::BeginGroup();
    ImGui::TextColored(col::TextDim, "%s", label);
    ImGui::SameLine(0, 6);
    ImGui::TextColored(col::Header, "%d%%", value);
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImVec2 sz(94.0f, 4.0f);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + sz.x, p.y + sz.y), ColorAlpha(col::Header, 0.065f), 3.0f);
    dl->AddRectFilled(p, ImVec2(p.x + sz.x * (value / 100.0f), p.y + sz.y), ColorAlpha(color, 0.95f), 3.0f);
    dl->AddRect(p, ImVec2(p.x + sz.x, p.y + sz.y), ColorAlpha(col::Header, 0.045f), 3.0f);
    ImGui::Dummy(sz);
    ImGui::EndGroup();
}



inline void DrawPinIcon(ImDrawList* dl, ImVec2 center, float r, ImU32 color) {
    float headR = r * 0.60f;
    float headCY = center.y - r * 0.18f;
    float tipY  = center.y + r * 0.92f;


    ImVec2 tri[3] = {
        ImVec2(center.x - headR * 0.82f, headCY + headR * 0.30f),
        ImVec2(center.x + headR * 0.82f, headCY + headR * 0.30f),
        ImVec2(center.x,                 tipY),
    };
    dl->AddTriangleFilled(tri[0], tri[1], tri[2], color);


    dl->AddCircleFilled(ImVec2(center.x, headCY), headR, color);


    ImU32 innerCol = IM_COL32(14, 14, 22, 230);
    dl->AddCircleFilled(ImVec2(center.x, headCY), headR * 0.36f, innerCol);
}

inline void DrawTitleFallbackLogo(ImDrawList* dl, ImVec2 min, ImVec2 max) {
    ImVec2 center((min.x + max.x) * 0.5f, (min.y + max.y) * 0.5f);
    float w = max.x - min.x;
    float h = max.y - min.y;
    ImU32 bg = IM_COL32(18, 20, 25, 255);
    ImU32 edge = IM_COL32(255, 255, 255, 34);
    ImU32 line = ImGui::GetColorU32(ImVec4(col::Accent.x, col::Accent.y, col::Accent.z, 0.82f));
    ImU32 dim = IM_COL32(120, 126, 150, 150);

    dl->AddRectFilled(min, max, bg, 5.0f);
    dl->AddRect(min, max, edge, 5.0f);

    float pad = w * 0.22f;
    float len = w * 0.22f;
    float left = min.x + pad;
    float right = max.x - pad;
    float top = min.y + pad;
    float bottom = max.y - pad;

    dl->AddLine(ImVec2(left, top), ImVec2(left + len, top), line, 1.2f);
    dl->AddLine(ImVec2(left, top), ImVec2(left, top + len), line, 1.2f);
    dl->AddLine(ImVec2(right, top), ImVec2(right - len, top), line, 1.2f);
    dl->AddLine(ImVec2(right, top), ImVec2(right, top + len), line, 1.2f);
    dl->AddLine(ImVec2(left, bottom), ImVec2(left + len, bottom), line, 1.2f);
    dl->AddLine(ImVec2(left, bottom), ImVec2(left, bottom - len), line, 1.2f);
    dl->AddLine(ImVec2(right, bottom), ImVec2(right - len, bottom), line, 1.2f);
    dl->AddLine(ImVec2(right, bottom), ImVec2(right, bottom - len), line, 1.2f);

    dl->AddCircle(center, w * 0.18f, dim, 18, 1.0f);
    dl->AddLine(ImVec2(center.x - w * 0.24f, center.y + h * 0.22f),
                ImVec2(center.x + w * 0.24f, center.y - h * 0.22f), line, 1.1f);
}

inline void AccentColorButton(ScanData& d, const ImVec2& size) {
    float radius = size.x * 0.5f;
    ImVec2 screenPos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##scanner-accent-btn", size);
    bool hovered = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 center(screenPos.x + radius, screenPos.y + radius);



    constexpr int kSlices = 18;
    for (int i = 0; i < kSlices; ++i) {
        float a0 = (float)i / kSlices * 6.28318530f - 1.57079632f;
        float a1 = (float)(i + 1) / kSlices * 6.28318530f - 1.57079632f;
        float hue = (float)i / kSlices;
        float r2, g2, b2;
        ImGui::ColorConvertHSVtoRGB(hue, 0.85f, 0.92f, r2, g2, b2);
        ImU32 sliceCol = IM_COL32((int)(r2*255), (int)(g2*255), (int)(b2*255), 230);
        dl->PathLineTo(center);
        dl->PathArcTo(center, radius, a0, a1, 4);
        dl->PathFillConvex(sliceCol);
    }


    float innerR = radius * 0.46f;
    dl->AddCircleFilled(center, innerR, ImGui::GetColorU32(d.accentColor));


    dl->AddCircle(center, innerR, IM_COL32(14, 14, 22, 180), 32, 1.2f);


    ImU32 borderCol = IM_COL32(255, 255, 255, hovered ? 130 : 40);
    dl->AddCircle(center, radius - 0.5f, borderCol, 32, 1.0f);

    if (hovered) ImGui::SetTooltip("Mudar cor do scanner");
    if (clicked) ImGui::OpenPopup("##scanner-accent-popup");

    if (ImGui::BeginPopup("##scanner-accent-popup")) {
        ImGui::TextColored(col::Header, "Cor do scanner");
        ImGui::Spacing();

        if (ImGui::ColorPicker3("##scanner-accent-picker", (float*)&d.accentColor,
                                ImGuiColorEditFlags_NoAlpha | ImGuiColorEditFlags_PickerHueWheel)) {
            d.accentColor.w = 1.0f;
            col::SetAccentColor(d.accentColor);
        }

        const ImVec4 presets[] = {
            ImVec4(0.24f, 0.26f, 0.30f, 1.00f),
            ImVec4(0.12f, 0.13f, 0.15f, 1.00f),
            ImVec4(0.58f, 0.28f, 1.00f, 1.00f),
            ImVec4(0.10f, 0.62f, 1.00f, 1.00f),
            ImVec4(0.00f, 0.78f, 0.62f, 1.00f),
            ImVec4(1.00f, 0.48f, 0.18f, 1.00f),
            ImVec4(1.00f, 0.20f, 0.42f, 1.00f),
        };

        ImGui::Spacing();
        for (int i = 0; i < IM_ARRAYSIZE(presets); ++i) {
            ImGui::PushID(i);
            if (ImGui::ColorButton("##preset", presets[i],
                                   ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop,
                                   ImVec2(22.0f, 22.0f))) {
                d.accentColor = presets[i];
                col::SetAccentColor(d.accentColor);
            }
            ImGui::PopID();
            if (i + 1 < IM_ARRAYSIZE(presets))
                ImGui::SameLine(0, 6);
        }

        ImGui::Spacing();
        if (ImGui::Button("Resetar")) {
            d.accentColor = presets[0];
            col::SetAccentColor(d.accentColor);
        }

        ImGui::EndPopup();
    }
}




inline std::string FLow(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}


inline bool FMatch(const std::string& needle,
                   std::initializer_list<std::string> fields) {
    if (needle.empty()) return true;
    for (const auto& f : fields) {
        std::string low = FLow(f);
        if (low.find(needle) != std::string::npos) return true;
    }
    return false;
}



inline void FilterBar(const char* searchId, char* buf, size_t bufSz,
                      const char* comboId, int* sel, const char* comboItems, int numItems,
                      const char* clearId, const char* tip = nullptr) {
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(7, 4));
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputText(searchId, buf, (int)bufSz);
    if (tip && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", tip);
    ImGui::SameLine(0, 8);
    ImGui::SetNextItemWidth(128.0f);
    ImGui::Combo(comboId, sel, comboItems, numItems);
    if (buf[0] || *sel) {
        ImGui::SameLine(0, 8);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.070f, 0.074f, 0.088f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.105f, 0.110f, 0.128f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.145f, 0.150f, 0.170f, 1.0f));
        if (ImGui::Button(clearId)) { buf[0] = '\0'; *sel = 0; }
        ImGui::PopStyleColor(3);
    }
    ImGui::PopStyleVar();
}

}






inline void TitleBar(ScanData& d, void(*onMinimize)() = nullptr, void(*onClose)() = nullptr,
                     void(*onToggleTopmost)(bool) = nullptr) {
    const float barH = kTitleBarH;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::BgTitle);
    ImGui::BeginChild("##titlebar", ImVec2(0, barH), false,
                      ImGuiWindowFlags_NoScrollbar);

    ImDrawList* titleDl = ImGui::GetWindowDrawList();
    ImVec2 titlePos = ImGui::GetWindowPos();
    ImVec2 titleMax(titlePos.x + ImGui::GetWindowWidth(), titlePos.y + barH);
    titleDl->AddRectFilled(titlePos, titleMax, ImGui::GetColorU32(col::BgTitle));
    titleDl->AddLine(ImVec2(titlePos.x, titleMax.y - 1.0f),
                     ImVec2(titleMax.x, titleMax.y - 1.0f),
                     detail::ColorAlpha(col::Header, 0.070f), 1.0f);
    titleDl->AddLine(ImVec2(titlePos.x, titlePos.y),
                     ImVec2(titleMax.x, titlePos.y),
                     detail::ColorAlpha(col::Accent, 0.16f), 1.0f);

    const float kIconSize = 28.0f;
    const float kIconPad  = 8.0f;
    const float iconX = 8.0f;
    const float iconY = (barH - kIconSize) * 0.5f;
    ImVec2 iconMin(titlePos.x + iconX, titlePos.y + iconY);
    ImVec2 iconMax(iconMin.x + kIconSize, iconMin.y + kIconSize);
    if (d.logoTexture) {
        titleDl->AddImage((ImTextureID)d.logoTexture, iconMin, iconMax);
    } else {
        detail::DrawTitleFallbackLogo(titleDl, iconMin, iconMax);
    }
    float textStartX = iconX + kIconSize + kIconPad;
    ImGui::SetCursorPos(ImVec2(textStartX, (barH - ImGui::GetTextLineHeight()) * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_Text, col::Header);
    ImGui::Text("%s", d.title.c_str());
    ImGui::PopStyleColor();


    ImGui::SameLine(0, 14);
    {
        ImVec2 dotTopLeft = ImGui::GetCursorScreenPos();
        float lineH = ImGui::GetTextLineHeight();
        ImGui::InvisibleButton("##dbg-dot-title", ImVec2(14.0f, lineH));
        if (ImGui::IsItemHovered()) {
            if (d.debugMode)
                ImGui::SetTooltip(
                    "SeDebugPrivilege: ATIVO\n"
                    "O scanner tem acesso completo a processos\n"
                    "protegidos. WinScan e Emulador cobrem mais\n"
                    "processos nesta sessao.");
            else
                ImGui::SetTooltip(
                    "SeDebugPrivilege: INATIVO\n"
                    "Alguns processos protegidos podem nao ser\n"
                    "acessiveis durante o scan.\n"
                    "Ative o DBG na barra inferior para acesso completo.");
        }
        ImDrawList* dotDl = ImGui::GetWindowDrawList();
        ImVec2 center(dotTopLeft.x + 7.0f, dotTopLeft.y + lineH * 0.5f);
        float r = 4.5f;
        if (d.debugMode) {
            dotDl->AddCircleFilled(center, r + 3.0f,
                ImGui::GetColorU32(ImVec4(0.30f, 0.85f, 0.45f, 0.18f)));
            dotDl->AddCircleFilled(center, r,
                ImGui::GetColorU32(col::Green));
        } else {
            dotDl->AddCircleFilled(center, r,
                ImGui::GetColorU32(ImVec4(0.24f, 0.26f, 0.31f, 1.0f)));
        }
    }

    const ImVec2 buttonSize(28.0f, 24.0f);
    const ImVec2 colorButtonSize(22.0f, 22.0f);
    const ImVec2 pinButtonSize(22.0f, 22.0f);
    const float rightPad = 10.0f;
    const float buttonGap = 6.0f;
    const float versionGap = 18.0f;
    const float pinGap = 6.0f;
    const float closeX = ImGui::GetWindowWidth() - rightPad - buttonSize.x;
    const float minX = closeX - buttonGap - buttonSize.x;
    const ImVec2 versionSize = ImGui::CalcTextSize(d.version.c_str());
    const float versionX = minX - versionGap - versionSize.x;
    const float colorX = versionX - versionGap - colorButtonSize.x;
    const float pinX = colorX - pinGap - pinButtonSize.x;
    const float textY = (barH - ImGui::GetTextLineHeight()) * 0.5f;
    const float buttonY = (barH - buttonSize.y) * 0.5f;
    const float colorY = (barH - colorButtonSize.y) * 0.5f;
    const float pinY = (barH - pinButtonSize.y) * 0.5f;


    ImGui::SetCursorPos(ImVec2(pinX, pinY));
    ImGui::InvisibleButton("##pin-topmost", pinButtonSize);
    if (ImGui::IsItemClicked()) {
        d.alwaysOnTop = !d.alwaysOnTop;
        if (onToggleTopmost) onToggleTopmost(d.alwaysOnTop);
    }
    {
        bool pinHovered = ImGui::IsItemHovered();
        ImDrawList* pinDl = ImGui::GetWindowDrawList();
        ImVec2 pinMin = ImGui::GetItemRectMin();
        ImVec2 pinCenter(pinMin.x + pinButtonSize.x * 0.5f, pinMin.y + pinButtonSize.y * 0.5f);
        ImU32 pinCol;
        if (d.alwaysOnTop)
            pinCol = ImGui::GetColorU32(col::Accent);
        else if (pinHovered)
            pinCol = ImGui::GetColorU32(ImVec4(0.70f, 0.70f, 0.80f, 1.0f));
        else
            pinCol = ImGui::GetColorU32(ImVec4(0.38f, 0.38f, 0.48f, 1.0f));


        if (d.alwaysOnTop || pinHovered) {
            float bgAlpha = d.alwaysOnTop ? 0.15f : 0.08f;
            pinDl->AddCircleFilled(pinCenter, pinButtonSize.x * 0.5f,
                ImGui::GetColorU32(ImVec4(col::Accent.x, col::Accent.y, col::Accent.z, bgAlpha)));
        }
        detail::DrawPinIcon(pinDl, pinCenter, pinButtonSize.x * 0.38f, pinCol);
        if (pinHovered)
            ImGui::SetTooltip(d.alwaysOnTop ? "Desafixar janela do topo" : "Fixar janela no topo");
    }

    ImGui::SetCursorPos(ImVec2(colorX, colorY));
    detail::AccentColorButton(d, colorButtonSize);

    ImGui::SetCursorPos(ImVec2(versionX, textY));
    ImGui::TextColored(col::TextDim, "%s", d.version.c_str());

    ImGui::SetCursorPos(ImVec2(minX, buttonY));
    if (ImGui::Button("-", buttonSize) && onMinimize) onMinimize();
    ImGui::SetCursorPos(ImVec2(closeX, buttonY));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, col::Red);
    if (ImGui::Button("X", buttonSize) && onClose) onClose();
    ImGui::PopStyleColor();

    ImGui::EndChild();
    ImGui::PopStyleColor();


}

inline void DrawSidebarNavItem(ScanData& d, int page, const char* label,
                               const char* caption, const ImVec4& stateColor) {
    (void)caption;
    ImGui::PushID(page);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float w = ImGui::GetContentRegionAvail().x;
    const float h = 30.0f;
    ImGui::InvisibleButton("##nav-item", ImVec2(w, h));
    const bool active = d.activePage == page;
    const bool hovered = ImGui::IsItemHovered();
    if (ImGui::IsItemClicked())
        d.activePage = page;
    if (hovered)
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (active || hovered) {
        const ImVec4 bg = active
            ? detail::Mix(col::PanelLift, col::Accent, 0.10f)
            : col::PanelSoft;
        dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h),
                          detail::ColorAlpha(bg, active ? 0.95f : 0.62f), 4.0f);
        dl->AddRect(p, ImVec2(p.x + w, p.y + h),
                    detail::ColorAlpha(active ? col::Accent : col::Header,
                                       active ? 0.34f : 0.07f), 4.0f);
    }
    if (active)
        dl->AddRectFilled(p, ImVec2(p.x + 2.0f, p.y + h),
                          detail::ColorAlpha(col::Accent, 0.95f), 4.0f,
                          ImDrawFlags_RoundCornersLeft);

    const ImVec4 labelColor = active ? col::Header : col::Text;
    dl->AddCircleFilled(ImVec2(p.x + 12.0f, p.y + h * 0.5f), 2.8f,
                        detail::ColorAlpha(active ? col::Accent : stateColor, 0.95f), 16);
    dl->AddText(ImVec2(p.x + 22.0f, p.y + 7.0f),
                ImGui::GetColorU32(labelColor), label);
    ImGui::PopID();
}

inline void DrawSidebar(ScanData& d, float height) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::BgTitle);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 4.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 12.0f));
    ImGui::BeginChild("##sidebar", ImVec2(kSidebarW, height), true,
                      ImGuiWindowFlags_NoScrollbar);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetWindowPos();
    const ImVec2 panelMax(p.x + ImGui::GetWindowWidth(), p.y + ImGui::GetWindowHeight());
    dl->AddRectFilled(p, panelMax, ImGui::GetColorU32(col::BgTitle), 4.0f);

    auto sectionTitle = [&](const char* title) {
        ImGui::Dummy(ImVec2(0.0f, 5.0f));
        ImGui::TextColored(col::Header, "%s", title);
        const ImVec2 line = ImGui::GetCursorScreenPos();
        dl->AddLine(ImVec2(line.x, line.y + 1.0f),
                    ImVec2(line.x + ImGui::GetContentRegionAvail().x, line.y + 1.0f),
                    detail::ColorAlpha(col::Header, 0.14f), 1.0f);
        ImGui::Dummy(ImVec2(0.0f, 5.0f));
    };

    auto findService = [&](const char* name) -> const ServiceStatus* {
        for (const auto& service : d.services) {
            if (service.name == name)
                return &service;
        }
        return nullptr;
    };

    auto statusItem = [&](const char* label, const char* serviceName) {
        const ServiceStatus* service = findService(serviceName);
        const bool ok = service && service->ok;
        ImGui::TextColored(col::Text, "%s", label);
        ImGui::SameLine(0.0f, 5.0f);
        ImGui::TextColored(ok ? col::Green : col::Red, "%s", ok ? "+" : "x");
        if (service && !service->note.empty() && ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", service->note.c_str());
    };

    auto clockOnly = [](const std::string& value) {
        if (value.empty() || value == "-")
            return std::string("-");
        size_t space = value.find_last_of(' ');
        std::string clock = space == std::string::npos ? value : value.substr(space + 1);
        if (clock.size() >= 5)
            clock.resize(5);
        return clock;
    };

    ImGui::TextColored(col::Header, "INFO CHECK");
    ImGui::TextColored(col::TextDim, "RXVScan system overview");

    sectionTitle("Servicos / Sistema");
    if (ImGui::BeginTable("##sidebar-services", 3,
                          ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoHostExtendX)) {
        auto cell = [&](const char* label, const char* serviceName) {
            ImGui::TableNextColumn();
            statusItem(label, serviceName);
        };
        cell("Pca", "PcaSvc");
        cell("DPS", "DPS");
        cell("DiagTrack", "DiagTrack");
        cell("SysMain", "SysMain");
        cell("Sysmon", "Sysmon");
        cell("EventLog", "EventLog");
        cell("TPM 2.0", "TPM 2.0");
        cell("Secure Boot", "SecureBoot");
        cell("IOMMU", "IOMMU");
        ImGui::EndTable();
    }

    sectionTitle("Identificacao");
    ImGui::TextColored(col::TextDim, "HWID");
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
    ImGui::TextColored(col::Header, "%s", d.hwid.empty() ? "-" : d.hwid.c_str());
    ImGui::PopTextWrapPos();
    if (!d.hwid.empty() && ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Clique para copiar o HWID");
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            ImGui::SetClipboardText(d.hwid.c_str());
    }

    sectionTitle("Boot PC / Emulador");
    const std::string pcClock = clockOnly(d.boot);
    const std::string emuClock = clockOnly(d.emulatorOpenedAt);
    ImGui::TextColored(col::TextDim, "PC");
    ImGui::SameLine(72.0f);
    ImGui::TextColored(col::Header, "%s", pcClock.c_str());
    ImGui::TextColored(col::TextDim, "Emulador");
    ImGui::SameLine(72.0f);
    ImGui::TextColored(d.emulatorOpenedAt == "-" ? col::TextDim : col::Header,
                       "%s", emuClock.c_str());

    const float statusY = ImGui::GetWindowHeight() - 58.0f;
    if (ImGui::GetCursorPosY() < statusY)
        ImGui::SetCursorPosY(statusY);
    const bool finished = d.scanProgress >= 1.0f;
    ImGui::TextColored(finished ? col::Green : col::TextDim, "%s",
                       finished ? "SCAN CONCLUIDO" : "SCANNER EM EXECUCAO");
    ImGui::SameLine();
    ImGui::TextColored(col::Header, "%d%%",
                       (int)(detail::Saturate(d.scanProgress) * 100.0f));
    detail::ProgressStrip(d.scanProgress, finished ? col::Green : col::Header);

    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

inline void DrawPageHeader(const ScanData& d) {
    const char* title = "Visao geral";
    const char* description = "Resumo da verificacao, riscos e atalhos para os modulos.";
    const char* section = "DASHBOARD";
    switch (d.activePage) {
    case 2:
        title = "EFI Cheat Detect";
        description = "Analise de boot loaders, firmware e artefatos EFI suspeitos.";
        section = "INVESTIGACAO";
        break;
    case 3:
    case 5:
        title = "Driver & Kernel Integrity";
        description = "Assinaturas, hooks, callbacks e integridade do kernel.";
        section = "INVESTIGACAO";
        break;
    case 6:
        title = "Emulador";
        description = "Integridade de processos, memoria e ambiente do emulador.";
        section = "INVESTIGACAO";
        break;
    case 7:
        title = "Dispositivo";
        description = "Informacoes consolidadas do hardware e do Windows.";
        section = "SISTEMA";
        break;
    case 8:
        title = "Servicos";
        description = "Estado dos servicos essenciais acompanhados pelo scanner.";
        section = "SISTEMA";
        break;
    case 9:
        title = "Sysmon";
        description = "Eventos de seguranca, filtros e telemetria de processos.";
        section = "SISTEMA";
        break;
    default:
        break;
    }

    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::Bg);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 8.0f));
    ImGui::BeginChild("##page-header", ImVec2(0.0f, 48.0f), true,
                      ImGuiWindowFlags_NoScrollbar);

    const ImVec2 p = ImGui::GetWindowPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 labelSize = ImGui::CalcTextSize(title);
    const ImVec2 tagMin(p.x + 12.0f, p.y + 7.0f);
    const ImVec2 tagMax(tagMin.x + labelSize.x + 24.0f, tagMin.y + 28.0f);
    dl->AddRectFilled(tagMin, tagMax, ImGui::GetColorU32(col::PanelLift), 5.0f);
    dl->AddRect(tagMin, tagMax, detail::ColorAlpha(col::Header, 0.10f), 5.0f);
    dl->AddCircleFilled(ImVec2(tagMin.x + 10.0f, tagMin.y + 14.0f), 3.0f,
                        ImGui::GetColorU32(col::Accent), 12);
    dl->AddText(ImVec2(tagMin.x + 18.0f, tagMin.y + 7.0f),
                ImGui::GetColorU32(col::Header), title);
    dl->AddText(ImVec2(tagMax.x + 14.0f, tagMin.y + 7.0f),
                ImGui::GetColorU32(col::TextDim), description);
    const ImVec2 sectionSize = ImGui::CalcTextSize(section);
    dl->AddText(ImVec2(p.x + ImGui::GetWindowWidth() - sectionSize.x - 16.0f,
                       tagMin.y + 7.0f),
                ImGui::GetColorU32(col::TextDim), section);

    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
    ImGui::Spacing();
}


inline void DrawSysmon(ScanData& d, bool showInspectButton = false);

inline void DrawDashboard(ScanData& d) {
    int stoppedServices = 0;
    int restartedServices = 0;
    for (const auto& service : d.services) {
        if (!service.ok) ++stoppedServices;
        if (service.restarted) ++restartedServices;
    }

    int evidenceCount = 0;
    evidenceCount += (int)d.bam.size();
    evidenceCount += (int)d.prefetch.size();
    evidenceCount += (int)d.usnAnomalies.size();
    evidenceCount += (int)d.emulatorFindings.size();
    evidenceCount += (int)d.systemMemoryFindings.size();
    evidenceCount += (int)d.genericBypass.size();
    evidenceCount += (int)d.streamModFindings.size();
    evidenceCount += (int)d.remotePortFindings.size();
    evidenceCount += (int)d.registryFindings.size();
    evidenceCount += (int)d.clsidFindings.size();
    evidenceCount += (int)d.kernelAnomalies.size();

    int highRisk = 0;
    for (const auto& e : d.emulatorFindings) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.systemMemoryFindings) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.genericBypass) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.streamModFindings) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.remotePortFindings) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.registryFindings) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.clsidFindings) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.kernelAnomalies) if (e.severity == "HIGH" || e.severity == "CRITICAL") ++highRisk;
    for (const auto& e : d.bam) if (e.suspicious) ++highRisk;

    auto combinedDriverStatus = [&]() -> std::string {
        const std::string statuses[] = { d.driverIntegrityStatus, d.kernelDriverStatus };
        for (const auto& status : statuses)
            if (status == "DETECTED") return "DETECTED";
        for (const auto& status : statuses)
            if (status == "REVIEW") return "REVIEW";
        for (const auto& status : statuses)
            if (status == "Loading") return "Loading";
        if (d.driverIntegrityStatus == "OK" && d.kernelDriverStatus == "OK")
            return "OK";
        return "Waiting";
    };
    const std::string driverStatus = combinedDriverStatus();
    const int driverFindings = (int)(d.driverIntegrity.size() + d.kernelDrivers.size());
    const std::string emulatorTime = d.emulatorOpenedAt.empty() || d.emulatorOpenedAt == "-"
        ? "Horario ainda nao coletado"
        : "Ligado em: " + detail::CompactText(d.emulatorOpenedAt, 30);

    std::string verdict = highRisk > 0 ? "RISCO ALTO" : (evidenceCount > 0 || stoppedServices > 0 ? "REVISAO" : "ESTAVEL");
    ImVec4 verdictColor = highRisk > 0 ? col::Red : (evidenceCount > 0 || stoppedServices > 0 ? col::Yellow : col::Green);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::Panel);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 7.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 18));
    ImGui::BeginChild("##dashboard-hero", ImVec2(0, 176.0f), true, ImGuiWindowFlags_NoScrollbar);
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetWindowPos();
        ImVec2 panelMax(p.x + ImGui::GetWindowWidth(), p.y + ImGui::GetWindowHeight());
        dl->AddRectFilledMultiColor(p, panelMax,
            detail::ColorAlpha(detail::Mix(col::PanelLift, col::Accent, 0.18f), 0.88f),
            detail::ColorAlpha(col::Panel, 0.92f),
            detail::ColorAlpha(col::Panel, 0.92f),
            detail::ColorAlpha(detail::Mix(col::Panel, verdictColor, 0.08f), 0.92f));
        dl->AddLine(ImVec2(p.x + 20.0f, p.y + 54.0f), ImVec2(panelMax.x - 20.0f, p.y + 54.0f),
                    detail::ColorAlpha(col::Header, 0.070f), 1.0f);
    }

    ImGui::TextColored(col::TextDim, "RXVSCAN OVERVIEW");
    ImGui::SameLine();
    detail::StatusBadge(verdict.c_str(), verdictColor);
    ImGui::Spacing();
    ImGui::TextColored(col::Header, "%d%% scan concluido", (int)(detail::Saturate(d.scanProgress) * 100.0f));
    detail::ProgressStrip(d.scanProgress, verdictColor);

    if (ImGui::BeginTable("##dashboard-hero-grid", 4, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("risk", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("evidence", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("services", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("runtime", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        detail::SummaryCell("##sum-risk", "RISCO", highRisk > 0 ? std::to_string(highRisk) + " criticos" : "sem criticos", verdictColor);
        ImGui::TableNextColumn();
        detail::SummaryCell("##sum-evidence", "EVIDENCIAS", std::to_string(evidenceCount), evidenceCount ? col::Yellow : col::Green);
        ImGui::TableNextColumn();
        detail::SummaryCell("##sum-services", "SERVICOS", stoppedServices ? std::to_string(stoppedServices) + " parados" : "operacionais",
                            stoppedServices ? col::Red : col::Green);
        ImGui::TableNextColumn();
        detail::SummaryCell("##sum-runtime", "RUNTIME", d.speedScan + " / " + d.elapsed, col::Header);
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);

    ImGui::Spacing();

    static int dashboardPopupCategory = 0;
    bool openDashboardPopup = false;
    if (ImGui::BeginTable("##dashboard-stat-row", 4, ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (detail::DashboardStatCard("##stat-winscan", "WinScan", std::to_string((int)(d.systemMemoryFindings.size() + d.kernelAnomalies.size())),
                                      d.systemMemoryStatus.c_str(), detail::StatusColor(d.systemMemoryStatus, (int)d.systemMemoryFindings.size()))) {
            dashboardPopupCategory = 1;
            openDashboardPopup = true;
        }
        ImGui::TableNextColumn();
        if (detail::DashboardStatCard("##stat-bypass", "Bypass", std::to_string((int)(d.genericBypass.size() + d.streamModFindings.size() + d.remotePortFindings.size())),
                                      d.genericBypassStatus.c_str(), detail::StatusColor(d.genericBypassStatus, (int)d.genericBypass.size()))) {
            dashboardPopupCategory = 2;
            openDashboardPopup = true;
        }
        ImGui::TableNextColumn();
        if (detail::DashboardStatCard("##stat-forensics", "Forensics", std::to_string((int)(d.bam.size() + d.prefetch.size() + d.usnAnomalies.size())),
                                      d.usnAnomalyStatus.c_str(), detail::StatusColor(d.usnAnomalyStatus, (int)d.usnAnomalies.size()))) {
            dashboardPopupCategory = 3;
            openDashboardPopup = true;
        }
        ImGui::TableNextColumn();
        if (detail::DashboardStatCard("##stat-persist", "Persistence", std::to_string((int)(d.registryFindings.size() + d.clsidFindings.size())),
                                      d.registryStatus.c_str(), detail::StatusColor(d.registryStatus, (int)(d.registryFindings.size() + d.clsidFindings.size())))) {
            dashboardPopupCategory = 4;
            openDashboardPopup = true;
        }
        ImGui::EndTable();
    }

    if (openDashboardPopup)
        ImGui::OpenPopup("##dashboard-findings-popup");

    ImGui::SetNextWindowSize(ImVec2(920.0f, 590.0f), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, col::Panel);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.0f, 0.0f, 0.0f, 0.72f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.0f, 16.0f));
    if (ImGui::BeginPopupModal("##dashboard-findings-popup", nullptr,
                               ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                               ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar)) {
        const char* popupTitle =
            dashboardPopupCategory == 1 ? "Deteccoes do WinScan" :
            dashboardPopupCategory == 2 ? "Deteccoes de Bypass" :
            dashboardPopupCategory == 3 ? "Deteccoes Forenses" :
                                          "Deteccoes de Persistencia";

        const int popupTotal =
            dashboardPopupCategory == 1 ? (int)(d.systemMemoryFindings.size() + d.kernelAnomalies.size()) :
            dashboardPopupCategory == 2 ? (int)(d.genericBypass.size() + d.streamModFindings.size() + d.remotePortFindings.size()) :
            dashboardPopupCategory == 3 ? (int)(d.bam.size() + d.prefetch.size() + d.usnAnomalies.size()) :
                                          (int)(d.registryFindings.size() + d.clsidFindings.size());
        const ImVec4 popupAccent =
            dashboardPopupCategory == 1 ? detail::StatusColor(d.systemMemoryStatus, popupTotal) :
            dashboardPopupCategory == 2 ? detail::StatusColor(d.genericBypassStatus, popupTotal) :
            dashboardPopupCategory == 3 ? detail::StatusColor(d.usnAnomalyStatus, popupTotal) :
                                          detail::StatusColor(d.registryStatus, popupTotal);

        ImDrawList* popupDl = ImGui::GetWindowDrawList();
        const ImVec2 popupPos = ImGui::GetWindowPos();
        const ImVec2 popupMax(popupPos.x + ImGui::GetWindowWidth(),
                              popupPos.y + ImGui::GetWindowHeight());
        popupDl->AddRectFilled(popupPos, ImVec2(popupMax.x, popupPos.y + 78.0f),
                               ImGui::GetColorU32(detail::Mix(col::PanelLift, popupAccent, 0.08f)),
                               8.0f, ImDrawFlags_RoundCornersTop);
        popupDl->AddRectFilled(popupPos, ImVec2(popupMax.x, popupPos.y + 3.0f),
                               ImGui::GetColorU32(popupAccent), 8.0f,
                               ImDrawFlags_RoundCornersTop);
        popupDl->AddLine(ImVec2(popupPos.x + 20.0f, popupPos.y + 77.0f),
                         ImVec2(popupMax.x - 20.0f, popupPos.y + 77.0f),
                         ImGui::GetColorU32(detail::ColorAlpha(col::Header, 0.08f)));

        ImGui::TextColored(col::Header, "%s", popupTitle);
        ImGui::TextColored(col::TextDim, "Resultados agrupados desta categoria");
        ImGui::SameLine();
        detail::StatusBadge((std::to_string(popupTotal) + " ITENS").c_str(), popupAccent);

        ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 52.0f, 18.0f));
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, detail::ColorAlpha(col::Red, 0.22f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, detail::ColorAlpha(col::Red, 0.34f));
        if (ImGui::Button("X##close-dashboard-popup", ImVec2(30.0f, 28.0f)))
            ImGui::CloseCurrentPopup();
        ImGui::PopStyleColor(3);

        ImGui::SetCursorPosY(94.0f);
        ImGui::Spacing();

        int popupRows = 0;
        ImGui::PushStyleColor(ImGuiCol_ChildBg, col::Bg);
        ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f, 10.0f));
        ImGui::BeginChild("##dashboard-findings-list", ImVec2(0.0f, -52.0f), true,
                          ImGuiWindowFlags_AlwaysVerticalScrollbar);
        auto popupRow = [&](const char* source, const std::string& title,
                            const std::string& info, const std::string& severity) {
            const ImVec4 severityColor = detail::StatusColor(severity, 1);
            detail::BeginResultCard(("##dashboard-popup-row" + std::to_string(popupRows++)).c_str(),
                                    44.0f, severityColor);
            if (ImGui::BeginTable(("##dashboard-popup-grid" + std::to_string(popupRows)).c_str(), 3,
                                  ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
                ImGui::TableSetupColumn("source", ImGuiTableColumnFlags_WidthStretch, 0.14f);
                ImGui::TableSetupColumn("item", ImGuiTableColumnFlags_WidthStretch, 0.74f);
                ImGui::TableSetupColumn("level", ImGuiTableColumnFlags_WidthStretch, 0.12f);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(severityColor, "%s", source);
                ImGui::TableNextColumn();
                ImGui::TextColored(col::Header, "%s", detail::CompactText(title, 64).c_str());
                if (ImGui::IsItemHovered() && (!title.empty() || !info.empty()))
                    ImGui::SetTooltip("%s%s%s",
                                      title.c_str(),
                                      (!title.empty() && !info.empty()) ? "\n" : "",
                                      info.c_str());
                ImGui::TableNextColumn();
                detail::StatusBadge(severity.empty() ? "INFO" : severity.c_str(), severityColor);
                ImGui::EndTable();
            }
            detail::EndResultCard();
            ImGui::Spacing();
        };

        if (dashboardPopupCategory == 1) {
            for (const auto& f : d.systemMemoryFindings)
                popupRow("MEMORY", f.process, f.type + " | " + f.detail, f.severity);
            for (const auto& f : d.kernelAnomalies)
                popupRow("KERNEL", f.driverName.empty() ? f.type : f.driverName,
                         f.reason + " | " + f.detail, f.severity);
        } else if (dashboardPopupCategory == 2) {
            for (const auto& f : d.genericBypass)
                popupRow("BYPASS", f.process.empty() ? f.type : f.process,
                         f.target + " | " + f.detail, f.severity);
            for (const auto& f : d.streamModFindings)
                popupRow("STREAM", f.process.empty() ? f.type : f.process,
                         f.target + " | " + f.detail, f.severity);
            for (const auto& f : d.remotePortFindings)
                popupRow("PORT", f.process.empty() ? f.port : f.process,
                         f.reason + " | " + f.detail, f.severity);
        } else if (dashboardPopupCategory == 3) {
            for (const auto& f : d.bam)
                popupRow("BAM", detail::FileNameFromPath(f.path),
                         f.reason + " | " + f.detail, f.suspicious ? "HIGH" : "FLAG");
            for (const auto& f : d.prefetch)
                popupRow("PREFETCH", f.file, f.alias + " | " + f.note, f.severity);
            for (const auto& f : d.usnAnomalies)
                popupRow("USN", f.file, f.alias + " | " + f.note, f.severity);
        } else if (dashboardPopupCategory == 4) {
            for (const auto& f : d.registryFindings)
                popupRow("REGISTRY", f.value.empty() ? f.key : f.value,
                         f.reason + " | " + f.detail, f.severity);
            for (const auto& f : d.clsidFindings)
                popupRow("CLSID", f.friendlyName.empty() ? f.clsid : f.friendlyName,
                         f.reason + " | " + f.detail, f.severity);
        }

        if (popupRows == 0) {
            ImGui::Dummy(ImVec2(0.0f, 50.0f));
            ImGui::TextColored(col::Green, "Nenhuma deteccao nesta categoria.");
        }
        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);

        ImGui::TextColored(col::TextDim, "%d resultado%s", popupRows, popupRows == 1 ? "" : "s");
        ImGui::SameLine(ImGui::GetWindowWidth() - 148.0f);
        ImGui::PushStyleColor(ImGuiCol_Button, detail::Mix(col::PanelLift, popupAccent, 0.12f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, detail::Mix(col::PanelLift, popupAccent, 0.24f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, detail::Mix(col::PanelLift, popupAccent, 0.34f));
        if (ImGui::Button("Fechar", ImVec2(112.0f, 30.0f)))
            ImGui::CloseCurrentPopup();
        ImGui::PopStyleColor(3);
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(3);

    ImGui::Spacing();

    {
        const std::string shownHwid = d.hwid.empty() ? "Nao disponivel" : d.hwid;
        const std::string hwidLine = "Hwid: " + shownHwid;
        const float lineH = 42.0f;
        const ImVec2 p = ImGui::GetCursorScreenPos();
        const float width = ImGui::GetContentRegionAvail().x;

        ImGui::InvisibleButton("##dashboard-hwid", ImVec2(width, lineH));
        const bool hovered = ImGui::IsItemHovered();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec4 bg = hovered
            ? detail::Mix(col::PanelSoft, col::Accent, 0.07f)
            : col::PanelSoft;
        dl->AddRectFilled(p, ImVec2(p.x + width, p.y + lineH),
                          detail::ColorAlpha(bg, 0.68f), 5.0f);
        dl->AddRect(p, ImVec2(p.x + width, p.y + lineH),
                    detail::ColorAlpha(col::Header, hovered ? 0.13f : 0.065f), 5.0f);
        dl->AddRectFilled(p, ImVec2(p.x + 3.0f, p.y + lineH),
                          detail::ColorAlpha(d.hwidWarning.empty() ? col::Accent : col::Yellow, 0.90f),
                          5.0f, ImDrawFlags_RoundCornersLeft);
        dl->AddText(ImVec2(p.x + 16.0f, p.y + 12.0f),
                    ImGui::GetColorU32(d.hwidWarning.empty() ? col::Header : col::Yellow),
                    hwidLine.c_str());

        if (!d.hwid.empty() && hovered) {
            ImGui::SetTooltip("%s\nClique para copiar", d.hwid.c_str());
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                ImGui::SetClipboardText(d.hwid.c_str());
        }
    }

    ImGui::Spacing();

    if (ImGui::BeginTable("##dashboard-overview-grid", 2,
                          ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("system", ImGuiTableColumnFlags_WidthStretch, 0.54f);
        ImGui::TableSetupColumn("services", ImGuiTableColumnFlags_WidthStretch, 0.46f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();

        detail::BeginPanel("##dashboard-system", "System fingerprint", 236.0f);
        if (ImGui::SmallButton("Inspecionar##system"))
            d.activePage = 7;
        ImGui::Spacing();
        if (ImGui::BeginTable("##system-fingerprint-grid", 3,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-device", "DEVICE", d.device.empty() ? "-" : d.device);
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-os", "OS", d.osVersion.empty() ? "-" : d.osVersion);
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-mode", "BOOT", d.biosMode.empty() ? "-" : d.biosMode);
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-boot", "PC LIGADO EM", d.boot.empty() ? "-" : d.boot);
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-explorer", "EXPLORER", d.explorer.empty() ? "-" : d.explorer);
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-type", "SYSTEM TYPE", d.sysType.empty() ? "-" : d.sysType);
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-bios", "BIOS", d.biosVersion.empty() ? "-" : d.biosVersion);
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-pagefile", "PAGEFILE", d.pagefile.empty() ? "-" : d.pagefile);
            ImGui::TableNextColumn(); detail::SummaryCell("##fp-boot-mode", "FIRMWARE", d.biosMode.empty() ? "-" : d.biosMode);
            ImGui::EndTable();
        }
        detail::EndPanel();

        ImGui::TableNextColumn();
        detail::BeginPanel("##dashboard-services", "Service health", 236.0f);
        if (ImGui::SmallButton("Inspecionar##services"))
            d.activePage = 8;
        ImGui::SameLine();
        ImGui::TextColored(stoppedServices ? col::Red : col::Green,
                           stoppedServices ? "%d services stopped" : "All tracked services are responding", stoppedServices);
        if (restartedServices > 0) {
            ImGui::SameLine();
            ImGui::TextColored(col::Yellow, "%d restarted", restartedServices);
        }
        ImGui::Spacing();
        const char* wanted[] = { "PcaSvc", "DPS", "DiagTrack", "SysMain", "Sysmon", "EventLog", "PlugPlay", "TPM 2.0" };
        if (ImGui::BeginTable("##dashboard-service-grid", 4,
                              ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoHostExtendX)) {
            int cellId = 0;
            for (const char* name : wanted) {
                const ServiceStatus* found = nullptr;
                for (const auto& service : d.services) {
                    if (service.name == name) { found = &service; break; }
                }
                if (!found) continue;
                ImGui::TableNextColumn();
                ServiceStatus label = *found;
                if (label.name == "PlugPlay")
                    label.name = "Plug And Play";
                detail::ServiceCell(label, cellId++);
            }
            ImGui::EndTable();
        }
        detail::EndPanel();
        ImGui::EndTable();
    }

    ImGui::Spacing();

    if (ImGui::BeginTable("##dashboard-main-grid", 2, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("left", ImGuiTableColumnFlags_WidthStretch, 0.56f);
        ImGui::TableSetupColumn("right", ImGuiTableColumnFlags_WidthStretch, 0.44f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();

        detail::BeginPanel("##dashboard-modules", "Investigation modules", 386.0f);
        if (ImGui::BeginTable("##module-grid", 2, ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            detail::ModuleCard(d, "##module-efi", 2, "EFI Cheat Detect", d.efiCheatStatus,
                               (int)d.efiCheats.size(), "Boot loaders, EFI paths and unsigned artifacts", "run!pg2", 144.0f);
            ImGui::TableNextColumn();
            detail::ModuleCard(d, "##module-driver-int", 3, "Driver & Kernel Integrity", driverStatus,
                               driverFindings, "Loaded drivers, signatures, hooks and callbacks", "run!pg3", 144.0f);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            detail::ModuleCard(d, "##module-emulator", 6, "Emu Check", d.emulatorStatus,
                               (int)d.emulatorFindings.size(), emulatorTime.c_str(), nullptr, 144.0f);
            ImGui::EndTable();
        }
        detail::EndPanel();

        ImGui::TableNextColumn();
        detail::BeginPanel("##dashboard-evidence", "Recent evidence", 386.0f);
        int rows = 0;
        auto addRow = [&](const char* source, const std::string& main, const std::string& info, const ImVec4& color) {
            if (rows >= 7) return;
            detail::EvidenceRow(("##ev" + std::to_string(rows)).c_str(), source, main, info, color);
            ++rows;
        };
        for (const auto& e : d.bam)
            addRow("BAM", detail::FileNameFromPath(e.path), e.reason + "  " + e.detail, e.suspicious ? col::Red : col::Yellow);
        for (const auto& e : d.prefetch)
            addRow("PREF", e.file, e.severity + "  " + e.note, col::Yellow);
        for (const auto& e : d.systemMemoryFindings)
            addRow("WIN", e.process, e.type + "  " + e.detail, detail::StatusColor(e.severity));
        for (const auto& e : d.genericBypass)
            addRow("BYPASS", e.process.empty() ? e.type : e.process, e.target + "  " + e.detail, detail::StatusColor(e.severity));
        for (const auto& e : d.streamModFindings)
            addRow("STREAM", e.process.empty() ? e.type : e.process, e.target + "  " + e.detail, detail::StatusColor(e.severity));
        for (const auto& e : d.remotePortFindings)
            addRow("PORT", e.process.empty() ? e.port : e.process, e.reason + "  " + e.detail, detail::StatusColor(e.severity));
        for (const auto& e : d.registryFindings)
            addRow("REG", e.value.empty() ? e.key : e.value, e.reason + "  " + e.detail, detail::StatusColor(e.severity));
        for (const auto& e : d.clsidFindings)
            addRow("CLSID", e.friendlyName.empty() ? e.clsid : e.friendlyName, e.reason + "  " + e.detail, detail::StatusColor(e.severity));
        if (rows == 0) {
            ImGui::Dummy(ImVec2(0.0f, 54.0f));
            ImGui::TextColored(col::Green, "Nenhuma evidencia relevante no momento");
            ImGui::TextColored(col::TextDim, "Os detalhes aparecem aqui conforme o scan encontra sinais.");
        }
        detail::EndPanel();
        ImGui::EndTable();
    }

    ImGui::Spacing();
    DrawSysmon(d, true);
}




inline void DrawServices(ScanData& d) {
    detail::BeginPanel("##services", "Services", 164.0f);
    ImGui::TextColored(col::TextDim, "PC LIGADO EM");
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextColored(col::Header, "%s", d.boot.empty() ? "-" : d.boot.c_str());
    ImGui::Spacing();
    const char* wanted[] = {
        "PcaSvc", "DPS", "DiagTrack", "SysMain", "Sysmon", "EventLog",
        "PlugPlay", "TPM 2.0"
    };

    if (ImGui::BeginTable("##services-row", 8, ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoHostExtendX)) {
        int cellId = 0;
        for (const char* name : wanted) {
            const ServiceStatus* found = nullptr;
            for (const auto& service : d.services) {
                if (service.name == name) {
                    found = &service;
                    break;
                }
            }

            ImGui::TableNextColumn();
            if (found) {
                ServiceStatus label = *found;
                if (label.name == "PlugPlay")
                    label.name = "Plug And Play";
                detail::ServiceCell(label, cellId++);
            }
        }
        ImGui::EndTable();
    }
    detail::EndPanel();
}

// ───────────────────────────────────────────────────────────────────────────
// Sysmon derived data (lazy, recomputed when sysmonEvents grows or scan resets).
// Severity heuristics live here so the renderer just reads a uint8_t per event.
// ───────────────────────────────────────────────────────────────────────────

struct SysmonProcessAggregate {
    std::string basename;
    std::string fullPath;
    int totalEvents = 0;
    int perEventCount[64] = {};   // indexed by sysmon event id; only 1/6/7/8/10/13/22 used
    uint8_t perEventSeverity[64] = {}; // max severity seen per event id
    uint8_t maxSeverity = 0;
};

namespace detail_sysmon {

inline std::string ToLowerCopy(const std::string& s) {
    std::string out = s;
    for (auto& c : out)
        c = (char)std::tolower((unsigned char)c);
    return out;
}

inline std::string BaseNameOfPathA(const std::string& p) {
    if (p.empty()) return "";
    size_t slash = p.find_last_of("\\/");
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

inline bool ContainsCaseInsensitive(const std::string& hay, const char* needle) {
    return detail::FLow(hay).find(needle) != std::string::npos;
}

inline bool EndsWith(const std::string& s, const char* suffix) {
    size_t n = strlen(suffix);
    if (s.size() < n) return false;
    return _stricmp(s.c_str() + s.size() - n, suffix) == 0;
}

inline bool IsIpv4Literal(const std::string& q) {
    if (q.empty() || q.size() > 15) return false;
    int dots = 0, run = 0;
    for (char c : q) {
        if (c == '.') {
            if (run == 0 || run > 3) return false;
            ++dots; run = 0;
        } else if (c >= '0' && c <= '9') {
            ++run;
        } else {
            return false;
        }
    }
    return dots == 3 && run > 0 && run <= 3;
}

inline uint32_t MinuteFromHms(const std::string& time) {
    // Expect "HH:MM:SS" — fall back to 0.
    if (time.size() < 5) return 0;
    int hh = (time[0] - '0') * 10 + (time[1] - '0');
    int mm = (time[3] - '0') * 10 + (time[4] - '0');
    if (hh < 0 || hh > 23 || mm < 0 || mm > 59) return 0;
    return (uint32_t)(hh * 60 + mm);
}

inline uint8_t ScoreSeverity(const SysmonEvent& e) {
    auto contains = [](const std::string& s, const char* needle) {
        return detail::FLow(s).find(needle) != std::string::npos;
    };
    switch (e.eventId) {
        case 8:
            return 2; // CreateRemoteThread — always elevate
        case 10: {
            if (contains(e.access, "0x1f0fff") || contains(e.access, "0x1fffff") ||
                contains(e.access, "vm_write") || contains(e.access, "create_thread"))
                return 2;
            if (contains(e.callTrace, "unknown("))
                return 2;
            return 0;
        }
        case 1: {
            if (contains(e.commandLine, "-enc") || contains(e.commandLine, "-w hidden") ||
                contains(e.commandLine, "iex") || contains(e.commandLine, "downloadstring") ||
                contains(e.commandLine, "frombase64string"))
                return 2;
            static const char* kShells[] = {
                "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe", nullptr
            };
            std::string parentBn = ToLowerCopy(BaseNameOfPathA(e.parentProcess));
            std::string childBn  = ToLowerCopy(BaseNameOfPathA(e.process));
            bool parentShell = false, childShell = false;
            for (int i = 0; kShells[i]; ++i) {
                if (parentBn == kShells[i]) parentShell = true;
                if (childBn  == kShells[i]) childShell  = true;
            }
            if (parentShell && childShell)
                return 1;
            return 0;
        }
        case 22: {
            if (IsIpv4Literal(e.queryName))
                return 1;
            std::string q = ToLowerCopy(e.queryName);
            const char* kSusTlds[] = { ".onion", ".xyz", ".top", ".ru", ".cn", nullptr };
            for (int i = 0; kSusTlds[i]; ++i)
                if (EndsWith(q, kSusTlds[i])) return 1;
            return 0;
        }
        case 13: {
            if (contains(e.registryObject, "\\run\\") ||
                contains(e.registryObject, "\\runonce\\") ||
                contains(e.registryObject, "image file execution options") ||
                contains(e.registryObject, "appinit_dlls"))
                return 1;
            return 0;
        }
        case 6:
        case 7: {
            std::string p = ToLowerCopy(e.imageLoaded);
            if (p.empty()) return 0;
            bool inSystem  = p.find("c:\\windows\\") != std::string::npos;
            bool inProgram = p.find("c:\\program files") != std::string::npos;
            if (!inSystem && !inProgram)
                return 1;
            return 0;
        }
    }
    return 0;
}

} // namespace detail_sysmon

inline void ComputeSysmonDerived(ScanData& d) {
    const size_t n = d.sysmonEvents.size();
    if (d.sysmonDerivedReady &&
        d.sysmonEventMinute.size() == n &&
        d.sysmonEventSeverity.size() == n)
        return;
    d.sysmonEventMinute.assign(n, 0);
    d.sysmonEventSeverity.assign(n, 0);
    for (size_t i = 0; i < n; ++i) {
        const auto& e = d.sysmonEvents[i];
        d.sysmonEventMinute[i]   = detail_sysmon::MinuteFromHms(e.time);
        d.sysmonEventSeverity[i] = detail_sysmon::ScoreSeverity(e);
    }
    d.sysmonDerivedReady = true;
}

// Builds the per-process aggregate table sorted by total events desc, max severity tiebreak.
inline std::vector<SysmonProcessAggregate> BuildSysmonProcessAggregates(const ScanData& d) {
    std::unordered_map<std::string, SysmonProcessAggregate> bag;
    bag.reserve(64);
    for (size_t i = 0; i < d.sysmonEvents.size(); ++i) {
        const auto& e = d.sysmonEvents[i];
        // Prefer sourceProcess when set (events 8/10), else process.
        std::string full = e.sourceProcess.empty() ? e.process : e.sourceProcess;
        if (full.empty()) continue;
        std::string base = detail_sysmon::BaseNameOfPathA(full);
        std::string key  = detail_sysmon::ToLowerCopy(base);
        auto it = bag.find(key);
        if (it == bag.end()) {
            SysmonProcessAggregate agg;
            agg.basename = base;
            agg.fullPath = full;
            it = bag.emplace(key, std::move(agg)).first;
        }
        auto& agg = it->second;
        ++agg.totalEvents;
        if (e.eventId >= 0 && e.eventId < 64) {
            ++agg.perEventCount[e.eventId];
            uint8_t s = (i < d.sysmonEventSeverity.size()) ? d.sysmonEventSeverity[i] : 0;
            if (s > agg.perEventSeverity[e.eventId])
                agg.perEventSeverity[e.eventId] = s;
            if (s > agg.maxSeverity) agg.maxSeverity = s;
        }
    }
    std::vector<SysmonProcessAggregate> out;
    out.reserve(bag.size());
    for (auto& kv : bag) out.push_back(std::move(kv.second));
    std::sort(out.begin(), out.end(),
              [](const SysmonProcessAggregate& a, const SysmonProcessAggregate& b){
                  if (a.maxSeverity != b.maxSeverity) return a.maxSeverity > b.maxSeverity;
                  return a.totalEvents > b.totalEvents;
              });
    return out;
}

inline ImVec4 SysmonSeverityColor(uint8_t sev) {
    switch (sev) {
        case 2: return col::Red;
        case 1: return col::Yellow;
        default: return col::Green;
    }
}

// Renders the body that used to live inline in the legacy per-event card.
// Called both from Flat mode (preserves layout) and Triage mode (inside the
// expanded-row container). `sevColor` drives the badge color so the same body
// reads green/yellow/red based on heuristics instead of always red.
inline void DrawSysmonExpandedBody(const ScanData& d, size_t i, const ImVec4& sevColor) {
    const auto& e = d.sysmonEvents[i];
    if (e.eventId == 10) {
        if (ImGui::BeginTable(("##sysmon-e10-all" + std::to_string(i)).c_str(), 4,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("when",   ImGuiTableColumnFlags_WidthStretch, 0.26f);
            ImGui::TableSetupColumn("source", ImGuiTableColumnFlags_WidthStretch, 0.27f);
            ImGui::TableSetupColumn("target", ImGuiTableColumnFlags_WidthStretch, 0.27f);
            ImGui::TableSetupColumn("access", ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "WHEN");
            ImGui::TextColored(col::Header, "%s  %s", e.date.c_str(), e.time.c_str());

            std::string srcPath = e.sourceProcess.empty() ? e.process : e.sourceProcess;
            ImGui::TableNextColumn();
            detail::ProcessLink("SOURCE", srcPath, ("sysmon-src" + std::to_string(i)).c_str());

            ImGui::TableNextColumn();
            detail::ProcessLink("TARGET", e.targetProcess, ("sysmon-tgt" + std::to_string(i)).c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "ACCESS");
            detail::StatusBadge(e.access.empty() ? "-" : e.access.c_str(), sevColor);
            ImGui::EndTable();
        }
        ImGui::Spacing();
        ImGui::TextColored(col::TextDim, "CALLTRACE");
        std::string ct = e.callTrace.empty() ? "-" : e.callTrace;
        std::string ctShort = detail::CompactText(ct, 120);
        ImGui::TextColored(col::Text, "%s", ctShort.c_str());
        if (ctShort != ct && ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", ct.c_str());
    } else if (ImGui::BeginTable(("##sysmon-card-grid" + std::to_string(i)).c_str(), 4,
                          ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("when",    ImGuiTableColumnFlags_WidthStretch, 0.18f);
        ImGui::TableSetupColumn("id",      ImGuiTableColumnFlags_WidthStretch, 0.10f);
        ImGui::TableSetupColumn("type",    ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("detail",  ImGuiTableColumnFlags_WidthStretch, 0.50f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "WHEN");
        ImGui::TextColored(col::Header, "%s  %s", e.date.c_str(), e.time.c_str());

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "ID");
        detail::StatusBadge(std::to_string(e.eventId).c_str(), sevColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "TYPE");
        ImGui::TextColored(col::Header, "%s", detail::CompactText(e.type, 34).c_str());

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "DETAIL");
        detail::ProcessLink("PROCESS", e.process, ("sysmon-process" + std::to_string(i)).c_str());
        detail::WrappedValue("INFO", e.detail, col::Text);

        ImGui::EndTable();
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Triage view — process-centric + timeline + compact rows with inline expand.
// Reachable via the [Triage]/[Flat] toggle in Zone A. Flat mode falls through
// to the legacy code path below this function.
// ───────────────────────────────────────────────────────────────────────────
inline void DrawSysmonTriage(ScanData& d, bool showInspectButton) {
    ComputeSysmonDerived(d);

    constexpr int kBuckets = 60;
    const size_t n = d.sysmonEvents.size();

    // ── histogram buckets (computed per frame; n is at most a few thousand) ──
    uint32_t minMinute = 0, maxMinute = 0;
    bool haveAny = false;
    for (size_t i = 0; i < n; ++i) {
        uint32_t m = d.sysmonEventMinute[i];
        if (!haveAny) { minMinute = maxMinute = m; haveAny = true; }
        else { if (m < minMinute) minMinute = m; if (m > maxMinute) maxMinute = m; }
    }
    if (maxMinute == minMinute) maxMinute = minMinute + 1;
    const uint32_t span = maxMinute - minMinute + 1;
    int      bucketCount[kBuckets] = {};
    uint8_t  bucketSev[kBuckets]   = {};
    auto bucketOf = [&](uint32_t m) -> int {
        if (span == 0) return 0;
        uint64_t b = ((uint64_t)(m - minMinute) * kBuckets) / span;
        if (b >= (uint64_t)kBuckets) b = kBuckets - 1;
        return (int)b;
    };
    int maxBucket = 0;
    for (size_t i = 0; i < n; ++i) {
        int b = bucketOf(d.sysmonEventMinute[i]);
        ++bucketCount[b];
        uint8_t s = d.sysmonEventSeverity[i];
        if (s > bucketSev[b]) bucketSev[b] = s;
        if (bucketCount[b] > maxBucket) maxBucket = bucketCount[b];
    }

    // ── process aggregates ──
    std::vector<SysmonProcessAggregate> procs = BuildSysmonProcessAggregates(d);

    // ── visible filter ──
    auto lower = [](std::string text) {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return (char)std::tolower(c);
        });
        return text;
    };
    static const int kEventIds[] = { 0, 1, 6, 7, 8, 10, 13, 22 };
    int eventFilter = (d.sysmonEventFilter >= 0 && d.sysmonEventFilter < (int)IM_ARRAYSIZE(kEventIds))
                      ? kEventIds[d.sysmonEventFilter] : 0;
    std::string textNeedle = lower(d.sysmonTextFilter);
    std::string procNeedle = lower(d.sysmonProcessFilter);

    std::vector<size_t> visible;
    visible.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const auto& e = d.sysmonEvents[i];
        if (eventFilter != 0 && e.eventId != eventFilter) continue;
        if (d.sysmonTimeBucket >= 0 && bucketOf(d.sysmonEventMinute[i]) != d.sysmonTimeBucket) continue;
        if (!procNeedle.empty()) {
            std::string src = e.sourceProcess.empty() ? e.process : e.sourceProcess;
            std::string bn = lower(detail_sysmon::BaseNameOfPathA(src));
            if (bn != procNeedle) continue;
        }
        if (!textNeedle.empty()) {
            std::string hay = lower(e.type + " " + e.process + " " + e.detail + " " +
                                    e.sourceProcess + " " + e.targetProcess + " " + e.access + " " +
                                    e.callTrace + " " + e.parentProcess + " " + e.commandLine + " " +
                                    e.user + " " + e.imageLoaded + " " + e.registryObject + " " +
                                    e.queryName + " " + e.startAddress + " " + e.date + " " + e.time);
            if (hay.find(textNeedle) == std::string::npos) continue;
        }
        visible.push_back(i);
    }

    // ── panel ──
    const float zoneA = 36.0f;
    const float zoneB = n == 0 ? 0.0f : 60.0f;
    const float zoneC = procs.empty() ? 0.0f : 88.0f;
    const float zoneD = 38.0f;
    const float listH = 420.0f;
    const float panelH = 96.0f + zoneA + zoneB + zoneC + zoneD + listH;
    detail::BeginPanel("##sysmon", "Sysmon", panelH);

    ImVec4 statusColor = d.sysmonEvents.empty() ? col::TextDim : col::Green;
    if (d.sysmonStatus.find("unavailable") != std::string::npos) statusColor = col::Yellow;

    if (showInspectButton) {
        if (ImGui::SmallButton("Inspecionar##sysmon-triage"))
            d.activePage = 9;
        ImGui::SameLine();
    }

    // ── Zone A: status row + mode toggle ──
    ImGui::TextColored(col::TextDim, "STATUS");
    ImGui::SameLine();
    ImGui::TextColored(statusColor, "%s", d.sysmonStatus.c_str());
    ImGui::SameLine(0.0f, 22.0f);
    ImGui::TextColored(col::TextDim, "EVENTS");
    ImGui::SameLine();
    detail::StatusBadge(std::to_string((int)n).c_str(), statusColor);
    ImGui::SameLine(0.0f, 22.0f);
    ImGui::TextColored(col::TextDim, "SHOWING");
    ImGui::SameLine();
    detail::StatusBadge((std::to_string((int)visible.size()) + " / " + std::to_string((int)n)).c_str(), statusColor);

    {
        const float btnW = 64.0f;
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - btnW * 2.0f - 6.0f + ImGui::GetCursorPosX() - ImGui::GetCursorPosX());
        ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - btnW * 2.0f - 6.0f);
        const bool triageActive = d.sysmonViewMode == 0;
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImGui::GetColorU32(triageActive ? col::Accent : col::PanelSoft));
        if (ImGui::SmallButton("Triage##sm-mode")) d.sysmonViewMode = 0;
        ImGui::PopStyleColor();
        ImGui::SameLine(0.0f, 4.0f);
        ImGui::PushStyleColor(ImGuiCol_Button,
                              ImGui::GetColorU32(!triageActive ? col::Accent : col::PanelSoft));
        if (ImGui::SmallButton("Flat##sm-mode")) d.sysmonViewMode = 1;
        ImGui::PopStyleColor();
    }
    ImGui::Spacing();

    // ── Zone B: time histogram ──
    if (n > 0) {
        const ImVec2 histMin = ImGui::GetCursorScreenPos();
        const float histW = ImGui::GetContentRegionAvail().x;
        const float histH = 54.0f;
        const ImVec2 histMax(histMin.x + histW, histMin.y + histH);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(histMin, histMax, ImGui::GetColorU32(col::PanelSoft), 4.0f);
        const float barW = histW / (float)kBuckets;
        ImGui::InvisibleButton("##sm-hist", ImVec2(histW, histH));
        const bool histHovered = ImGui::IsItemHovered();
        const ImVec2 mp = ImGui::GetIO().MousePos;
        int hoverBucket = -1;
        if (histHovered) {
            int hb = (int)((mp.x - histMin.x) / barW);
            if (hb >= 0 && hb < kBuckets) hoverBucket = hb;
        }
        const float maxH = histH - 8.0f;
        const double logMax = std::log((double)maxBucket + 1.0);
        for (int b = 0; b < kBuckets; ++b) {
            if (bucketCount[b] == 0 && b != d.sysmonTimeBucket && b != hoverBucket) continue;
            float ratio = (logMax > 0.0)
                          ? (float)(std::log((double)bucketCount[b] + 1.0) / logMax)
                          : 0.0f;
            float bh = (bucketCount[b] > 0) ? ((ratio * maxH) > 2.0f ? (ratio * maxH) : 2.0f) : 0.0f;
            ImVec2 a(histMin.x + b * barW + 1.0f, histMax.y - bh - 4.0f);
            ImVec2 c(histMin.x + (b + 1) * barW - 1.0f, histMax.y - 4.0f);
            ImVec4 col = SysmonSeverityColor(bucketSev[b]);
            if (bucketCount[b] > 0)
                dl->AddRectFilled(a, c, ImGui::GetColorU32(col), 1.5f);
            if (b == d.sysmonTimeBucket) {
                dl->AddRect(ImVec2(a.x - 1, histMin.y + 2), ImVec2(c.x + 1, histMax.y - 2),
                            ImGui::GetColorU32(col::Accent), 2.0f, 0, 1.5f);
            }
        }
        if (hoverBucket >= 0) {
            uint32_t bm = minMinute + (uint32_t)((uint64_t)hoverBucket * span / kBuckets);
            char buf[64];
            snprintf(buf, sizeof(buf), "%02u:%02u — %d eventos",
                     (unsigned)(bm / 60), (unsigned)(bm % 60), bucketCount[hoverBucket]);
            ImGui::SetTooltip("%s", buf);
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                d.sysmonTimeBucket = (d.sysmonTimeBucket == hoverBucket) ? -1 : hoverBucket;
            }
        }
        ImGui::Spacing();
    }

    // ── Zone C: top offenders (horizontal scroll) ──
    if (!procs.empty()) {
        ImGui::BeginChild("##sm-offenders", ImVec2(0.0f, 76.0f), false,
                          ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        const int shown = (int)(procs.size() < (size_t)8 ? procs.size() : (size_t)8);
        for (int p = 0; p < shown; ++p) {
            const auto& agg = procs[p];
            if (p > 0) ImGui::SameLine(0.0f, 6.0f);
            ImGui::PushID(p);
            const ImVec2 cp = ImGui::GetCursorScreenPos();
            const float w = 230.0f, h = 64.0f;
            ImGui::InvisibleButton("##sm-off-card", ImVec2(w, h));
            const bool cardHover = ImGui::IsItemHovered();
            const bool cardClick = ImGui::IsItemClicked();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            const bool selected = _stricmp(d.sysmonProcessFilter, agg.basename.c_str()) == 0;
            dl->AddRectFilled(cp, ImVec2(cp.x + w, cp.y + h),
                              ImGui::GetColorU32(selected ? col::PanelLift
                                                          : (cardHover ? col::PanelSoft : col::Panel)),
                              4.0f);
            dl->AddRectFilled(cp, ImVec2(cp.x + 4.0f, cp.y + h),
                              ImGui::GetColorU32(SysmonSeverityColor(agg.maxSeverity)), 1.5f);
            std::string bn = detail::CompactText(agg.basename, 24);
            dl->AddText(ImVec2(cp.x + 12.0f, cp.y + 8.0f),
                        ImGui::GetColorU32(col::Header), bn.c_str());
            std::string fp = detail::CompactText(detail::CompactPath(agg.fullPath, 32), 32);
            dl->AddText(ImVec2(cp.x + 12.0f, cp.y + 26.0f),
                        ImGui::GetColorU32(col::TextDim), fp.c_str());
            // event-id chips along the bottom row
            float chipX = cp.x + 12.0f;
            const float chipY = cp.y + 44.0f;
            for (int idIdx = 1; idIdx < (int)IM_ARRAYSIZE(kEventIds); ++idIdx) {
                int id = kEventIds[idIdx];
                int cnt = agg.perEventCount[id];
                if (cnt == 0) continue;
                char buf[24];
                snprintf(buf, sizeof(buf), "%d×%d", id, cnt);
                const ImVec2 ts = ImGui::CalcTextSize(buf);
                const float chipW = ts.x + 10.0f;
                if (chipX + chipW > cp.x + w - 8.0f) break;
                ImVec4 chipCol = SysmonSeverityColor(agg.perEventSeverity[id]);
                dl->AddRectFilled(ImVec2(chipX, chipY),
                                  ImVec2(chipX + chipW, chipY + ts.y + 4.0f),
                                  ImGui::GetColorU32(detail::ColorAlpha(chipCol, 0.18f)), 2.0f);
                dl->AddText(ImVec2(chipX + 5.0f, chipY + 1.0f),
                            ImGui::GetColorU32(chipCol), buf);
                chipX += chipW + 4.0f;
            }
            if (cardHover) {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                ImGui::SetTooltip("%s\n%s", agg.basename.c_str(), agg.fullPath.c_str());
            }
            if (cardClick) {
                if (selected) d.sysmonProcessFilter[0] = '\0';
                else {
                    strncpy_s(d.sysmonProcessFilter, sizeof(d.sysmonProcessFilter),
                              agg.basename.c_str(), _TRUNCATE);
                }
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }

    // ── Zone D: active filter chips + text search ──
    auto drawPill = [](const char* label) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetColorU32(col::PanelLift));
        ImGui::SmallButton(label);
        ImGui::PopStyleColor();
        ImGui::SameLine(0.0f, 2.0f);
    };
    if (d.sysmonProcessFilter[0]) {
        std::string lab = std::string("process: ") + d.sysmonProcessFilter;
        drawPill(lab.c_str());
        if (ImGui::SmallButton("x##sm-pp")) d.sysmonProcessFilter[0] = '\0';
        ImGui::SameLine(0.0f, 8.0f);
    }
    if (eventFilter != 0) {
        std::string lab = std::string("event: ") + std::to_string(eventFilter);
        drawPill(lab.c_str());
        if (ImGui::SmallButton("x##sm-pe")) d.sysmonEventFilter = 0;
        ImGui::SameLine(0.0f, 8.0f);
    }
    if (d.sysmonTimeBucket >= 0) {
        uint32_t bm = minMinute + (uint32_t)((uint64_t)d.sysmonTimeBucket * span / kBuckets);
        char buf[40];
        snprintf(buf, sizeof(buf), "time: %02u:%02u", (unsigned)(bm / 60), (unsigned)(bm % 60));
        drawPill(buf);
        if (ImGui::SmallButton("x##sm-pt")) d.sysmonTimeBucket = -1;
        ImGui::SameLine(0.0f, 8.0f);
    }
    if (d.sysmonTextFilter[0]) {
        std::string lab = std::string("text: ") + d.sysmonTextFilter;
        drawPill(lab.c_str());
        if (ImGui::SmallButton("x##sm-px")) d.sysmonTextFilter[0] = '\0';
        ImGui::SameLine(0.0f, 8.0f);
    }
    {
        const float searchW = 240.0f;
        ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - searchW);
        ImGui::SetNextItemWidth(searchW);
        ImGui::InputTextWithHint("##sm-text", "buscar...", d.sysmonTextFilter, sizeof(d.sysmonTextFilter));
    }
    ImGui::Spacing();

    // ── Zone E: compact event list with clipper + inline expand ──
    ImGui::BeginChild("##sm-list", ImVec2(0.0f, listH), true,
                      ImGuiWindowFlags_AlwaysVerticalScrollbar);
    ImGuiListClipper clipper;
    clipper.Begin((int)visible.size(), 32.0f);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            size_t i = visible[row];
            const auto& e = d.sysmonEvents[i];
            uint8_t sev = d.sysmonEventSeverity[i];
            ImVec4 sevColor = SysmonSeverityColor(sev);
            const bool expanded = (int)i == d.sysmonExpandedIdx;
            const float rowH = expanded ? 184.0f : 30.0f;
            ImGui::PushID((int)i);
            const ImVec2 rp = ImGui::GetCursorScreenPos();
            const float rowW = ImGui::GetContentRegionAvail().x;
            ImGui::InvisibleButton("##sm-row-hit", ImVec2(rowW, 28.0f));
            const bool rowHover = ImGui::IsItemHovered();
            const bool rowClick = ImGui::IsItemClicked();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            if (rowHover || expanded) {
                dl->AddRectFilled(rp, ImVec2(rp.x + rowW, rp.y + 28.0f),
                                  ImGui::GetColorU32(detail::ColorAlpha(col::PanelSoft,
                                                                        expanded ? 0.65f : 0.35f)),
                                  3.0f);
            }
            // sev bar
            dl->AddRectFilled(rp, ImVec2(rp.x + 3.0f, rp.y + 28.0f),
                              ImGui::GetColorU32(sevColor), 1.5f);
            // time
            dl->AddText(ImVec2(rp.x + 10.0f, rp.y + 6.0f),
                        ImGui::GetColorU32(col::TextDim), e.time.c_str());
            // event id badge
            char idBuf[8];
            snprintf(idBuf, sizeof(idBuf), "%d", e.eventId);
            const ImVec2 idSize = ImGui::CalcTextSize(idBuf);
            const float badgeX = rp.x + 78.0f;
            dl->AddRectFilled(ImVec2(badgeX, rp.y + 4.0f),
                              ImVec2(badgeX + idSize.x + 12.0f, rp.y + 22.0f),
                              ImGui::GetColorU32(detail::ColorAlpha(sevColor, 0.20f)), 2.0f);
            dl->AddText(ImVec2(badgeX + 6.0f, rp.y + 5.0f),
                        ImGui::GetColorU32(sevColor), idBuf);
            // process basename
            std::string srcPath = e.sourceProcess.empty() ? e.process : e.sourceProcess;
            std::string bn = detail::CompactText(detail_sysmon::BaseNameOfPathA(srcPath), 24);
            dl->AddText(ImVec2(rp.x + 130.0f, rp.y + 6.0f),
                        ImGui::GetColorU32(col::Header), bn.c_str());
            // one-line detail
            std::string detailLine;
            switch (e.eventId) {
                case 10: detailLine = "→ " + detail_sysmon::BaseNameOfPathA(e.targetProcess) +
                                      "  " + e.access; break;
                case 8:  detailLine = "→ " + detail_sysmon::BaseNameOfPathA(e.targetProcess) +
                                      "  start=" + e.startAddress; break;
                case 22: detailLine = e.queryName; break;
                case 13: detailLine = e.registryObject; break;
                case 6:
                case 7:  detailLine = e.imageLoaded; break;
                case 1:  detailLine = e.commandLine; break;
                default: detailLine = e.detail; break;
            }
            detailLine = detail::CompactText(detailLine, 80);
            dl->AddText(ImVec2(rp.x + 290.0f, rp.y + 6.0f),
                        ImGui::GetColorU32(col::Text), detailLine.c_str());
            if (rowHover) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            if (rowClick) d.sysmonExpandedIdx = expanded ? -1 : (int)i;
            // Expanded body — re-uses the legacy renderer.
            if (expanded) {
                ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + 30.0f));
                ImGui::Indent(8.0f);
                DrawSysmonExpandedBody(d, i, sevColor);
                ImGui::Unindent(8.0f);
                ImGui::SetCursorScreenPos(ImVec2(rp.x, rp.y + rowH + 2.0f));
            }
            ImGui::PopID();
        }
    }
    clipper.End();
    ImGui::EndChild();

    detail::EndPanel();
}

inline void DrawSysmon(ScanData& d, bool showInspectButton) {
    if (d.sysmonViewMode == 0) {
        DrawSysmonTriage(d, showInspectButton);
        return;
    }
    ComputeSysmonDerived(d);
    auto lower = [](std::string text) {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return (char)std::tolower(c);
        });
        return text;
    };

    int selectedId = 0;
    static const int eventIds[] = { 0, 1, 6, 7, 8, 10, 13, 22 };
    if (d.sysmonEventFilter >= 0 && d.sysmonEventFilter < (int)(sizeof(eventIds) / sizeof(eventIds[0])))
        selectedId = eventIds[d.sysmonEventFilter];

    std::string filterText = lower(d.sysmonTextFilter);
    std::string accessFilter = lower(d.sysmonAccessFilter);
    std::string sourceFilter = lower(d.sysmonSourceFilter);
    std::string targetFilter = lower(d.sysmonTargetFilter);
    std::string callTraceFilter = lower(d.sysmonCallTraceFilter);
    std::string parentFilter = lower(d.sysmonParentFilter);
    std::string commandFilter = lower(d.sysmonCommandFilter);
    std::string imageFilter = lower(d.sysmonImageFilter);
    std::string userFilter = lower(d.sysmonUserFilter);
    std::string registryFilter = lower(d.sysmonRegistryFilter);
    std::string dnsFilter = lower(d.sysmonDnsFilter);
    std::string startFilter = lower(d.sysmonStartFilter);
    const bool event1Selected = selectedId == 1;
    const bool event6or7Selected = selectedId == 6 || selectedId == 7;
    const bool event8Selected = selectedId == 8;
    const bool event10Selected = selectedId == 10;
    const bool event13Selected = selectedId == 13;
    const bool event22Selected = selectedId == 22;
    std::vector<size_t> visible;
    visible.reserve(d.sysmonEvents.size());
    for (size_t i = 0; i < d.sysmonEvents.size(); ++i) {
        const auto& e = d.sysmonEvents[i];
        if (selectedId != 0 && e.eventId != selectedId)
            continue;

        if (!filterText.empty()) {
            std::string haystack = lower(e.type + " " + e.process + " " + e.detail + " " +
                                         e.sourceProcess + " " + e.targetProcess + " " + e.access + " " +
                                         e.callTrace + " " + e.parentProcess + " " + e.commandLine + " " +
                                         e.user + " " + e.currentDirectory + " " + e.imageLoaded + " " +
                                         e.registryObject + " " + e.queryName + " " + e.startAddress + " " +
                                         e.date + " " + e.time + " " + std::to_string(e.eventId));
            if (haystack.find(filterText) == std::string::npos)
                continue;
        }

        if (event1Selected) {
            if (!imageFilter.empty() && lower(e.process).find(imageFilter) == std::string::npos)
                continue;
            if (!parentFilter.empty() && lower(e.parentProcess).find(parentFilter) == std::string::npos)
                continue;
            if (!commandFilter.empty() && lower(e.commandLine).find(commandFilter) == std::string::npos)
                continue;
            if (!userFilter.empty() && lower(e.user).find(userFilter) == std::string::npos)
                continue;
        }

        if (event6or7Selected) {
            if (!imageFilter.empty() && lower(e.imageLoaded).find(imageFilter) == std::string::npos)
                continue;
            if (!sourceFilter.empty() && lower(e.process).find(sourceFilter) == std::string::npos)
                continue;
        }

        if (event8Selected) {
            if (!sourceFilter.empty() && lower(e.sourceProcess.empty() ? e.process : e.sourceProcess).find(sourceFilter) == std::string::npos)
                continue;
            if (!targetFilter.empty() && lower(e.targetProcess).find(targetFilter) == std::string::npos)
                continue;
            if (!startFilter.empty() && lower(e.startAddress).find(startFilter) == std::string::npos)
                continue;
        }

        if (event10Selected) {
            if (!accessFilter.empty() && lower(e.access).find(accessFilter) == std::string::npos)
                continue;
            if (!sourceFilter.empty() && lower(e.sourceProcess).find(sourceFilter) == std::string::npos)
                continue;
            if (!targetFilter.empty() && lower(e.targetProcess).find(targetFilter) == std::string::npos)
                continue;
            if (!callTraceFilter.empty() && lower(e.callTrace).find(callTraceFilter) == std::string::npos)
                continue;
        }

        if (event13Selected) {
            if (!sourceFilter.empty() && lower(e.process).find(sourceFilter) == std::string::npos)
                continue;
            if (!registryFilter.empty() && lower(e.registryObject).find(registryFilter) == std::string::npos)
                continue;
        }

        if (event22Selected) {
            if (!sourceFilter.empty() && lower(e.process).find(sourceFilter) == std::string::npos)
                continue;
            if (!dnsFilter.empty() && lower(e.queryName).find(dnsFilter) == std::string::npos)
                continue;
        }

        visible.push_back(i);
    }

    const bool hasSpecificFilters = selectedId != 0 && selectedId != 10;
    const float cardH = event10Selected ? 112.0f : 96.0f;
    const float panelContentH = (event10Selected || hasSpecificFilters ? 242.0f : 178.0f) + (float)visible.size() * (cardH + 8.0f);
    const float panelH = panelContentH;
    detail::BeginPanel("##sysmon", "Sysmon", panelH);

    ImVec4 statusColor = d.sysmonEvents.empty() ? col::TextDim : col::Green;
    if (d.sysmonStatus.find("unavailable") != std::string::npos)
        statusColor = col::Yellow;

    if (showInspectButton) {
        if (ImGui::SmallButton("Inspecionar##sysmon"))
            d.activePage = 9;
        ImGui::Spacing();
    }

    if (ImGui::BeginTable("##sysmon-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("events", ImGuiTableColumnFlags_WidthStretch, 0.18f);
        ImGui::TableSetupColumn("ids",    ImGuiTableColumnFlags_WidthStretch, 0.60f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        ImGui::TextColored(statusColor, "%s", d.sysmonStatus.c_str());

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "EVENTS");
        detail::StatusBadge(std::to_string((int)d.sysmonEvents.size()).c_str(), statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "PULLING");
        ImGui::TextColored(col::Header, "1, 6, 7, 8, 10, 13, 22");
        ImGui::EndTable();
    }

    ImGui::Spacing();
    if (ImGui::BeginTable("##sysmon-filters", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("event", ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("text",  ImGuiTableColumnFlags_WidthStretch, 0.58f);
        ImGui::TableSetupColumn("shown", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "EVENT FILTER");
        const char* eventLabels[] = { "All logs", "Event 1", "Event 6", "Event 7", "Event 8", "Event 10", "Event 13", "Event 22" };
        ImGui::SetNextItemWidth(-1);
        ImGui::Combo("##sysmon-event-filter", &d.sysmonEventFilter, eventLabels, IM_ARRAYSIZE(eventLabels));

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SEARCH");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextWithHint("##sysmon-text-filter", "process, access, image, registry, dns...", d.sysmonTextFilter, sizeof(d.sysmonTextFilter));

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SHOWING");
        std::string showing = std::to_string((int)visible.size()) + " / " + std::to_string((int)d.sysmonEvents.size());
        detail::StatusBadge(showing.c_str(), statusColor);

        ImGui::EndTable();
    }

    if (event10Selected) {
        ImGui::Spacing();
        if (ImGui::BeginTable("##sysmon-event10-filters", 4, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("source", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("target", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("access", ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("trace",  ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "SOURCE PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-source-filter", "quem acessou...", d.sysmonSourceFilter, sizeof(d.sysmonSourceFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "TARGET PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-target-filter", "quem foi acessado...", d.sysmonTargetFilter, sizeof(d.sysmonTargetFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "ACCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-access-filter", "0x1410...", d.sysmonAccessFilter, sizeof(d.sysmonAccessFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "CALLTRACE");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-calltrace-filter", "dll, module, offset...", d.sysmonCallTraceFilter, sizeof(d.sysmonCallTraceFilter));

            ImGui::EndTable();
        }
    } else if (event1Selected) {
        ImGui::Spacing();
        if (ImGui::BeginTable("##sysmon-event1-filters", 4, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("image",  ImGuiTableColumnFlags_WidthStretch, 0.25f);
            ImGui::TableSetupColumn("parent", ImGuiTableColumnFlags_WidthStretch, 0.25f);
            ImGui::TableSetupColumn("cmd",    ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableSetupColumn("user",   ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "PROCESS IMAGE");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e1-image-filter", "process path/name...", d.sysmonImageFilter, sizeof(d.sysmonImageFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "PARENT PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e1-parent-filter", "parent path/name...", d.sysmonParentFilter, sizeof(d.sysmonParentFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "COMMAND LINE");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e1-command-filter", "args, flags, path...", d.sysmonCommandFilter, sizeof(d.sysmonCommandFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "USER");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e1-user-filter", "domain\\user...", d.sysmonUserFilter, sizeof(d.sysmonUserFilter));

            ImGui::EndTable();
        }
    } else if (event6or7Selected) {
        ImGui::Spacing();
        if (ImGui::BeginTable("##sysmon-module-filters", 2, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("process", ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableSetupColumn("image",   ImGuiTableColumnFlags_WidthStretch, 0.66f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, selectedId == 6 ? "PROCESS" : "PROCESS IMAGE");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-module-process-filter", "owner process...", d.sysmonSourceFilter, sizeof(d.sysmonSourceFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, selectedId == 6 ? "DRIVER" : "IMAGE LOADED");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-module-image-filter", "driver/module path...", d.sysmonImageFilter, sizeof(d.sysmonImageFilter));

            ImGui::EndTable();
        }
    } else if (event8Selected) {
        ImGui::Spacing();
        if (ImGui::BeginTable("##sysmon-event8-filters", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("source", ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableSetupColumn("target", ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableSetupColumn("start",  ImGuiTableColumnFlags_WidthStretch, 0.32f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "SOURCE PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e8-source-filter", "source process...", d.sysmonSourceFilter, sizeof(d.sysmonSourceFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "TARGET PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e8-target-filter", "target process...", d.sysmonTargetFilter, sizeof(d.sysmonTargetFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "START ADDRESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e8-start-filter", "0x...", d.sysmonStartFilter, sizeof(d.sysmonStartFilter));

            ImGui::EndTable();
        }
    } else if (event13Selected) {
        ImGui::Spacing();
        if (ImGui::BeginTable("##sysmon-event13-filters", 2, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("process", ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableSetupColumn("registry", ImGuiTableColumnFlags_WidthStretch, 0.66f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e13-process-filter", "process path/name...", d.sysmonSourceFilter, sizeof(d.sysmonSourceFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "REGISTRY OBJECT");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e13-registry-filter", "key/value...", d.sysmonRegistryFilter, sizeof(d.sysmonRegistryFilter));

            ImGui::EndTable();
        }
    } else if (event22Selected) {
        ImGui::Spacing();
        if (ImGui::BeginTable("##sysmon-event22-filters", 2, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("process", ImGuiTableColumnFlags_WidthStretch, 0.34f);
            ImGui::TableSetupColumn("dns",     ImGuiTableColumnFlags_WidthStretch, 0.66f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "PROCESS");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e22-process-filter", "process path/name...", d.sysmonSourceFilter, sizeof(d.sysmonSourceFilter));

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DNS QUERY");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##sysmon-e22-dns-filter", "domain...", d.sysmonDnsFilter, sizeof(d.sysmonDnsFilter));

            ImGui::EndTable();
        }
    }

    ImGui::Spacing();
    for (size_t row = 0; row < visible.size(); ++row) {
        size_t i = visible[row];
        uint8_t sev = (i < d.sysmonEventSeverity.size()) ? d.sysmonEventSeverity[i] : 0;
        ImVec4 sevColor = SysmonSeverityColor(sev);
        detail::BeginResultCard(("##sysmon-card" + std::to_string(i)).c_str(), cardH, sevColor);
        DrawSysmonExpandedBody(d, i, sevColor);
        detail::EndResultCard();
        ImGui::Spacing();
    }

    detail::EndPanel();
}

inline void DrawHwid(ScanData& d) {
    detail::BeginPanel("##hwid", "HWID", 112.0f);

    ImGui::TextColored(col::TextDim, "FINGERPRINT");

    std::string shownHwid = detail::CompactText(d.hwid, 118);
    ImGui::TextColored(col::Header, "%s", shownHwid.c_str());
    if (!d.hwid.empty() && ImGui::IsItemHovered()) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::SetTooltip("%s", d.hwid.c_str());
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
            ImGui::SetClipboardText(d.hwid.c_str());
    }

    detail::EndPanel();
}

inline void DrawSystem(ScanData& d) {
    detail::BeginPanel("##system", "System", 184.0f);
    if (ImGui::BeginTable("##system-grid", 4, ImGuiTableFlags_SizingStretchSame)) {
        ImGui::TableNextColumn(); detail::KeyValueCell("Boot", d.boot);
        ImGui::TableNextColumn(); detail::KeyValueCell("Explorer", d.explorer);
        ImGui::TableNextColumn(); detail::KeyValueCell("BIOS Version/Date", d.biosVersion);
        ImGui::TableNextColumn(); detail::KeyValueCell("BIOS Mode", d.biosMode);
        ImGui::TableNextColumn(); detail::KeyValueCell("Version OS", d.osVersion);
        ImGui::TableNextColumn(); detail::KeyValueCell("Device", d.device);
        ImGui::TableNextColumn(); detail::KeyValueCell("Pagination File", d.pagefile);
        ImGui::TableNextColumn(); detail::KeyValueCell("System Type", d.sysType);
        ImGui::EndTable();
    }
    detail::EndPanel();
}

inline void DrawInspectToolbar(ScanData& d, const char* title) {
    if (ImGui::Button("< Voltar"))
        d.activePage = 1;
    ImGui::SameLine(0.0f, 14.0f);
    ImGui::TextColored(col::Header, "Inspecionando: %s", title);

    const float controlsWidth = 190.0f;
    ImGui::SameLine(ImGui::GetWindowWidth() - controlsWidth);
    if (ImGui::Button("-##inspect-zoom")) {
        d.inspectZoom -= 0.10f;
        if (d.inspectZoom < 1.0f)
            d.inspectZoom = 1.0f;
    }
    ImGui::SameLine();
    ImGui::TextColored(col::TextDim, "%d%%", (int)(d.inspectZoom * 100.0f + 0.5f));
    ImGui::SameLine();
    if (ImGui::Button("+##inspect-zoom")) {
        d.inspectZoom += 0.10f;
        if (d.inspectZoom > 1.8f)
            d.inspectZoom = 1.8f;
    }
    ImGui::SameLine();
    if (ImGui::Button("100%##inspect-reset"))
        d.inspectZoom = 1.0f;

    ImGui::Separator();
    ImGui::Spacing();
}

inline void DrawSystemInspector(ScanData& d) {
    DrawInspectToolbar(d, "Sistema");
    ImGui::SetWindowFontScale(d.inspectZoom);

    ImGui::TextColored(col::Header, "System fingerprint");
    ImGui::TextColored(col::TextDim, "Informacoes completas do computador e da inicializacao.");
    ImGui::Spacing();

    if (ImGui::BeginTable("##inspect-system-grid", 2,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                          ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("label", ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableSetupColumn("value", ImGuiTableColumnFlags_WidthStretch, 0.76f);
        auto row = [](const char* label, const std::string& value) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "%s", label);
            ImGui::TableNextColumn();
            ImGui::TextColored(col::Header, "%s", value.empty() ? "-" : value.c_str());
        };
        row("DEVICE", d.device);
        row("OS", d.osVersion);
        row("PC LIGADO EM", d.boot);
        row("EXPLORER INICIADO EM", d.explorer);
        row("BIOS", d.biosVersion);
        row("FIRMWARE", d.biosMode);
        row("SYSTEM TYPE", d.sysType);
        row("PAGEFILE", d.pagefile);
        row("HWID", d.hwid);
        ImGui::EndTable();
    }

    ImGui::SetWindowFontScale(1.0f);
}

inline void DrawServicesInspector(ScanData& d) {
    DrawInspectToolbar(d, "Servicos");
    ImGui::SetWindowFontScale(d.inspectZoom);

    ImGui::TextColored(col::Header, "Service health");
    ImGui::TextColored(col::TextDim, "Estado, reinicializacao e detalhes de cada servico monitorado.");
    ImGui::Spacing();

    if (ImGui::BeginTable("##inspect-services-grid", 3,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                          ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("service", ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("state", ImGuiTableColumnFlags_WidthStretch, 0.18f);
        ImGui::TableSetupColumn("detail", ImGuiTableColumnFlags_WidthStretch, 0.60f);
        ImGui::TableHeadersRow();
        for (const auto& service : d.services) {
            const ImVec4 stateColor = !service.ok ? col::Red : (service.restarted ? col::Yellow : col::Green);
            const char* state = !service.ok ? "STOPPED" : (service.restarted ? "RESTARTED" : "OK");
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(col::Header, "%s", service.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextColored(stateColor, "%s", state);
            ImGui::TableNextColumn();
            ImGui::TextColored(col::Text, "%s", service.note.empty() ? "-" : service.note.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::SetWindowFontScale(1.0f);
}

inline void DrawSysmonInspector(ScanData& d) {
    DrawInspectToolbar(d, "Sysmon");
    ImGui::SetWindowFontScale(d.inspectZoom);
    DrawSysmon(d, false);
    ImGui::SetWindowFontScale(1.0f);
}

inline void DrawBam(ScanData& d) {
    const float cardH = 78.0f;
    const float panelH = 138.0f + (float)d.bam.size() * cardH;
    detail::BeginPanel("##bam", "BAM", panelH);
    ImGui::TextColored(col::Red, "Unsigned apps and deleted-after-boot entries");
    ImGui::SameLine();
    ImGui::TextColored(col::TextDim, "%d entries", (int)d.bam.size());
    ImGui::Spacing();
    detail::FilterBar("##bam-s", d.bamFilter, sizeof(d.bamFilter),
                      "##bam-reason", &d.bamReasonFilter, "ALL\0UNSIGNED\0DELETED\0REPLACED\0", 4,
                      "Limpar##bam", "Buscar por path ou detail");
    ImGui::Spacing();
    { const std::string needle = detail::FLow(std::string(d.bamFilter));
    for (size_t i = 0; i < d.bam.size(); ++i) {
        const auto& e = d.bam[i];
        if (d.bamReasonFilter == 1 && e.reason != "UNSIGNED")  continue;
        if (d.bamReasonFilter == 2 && e.reason != "DELETED")   continue;
        if (d.bamReasonFilter == 3 && e.reason != "REPLACED")  continue;
        if (!detail::FMatch(needle, { e.path, e.reason, e.detail, e.pathClass })) continue;
        ImVec4 accent = e.suspicious ? col::Red : col::Green;
        detail::BeginFlatResultRow(("##bam-row" + std::to_string(i)).c_str(), cardH);
        if (ImGui::BeginTable(("##bam-card-grid" + std::to_string(i)).c_str(), 4,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("when", ImGuiTableColumnFlags_WidthStretch, 0.18f);
            ImGui::TableSetupColumn("path", ImGuiTableColumnFlags_WidthStretch, 0.52f);
            ImGui::TableSetupColumn("result", ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableSetupColumn("open", ImGuiTableColumnFlags_WidthStretch, 0.08f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "WHEN");
            ImGui::TextColored(col::Header, "%s  %s", e.date.c_str(), e.time.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "EXECUTABLE");
            std::string path = detail::CompactPath(e.path, 120);
            ImGui::TextColored(col::Header, "%s", path.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", e.path.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "RESULT");
            detail::StatusBadge(e.reason.empty() ? (e.suspicious ? "FLAG" : "OK") : e.reason.c_str(), accent);
            if (!e.detail.empty()) {
                std::string compact = detail::CompactText(e.detail, 26);
                ImGui::TextColored(col::TextDim, "%s", compact.c_str());
                std::string tooltip = e.detail;
                if (!e.pathClass.empty())
                    tooltip += " | path_class=" + e.pathClass;
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", tooltip.c_str());
            } else if (!e.pathClass.empty()) {
                ImGui::TextColored(col::TextDim, "%s", e.pathClass.c_str());
            }

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "OPEN");
            ImGui::PushID((int)i);
            if (detail::FolderButton("##bamopen")) {
                std::string cmd = "explorer /select,\"" + e.path + "\"";
                system(cmd.c_str());
            }
            ImGui::PopID();
            ImGui::EndTable();
        }
        detail::EndFlatResultRow();
    } }
    detail::EndPanel();
}

inline void DrawPrefetch(ScanData& d) {
    const float cardH = 92.0f;
    const float panelH = 112.0f + (float)d.prefetch.size() * (cardH + 8.0f);
    detail::BeginPanel("##prefetch", "Prefetch", panelH);
    if (d.prefetchHits > 0)
        ImGui::TextColored(col::Red, "%d hidden prefetch mismatch(es)", d.prefetchHits);
    else
        ImGui::TextColored(col::Green, "No hidden prefetch mismatches");
    ImGui::Spacing();

    for (size_t i = 0; i < d.prefetch.size(); ++i) {
        const auto& p = d.prefetch[i];
        detail::BeginResultCard(("##prefetch-card" + std::to_string(i)).c_str(), cardH, col::Yellow);
        if (ImGui::BeginTable(("##prefetch-card-grid" + std::to_string(i)).c_str(), 4,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("when", ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("file", ImGuiTableColumnFlags_WidthStretch, 0.40f);
            ImGui::TableSetupColumn("detect", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("level", ImGuiTableColumnFlags_WidthStretch, 0.12f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "WHEN");
            ImGui::TextColored(col::Header, "%s  %s", p.date.c_str(), p.time.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "PREFETCH FILE");
            std::string file = detail::CompactText(p.file, 82);
            ImGui::TextColored(col::Header, "%s", file.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", p.file.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DETECT");
            std::string note = detail::CompactText(p.note, 62);
            ImGui::TextColored(col::Text, "%s", note.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s | %s", p.alias.c_str(), p.note.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(p.severity.c_str(), col::Yellow);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    }
    detail::EndPanel();
}

inline void DrawUsn(ScanData& d) {
    bool hasAnomalies = !d.usnAnomalies.empty();
    const float cardH = 96.0f;
    const float panelH = hasAnomalies
        ? 124.0f + (float)d.usnAnomalies.size() * (cardH + 8.0f)
        : 124.0f;

    detail::BeginPanel("##usn", "USN Journal", panelH);

    bool hasHigh = false;
    for (const auto& a : d.usnAnomalies)
        if (a.severity == "HIGH") { hasHigh = true; break; }
    ImVec4 resultColor = hasAnomalies ? (hasHigh ? col::Red : col::Yellow) : col::Green;
    std::string resultLabel = hasAnomalies ? (hasHigh ? "ANOMALY" : "REVIEW") : "OK";
    ImVec4 statusColor = hasAnomalies ? resultColor : col::Green;

    if (ImGui::BeginTable("##usn-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch, 0.28f);
        ImGui::TableSetupColumn("drive",  ImGuiTableColumnFlags_WidthStretch, 0.54f);
        ImGui::TableSetupColumn("result", ImGuiTableColumnFlags_WidthStretch, 0.18f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        detail::SummaryCell("##usn-status", "STATUS", d.usnStatus.empty() ? "Waiting" : d.usnStatus, statusColor);

        ImGui::TableNextColumn();
        detail::SummaryCell("##usn-drive", "DRIVE / JOURNAL", d.usnDrive.empty() ? "-" : d.usnDrive, col::Text);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "RESULT");
        detail::StatusBadge(resultLabel.c_str(), resultColor);

        ImGui::EndTable();
    }

    // Anomaly findings list — same card pattern as prefetch
    if (hasAnomalies) {
        ImGui::Spacing();
        for (size_t i = 0; i < d.usnAnomalies.size(); ++i) {
            const auto& a = d.usnAnomalies[i];
            ImVec4 sevColor = (a.severity == "HIGH") ? col::Red : col::Yellow;
            detail::BeginResultCard(("##usn-anomaly-" + std::to_string(i)).c_str(), cardH, sevColor);
            if (ImGui::BeginTable(("##usn-anomaly-grid-" + std::to_string(i)).c_str(), 4,
                                  ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
                ImGui::TableSetupColumn("tag",    ImGuiTableColumnFlags_WidthStretch, 0.22f);
                ImGui::TableSetupColumn("drive",  ImGuiTableColumnFlags_WidthStretch, 0.10f);
                ImGui::TableSetupColumn("detail", ImGuiTableColumnFlags_WidthStretch, 0.56f);
                ImGui::TableSetupColumn("level",  ImGuiTableColumnFlags_WidthStretch, 0.12f);
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "ANOMALIA");
                ImGui::TextColored(sevColor, "%s", a.alias.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "DRIVE");
                ImGui::TextColored(col::Header, "%s", a.file.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "DETALHE");
                std::string note = detail::CompactText(a.note, 90);
                ImGui::TextColored(col::Text, "%s", note.c_str());
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", a.note.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "LEVEL");
                detail::StatusBadge(a.severity.c_str(), sevColor);
                ImGui::EndTable();
            }
            detail::EndResultCard();
            ImGui::Spacing();
        }
    }

    detail::EndPanel();
}

inline void DrawEmulator(ScanData& d) {
    const float cardH = 96.0f;
    const float panelH = 126.0f + (float)d.emulatorFindings.size() * (cardH + 8.0f);
    detail::BeginPanel("##emulator", "Emulator", panelH);

    ImVec4 statusColor = col::TextDim;
    if (d.emulatorStatus == "OK")
        statusColor = col::Green;
    else if (d.emulatorStatus == "CLOSED")
        statusColor = col::Yellow;
    else if (d.emulatorStatus == "DETECTED")
        statusColor = col::Red;

    if (ImGui::BeginTable("##emulator-summary", 4, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch, 0.16f);
        ImGui::TableSetupColumn("result", ImGuiTableColumnFlags_WidthStretch, 0.46f);
        ImGui::TableSetupColumn("opened", ImGuiTableColumnFlags_WidthStretch, 0.22f);
        ImGui::TableSetupColumn("count",  ImGuiTableColumnFlags_WidthStretch, 0.16f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(d.emulatorStatus.c_str(), statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "INTEGRITY");
        ImGui::TextColored(statusColor, "%s", d.emulatorResult.c_str());

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "OPENED");
        ImGui::TextColored(d.emulatorOpenedAt == "-" ? col::TextDim : col::Header,
                           "%s", detail::CompactText(d.emulatorOpenedAt, 28).c_str());
        if (d.emulatorOpenedAt != "-" && ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", d.emulatorOpenedAt.c_str());

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)d.emulatorFindings.size()).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    detail::FilterBar("##emu-s", d.memFilter, sizeof(d.memFilter),
                      "##emu-sev", &d.memSevFilter, "ALL\0HIGH\0MEDIUM\0", 3,
                      "Limpar##emu", "Buscar por process, type ou detail");
    ImGui::Spacing();
    { const std::string needle = detail::FLow(std::string(d.memFilter));
    for (size_t i = 0; i < d.emulatorFindings.size(); ++i) {
        const auto& f = d.emulatorFindings[i];
        if (d.memSevFilter == 1 && f.severity != "HIGH")   continue;
        if (d.memSevFilter == 2 && f.severity != "MEDIUM") continue;
        if (!detail::FMatch(needle, { f.process, f.type, f.detail })) continue;
        ImVec4 emu_cc = f.severity == "MEDIUM" ? col::Yellow : col::Red;
        detail::BeginResultCard(("##emu-card" + std::to_string(i)).c_str(), cardH, emu_cc);
        {
            std::string headline = detail::FindingHeadline(f.type, f.process, f.address);
            ImGui::TextColored(emu_cc, "%s", detail::CompactText(headline, 110).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", headline.c_str());
        }
        if (ImGui::BeginTable(("##emu-card-grid" + std::to_string(i)).c_str(), 3,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("detail",  ImGuiTableColumnFlags_WidthStretch, 0.78f);
            ImGui::TableSetupColumn("level",   ImGuiTableColumnFlags_WidthStretch, 0.12f);
            ImGui::TableSetupColumn("copy",    ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DETAIL");
            std::string detailText = detail::CompactText(f.detail, 120);
            ImGui::TextColored(col::Text, "%s", detailText.c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.severity.c_str(), emu_cc);

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "ADDR");
            detail::CopyableValue(f.address, col::Header);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    } }
    detail::EndPanel();
}

inline void DrawSystemMemory(ScanData& d) {
    const float cardH  = 104.0f;
    const float cardKH = 96.0f;
    size_t totalFindings = d.systemMemoryFindings.size() + d.kernelAnomalies.size();
    const float panelH = 126.0f + (float)totalFindings * (cardH + 8.0f);
    detail::BeginPanel("##winscan", "WinScan", panelH);

    // Combined status: kernel anomalies + user-mode memory findings
    bool kernelDetected = d.kernelAnomalyStatus == "DETECTED";
    bool kernelReview   = d.kernelAnomalyStatus == "REVIEW";
    bool memDetected    = d.systemMemoryStatus == "DETECTED";
    std::string combinedStatus =
        (memDetected || kernelDetected) ? "DETECTED" :
        kernelReview                    ? "REVIEW"   :
        (d.systemMemoryStatus == "OK" && (d.kernelAnomalyStatus == "OK" || d.kernelAnomalyStatus == "Waiting"))
                                        ? "OK"       : d.systemMemoryStatus;

    ImVec4 statusColor = col::TextDim;
    if      (combinedStatus == "OK")       statusColor = col::Green;
    else if (combinedStatus == "DETECTED") statusColor = col::Red;
    else if (combinedStatus == "REVIEW")   statusColor = col::Yellow;

    if (ImGui::BeginTable("##sysmem-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableSetupColumn("scan",     ImGuiTableColumnFlags_WidthStretch, 0.52f);
        ImGui::TableSetupColumn("count",    ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(combinedStatus.c_str(), statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            combinedStatus == "OK"       ? "No memory anomalies detected" :
            combinedStatus == "DETECTED" ? "Memory anomalies detected — injected code, mapper or hollowing" :
            combinedStatus == "REVIEW"   ? "Suspicious kernel modules — review required" :
            "Scanning...");

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)totalFindings).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    detail::FilterBar("##sm-s", d.memFilter, sizeof(d.memFilter),
                      "##sm-type", &d.memTypeFilter,
                      "ALL\0MANUALMAPPING\0MAPPER\0HOLLOWING\0MEMORY INJECT\0THREAD INJECT\0MEMORY PROTECT\0THREAD PROTECT\0", 8,
                      "Limpar##sm", "Buscar por process, tag, driver ou detail");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90.0f);
    ImGui::Combo("##sm-sev", &d.memSevFilter, "ALL SEV\0HIGH\0MEDIUM\0");
    ImGui::Spacing();
    static const char* kMemTypes[] = {
        "", "MANUALMAPPING", "MAPPER", "HOLLOWING",
        "MEMORY INJECT", "THREAD INJECT", "MEMORY PROTECT", "THREAD PROTECT"
    };
    { const std::string needle = detail::FLow(std::string(d.memFilter));

    // User-mode memory findings
    for (size_t i = 0; i < d.systemMemoryFindings.size(); ++i) {
        const auto& f = d.systemMemoryFindings[i];
        if (d.memTypeFilter > 0 && f.type != kMemTypes[d.memTypeFilter]) continue;
        if (d.memSevFilter == 1 && f.severity != "HIGH")   continue;
        if (d.memSevFilter == 2 && f.severity != "MEDIUM") continue;
        if (!detail::FMatch(needle, { f.process, f.type, f.detail })) continue;
        ImVec4 cardColor = (f.severity == "HIGH") ? col::Red : col::Yellow;
        detail::BeginResultCard(("##sm-card" + std::to_string(i)).c_str(), cardH, cardColor);
        {
            std::string headline = detail::FindingHeadline(f.type, f.process, f.address);
            ImGui::TextColored(cardColor, "%s", detail::CompactText(headline, 110).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", headline.c_str());
        }
        if (ImGui::BeginTable(("##sm-card-grid" + std::to_string(i)).c_str(), 3,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("detail",  ImGuiTableColumnFlags_WidthStretch, 0.78f);
            ImGui::TableSetupColumn("level",   ImGuiTableColumnFlags_WidthStretch, 0.12f);
            ImGui::TableSetupColumn("copy",    ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DETAIL");
            ImGui::TextColored(col::Text, "%s", detail::CompactText(f.detail, 120).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.severity.c_str(), cardColor);

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "ADDR");
            detail::CopyableValue(f.address, col::Header);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    }

    // Kernel anomaly findings (mapper, hollowing, BYOVD)
    for (size_t i = 0; i < d.kernelAnomalies.size(); ++i) {
        const auto& f = d.kernelAnomalies[i];
        if (d.memTypeFilter > 0 && f.type != kMemTypes[d.memTypeFilter]) continue;
        if (d.memSevFilter == 1 && f.severity != "HIGH")   continue;
        if (d.memSevFilter == 2 && f.severity != "MEDIUM") continue;
        if (!detail::FMatch(needle, { f.driverName, f.type, f.reason, f.detail, f.path })) continue;
        ImVec4 cardColor = f.severity == "HIGH" ? col::Red : col::Yellow;
        detail::BeginResultCard(("##kanom-card" + std::to_string(i)).c_str(), cardKH, cardColor);
        if (ImGui::BeginTable(("##kanom-grid" + std::to_string(i)).c_str(), 5,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("tag",    ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("driver", ImGuiTableColumnFlags_WidthStretch, 0.18f);
            ImGui::TableSetupColumn("reason", ImGuiTableColumnFlags_WidthStretch, 0.40f);
            ImGui::TableSetupColumn("base",   ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("level",  ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "TAG");
            ImGui::TextColored(col::Header, "%s", f.type.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DRIVER");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.driverName, 20).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.path.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "REASON");
            ImGui::TextColored(cardColor, "%s", detail::CompactText(f.reason, 50).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%s", f.reason.c_str(), f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "BASE");
            if (f.loadAddress != 0) {
                char addrBuf[32];
                snprintf(addrBuf, sizeof(addrBuf), "0x%016llX", (unsigned long long)f.loadAddress);
                detail::CopyableValue(addrBuf, col::Header);
            } else {
                ImGui::TextColored(col::TextDim, "n/a");
            }

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.severity.c_str(), cardColor);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    } }

    detail::EndPanel();
}

inline void DrawGenericBypass(ScanData& d) {
    const float cardH      = 100.0f;
    const float totalCards = (float)(d.genericBypass.size() + d.streamModFindings.size() + d.remotePortFindings.size());
    const float panelH     = 126.0f + totalCards * (cardH + 8.0f);
    detail::BeginPanel("##generic-bypass", "Generic Bypass", panelH);

    const size_t totalFindings = d.genericBypass.size() + d.streamModFindings.size() + d.remotePortFindings.size();
    bool loading = (d.genericBypassStatus == "Loading" || d.genericBypassStatus == "Waiting" ||
                    d.streamModStatus     == "Loading" || d.streamModStatus     == "Waiting" ||
                    d.remotePortStatus    == "Loading" || d.remotePortStatus    == "Waiting");
    ImVec4 statusColor = loading ? col::TextDim : (totalFindings == 0 ? col::Green : col::Red);
    const char* statusText = loading ? "Loading" : (totalFindings == 0 ? "OK" : "DETECTED");

    if (ImGui::BeginTable("##generic-bypass-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableSetupColumn("scan",     ImGuiTableColumnFlags_WidthStretch, 0.52f);
        ImGui::TableSetupColumn("findings", ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(statusText, statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            loading          ? "Scanning bypass indicators..." :
            totalFindings == 0 ? "No bypass or stream mod indicators detected" :
            "Review handle, hook, log tamper or stream mod indicators");

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)totalFindings).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    detail::FilterBar("##bypass-s", d.bypassFilter, sizeof(d.bypassFilter),
                      "##bypass-type", &d.bypassTypeFilter,
                      "ALL\0HANDLE\0AV_EXCLUSION\0AV_REMOVAL\0SYSMON\0EVENTLOG\0REMOTETHREAD\0PROC_ACCESS\0CHEAT_DOMAIN\0EXPLORER\0"
                      "CAPTURE_EXCLUDE\0OBS_PLUGIN\0OBS_INJECT\0VIRTUAL_DISPLAY\0DWM_INJECT\0DWM_HOOK\0"
                      "OVERLAY\0NVFBC_ALLOW\0VIRTUAL_CAMERA\0REMOTE_PORT\0", 20,
                      "Limpar##bypass", "Buscar por process, target ou detail");
    ImGui::Spacing();

    static const char* kBypassTypes[] = {
        "",
        "HANDLE", "AV_EXCLUSION", "AV_REMOVAL", "SYSMON", "EVENTLOG", "REMOTETHREAD", "PROC_ACCESS", "CHEAT_DOMAIN", "EXPLORER",
        "CAPTURE_EXCLUDE", "OBS_PLUGIN", "OBS_INJECT", "VIRTUAL_DISPLAY", "DWM_INJECT", "DWM_HOOK",
        "OVERLAY", "NVFBC_ALLOW", "VIRTUAL_CAMERA", "REMOTE_PORT"
    };
    // indices 1-9   → generic bypass only
    // indices 10-18 → stream mod only
    // index   19    → remote port only
    const bool showBypass     = d.bypassTypeFilter == 0 || (d.bypassTypeFilter >= 1 && d.bypassTypeFilter <= 9);
    const bool showStreamMod  = d.bypassTypeFilter == 0 || (d.bypassTypeFilter >= 10 && d.bypassTypeFilter <= 18);
    const bool showRemotePort = d.bypassTypeFilter == 0 || d.bypassTypeFilter == 19;

    const std::string needle = detail::FLow(std::string(d.bypassFilter));

    if (showBypass) {
        for (size_t i = 0; i < d.genericBypass.size(); ++i) {
            const auto& f = d.genericBypass[i];
            if (d.bypassTypeFilter >= 1 && d.bypassTypeFilter <= 9 &&
                f.type != kBypassTypes[d.bypassTypeFilter]) continue;
            if (!detail::FMatch(needle, { f.type, f.process, f.target, f.detail })) continue;
            ImVec4 cardColor = (f.severity == "HIGH" || f.severity == "CRITICAL") ? col::Red : col::Yellow;
            detail::BeginResultCard(("##gb-card" + std::to_string(i)).c_str(), cardH, cardColor);
            if (ImGui::BeginTable(("##gb-grid" + std::to_string(i)).c_str(), 4,
                                  ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
                ImGui::TableSetupColumn("type",    ImGuiTableColumnFlags_WidthStretch, 0.14f);
                ImGui::TableSetupColumn("summary", ImGuiTableColumnFlags_WidthStretch, 0.50f);
                ImGui::TableSetupColumn("process", ImGuiTableColumnFlags_WidthStretch, 0.26f);
                ImGui::TableSetupColumn("level",   ImGuiTableColumnFlags_WidthStretch, 0.10f);
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "TYPE");
                ImGui::TextColored(col::Header, "%s", f.type.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "SUMMARY");
                std::string summary = f.detail + ": " + f.date + " " + f.time;
                ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
                ImGui::TextColored(col::Header, "%s", summary.c_str());
                ImGui::PopTextWrapPos();

                ImGui::TableNextColumn();
                detail::ProcessLink("PROCESS", f.process, ("gb-process" + std::to_string(i)).c_str());
                if (!f.target.empty() && f.target != "-")
                    detail::ProcessLink("TARGET", f.target, ("gb-target" + std::to_string(i)).c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "LEVEL");
                detail::StatusBadge(f.severity.c_str(), cardColor);
                ImGui::EndTable();
            }
            detail::EndResultCard();
            ImGui::Spacing();
        }
    }

    if (showStreamMod) {
        for (size_t i = 0; i < d.streamModFindings.size(); ++i) {
            const auto& f = d.streamModFindings[i];
            if (d.bypassTypeFilter >= 10 && d.bypassTypeFilter <= 18 &&
                f.type != kBypassTypes[d.bypassTypeFilter]) continue;
            if (!detail::FMatch(needle, { f.type, f.process, f.target, f.detail })) continue;
            ImVec4 cc = (f.severity == "HIGH")  ? col::Red   :
                        (f.severity == "MEDIUM") ? col::Yellow : col::TextDim;
            detail::BeginResultCard(("##sm-card" + std::to_string(i)).c_str(), cardH, cc);
            if (ImGui::BeginTable(("##sm-grid" + std::to_string(i)).c_str(), 4,
                                  ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
                ImGui::TableSetupColumn("type",    ImGuiTableColumnFlags_WidthStretch, 0.14f);
                ImGui::TableSetupColumn("summary", ImGuiTableColumnFlags_WidthStretch, 0.50f);
                ImGui::TableSetupColumn("process", ImGuiTableColumnFlags_WidthStretch, 0.26f);
                ImGui::TableSetupColumn("level",   ImGuiTableColumnFlags_WidthStretch, 0.10f);
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "TYPE");
                ImGui::TextColored(col::Header, "%s", f.type.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "SUMMARY");
                ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
                ImGui::TextColored(col::Header, "%s", f.detail.c_str());
                ImGui::PopTextWrapPos();

                ImGui::TableNextColumn();
                detail::ProcessLink("PROCESS", f.process, ("sm-process" + std::to_string(i)).c_str());
                if (!f.target.empty() && f.target != "-")
                    detail::ProcessLink("TARGET", f.target, ("sm-target" + std::to_string(i)).c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "LEVEL");
                detail::StatusBadge(f.severity.c_str(), cc);
                ImGui::EndTable();
            }
            detail::EndResultCard();
            ImGui::Spacing();
        }
    }

    if (showRemotePort) {
        for (size_t i = 0; i < d.remotePortFindings.size(); ++i) {
            const auto& f = d.remotePortFindings[i];
            if (!detail::FMatch(needle, { std::string("REMOTE_PORT"), f.process, f.path,
                                          f.port, f.bindAddress, f.reason, f.detail,
                                          f.scriptOrHost, f.firewallRule, f.tunnelPeer })) continue;
            ImVec4 cc = (f.severity == "HIGH")   ? col::Red    :
                        (f.severity == "MEDIUM") ? col::Yellow : col::TextDim;
            detail::BeginResultCard(("##rp-card" + std::to_string(i)).c_str(), cardH, cc);
            if (ImGui::BeginTable(("##rp-grid" + std::to_string(i)).c_str(), 4,
                                  ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
                ImGui::TableSetupColumn("type",    ImGuiTableColumnFlags_WidthStretch, 0.14f);
                ImGui::TableSetupColumn("summary", ImGuiTableColumnFlags_WidthStretch, 0.50f);
                ImGui::TableSetupColumn("process", ImGuiTableColumnFlags_WidthStretch, 0.26f);
                ImGui::TableSetupColumn("level",   ImGuiTableColumnFlags_WidthStretch, 0.10f);
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "REMOTE_PORT");
                ImGui::TextColored(col::Header, "%s/%s", f.protocol.c_str(), f.port.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "SUMMARY");
                std::string summary = f.reason + "  [" + f.bindAddress + "]";
                if (!f.scriptOrHost.empty())  summary += "  via " + f.scriptOrHost;
                if (!f.tunnelPeer.empty())    summary += "  + tunnel:" + f.tunnelPeer;
                if (!f.firewallRule.empty())  summary += "  fw:" + f.firewallRule;
                ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
                ImGui::TextColored(col::Header, "%s", summary.c_str());
                ImGui::PopTextWrapPos();

                ImGui::TableNextColumn();
                detail::ProcessLink("PROCESS", f.process, ("rp-process" + std::to_string(i)).c_str());
                if (!f.signer.empty())
                    ImGui::TextColored(col::TextDim, "%s", f.signer.c_str());

                ImGui::TableNextColumn();
                ImGui::TextColored(col::TextDim, "LEVEL");
                detail::StatusBadge(f.severity.c_str(), cc);
                ImGui::EndTable();
            }
            detail::EndResultCard();
            ImGui::Spacing();
        }
    }

    detail::EndPanel();
}

inline void DrawKernelAnomalies(ScanData& d) {
    const float cardH  = 96.0f;
    float panelH = 126.0f + (float)d.kernelAnomalies.size() * (cardH + 8.0f);
    detail::BeginPanel("##kernel-anomalies", "Kernel Anomalies", panelH);

    ImVec4 statusColor = col::TextDim;
    if      (d.kernelAnomalyStatus == "OK")       statusColor = col::Green;
    else if (d.kernelAnomalyStatus == "DETECTED")  statusColor = col::Red;
    else if (d.kernelAnomalyStatus == "REVIEW")    statusColor = col::Yellow;

    if (ImGui::BeginTable("##kanom-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("s", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("d", ImGuiTableColumnFlags_WidthStretch, 0.56f);
        ImGui::TableSetupColumn("h", ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(d.kernelAnomalyStatus.c_str(), statusColor);
        ImGui::TableNextColumn(); ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            d.kernelAnomalyStatus == "OK"       ? "No kernel memory anomalies detected" :
            d.kernelAnomalyStatus == "DETECTED" ? "Kernel anomalies detected — mapper or hollowing suspected" :
            d.kernelAnomalyStatus == "REVIEW"   ? "Suspicious kernel modules — review required" :
            "Waiting for scan");
        ImGui::TableNextColumn(); ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)d.kernelAnomalies.size()).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    { for (size_t i = 0; i < d.kernelAnomalies.size(); ++i) {
        const auto& f = d.kernelAnomalies[i];
        ImVec4 cardColor = f.severity == "HIGH" ? col::Red : col::Yellow;
        detail::BeginResultCard(("##kanom-card" + std::to_string(i)).c_str(), cardH, cardColor);
        if (ImGui::BeginTable(("##kanom-grid" + std::to_string(i)).c_str(), 4,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("driver",  ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableSetupColumn("reason",  ImGuiTableColumnFlags_WidthStretch, 0.44f);
            ImGui::TableSetupColumn("base",    ImGuiTableColumnFlags_WidthStretch, 0.24f);
            ImGui::TableSetupColumn("level",   ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DRIVER");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.driverName, 22).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.path.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "REASON");
            ImGui::TextColored(cardColor, "%s", detail::CompactText(f.reason, 50).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%s", f.reason.c_str(), f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "BASE");
            if (f.loadAddress != 0) {
                char addrBuf[32];
                snprintf(addrBuf, sizeof(addrBuf), "0x%016llX", (unsigned long long)f.loadAddress);
                detail::CopyableValue(addrBuf, col::Header);
            } else {
                ImGui::TextColored(col::TextDim, "n/a");
            }

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.severity.c_str(), cardColor);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    } }

    detail::EndPanel();
}

inline void DrawEfiCheatDetect(ScanData& d) {
    const float cardH = 46.0f;
    const float panelH = 148.0f + (float)d.efiCheats.size() * (cardH + 8.0f);
    detail::BeginPanel("##efi-cheat-detect", "EFI Cheat Detect", panelH);

    ImVec4 statusColor = col::TextDim;
    if (d.efiCheatStatus == "OK")
        statusColor = col::Green;
    else if (d.efiCheatStatus == "DETECTED")
        statusColor = col::Red;
    else if (d.efiCheatStatus == "REVIEW")
        statusColor = col::Yellow;

    if (ImGui::BeginTable("##efi-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("scope",  ImGuiTableColumnFlags_WidthStretch, 0.56f);
        ImGui::TableSetupColumn("hits",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(d.efiCheatStatus.c_str(), statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            d.efiCheatStatus == "OK" ? "No suspicious .efi files found" :
            d.efiCheatStatus == "DETECTED" ? "Review unsigned or cheat-like EFI loaders" :
            d.efiCheatStatus == "REVIEW" ? "EFI locations were partially accessible" :
            "Waiting for xv!pg2 or scanner run");

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)d.efiCheats.size()).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    if (detail::ScanPageButton("##efi-run", d.efiCheatStatus == "Loading"))
        d.pendingCommand = "run!pg2";
    ImGui::Spacing();
    detail::FilterBar("##efi-s", d.efiFilter, sizeof(d.efiFilter),
                      "##efi-sev", &d.efiSevFilter, "ALL\0HIGH\0MEDIUM\0", 3,
                      "Limpar##efi", "Buscar por path, reason ou detail");
    ImGui::Spacing();
    { const std::string needle = detail::FLow(std::string(d.efiFilter));
    for (size_t i = 0; i < d.efiCheats.size(); ++i) {
        const auto& f = d.efiCheats[i];
        if (d.efiSevFilter == 1 && f.severity != "HIGH")   continue;
        if (d.efiSevFilter == 2 && f.severity != "MEDIUM") continue;
        if (!detail::FMatch(needle, { detail::FileNameFromPath(f.path), f.path, f.reason, f.detail })) continue;
        ImVec4 cardColor = (f.severity == "HIGH" || f.severity == "CRITICAL") ? col::Red : col::Yellow;
        detail::BeginResultCard(("##efi-card" + std::to_string(i)).c_str(), cardH, cardColor);
        if (ImGui::BeginTable(("##efi-grid" + std::to_string(i)).c_str(), 3,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("file",   ImGuiTableColumnFlags_WidthStretch, 0.36f);
            ImGui::TableSetupColumn("reason", ImGuiTableColumnFlags_WidthStretch, 0.52f);
            ImGui::TableSetupColumn("level",  ImGuiTableColumnFlags_WidthStretch, 0.12f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(cardColor, "%s", detail::CompactText(detail::FileNameFromPath(f.path), 30).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%s %s\n%s", f.path.c_str(), f.date.c_str(), f.time.c_str(), f.detail.c_str());
            ImGui::SameLine();
            if (detail::FolderButton(("##efiopen" + std::to_string(i)).c_str())) {
                std::string cmd = "explorer /select,\"" + f.path + "\"";
                system(cmd.c_str());
            }

            ImGui::TableNextColumn();
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.reason, 70).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%s", f.reason.c_str(), f.detail.c_str());

            ImGui::TableNextColumn();
            detail::StatusBadge(f.severity.c_str(), cardColor);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    } }

    detail::EndPanel();
}

inline void DrawDriverIntegrity(ScanData& d) {
    const float cardH  = 46.0f;
    float panelH = 148.0f + (float)d.driverIntegrity.size() * (cardH + 8.0f);
    detail::BeginPanel("##drv-integrity", "Kernel Driver Integrity", panelH);

    ImVec4 statusColor = col::TextDim;
    if      (d.driverIntegrityStatus == "OK")       statusColor = col::Green;
    else if (d.driverIntegrityStatus == "DETECTED")  statusColor = col::Red;
    else if (d.driverIntegrityStatus == "REVIEW")    statusColor = col::Yellow;

    if (ImGui::BeginTable("##drvint-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("scope",  ImGuiTableColumnFlags_WidthStretch, 0.56f);
        ImGui::TableSetupColumn("hits",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(d.driverIntegrityStatus.c_str(), statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            d.driverIntegrityStatus == "OK"       ? "Kernel drivers and ntdll intact — no modifications detected" :
            d.driverIntegrityStatus == "DETECTED" ? "Driver or ntdll integrity violations detected" :
            d.driverIntegrityStatus == "REVIEW"   ? "Driver or ntdll integrity check needs review" :
            d.driverIntegrityStatus == "Loading"  ? "Scanning driver and ntdll integrity..." :
            "Type xv!pg3 to run integrity scan");

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)d.driverIntegrity.size()).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    if (detail::ScanPageButton("##drvint-run", d.driverIntegrityStatus == "Loading"))
        d.pendingCommand = "run!pg3";
    ImGui::Spacing();
    detail::FilterBar("##drvint-s", d.drvIntFilter, sizeof(d.drvIntFilter),
                      "##drvint-sev", &d.drvIntSevFilter, "ALL\0HIGH\0MEDIUM\0", 3,
                      "Limpar##drvint", "Buscar por nome, path, reason, detail ou hooks");
    ImGui::SameLine();
    static bool drvIntCallbackOnly = false;
    ImGui::Checkbox("callbacks only##drvint", &drvIntCallbackOnly);
    ImGui::Spacing();
    { const std::string needle = detail::FLow(std::string(d.drvIntFilter));
    for (size_t i = 0; i < d.driverIntegrity.size(); ++i) {
        const auto& f = d.driverIntegrity[i];
        if (d.drvIntSevFilter == 1 && f.severity != "HIGH")   continue;
        if (d.drvIntSevFilter == 2 && f.severity != "MEDIUM") continue;
        if (drvIntCallbackOnly && !f.hasCallbackSurface)       continue;
        if (!detail::FMatch(needle, { f.driverName, f.path, f.reason, f.detail, f.logSource, f.hookedFunctions, f.callbackSurface, f.signerName })) continue;
        ImVec4 cardColor = f.severity == "HIGH"   ? col::Red :
                           f.severity == "MEDIUM" ? col::Yellow : col::Green;
        detail::BeginResultCard(("##drvint-card" + std::to_string(i)).c_str(), cardH, cardColor);
        if (ImGui::BeginTable(("##drvint-grid" + std::to_string(i)).c_str(), 3,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("driver", ImGuiTableColumnFlags_WidthStretch, 0.30f);
            ImGui::TableSetupColumn("info",   ImGuiTableColumnFlags_WidthStretch, 0.58f);
            ImGui::TableSetupColumn("level",  ImGuiTableColumnFlags_WidthStretch, 0.12f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(cardColor, "%s", detail::CompactText(f.driverName, 26).c_str());
            if (ImGui::IsItemHovered()) {
                std::string tip = f.path;
                if (!f.reason.empty())          tip += "\n" + f.reason;
                if (!f.detail.empty())          tip += "\n" + f.detail;
                if (!f.signerName.empty())      tip += "\nsigner: " + f.signerName;
                if (!f.sha256.empty())          tip += "\nsha256: " + f.sha256;
                if (!f.hookedFunctions.empty()) tip += "\nhooks: " + f.hookedFunctions;
                if (!f.callbackSurface.empty()) tip += "\ncallbacks: " + f.callbackSurface;
                if (f.loadAddress != 0) {
                    char addrBuf[64];
                    snprintf(addrBuf, sizeof(addrBuf), "\nbase: 0x%016llX", (unsigned long long)f.loadAddress);
                    tip += addrBuf;
                }
                if (!f.logSource.empty())       tip += "\nlogs: " + f.logSource;
                ImGui::SetTooltip("%s", tip.c_str());
            }
            ImGui::SameLine();
            if (detail::FolderButton(("##drvintopen" + std::to_string(i)).c_str())) {
                std::string cmd = "explorer /select,\"" + f.path + "\"";
                system(cmd.c_str());
            }

            ImGui::TableNextColumn();
            std::string summary = f.reason;
            if (f.hasHooks)                summary += "  hooks";
            else if (f.hasCallbackSurface) summary += "  callbacks";
            summary += f.signedOk ? "  signed" : "  unsigned";
            if (!f.hashMatch && f.referenceSource != "none" && !f.referenceSource.empty())
                summary += "  hash DIFFER";
            ImGui::TextColored(col::Header, "%s", detail::CompactText(summary, 60).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", f.reason.c_str(), f.detail.c_str());

            ImGui::TableNextColumn();
            detail::StatusBadge(f.severity.c_str(), cardColor);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    } }

    detail::EndPanel();
}

inline void DrawKernelDrivers(ScanData& d) {
    const std::string needle = detail::FLow(std::string(d.kdrvFilter));
    static const char* kSev[] = { "ALL", "HIGH", "MEDIUM" };
    const float cardH  = 100.0f;
    float panelH = 182.0f + (float)d.kernelDrivers.size() * (cardH + 8.0f);
    detail::BeginPanel("##kernel-drivers", "Kernel Driver Scan", panelH);

    ImVec4 statusColor = d.kernelDriverStatus == "OK"       ? col::Green :
                         d.kernelDriverStatus == "DETECTED" ? col::Red   :
                         d.kernelDriverStatus == "REVIEW"   ? col::Yellow : col::TextDim;

    if (ImGui::BeginTable("##kdrv-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("s", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("d", ImGuiTableColumnFlags_WidthStretch, 0.56f);
        ImGui::TableSetupColumn("h", ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(d.kernelDriverStatus.c_str(), statusColor);
        ImGui::TableNextColumn(); ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            d.kernelDriverStatus == "OK"       ? "No suspicious kernel drivers found" :
            d.kernelDriverStatus == "DETECTED" ? "Suspicious drivers detected" :
            d.kernelDriverStatus == "REVIEW"   ? "Driver enumeration partially failed" : "Waiting");
        ImGui::TableNextColumn(); ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)d.kernelDrivers.size()).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    detail::FilterBar("##kdrv-s", d.kdrvFilter, sizeof(d.kdrvFilter),
                      "##kdrv-sev", &d.kdrvSevFilter, "ALL\0HIGH\0MEDIUM\0", 3,
                      "Limpar##kdrv", "Buscar por nome, path ou reason");
    ImGui::Spacing();

    for (size_t i = 0; i < d.kernelDrivers.size(); ++i) {
        const auto& f = d.kernelDrivers[i];
        if (d.kdrvSevFilter == 1 && f.severity != "HIGH")   continue;
        if (d.kdrvSevFilter == 2 && f.severity != "MEDIUM") continue;
        if (!detail::FMatch(needle, { detail::FileNameFromPath(f.path), f.path, f.reason, f.detail }))
            continue;

        ImVec4 cardColor = f.severity == "HIGH" ? col::Red : col::Yellow;
        detail::BeginResultCard(("##kdrv-c" + std::to_string(i)).c_str(), cardH, cardColor);
        if (ImGui::BeginTable(("##kdrv-g" + std::to_string(i)).c_str(), 5,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("w", ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("d", ImGuiTableColumnFlags_WidthStretch, 0.26f);
            ImGui::TableSetupColumn("r", ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("e", ImGuiTableColumnFlags_WidthStretch, 0.28f);
            ImGui::TableSetupColumn("l", ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "WHEN");
            ImGui::TextColored(col::Header, "%s %s", f.date.c_str(), f.time.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DRIVER");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(detail::FileNameFromPath(f.path), 30).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.path.c_str());
            ImGui::SameLine();
            if (detail::FolderButton(("##ko" + std::to_string(i)).c_str())) {
                system(("explorer /select,\"" + f.path + "\"").c_str());
            }

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "REASON");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.reason, 30).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.reason.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DETAIL");
            ImGui::TextColored(col::Text, "%s", detail::CompactText(f.detail, 58).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.severity.c_str(), cardColor);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    }
    detail::EndPanel();
}

inline void DrawRegistryAndClsidFindings(ScanData& d) {
    const float regCardH   = 100.0f;
    const float clsidCardH = 106.0f;
    const float panelH = 196.0f
        + (float)d.registryFindings.size() * (regCardH + 8.0f)
        + (float)d.clsidFindings.size()    * (clsidCardH + 8.0f);
    detail::BeginPanel("##registry-com-persist", "Registry & COM Hijack Detection", panelH);

    // Combined status = worst-of(registryStatus, clsidStatus)
    auto statusRank = [](const std::string& s) {
        if (s == "DETECTED") return 3;
        if (s == "REVIEW")   return 2;
        if (s == "OK")       return 1;
        return 0;
    };
    const std::string& combinedStatus =
        statusRank(d.registryStatus) >= statusRank(d.clsidStatus) ? d.registryStatus : d.clsidStatus;

    ImVec4 statusColor = col::TextDim;
    if (combinedStatus == "OK")           statusColor = col::Green;
    else if (combinedStatus == "DETECTED") statusColor = col::Red;
    else if (combinedStatus == "REVIEW")   statusColor = col::Yellow;

    const size_t totalFindings = d.registryFindings.size() + d.clsidFindings.size();

    if (ImGui::BeginTable("##reg-clsid-summary", 3, ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("scope",  ImGuiTableColumnFlags_WidthStretch, 0.56f);
        ImGui::TableSetupColumn("hits",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableNextRow();

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "STATUS");
        detail::StatusBadge(combinedStatus.c_str(), statusColor);

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "SCAN");
        ImGui::TextColored(statusColor,
            combinedStatus == "OK"       ? "No registry or COM hijack techniques detected" :
            combinedStatus == "DETECTED" ? "Hijack technique(s) detected — review entries below" :
            "Waiting for scanner run");

        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "FINDINGS");
        detail::StatusBadge(std::to_string((int)totalFindings).c_str(), statusColor);
        ImGui::EndTable();
    }

    ImGui::Spacing();
    detail::SectionTitle(("Registry Hijack  (" + std::to_string((int)d.registryFindings.size()) + ")").c_str());
    for (size_t i = 0; i < d.registryFindings.size(); ++i) {
        const auto& f = d.registryFindings[i];
        ImVec4 cardColor = (f.severity == "HIGH")   ? col::Red :
                           (f.severity == "MEDIUM") ? col::Yellow : col::TextDim;
        detail::BeginResultCard(("##reg-card" + std::to_string(i)).c_str(), regCardH, cardColor);
        if (ImGui::BeginTable(("##reg-grid" + std::to_string(i)).c_str(), 5,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("key",    ImGuiTableColumnFlags_WidthStretch, 0.22f);
            ImGui::TableSetupColumn("value",  ImGuiTableColumnFlags_WidthStretch, 0.14f);
            ImGui::TableSetupColumn("data",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
            ImGui::TableSetupColumn("reason", ImGuiTableColumnFlags_WidthStretch, 0.30f);
            ImGui::TableSetupColumn("level",  ImGuiTableColumnFlags_WidthStretch, 0.10f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "KEY");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.key, 36).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.key.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "VALUE");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.value, 22).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.value.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "DATA");
            ImGui::TextColored(col::Text, "%s", detail::CompactText(detail::FileNameFromPath(f.data), 36).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", f.data.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "REASON");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.reason, 46).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", f.reason.c_str(), f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.severity.c_str(), cardColor);
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    }

    ImGui::Spacing();
    detail::SectionTitle(("COM / CLSID  (" + std::to_string((int)d.clsidFindings.size()) + ")").c_str());
    for (size_t i = 0; i < d.clsidFindings.size(); ++i) {
        auto& f = d.clsidFindings[i];
        ImVec4 cardColor = (f.severity == "HIGH") ? col::Red : col::Yellow;
        if (f.cleaned) cardColor = col::Green;
        detail::BeginResultCard(("##clsid-card" + std::to_string(i)).c_str(), clsidCardH, cardColor);
        if (ImGui::BeginTable(("##clsid-grid" + std::to_string(i)).c_str(), 6,
                              ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
            ImGui::TableSetupColumn("clsid",  ImGuiTableColumnFlags_WidthStretch, 0.20f);
            ImGui::TableSetupColumn("name",   ImGuiTableColumnFlags_WidthStretch, 0.16f);
            ImGui::TableSetupColumn("path",   ImGuiTableColumnFlags_WidthStretch, 0.24f);
            ImGui::TableSetupColumn("reason", ImGuiTableColumnFlags_WidthStretch, 0.24f);
            ImGui::TableSetupColumn("level",  ImGuiTableColumnFlags_WidthStretch, 0.08f);
            ImGui::TableSetupColumn("action", ImGuiTableColumnFlags_WidthStretch, 0.08f);
            ImGui::TableNextRow();

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "CLSID");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.clsid, 28).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hive: %s\n%s", f.hivePath.c_str(), f.clsid.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "NAME");
            ImGui::TextColored(col::Text, "%s", detail::CompactText(f.friendlyName.empty() ? f.serverType : f.friendlyName, 22).c_str());
            if (ImGui::IsItemHovered() && !f.friendlyName.empty())
                ImGui::SetTooltip("%s", f.friendlyName.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "SERVER PATH");
            ImGui::TextColored(f.isSigned ? col::Text : col::Yellow,
                               "%s", detail::CompactText(f.serverPath.empty() ? "(no server key)" : detail::FileNameFromPath(f.serverPath), 36).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\nExists: %s | Signed: %s",
                    f.serverPath.c_str(),
                    f.fileExists ? "yes" : "no",
                    f.isSigned   ? "yes" : "no");

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "REASON");
            ImGui::TextColored(col::Header, "%s", detail::CompactText(f.reason, 38).c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", f.reason.c_str(), f.detail.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "LEVEL");
            detail::StatusBadge(f.cleaned ? "CLEAN" : f.severity.c_str(),
                                f.cleaned ? col::Green : cardColor);

            ImGui::TableNextColumn();
            ImGui::TextColored(col::TextDim, "ACTION");
            if (f.cleaned) {
                ImGui::TextColored(col::Green, "Cleaned");
            } else if (f.canClean) {
                ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.65f, 0.12f, 0.12f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.18f, 0.18f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.90f, 0.22f, 0.22f, 1.0f));
                std::string btnId = "Clean##clsid" + std::to_string(i);
                if (ImGui::Button(btnId.c_str())) {
                    d.clsidPendingCleanIdx = (int)i;
                    ImGui::OpenPopup("##clsid-clean-confirm");
                }
                ImGui::PopStyleColor(3);
            } else {
                ImGui::TextColored(col::TextDim, "-");
            }
            ImGui::EndTable();
        }
        detail::EndResultCard();
        ImGui::Spacing();
    }

    // Confirmation modal — must be in same call stack as OpenPopup
    if (ImGui::BeginPopupModal("##clsid-clean-confirm", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        int idx = d.clsidPendingCleanIdx;
        if (idx >= 0 && idx < (int)d.clsidFindings.size()) {
            const auto& cf = d.clsidFindings[idx];
            ImGui::TextColored(col::Yellow, "Remove CLSID registry key?");
            ImGui::Spacing();
            ImGui::TextColored(col::TextDim, "CLSID:"); ImGui::SameLine();
            ImGui::TextColored(col::Header,  "%s", cf.clsid.c_str());
            ImGui::TextColored(col::TextDim, "Hive: "); ImGui::SameLine();
            ImGui::TextColored(col::Header,  "%s\\SOFTWARE\\Classes\\CLSID", cf.hivePath.c_str());
            ImGui::Spacing();
            ImGui::TextColored(col::TextDim, "This will delete the key and all subkeys.");
            ImGui::Spacing();
        }
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.65f, 0.12f, 0.12f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.18f, 0.18f, 1.0f));
        if (ImGui::Button("Confirm", ImVec2(120, 0))) {
            d.clsidCleanConfirmed = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            d.clsidPendingCleanIdx = -1;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    detail::EndPanel();
}

inline void DrawBottom(ScanData& d) {
    const float statusH = kStatusH;
    const float termH   = d.terminalExpanded ? kTerminalExpandedH : kTerminalH;


    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::BgTitle);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 7.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        d.terminalExpanded ? ImVec2(12, 10) : ImVec2(12, 9));
    ImGui::BeginChild("##terminal", ImVec2(0, termH), true, ImGuiWindowFlags_NoScrollbar);

    if (d.terminalExpanded) {
        ImGui::TextColored(col::Header, "LOGS DO SCANNER");
        ImGui::SameLine(0.0f, 10.0f);
        detail::StatusBadge((std::to_string(d.terminalLog.size()) + " LINHAS").c_str(),
                            d.terminalLog.empty() ? col::TextDim : col::Green);

        const float controlsW = 252.0f;
        ImGui::SameLine(ImGui::GetWindowWidth() - controlsW);
        if (ImGui::SmallButton("Copiar tudo")) {
            std::string allLogs;
            for (const auto& line : d.terminalLog) {
                allLogs += line;
                allLogs += '\n';
            }
            ImGui::SetClipboardText(allLogs.c_str());
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Limpar"))
            d.terminalLog.clear();
        ImGui::SameLine();
        if (ImGui::SmallButton("Recolher"))
            d.terminalExpanded = false;

        ImGui::PushStyleColor(ImGuiCol_ChildBg, col::Bg);
        ImGui::PushStyleColor(ImGuiCol_Border, detail::ColorAlpha(col::Header, 0.07f));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f, 7.0f));
        ImGui::BeginChild("##terminal-history", ImVec2(0.0f, 92.0f), true,
                          ImGuiWindowFlags_AlwaysVerticalScrollbar);

        static size_t previousLogCount = 0;
        for (size_t i = 0; i < d.terminalLog.size(); ++i) {
            const std::string& line = d.terminalLog[i];
            ImVec4 lineColor = col::Text;
            const std::string lower = detail::FLow(line);
            if (lower.find("error") != std::string::npos ||
                lower.find("falha") != std::string::npos ||
                lower.find("failed") != std::string::npos) {
                lineColor = col::Red;
            } else if (lower.find("[export]") != std::string::npos) {
                lineColor = col::Yellow;
            } else if (lower.find("loaded") != std::string::npos ||
                       lower.find("finished") != std::string::npos ||
                       lower.find("concluido") != std::string::npos) {
                lineColor = col::Green;
            } else if (lower.find("started") != std::string::npos ||
                       lower.find("running") != std::string::npos ||
                       lower.find("opening") != std::string::npos) {
                lineColor = col::Header;
            }

            ImGui::PushID((int)i);
            ImGui::TextColored(col::TextDim, "%03d", (int)i + 1);
            ImGui::SameLine(0.0f, 10.0f);
            ImGui::TextColored(lineColor, "%s", line.c_str());
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Clique para copiar esta linha");
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                    ImGui::SetClipboardText(line.c_str());
            }
            ImGui::PopID();
        }
        if (d.terminalLog.empty())
            ImGui::TextColored(col::TextDim, "Nenhuma atividade registrada.");
        if (d.terminalLog.size() != previousLogCount && !d.terminalLog.empty())
            ImGui::SetScrollHereY(1.0f);
        previousLogCount = d.terminalLog.size();

        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
    }

    if (!d.terminalExpanded) {
        if (ImGui::Button(("Logs  " + std::to_string(d.terminalLog.size()) + "##open-logs").c_str(),
                          ImVec2(88.0f, 0.0f)))
            d.terminalExpanded = true;
        ImGui::SameLine(0.0f, 8.0f);
    }
    ImGui::TextColored(col::Accent, ">");
    ImGui::SameLine(0.0f, 8.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, col::PanelSoft);
    ImGui::PushStyleColor(ImGuiCol_Text, col::Header);
    ImGui::PushStyleColor(ImGuiCol_TextDisabled, col::TextDim);
    ImGui::SetNextItemWidth(-1);
    if (ImGui::InputTextWithHint("##terminal-input", "Digite um comando e pressione Enter...",
                                 d.terminalInput, sizeof(d.terminalInput),
                                 ImGuiInputTextFlags_EnterReturnsTrue)) {
        if (d.terminalInput[0] != '\0') {
            d.pendingCommand = d.terminalInput;
            d.terminalLog.push_back(std::string("> ") + d.terminalInput);
            if (d.terminalLog.size() > 200)
                d.terminalLog.erase(d.terminalLog.begin());
            d.terminalNotif = (int)d.terminalLog.size();
            d.terminalInput[0] = '\0';
        }
    }
    ImGui::PopStyleColor(3);

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);


    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::BgTitle);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 7.0f);
    ImGui::BeginChild("##status", ImVec2(0, statusH), false,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPosY(5.0f);
    ImGui::SetCursorPosX(14.0f);
    detail::MiniMeter("CPU", d.cpu, col::Yellow);
    ImGui::SameLine(0, 18);
    detail::MiniMeter("RAM", d.ram, col::Red);
    ImGui::SameLine(0, 18);
    detail::MiniMeter("GPU", d.gpu, col::Green);
    ImGui::SameLine(0, 22);
    ImGui::TextColored(col::TextDim, "Speed Scan:");
    ImGui::SameLine(0, 6);
    ImGui::TextColored(col::Header, "%s", d.speedScan.c_str());
    ImGui::SameLine(0, 18);
    ImGui::TextColored(col::TextDim, "Scan:");
    ImGui::SameLine(0, 6);
    ImGui::TextColored(col::Header, "%d%%", (int)(d.scanProgress * 100.0f));
    ImGui::SameLine(0, 18);
    ImGui::TextColored(col::TextDim, "Aberto:");
    ImGui::SameLine(0, 6);
    ImGui::TextColored(col::Header, "%s", d.elapsed.c_str());


    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
}


inline float LoadingIntroDuration() {
    return kLoadingHoldSeconds + kLoadingMorphSeconds;
}

inline bool RenderLoadingOverlay(ScanData& d, float elapsedSeconds) {
    col::SetAccentColor(d.accentColor);

    const float total = LoadingIntroDuration();
    if (elapsedSeconds >= total)
        return false;

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImDrawList* dl = ImGui::GetForegroundDrawList();

    ImVec2 vpMin = vp->WorkPos;
    ImVec2 vpSize = vp->WorkSize;
    ImVec2 center(vpMin.x + vpSize.x * 0.5f, vpMin.y + vpSize.y * 0.5f);

    float enterT = detail::SmootherStep(detail::Saturate(elapsedSeconds / 0.36f));
    float pulse = 0.5f + 0.5f * std::sin(elapsedSeconds * 3.8f);
    float scale = detail::Lerp(0.97f, 1.0f, enterT);
    const ImVec2 compactSize(430.0f * scale, 238.0f * scale);
    const ImVec2 compactMin(center.x - compactSize.x * 0.5f,
                            center.y - compactSize.y * 0.5f);
    const ImVec2 compactMax(compactMin.x + compactSize.x, compactMin.y + compactSize.y);
    const float alpha = enterT;
    const ImVec4 loadAccent = col::Accent;

    float introProgress = detail::Lerp(0.10f, 0.90f, detail::SmootherStep(detail::Saturate(elapsedSeconds / total)));
    float scannerProgress = detail::Saturate(d.scanProgress) * 0.82f;
    float progress = introProgress > scannerProgress ? introProgress : scannerProgress;
    progress = detail::Saturate(progress);

    dl->AddRectFilled(vpMin, ImVec2(vpMin.x + vpSize.x, vpMin.y + vpSize.y),
                      detail::ColorAlpha(detail::LoadOnyx, alpha));
    dl->AddRectFilled(compactMin, compactMax,
                      detail::ColorAlpha(col::Panel, alpha), 8.0f);
    dl->AddRect(compactMin, compactMax,
                detail::ColorAlpha(col::Header, alpha * 0.10f), 8.0f);
    dl->AddRectFilled(compactMin, ImVec2(compactMax.x, compactMin.y + 2.0f),
                      detail::ColorAlpha(loadAccent, alpha * 0.90f), 8.0f,
                      ImDrawFlags_RoundCornersTop);

    const ImVec2 logoMin(compactMin.x + 28.0f, compactMin.y + 30.0f);
    const ImVec2 logoMax(logoMin.x + 54.0f, logoMin.y + 54.0f);
    if (d.logoTexture) {
        dl->AddImage((ImTextureID)d.logoTexture, logoMin, logoMax,
                     ImVec2(0, 0), ImVec2(1, 1),
                     detail::ColorAlpha(detail::LoadWhite, alpha));
    } else {
        detail::DrawTitleFallbackLogo(dl, logoMin, logoMax);
    }

    const float textX = logoMax.x + 20.0f;
    dl->AddText(ImGui::GetFont(), 24.0f, ImVec2(textX, compactMin.y + 31.0f),
                detail::ColorAlpha(detail::LoadWhite, alpha), "RXVScan");
    dl->AddText(ImVec2(textX, compactMin.y + 62.0f),
                detail::ColorAlpha(detail::LoadMuted, alpha),
                "Preparando o ambiente de verificacao");

    const char* stage =
        elapsedSeconds < 0.72f ? "Carregando interface" :
        elapsedSeconds < 1.45f ? "Inicializando modulos" :
                                 "Iniciando scanner";
    const float statusY = compactMin.y + 119.0f;
    dl->AddCircleFilled(ImVec2(compactMin.x + 31.0f, statusY + 7.0f),
                        3.0f, detail::ColorAlpha(loadAccent, alpha * (0.62f + pulse * 0.34f)), 16);
    dl->AddText(ImVec2(compactMin.x + 43.0f, statusY),
                detail::ColorAlpha(detail::LoadWhite, alpha * 0.90f), stage);

    char percentText[16] = {};
    snprintf(percentText, sizeof(percentText), "%d%%", (int)(progress * 100.0f));
    const ImVec2 percentSize = ImGui::CalcTextSize(percentText);
    dl->AddText(ImVec2(compactMax.x - percentSize.x - 28.0f, statusY),
                detail::ColorAlpha(detail::LoadMuted, alpha), percentText);

    const ImVec2 railMin(compactMin.x + 28.0f, compactMin.y + 157.0f);
    const ImVec2 railMax(compactMax.x - 28.0f, railMin.y + 6.0f);
    dl->AddRectFilled(railMin, railMax,
                      detail::ColorAlpha(detail::LoadWhite, alpha * 0.08f), 4.0f);
    dl->AddRectFilled(railMin,
                      ImVec2(railMin.x + (railMax.x - railMin.x) * progress, railMax.y),
                      detail::ColorAlpha(loadAccent, alpha * 0.92f), 4.0f);
    dl->AddLine(ImVec2(compactMin.x + 28.0f, compactMin.y + 190.0f),
                ImVec2(compactMax.x - 28.0f, compactMin.y + 190.0f),
                detail::ColorAlpha(detail::LoadWhite, alpha * 0.06f));
    dl->AddText(ImVec2(compactMin.x + 28.0f, compactMin.y + 203.0f),
                detail::ColorAlpha(detail::LoadMuted, alpha * 0.72f),
                "Verificando componentes locais e permissoes do sistema");

    return true;
}

// Janela final do scanner: apenas uma barra de progresso com o estagio atual.
// Os resultados completos sao enviados em tempo real para o site (aba ResultScan).
inline void RenderScanProgressOverlay(ScanData& d, void(*onClose)() = nullptr) {
    col::SetAccentColor(d.accentColor);

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImDrawList* dl = ImGui::GetForegroundDrawList();

    const ImVec2 winMin = vp->WorkPos;
    const ImVec2 winMax(winMin.x + vp->WorkSize.x, winMin.y + vp->WorkSize.y);
    const float now = (float)ImGui::GetTime();

    const bool failed = d.speedScan == "error";
    const bool finished = !failed && detail::Saturate(d.scanProgress) >= 1.0f;
    const float progress = detail::Saturate(d.scanProgress);
    const ImVec4 accent = failed ? col::Red : col::Accent;

    // fundo do cartao + leve grade animada + brilho percorrendo a borda
    dl->AddRectFilled(winMin, winMax, ImGui::GetColorU32(col::Panel), 8.0f);
    dl->PushClipRect(winMin, winMax, true);
    detail::DrawLoadingMicroGrid(dl, winMin, winMax, now, finished || failed ? 0.5f : 1.0f);
    dl->PopClipRect();
    dl->AddRect(winMin, winMax, detail::ColorAlpha(col::Header, 0.10f), 8.0f);
    if (!finished && !failed)
        detail::DrawLoadingBorderSweep(dl, winMin, winMax, now, 0.8f);
    detail::DrawLoadingCorners(dl, winMin, winMax, 18.0f, 0.35f);
    dl->AddRectFilled(winMin, ImVec2(winMax.x, winMin.y + 2.0f),
                      detail::ColorAlpha(accent, 0.90f), 8.0f, ImDrawFlags_RoundCornersTop);

    const ImVec2 logoMin(winMin.x + 28.0f, winMin.y + 30.0f);
    const ImVec2 logoMax(logoMin.x + 54.0f, logoMin.y + 54.0f);
    if (d.logoTexture) {
        dl->AddImage((ImTextureID)d.logoTexture, logoMin, logoMax,
                     ImVec2(0, 0), ImVec2(1, 1), ImGui::GetColorU32(detail::LoadWhite));
    } else {
        detail::DrawTitleFallbackLogo(dl, logoMin, logoMax);
    }

    const float textX = logoMax.x + 20.0f;
    dl->AddText(ImGui::GetFont(), 24.0f, ImVec2(textX, winMin.y + 31.0f),
                ImGui::GetColorU32(detail::LoadWhite), "RXVScan");
    dl->AddText(ImVec2(textX, winMin.y + 62.0f), ImGui::GetColorU32(detail::LoadMuted),
                failed ? "Falha durante a analise" : finished ? "Analise concluida" : "Analisando sua maquina");

    // botao de fechar no canto superior direito
    if (onClose) {
        const ImVec2 btnMax(winMax.x - 18.0f, winMin.y + 32.0f);
        const ImVec2 btnMin(btnMax.x - 22.0f, btnMax.y - 22.0f);
        ImGuiIO& io = ImGui::GetIO();
        const bool hover = io.MousePos.x >= btnMin.x && io.MousePos.x <= btnMax.x &&
                           io.MousePos.y >= btnMin.y && io.MousePos.y <= btnMax.y;
        if (hover)
            dl->AddRectFilled(btnMin, btnMax, detail::ColorAlpha(detail::LoadWhite, 0.08f), 5.0f);
        ImVec4 xColor = hover ? detail::LoadWhite : detail::LoadMuted;
        dl->AddLine(ImVec2(btnMin.x + 6.0f, btnMin.y + 6.0f), ImVec2(btnMax.x - 6.0f, btnMax.y - 6.0f),
                    ImGui::GetColorU32(xColor), 1.6f);
        dl->AddLine(ImVec2(btnMax.x - 6.0f, btnMin.y + 6.0f), ImVec2(btnMin.x + 6.0f, btnMax.y - 6.0f),
                    ImGui::GetColorU32(xColor), 1.6f);
        if (hover && io.MouseClicked[0])
            onClose();
    }

    dl->AddLine(ImVec2(winMin.x + 28.0f, winMin.y + 96.0f), ImVec2(winMax.x - 28.0f, winMin.y + 96.0f),
                detail::ColorAlpha(detail::LoadWhite, 0.06f));

    // linha de status: ponto pulsante + etapa atual + selo de porcentagem
    const float statusY = winMin.y + 119.0f;
    const float pulse = 0.5f + 0.5f * std::sin(now * 3.8f);
    dl->AddCircleFilled(ImVec2(winMin.x + 32.0f, statusY + 7.0f), 5.0f,
                        detail::ColorAlpha(accent, 0.16f), 16);
    dl->AddCircleFilled(ImVec2(winMin.x + 32.0f, statusY + 7.0f), 3.0f,
                        detail::ColorAlpha(accent, finished || failed ? 1.0f : (0.62f + pulse * 0.34f)), 16);
    dl->AddText(ImVec2(winMin.x + 46.0f, statusY), detail::ColorAlpha(detail::LoadWhite, 0.92f),
                d.currentStage.c_str());

    char percentText[16] = {};
    snprintf(percentText, sizeof(percentText), "%d%%", (int)(progress * 100.0f));
    const ImVec2 percentSize = ImGui::CalcTextSize(percentText);
    const ImVec2 badgeMax(winMax.x - 24.0f, statusY - 4.0f);
    const ImVec2 badgeMin(badgeMax.x - percentSize.x - 16.0f, badgeMax.y + 18.0f);
    dl->AddRectFilled(badgeMin, badgeMax, detail::ColorAlpha(accent, 0.14f), 4.0f);
    dl->AddRect(badgeMin, badgeMax, detail::ColorAlpha(accent, 0.30f), 4.0f);
    dl->AddText(ImVec2(badgeMin.x + 8.0f, statusY), detail::ColorAlpha(detail::LoadWhite, 0.92f), percentText);

    // barra de progresso com brilho na ponta
    const ImVec2 railMin(winMin.x + 28.0f, winMin.y + 157.0f);
    const ImVec2 railMax(winMax.x - 28.0f, railMin.y + 8.0f);
    dl->AddRectFilled(railMin, railMax, detail::ColorAlpha(detail::LoadWhite, 0.08f), 4.0f);
    const float fillX = railMin.x + (railMax.x - railMin.x) * progress;
    dl->AddRectFilled(railMin, ImVec2(fillX, railMax.y),
                      detail::ColorAlpha(accent, finished || failed ? 1.0f : 0.92f), 4.0f);
    if (!finished && !failed) {
        dl->AddCircleFilled(ImVec2(fillX, (railMin.y + railMax.y) * 0.5f), 6.0f,
                            detail::ColorAlpha(accent, 0.55f + pulse * 0.25f), 16);
    }
    dl->AddRect(railMin, railMax, detail::ColorAlpha(col::Header, 0.06f), 4.0f);

    // visualizacao de atividade ao vivo do scanner
    const ImVec2 activityMin(winMin.x + 28.0f, winMin.y + 192.0f);
    const ImVec2 activityMax(winMax.x - 28.0f, winMin.y + 318.0f);
    if (!finished && !failed) {
        detail::DrawLoadingSignalBars(dl, activityMin, activityMax, now, 0.85f);
        detail::DrawLoadingBeam(dl, activityMin, activityMax, now, 0.7f);
    } else {
        dl->AddText(ImVec2(activityMin.x, activityMin.y + (activityMax.y - activityMin.y) * 0.5f - 8.0f),
                    detail::ColorAlpha(detail::LoadMuted, 0.6f),
                    failed ? "Verificacao interrompida." : "Verificacao finalizada com sucesso.");
    }

    dl->AddLine(ImVec2(winMin.x + 28.0f, winMin.y + 338.0f), ImVec2(winMax.x - 28.0f, winMin.y + 338.0f),
                detail::ColorAlpha(detail::LoadWhite, 0.06f));
    dl->AddText(ImVec2(winMin.x + 28.0f, winMin.y + 352.0f),
                detail::ColorAlpha(detail::LoadMuted, 0.78f),
                finished
                    ? "Resultados completos disponiveis em rxvteam.com (aba ResultScan)"
                    : failed
                        ? "Os resultados parciais ja foram enviados para rxvteam.com (aba ResultScan)"
                        : "Os resultados sao enviados em tempo real para rxvteam.com (aba ResultScan)");
    dl->AddText(ImVec2(winMin.x + 28.0f, winMin.y + 374.0f),
                detail::ColorAlpha(detail::LoadMuted, 0.50f),
                "Nao feche esta janela durante a varredura.");
}

#if 0
inline void RenderLogin(ScanData& d, LoginState& auth,
                        void(*onMinimize)() = nullptr, void(*onClose)() = nullptr,
                        void(*onToggleTopmost)(bool) = nullptr) {
    (void)onToggleTopmost;
    col::SetAccentColor(d.accentColor);

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_NoScrollbar;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##rxvscan-login", nullptr, flags);
    ImGui::PopStyleVar();

    detail::DrawAppBackground(ImGui::GetWindowDrawList(), ImGui::GetWindowPos(),
                              ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowSize().x,
                                     ImGui::GetWindowPos().y + ImGui::GetWindowSize().y));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetWindowPos();
    const ImVec2 cardMax(p.x + ImGui::GetWindowWidth(), p.y + ImGui::GetWindowHeight());
    dl->AddRectFilled(p, cardMax, ImGui::GetColorU32(col::BgTitle), 8.0f);
    dl->AddRect(p, cardMax, detail::ColorAlpha(col::Header, 0.10f), 8.0f);
    dl->AddRectFilled(p, ImVec2(cardMax.x, p.y + 2.0f),
                      ImGui::GetColorU32(col::Accent), 8.0f,
                      ImDrawFlags_RoundCornersTop);

    const ImVec2 logoMin(p.x + 26.0f, p.y + 24.0f);
    const ImVec2 logoMax(logoMin.x + 46.0f, logoMin.y + 46.0f);
    if (d.logoTexture)
        dl->AddImage((ImTextureID)d.logoTexture, logoMin, logoMax);
    else
        detail::DrawTitleFallbackLogo(dl, logoMin, logoMax);

    dl->AddText(ImGui::GetFont(), 21.0f, ImVec2(p.x + 88.0f, p.y + 24.0f),
                ImGui::GetColorU32(col::Header), "RXVScan");
    dl->AddText(ImVec2(p.x + 88.0f, p.y + 53.0f),
                ImGui::GetColorU32(col::TextDim), "Acesso seguro ao scanner");

    const ImVec4 connectionColor = auth.pinSent ? col::Green :
                                   (auth.sending ? col::Yellow : col::Red);
    const char* connectionText = auth.pinSent ? "PIN DISPONIVEL" :
                                 (auth.sending ? "CONECTANDO" : "AGUARDANDO");
    const ImVec2 connectionSize = ImGui::CalcTextSize(connectionText);
    const ImVec2 connectionMin(cardMax.x - connectionSize.x - 48.0f, p.y + 53.0f);
    dl->AddCircleFilled(ImVec2(connectionMin.x, connectionMin.y + 7.0f),
                        3.0f, ImGui::GetColorU32(connectionColor), 16);
    dl->AddText(ImVec2(connectionMin.x + 10.0f, connectionMin.y),
                ImGui::GetColorU32(connectionColor), connectionText);

    dl->AddLine(ImVec2(p.x + 24.0f, p.y + 88.0f),
                ImVec2(cardMax.x - 24.0f, p.y + 88.0f),
                detail::ColorAlpha(col::Header, 0.08f));

    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 78.0f, 14.0f));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, detail::ColorAlpha(col::Header, 0.08f));
    if (ImGui::Button("-##login-min", ImVec2(29.0f, 27.0f)) && onMinimize)
        onMinimize();
    ImGui::SameLine(0.0f, 3.0f);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, detail::ColorAlpha(col::Red, 0.22f));
    if (ImGui::Button("X##login-close", ImVec2(29.0f, 27.0f)) && onClose)
        onClose();
    ImGui::PopStyleColor(3);

    ImGui::SetCursorPos(ImVec2(24.0f, 104.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, detail::ColorAlpha(col::PanelSoft, 0.48f));
    ImGui::PushStyleColor(ImGuiCol_Border, detail::ColorAlpha(col::Header, 0.08f));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(15.0f, 12.0f));
    ImGui::BeginChild("##login-identity", ImVec2(ImGui::GetWindowWidth() - 48.0f, 76.0f),
                      true, ImGuiWindowFlags_NoScrollbar);
    if (ImGui::BeginTable("##login-identity-grid", 2,
                          ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoHostExtendX)) {
        ImGui::TableSetupColumn("device", ImGuiTableColumnFlags_WidthStretch, 0.36f);
        ImGui::TableSetupColumn("hwid", ImGuiTableColumnFlags_WidthStretch, 0.64f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "DISPOSITIVO");
        ImGui::TextColored(col::Header, "%s", d.device.empty() ? "-" : d.device.c_str());
        ImGui::TableNextColumn();
        ImGui::TextColored(col::TextDim, "IDENTIFICACAO");
        const std::string shownHwid = d.hwid.empty() ? "-" : detail::CompactText(d.hwid, 38);
        ImGui::TextColored(d.hwidWarning.empty() ? col::Header : col::Yellow,
                           "%s", shownHwid.c_str());
        if (!d.hwid.empty() && ImGui::IsItemHovered()) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            ImGui::SetTooltip("%s\nClique para copiar", d.hwid.c_str());
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                ImGui::SetClipboardText(d.hwid.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);

    ImGui::SetCursorPos(ImVec2(24.0f, 198.0f));
    ImGui::TextColored(col::Header, "Codigo de verificacao");
    ImGui::TextColored(col::TextDim, "Insira o PIN de 6 digitos enviado para autorizar o acesso.");
    ImGui::Dummy(ImVec2(0.0f, 5.0f));
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - 48.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14.0f, 11.0f));
    ImGui::InputTextWithHint("##login-pin", "000000", auth.pinInput, sizeof(auth.pinInput),
                             ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_Password |
                             ImGuiInputTextFlags_EnterReturnsTrue);
    const bool enterPressed = ImGui::IsItemDeactivatedAfterEdit() &&
                              ImGui::IsKeyPressed(ImGuiKey_Enter);
    ImGui::PopStyleVar();

    ImGui::Dummy(ImVec2(0.0f, 5.0f));
    ImGui::TextColored(auth.authenticated ? col::Green :
                       (auth.pinSent ? col::Green :
                        (auth.sending ? col::Yellow : col::Red)),
                       "%s", auth.status.c_str());
    if (auth.pinSent && auth.secondsRemaining > 0) {
        ImGui::SameLine();
        ImGui::TextColored(col::TextDim, "(%02d:%02d)",
                           auth.secondsRemaining / 60, auth.secondsRemaining % 60);
    }
    ImGui::Dummy(ImVec2(0.0f, 8.0f));

    ImGui::BeginDisabled(auth.sending || !auth.pinSent || std::strlen(auth.pinInput) != 6);
    ImGui::PushStyleColor(ImGuiCol_Button, detail::Mix(col::PanelLift, col::Accent, 0.14f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, detail::Mix(col::PanelLift, col::Accent, 0.24f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, detail::Mix(col::PanelLift, col::Accent, 0.34f));
    if (ImGui::Button("Verificar e continuar",
                      ImVec2(ImGui::GetWindowWidth() - 48.0f, 42.0f)) || enterPressed)
        auth.verifyRequested = true;
    ImGui::PopStyleColor(3);
    ImGui::EndDisabled();

    ImGui::Dummy(ImVec2(0.0f, 8.0f));
    ImGui::TextColored(col::TextDim, "%d tentativas restantes", auth.attemptsRemaining);
    ImGui::SameLine(ImGui::GetWindowWidth() - 142.0f);
    ImGui::BeginDisabled(auth.sending);
    if (ImGui::SmallButton("Reenviar codigo"))
        auth.sendRequested = true;
    ImGui::EndDisabled();

    ImGui::End();
}
#endif

inline void DrawMonitorIcon(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                            ImU32 color) {
    const float w = max.x - min.x;
    const float h = max.y - min.y;
    const float thickness = 1.8f;
    const ImVec2 screenMin(min.x + w * 0.10f, min.y + h * 0.12f);
    const ImVec2 screenMax(max.x - w * 0.10f, min.y + h * 0.70f);
    dl->AddRect(screenMin, screenMax, color, 3.0f, 0, thickness);
    dl->AddLine(ImVec2(min.x + w * 0.50f, screenMax.y),
                ImVec2(min.x + w * 0.50f, min.y + h * 0.84f), color, thickness);
    dl->AddLine(ImVec2(min.x + w * 0.31f, min.y + h * 0.86f),
                ImVec2(min.x + w * 0.69f, min.y + h * 0.86f), color, thickness);
}

inline void DrawUsbIcon(ImDrawList* dl, const ImVec2& min, const ImVec2& max,
                        ImU32 color) {
    const float w = max.x - min.x;
    const float h = max.y - min.y;
    const float thickness = 1.8f;
    const ImVec2 bodyMin(min.x + w * 0.18f, min.y + h * 0.34f);
    const ImVec2 bodyMax(min.x + w * 0.72f, min.y + h * 0.78f);
    dl->AddRect(bodyMin, bodyMax, color, 3.0f, 0, thickness);
    const ImVec2 plugMin(min.x + w * 0.72f, min.y + h * 0.43f);
    const ImVec2 plugMax(min.x + w * 0.91f, min.y + h * 0.69f);
    dl->AddRect(plugMin, plugMax, color, 1.5f, 0, thickness);
    dl->AddLine(ImVec2(min.x + w * 0.79f, plugMin.y),
                ImVec2(min.x + w * 0.79f, plugMin.y - h * 0.10f), color, thickness);
    dl->AddLine(ImVec2(min.x + w * 0.86f, plugMin.y),
                ImVec2(min.x + w * 0.86f, plugMin.y - h * 0.10f), color, thickness);
    dl->AddCircleFilled(ImVec2(min.x + w * 0.34f, min.y + h * 0.56f),
                        1.8f, color, 12);
}

inline bool MainNavigationItem(const char* id, const char* label, const char* caption,
                               int count, bool active, const ImVec4& stateColor,
                               float width, void* iconTexture = nullptr,
                               bool monitorFallback = false) {
    ImGui::PushID(id);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float h = 58.0f;
    ImGui::InvisibleButton("##main-nav", ImVec2(width, h));
    const bool hovered = ImGui::IsItemHovered();
    const bool clicked = ImGui::IsItemClicked();
    if (hovered)
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (hovered || active) {
        dl->AddRectFilled(p, ImVec2(p.x + width, p.y + h),
                          detail::ColorAlpha(col::PanelSoft, active ? 0.72f : 0.42f),
                          4.0f);
    }
    if (active) {
        dl->AddRectFilled(ImVec2(p.x + 12.0f, p.y + h - 2.0f),
                          ImVec2(p.x + width - 12.0f, p.y + h),
                          ImGui::GetColorU32(stateColor), 2.0f);
    }

    float textX = p.x + 28.0f;
    if (iconTexture || monitorFallback) {
        const ImVec2 iconMin(p.x + 10.0f, p.y + 8.0f);
        const ImVec2 iconMax(p.x + 46.0f, p.y + 44.0f);
        if (iconTexture) {
            dl->AddImageRounded((ImTextureID)iconTexture, iconMin, iconMax,
                                ImVec2(0.08f, 0.08f), ImVec2(0.92f, 0.92f),
                                IM_COL32_WHITE, 5.0f);
        } else {
            DrawMonitorIcon(dl, iconMin, iconMax,
                            ImGui::GetColorU32(active ? col::Header : col::Text));
        }
        textX = p.x + 56.0f;
    } else {
        dl->AddCircleFilled(ImVec2(p.x + 16.0f, p.y + 20.0f), 3.2f,
                            detail::ColorAlpha(stateColor, active ? 1.0f : 0.72f), 16);
    }
    dl->AddText(ImVec2(textX, p.y + 10.0f),
                ImGui::GetColorU32(active ? col::Header : col::Text), label);
    dl->AddText(ImVec2((iconTexture || monitorFallback) ? textX : p.x + 15.0f, p.y + 35.0f),
                ImGui::GetColorU32(col::TextDim), caption);

    const std::string countText = std::to_string(count);
    const ImVec2 countSize = ImGui::CalcTextSize(countText.c_str());
    dl->AddText(ImVec2(p.x + width - countSize.x - 15.0f, p.y + 10.0f),
                ImGui::GetColorU32(count > 0 ? stateColor : col::TextDim),
                countText.c_str());
    ImGui::PopID();
    return clicked;
}

inline bool SubNavigationItem(const char* id, const char* label, int count,
                              bool active, float width) {
    ImGui::PushID(id);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float h = 39.0f;
    ImGui::InvisibleButton("##sub-nav", ImVec2(width, h));
    const bool hovered = ImGui::IsItemHovered();
    const bool clicked = ImGui::IsItemClicked();
    if (hovered)
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (active || hovered)
        dl->AddRectFilled(p, ImVec2(p.x + width, p.y + h),
                          detail::ColorAlpha(col::PanelSoft, active ? 0.62f : 0.32f), 4.0f);
    dl->AddText(ImVec2(p.x + 13.0f, p.y + 10.0f),
                ImGui::GetColorU32(active ? col::Header : col::TextDim), label);
    const std::string countText = std::to_string(count);
    const ImVec2 countSize = ImGui::CalcTextSize(countText.c_str());
    dl->AddText(ImVec2(p.x + width - countSize.x - 13.0f, p.y + 10.0f),
                ImGui::GetColorU32(active ? col::Text : col::TextDim), countText.c_str());
    ImGui::PopID();
    return clicked;
}

inline void DrawMainScannerSections(ScanData& d) {
    const int archiveCount = (int)d.bam.size();
    const int emuCount = (int)d.emulatorFindings.size();
    const int winCount = (int)(d.systemMemoryFindings.size() + d.kernelAnomalies.size());
    const int bypassCount = (int)(d.genericBypass.size() + d.streamModFindings.size() +
                                  d.remotePortFindings.size());
    const float sectionWidth = ImGui::GetContentRegionAvail().x;

    MainNavigationItem("archives", "Archives \xF0\x9F\x93\x82", "Arquivos detectados", archiveCount,
                       true, archiveCount ? col::Yellow : col::Green, sectionWidth);
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    DrawBam(d);
    ImGui::Dummy(ImVec2(0.0f, 10.0f));

    MainNavigationItem("emu", "Emu Checker", "Deteccoes do emulador", emuCount,
                       true, detail::StatusColor(d.emulatorStatus, emuCount),
                       sectionWidth, d.emuIconTexture, true);
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    DrawEmulator(d);
    ImGui::Dummy(ImVec2(0.0f, 10.0f));

    MainNavigationItem("winscan", "WinScan", "Deteccoes de memoria e kernel", winCount,
                       true, detail::StatusColor(d.systemMemoryStatus, winCount),
                       sectionWidth, d.winScanIconTexture);
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    DrawSystemMemory(d);
    ImGui::Dummy(ImVec2(0.0f, 10.0f));

    MainNavigationItem("bypass", "Generic Bypass \xF0\x9F\x9A\xA8", "Deteccoes de hooks e acessos",
                       bypassCount, true,
                       detail::StatusColor(d.genericBypassStatus, bypassCount),
                       sectionWidth);
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    DrawGenericBypass(d);
}

inline bool ShortcutButton(const char* id, const char* label, void* texture,
                           bool active, const ImVec2& size) {
    ImGui::PushID(id);
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##shortcut", size);
    const bool hovered = ImGui::IsItemHovered();
    const bool clicked = ImGui::IsItemClicked();
    if (hovered)
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 rectMax(p.x + size.x, p.y + size.y);
    if (active || hovered)
        dl->AddRectFilled(p, rectMax,
                          detail::ColorAlpha(col::PanelSoft, active ? 0.78f : 0.46f), 5.0f);
    dl->AddRect(p, rectMax,
                detail::ColorAlpha(active ? col::Accent : col::Header,
                                   active ? 0.32f : 0.08f), 5.0f);
    if (active)
        dl->AddRectFilled(ImVec2(p.x + 10.0f, rectMax.y - 2.0f),
                          ImVec2(rectMax.x - 10.0f, rectMax.y),
                          ImGui::GetColorU32(col::Accent), 2.0f);

    const float iconSize = size.y - 10.0f;
    const ImVec2 iconMin(p.x + 8.0f, p.y + 5.0f);
    const ImVec2 iconMax(iconMin.x + iconSize, iconMin.y + iconSize);
    dl->AddRectFilled(ImVec2(iconMin.x - 2.0f, iconMin.y - 2.0f),
                      ImVec2(iconMax.x + 2.0f, iconMax.y + 2.0f),
                      detail::ColorAlpha(col::Header, active ? 0.13f : 0.08f), 7.0f);
    dl->AddRect(ImVec2(iconMin.x - 2.0f, iconMin.y - 2.0f),
                ImVec2(iconMax.x + 2.0f, iconMax.y + 2.0f),
                detail::ColorAlpha(active ? col::Accent : col::Header,
                                   active ? 0.40f : 0.14f), 7.0f);
    if (texture) {
        dl->AddImageRounded((ImTextureID)texture, iconMin, iconMax,
                            ImVec2(0.16f, 0.16f), ImVec2(0.84f, 0.84f),
                            IM_COL32_WHITE, 5.0f);
    } else if (strcmp(id, "efi-checker") == 0) {
        DrawUsbIcon(dl, iconMin, iconMax, ImGui::GetColorU32(col::Header));
    } else {
        dl->AddRect(iconMin, iconMax, detail::ColorAlpha(col::Header, 0.18f), 5.0f);
        dl->AddCircleFilled(ImVec2((iconMin.x + iconMax.x) * 0.5f,
                                   (iconMin.y + iconMax.y) * 0.5f),
                            3.0f, ImGui::GetColorU32(col::Accent), 16);
    }
    dl->AddText(ImVec2(iconMax.x + 13.0f, p.y + (size.y - ImGui::GetTextLineHeight()) * 0.5f),
                ImGui::GetColorU32(active ? col::Header : col::Text), label);
    ImGui::PopID();
    return clicked;
}

inline void DrawShortcutBar(ScanData& d) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, col::BgTitle);
    ImGui::PushStyleColor(ImGuiCol_Border, col::Sep);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 7.0f));
    ImGui::BeginChild("##shortcut-bar", ImVec2(0.0f, 68.0f), true,
                      ImGuiWindowFlags_NoScrollbar);

    if (ShortcutButton("general", "General", d.generalIconTexture,
                       d.activePage == 1, ImVec2(162.0f, 52.0f)))
        d.activePage = 1;
    ImGui::SameLine(0.0f, 6.0f);
    if (ShortcutButton("sysmon", "Sysmon", d.sysmonIconTexture,
                       d.activePage == 9, ImVec2(162.0f, 52.0f)))
        d.activePage = 9;
    ImGui::SameLine(0.0f, 6.0f);
    if (ShortcutButton("efi-checker", "EFI Checker", d.efiIconTexture,
                       d.activePage == 2, ImVec2(198.0f, 52.0f)))
        d.activePage = 2;
    ImGui::SameLine(0.0f, 6.0f);
    if (ShortcutButton("kernel-scan", "Kernel Scan", d.kernelScanIconTexture,
                       d.activePage == 3, ImVec2(198.0f, 52.0f)))
        d.activePage = 3;

    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
    ImGui::Dummy(ImVec2(0.0f, 5.0f));
}




inline void Render(ScanData& d, void(*onMinimize)() = nullptr, void(*onClose)() = nullptr,
                   void(*onToggleTopmost)(bool) = nullptr) {
    col::SetAccentColor(d.accentColor);

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_NoScrollbar;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##rxvscan", nullptr, flags);
    ImGui::PopStyleVar();

    detail::DrawAppBackground(ImGui::GetWindowDrawList(), ImGui::GetWindowPos(),
                              ImVec2(ImGui::GetWindowPos().x + ImGui::GetWindowSize().x,
                                     ImGui::GetWindowPos().y + ImGui::GetWindowSize().y));
    detail::DrawAnimatedScannerBorder(ImGui::GetWindowPos(), ImGui::GetWindowSize());

    TitleBar(d, onMinimize, onClose, onToggleTopmost);


    const float terminalHeight = d.terminalExpanded ? kTerminalExpandedH : kTerminalH;
    float reserved = terminalHeight + kStatusH + 18.0f;
    const float bodyHeight = ImGui::GetWindowHeight() - ImGui::GetCursorPosY() - reserved;
    ImGui::SetCursorPosX(kOuterPad);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::BeginChild("##workspace",
                      ImVec2(ImGui::GetWindowWidth() - kOuterPad * 2.0f, bodyHeight),
                      false, ImGuiWindowFlags_NoScrollbar);
    ImGui::PopStyleVar();

    DrawSidebar(d, bodyHeight);
    ImGui::SameLine(0.0f, kBodyGap);

    ImGuiWindowFlags contentFlags = ImGuiWindowFlags_AlwaysVerticalScrollbar;
    ImGui::BeginChild("##content", ImVec2(0.0f, bodyHeight), false, contentFlags);
    DrawShortcutBar(d);
    if (d.activePage == 2) {
        DrawEfiCheatDetect(d);
    } else if (d.activePage == 3) {
        DrawDriverIntegrity(d);
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        DrawKernelDrivers(d);
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        DrawKernelAnomalies(d);
    } else if (d.activePage == 9) {
        DrawSysmonInspector(d);
    } else {
        DrawMainScannerSections(d);
    }

    ImGui::EndChild();
    ImGui::EndChild();

    ImGui::SetCursorPosX(kOuterPad);
    ImGui::SetNextItemWidth(ImGui::GetWindowWidth() - kOuterPad * 2.0f);
    ImGui::BeginGroup();
    DrawBottom(d);
    ImGui::EndGroup();

    ImGui::End();
}




inline ScanData MakeSampleData() {
    ScanData d;
    d.services = {
        {"Sysmon", true}, {"SysMain", true}, {"EventLog", true}, {"BAM", true},
        {"TPM 2.0", true}, {"SecureBoot", true}, {"IOMMU", false}, {"DPS", false},
        {"PcaSvc", true}, {"PlugPlay", true}, {"DiagTrack", true}, {"Firewall", true},
        {"Windows Defender", true},
    };
    d.hwid = "88800626cc766a20f1f4b85bc8ff176cc0095a43db0ca1433cfaf8d1816840b";
    d.hwidWarning = "HWID Default String: BIOS serial: Default String | BaseBoard serial: Default String";
    d.boot        = "28/05/2026 23:01:43";
    d.explorer    = "28/05/2026 23:01:57";
    d.biosVersion = "F7 DB, 24/06/2021";
    d.biosMode    = "UEFI";
    d.osVersion   = "Windows 10 Pro 22H2 (10.0.19045.6466)";
    d.device      = "DESKTOP-RJI7MOG";
    d.pagefile    = "C:\\pagefile.sys";
    d.sysType     = "x64";
    d.bam = {
        {"29/05/2026", "02:38:09", "C:\\Users\\iago\\Desktop\\scaN.exe", "UNSIGNED", "entropy 7.80 (packed)", "UserProfile", true},
        {"28/05/2026", "23:09:27", "C:\\Users\\iago\\Downloads\\MacroRunner\\2.11.0.0\\macro_runner.exe", "DELETED", "removed after boot", "UserProfile", true},
    };
    d.prefetchHits = 2;
    d.prefetch = {
        {"15/05/2026", "13:39:06", "MEDIUM", "generic rotating loader alias",
         "LGHUB_SOFTWARE_MANAGER.EXE-50C2E978.pf", "Known Rotating Cheat Loader Alias"},
        {"05/05/2026", "14:15:37", "MEDIUM", "generic rotating loader alias",
         "LGHUB_SOFTWARE_MANAGER.EXE-9EC66FD3.pf", "Known Rotating Cheat Loader Alias"},
    };
    d.usnStatus = "NTFS: OK | Journal: OK";
    d.usnDrive  = "C:\\ [NTFS] - Ativo | First Entry: 26/05/2026 23:58:27";
    d.sysmonStatus = "Loaded after boot";
    // 32 synthetic events spanning IDs 1/6/7/8/10/13/22, 4 processes, two
    // clusters at 14:02 and 14:47, and at least one trigger for each severity
    // tier so the Triage view (histogram + offenders + sev coloring) is testable
    // without a live Sysmon channel.
    auto E = [](const char* time, int id, const char* type,
                const char* process, const char* detail,
                const char* parent = "", const char* cmd = "",
                const char* user = "", const char* image = "",
                const char* reg = "", const char* dns = "",
                const char* src = "", const char* tgt = "",
                const char* access = "", const char* calltrace = "") {
        SysmonEvent e;
        e.date = "29/05/2026"; e.time = time;
        e.eventId = id; e.type = type; e.process = process; e.detail = detail;
        e.parentProcess = parent; e.commandLine = cmd; e.user = user;
        e.imageLoaded = image; e.registryObject = reg; e.queryName = dns;
        e.sourceProcess = src; e.targetProcess = tgt;
        e.access = access; e.callTrace = calltrace;
        return e;
    };
    d.sysmonEvents = {
        // 14:02 cluster — explorer routine
        E("14:02:08", 1, "Process Create", "C:\\Windows\\explorer.exe", "started",
          "C:\\Windows\\System32\\userinit.exe", "C:\\Windows\\explorer.exe", "DESKTOP\\iago"),
        E("14:02:11", 7, "Image Loaded", "C:\\Windows\\explorer.exe", "shell32.dll",
          "", "", "", "C:\\Windows\\System32\\shell32.dll"),
        E("14:02:14", 22, "DNS Query", "C:\\Windows\\explorer.exe", "lookup",
          "", "", "", "", "", "msftconnecttest.com"),
        E("14:02:21", 6, "Driver Loaded", "C:\\Windows\\System32\\svchost.exe", "tcpip.sys",
          "", "", "", "C:\\Windows\\System32\\drivers\\tcpip.sys"),
        E("14:02:33", 13, "Registry Set", "C:\\Windows\\explorer.exe", "user pref",
          "", "", "", "", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"),
        E("14:02:48", 1, "Process Create", "C:\\Windows\\System32\\notepad.exe", "spawned",
          "C:\\Windows\\explorer.exe", "notepad.exe", "DESKTOP\\iago"),
        // 14:47 spike — cheat.exe + powershell suspicious
        E("14:47:02", 1, "Process Create", "C:\\Users\\iago\\Downloads\\cheat.exe", "spawned",
          "C:\\Windows\\explorer.exe", "cheat.exe --inject", "DESKTOP\\iago"),
        E("14:47:03", 7, "Image Loaded", "C:\\Users\\iago\\Downloads\\cheat.exe", "rare runtime",
          "", "", "", "C:\\Users\\iago\\AppData\\Local\\Temp\\rxstub.dll"),
        E("14:47:04", 22, "DNS Query", "C:\\Users\\iago\\Downloads\\cheat.exe", "C2 lookup",
          "", "", "", "", "", "194.5.97.12"),
        E("14:47:05", 22, "DNS Query", "C:\\Users\\iago\\Downloads\\cheat.exe", "exfil channel",
          "", "", "", "", "", "panel.darkops.xyz"),
        E("14:47:06", 13, "Registry Set", "C:\\Users\\iago\\Downloads\\cheat.exe", "persistence",
          "", "", "", "", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\rxstub"),
        E("14:47:07", 8, "CreateRemoteThread", "C:\\Users\\iago\\Downloads\\cheat.exe", "remote thread",
          "", "", "", "", "", "", "C:\\Users\\iago\\Downloads\\cheat.exe",
          "C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe", "", "0x00007FFC5A11C0A0"),
        E("14:47:08", 10, "Process Access", "C:\\Users\\iago\\Downloads\\cheat.exe", "VM_WRITE",
          "", "", "", "", "", "", "C:\\Users\\iago\\Downloads\\cheat.exe",
          "C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe", "0x1F0FFF",
          "C:\\Windows\\System32\\ntdll.dll+0x9d1e4|UNKNOWN(0x1f3b0)"),
        E("14:47:09", 10, "Process Access", "C:\\Users\\iago\\Downloads\\cheat.exe", "VM_READ",
          "", "", "", "", "", "", "C:\\Users\\iago\\Downloads\\cheat.exe",
          "C:\\Program Files\\BlueStacks_nxt\\HD-Player.exe", "0x0010",
          "C:\\Windows\\System32\\ntdll.dll+0x9d1e4|C:\\Windows\\System32\\KernelBase.dll+0x1234"),
        E("14:47:12", 1, "Process Create", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "encoded command",
          "C:\\Users\\iago\\Downloads\\cheat.exe",
          "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA",
          "DESKTOP\\iago"),
        E("14:47:13", 22, "DNS Query", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "exfil", "", "", "", "", "", "exfil.darkops.top"),
        E("14:47:14", 7, "Image Loaded", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "Temp DLL", "", "", "", "C:\\Users\\iago\\AppData\\Local\\Temp\\rxstub2.dll"),
        E("14:47:15", 13, "Registry Set",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "AppInit hook",
          "", "", "", "",
          "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"),
        E("14:47:16", 1, "Process Create", "C:\\Windows\\System32\\cmd.exe", "shell spawn",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "cmd /c whoami", "DESKTOP\\iago"),
        E("14:47:18", 6, "Driver Loaded", "C:\\Users\\iago\\Downloads\\cheat.exe", "kernel driver",
          "", "", "", "C:\\Users\\iago\\AppData\\Local\\Temp\\rxhv.sys"),
        E("14:47:20", 8, "CreateRemoteThread", "C:\\Users\\iago\\Downloads\\cheat.exe", "second thread",
          "", "", "", "", "", "", "C:\\Users\\iago\\Downloads\\cheat.exe",
          "C:\\Windows\\System32\\lsass.exe", "", "0x00007FFC5A11E110"),
        E("14:47:22", 10, "Process Access", "C:\\Users\\iago\\Downloads\\cheat.exe", "lsass dump",
          "", "", "", "", "", "", "C:\\Users\\iago\\Downloads\\cheat.exe",
          "C:\\Windows\\System32\\lsass.exe", "0x1FFFFF",
          "C:\\Windows\\System32\\ntdll.dll+0x9d1e4|UNKNOWN(0x4080)"),
        // Mid-range chatter to give the histogram texture
        E("14:18:02", 7, "Image Loaded", "C:\\Windows\\System32\\svchost.exe", "iphlpapi.dll",
          "", "", "", "C:\\Windows\\System32\\iphlpapi.dll"),
        E("14:25:11", 22, "DNS Query", "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "cdn lookup",
          "", "", "", "", "", "cdn.mozilla.net"),
        E("14:31:44", 1, "Process Create", "C:\\Windows\\System32\\conhost.exe", "console host",
          "C:\\Windows\\System32\\cmd.exe", "\\??\\C:\\Windows\\System32\\conhost.exe", "DESKTOP\\iago"),
        E("14:34:05", 13, "Registry Set", "C:\\Windows\\explorer.exe", "MRU update",
          "", "", "", "", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"),
        E("14:38:29", 6, "Driver Loaded", "C:\\Windows\\System32\\svchost.exe", "audio driver",
          "", "", "", "C:\\Windows\\System32\\drivers\\portcls.sys"),
        E("14:42:17", 22, "DNS Query", "C:\\Windows\\explorer.exe", "msft telemetry",
          "", "", "", "", "", "vortex.data.microsoft.com"),
        E("14:50:01", 7, "Image Loaded", "C:\\Windows\\System32\\svchost.exe", "wlan svc",
          "", "", "", "C:\\Windows\\System32\\wlansvc.dll"),
        E("14:50:42", 22, "DNS Query", "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "lookup",
          "", "", "", "", "", "telemetry.mozilla.org"),
        E("14:53:18", 1, "Process Create", "C:\\Windows\\System32\\taskhostw.exe", "task host",
          "C:\\Windows\\System32\\svchost.exe", "taskhostw.exe", "DESKTOP\\iago"),
        E("14:55:02", 13, "Registry Set", "C:\\Windows\\System32\\svchost.exe", "service state",
          "", "", "", "", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters"),
    };
    d.emulatorChecking = false;
    d.emulatorProgress = 0.55f;
    d.emulatorResult = "No emulator integrity issues found";
    d.emulatorStatus = "OK";
    d.emulatorOpenedAt = "29/05/2026 02:40:00";
    d.emulatorFindings = {};
    d.genericBypassStatus = "Waiting";
    d.genericBypass = {};
    d.efiCheatStatus = "Waiting";
    d.efiCheats = {};
    d.terminalLog = {};
    d.terminalNotif = 1;
    return d;
}

}
