











#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include <d3d11.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <atomic>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <tchar.h>
#include <vector>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <tbs.h>
#include <winioctl.h>
#include <winsvc.h>
#include <wintrust.h>
#include <winevt.h>
#include <ncrypt.h>

#include "scanner_ui.h"
#include "detection_filters.h"
#include "resource.h"
#include "scanner_core.h"
#include "scanner_selfprotect.h"

#include <wincodec.h>
#pragma comment(lib, "windowscodecs.lib")

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")


static ID3D11Device*           g_pd3dDevice          = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext   = nullptr;
static IDXGISwapChain*         g_pSwapChain          = nullptr;
static UINT                    g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static HWND                    g_hWnd = nullptr;
std::atomic_bool        g_scanSlow = false;
std::atomic_bool        g_scanFinished = false;
std::atomic_int         g_scanTier = static_cast<int>(ScanTier::Light);

struct RuntimeUsage {
    int cpu = 0;
    int ram = 0;
    int gpu = 0;
    ScanTier tier = ScanTier::Light;
};

class RuntimeUsageSampler {
public:
    RuntimeUsageSampler() {
        GetSystemTimes(&lastIdle_, &lastKernel_, &lastUser_);
        if (PdhOpenQueryW(nullptr, 0, &gpuQuery_) == ERROR_SUCCESS) {
            if (PdhAddEnglishCounterW(gpuQuery_, L"\\GPU Engine(*)\\Utilization Percentage", 0, &gpuCounter_) == ERROR_SUCCESS) {
                gpuReady_ = true;
                PdhCollectQueryData(gpuQuery_);
            }
        }
    }

    ~RuntimeUsageSampler() {
        if (gpuQuery_)
            PdhCloseQuery(gpuQuery_);
    }

    RuntimeUsage Sample() {
        RuntimeUsage usage;
        usage.cpu = SampleCpu();
        usage.ram = SampleRam();
        usage.gpu = SampleGpu();
        if (usage.cpu >= 85 || usage.ram >= 90 || usage.gpu >= 90)
            usage.tier = ScanTier::Overloaded;
        else if (usage.cpu >= 60 || usage.ram >= 75 || usage.gpu >= 70)
            usage.tier = ScanTier::Busy;
        else
            usage.tier = ScanTier::Light;
        return usage;
    }

private:
    static ULONGLONG FtToU64(const FILETIME& ft) {
        ULARGE_INTEGER value = {};
        value.LowPart = ft.dwLowDateTime;
        value.HighPart = ft.dwHighDateTime;
        return value.QuadPart;
    }

    int SampleCpu() {
        FILETIME idle = {}, kernel = {}, user = {};
        if (!GetSystemTimes(&idle, &kernel, &user))
            return 0;

        ULONGLONG idleDelta = FtToU64(idle) - FtToU64(lastIdle_);
        ULONGLONG kernelDelta = FtToU64(kernel) - FtToU64(lastKernel_);
        ULONGLONG userDelta = FtToU64(user) - FtToU64(lastUser_);
        ULONGLONG total = kernelDelta + userDelta;

        lastIdle_ = idle;
        lastKernel_ = kernel;
        lastUser_ = user;

        if (total == 0)
            return lastCpu_;

        int cpu = (int)(((total - idleDelta) * 100ULL) / total);
        lastCpu_ = std::clamp(cpu, 0, 100);
        return lastCpu_;
    }

    int SampleRam() const {
        MEMORYSTATUSEX mem = {};
        mem.dwLength = sizeof(mem);
        if (!GlobalMemoryStatusEx(&mem))
            return 0;
        return std::clamp((int)mem.dwMemoryLoad, 0, 100);
    }

    int SampleGpu() {
        if (!gpuReady_)
            return lastGpu_;

        if (PdhCollectQueryData(gpuQuery_) != ERROR_SUCCESS)
            return lastGpu_;

        DWORD bufferSize = 0;
        DWORD itemCount = 0;
        PDH_STATUS status = PdhGetFormattedCounterArrayW(gpuCounter_, PDH_FMT_DOUBLE, &bufferSize, &itemCount, nullptr);
        if (status != PDH_MORE_DATA || bufferSize == 0)
            return lastGpu_;

        std::vector<BYTE> buffer(bufferSize);
        auto items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buffer.data());
        status = PdhGetFormattedCounterArrayW(gpuCounter_, PDH_FMT_DOUBLE, &bufferSize, &itemCount, items);
        if (status != ERROR_SUCCESS)
            return lastGpu_;

        double total = 0.0;
        for (DWORD i = 0; i < itemCount; ++i) {
            if (items[i].FmtValue.CStatus == ERROR_SUCCESS)
                total += items[i].FmtValue.doubleValue;
        }

        lastGpu_ = std::clamp((int)(total + 0.5), 0, 100);
        return lastGpu_;
    }

    FILETIME lastIdle_ = {};
    FILETIME lastKernel_ = {};
    FILETIME lastUser_ = {};
    int lastCpu_ = 0;
    int lastGpu_ = 0;
    PDH_HQUERY gpuQuery_ = nullptr;
    PDH_HCOUNTER gpuCounter_ = nullptr;
    bool gpuReady_ = false;
};

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
void ApplyRoundedWindow(HWND hWnd);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);


static void OnClose() { PostMessage(g_hWnd, WM_CLOSE, 0, 0); }


static void ApplyBackgroundScanPriority(HANDLE threadHandle) {
    if (!threadHandle)
        return;
    SetThreadPriority(threadHandle, THREAD_PRIORITY_BELOW_NORMAL);
    MEMORY_PRIORITY_INFORMATION memPrio = { MEMORY_PRIORITY_LOW };
    SetThreadInformation(threadHandle, ThreadMemoryPriority, &memPrio, sizeof(memPrio));
}


static const int kTitleBarHeight = 52;
static const int kTitleBarControlsWidth = 220;
static const int kAppWindowX = 60;
static const int kAppWindowY = 45;
static const int kAppWindowW = 1420;
static const int kAppWindowH = 800;
static const int kLoadingCardW = 540;
static const int kLoadingCardH = 420;

static int LoadingCardX() {
    return kAppWindowX + (kAppWindowW - kLoadingCardW) / 2;
}

static int LoadingCardY() {
    return kAppWindowY + (kAppWindowH - kLoadingCardH) / 2;
}


static void ApplyStartupWindowTransform(float loadingElapsed) {
    static bool finished = false;
    if (finished)
        return;

    const float total = ScannerUI::LoadingIntroDuration();
    if (loadingElapsed >= total) {
        SetWindowLongW(g_hWnd, GWL_EXSTYLE,
            GetWindowLongW(g_hWnd, GWL_EXSTYLE) & ~WS_EX_LAYERED);
        SetWindowPos(g_hWnd, nullptr, kAppWindowX, kAppWindowY, kAppWindowW, kAppWindowH,
            SWP_NOZORDER | SWP_NOACTIVATE);
        ApplyRoundedWindow(g_hWnd);
        finished = true;
        return;
    }

    SetLayeredWindowAttributes(g_hWnd, 0, 255, LWA_ALPHA);
}

static void LoadReadableFont(ImGuiIO& io) {
    const float fontSize = 16.0f;
    ImFontConfig config = {};
    config.OversampleH = 2;
    config.OversampleV = 2;
    config.PixelSnapH = true;

    ImFont* mainFont = io.Fonts->AddFontFromFileTTF(
        "C:\\Windows\\Fonts\\segoeui.ttf", fontSize, &config);
    if (!mainFont)
        mainFont = io.Fonts->AddFontFromFileTTF(
            "C:\\Windows\\Fonts\\segoeuisl.ttf", fontSize, &config);
    if (!mainFont)
        mainFont = io.Fonts->AddFontFromFileTTF(
            "imgui\\misc\\fonts\\Karla-Regular.ttf", fontSize, &config);
    if (!mainFont)
        mainFont = io.Fonts->AddFontFromFileTTF(
            "..\\..\\imgui\\misc\\fonts\\Karla-Regular.ttf", fontSize, &config);

    char exePath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    if (!mainFont && len > 0 && len < MAX_PATH) {
        std::string dir(exePath);
        size_t slash = dir.find_last_of("\\/");
        if (slash != std::string::npos) {
            dir.resize(slash);
            std::string fromRelease = dir + "\\..\\..\\imgui\\misc\\fonts\\Karla-Regular.ttf";
            mainFont = io.Fonts->AddFontFromFileTTF(fromRelease.c_str(), fontSize, &config);
            std::string fromExeDir = dir + "\\imgui\\misc\\fonts\\Karla-Regular.ttf";
            if (!mainFont)
                mainFont = io.Fonts->AddFontFromFileTTF(fromExeDir.c_str(), fontSize, &config);
        }
    }

    if (!mainFont)
        mainFont = io.Fonts->AddFontDefault();
    io.FontDefault = mainFont;

    static const ImWchar emojiRanges[] = {
        0x1F47E, 0x1F47E,
        0x1F3AD, 0x1F3AD,
        0x1F489, 0x1F489,
        0x1F4C2, 0x1F4C2,
        0x1F50E, 0x1F50E,
        0x1F6A8, 0x1F6A8,
        0x1F97E, 0x1F97E,
        0x1F9F5, 0x1F9F5,
        0x1FA9D, 0x1FA9D,
        0
    };
    ImFontConfig emojiConfig = {};
    emojiConfig.MergeMode = true;
    emojiConfig.PixelSnapH = true;
    emojiConfig.GlyphMinAdvanceX = fontSize;
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\seguiemj.ttf",
                                 fontSize + 1.0f, &emojiConfig, emojiRanges);

    io.FontGlobalScale = 1.0f;
}

static bool TryEnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid) &&
              AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

static void DisableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = 0;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
}

static std::wstring RandomAlphaNumTitle() {
    static constexpr wchar_t chars[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local ULONGLONG state = [] {
        LARGE_INTEGER qpc = {};
        QueryPerformanceCounter(&qpc);
        return (ULONGLONG)qpc.QuadPart ^ GetTickCount64() ^ 0x9E3779B97F4A7C15ULL;
    }();

    auto next = []() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };

    std::wstring out;
    out.reserve(12);
    for (int i = 0; i < 12; ++i)
        out.push_back(chars[next() % 62]);
    return out;
}

static void RandomizeWindowTitleLoop(std::atomic_bool& running) {
    while (running.load()) {
        SetWindowTextW(g_hWnd, RandomAlphaNumTitle().c_str());
        Sleep(250);
    }
}

static bool IsDebugPrivilegeActive() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    PRIVILEGE_SET ps = {};
    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &ps.Privilege[0].Luid);
    ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = FALSE;
    PrivilegeCheck(token, &ps, &result);
    CloseHandle(token);
    return result != FALSE;
}

static ID3D11ShaderResourceView* CreateTextureFromWicFrame(
    IWICImagingFactory* wic, IWICBitmapFrameDecode* frame, ID3D11Device* device) {
    if (!wic || !frame || !device)
        return nullptr;
    IWICFormatConverter* conv = nullptr;
    if (FAILED(wic->CreateFormatConverter(&conv)) || !conv) {
        return nullptr;
    }
    HRESULT hr = conv->Initialize(frame, GUID_WICPixelFormat32bppRGBA,
                                  WICBitmapDitherTypeNone, nullptr, 0.0,
                                  WICBitmapPaletteTypeCustom);
    if (FAILED(hr)) {
        conv->Release();
        return nullptr;
    }

    UINT w = 0, h = 0;
    if (FAILED(conv->GetSize(&w, &h)) || w == 0 || h == 0) {
        conv->Release();
        return nullptr;
    }
    std::vector<BYTE> px(w * h * 4);
    if (FAILED(conv->CopyPixels(nullptr, w * 4, (UINT)px.size(), px.data()))) {
        conv->Release();
        return nullptr;
    }
    conv->Release();

    D3D11_TEXTURE2D_DESC td = {};
    td.Width = w; td.Height = h;
    td.MipLevels = td.ArraySize = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = px.data();
    initData.SysMemPitch = w * 4;

    ID3D11Texture2D* tex = nullptr;
    if (FAILED(device->CreateTexture2D(&td, &initData, &tex)) || !tex)
        return nullptr;

    ID3D11ShaderResourceView* srv = nullptr;
    device->CreateShaderResourceView(tex, nullptr, &srv);
    tex->Release();
    return srv;
}

static ID3D11ShaderResourceView* LoadPngTexture(const wchar_t* path, ID3D11Device* device) {
    if (!path || !device)
        return nullptr;

    IWICImagingFactory* wic = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWICImagingFactory, (void**)&wic)) || !wic)
        return nullptr;

    IWICBitmapDecoder* dec = nullptr;
    if (FAILED(wic->CreateDecoderFromFilename(path, nullptr, GENERIC_READ,
                                              WICDecodeMetadataCacheOnLoad, &dec)) || !dec) {
        wic->Release();
        return nullptr;
    }

    IWICBitmapFrameDecode* frame = nullptr;
    const HRESULT hr = dec->GetFrame(0, &frame);
    dec->Release();
    if (FAILED(hr) || !frame) {
        wic->Release();
        return nullptr;
    }

    ID3D11ShaderResourceView* srv = CreateTextureFromWicFrame(wic, frame, device);
    frame->Release();
    wic->Release();
    return srv;
}

static ID3D11ShaderResourceView* LoadPngResource(int resourceId,
                                                ID3D11Device* device) {
    if (!device)
        return nullptr;

    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!resource)
        return nullptr;
    HGLOBAL loaded = LoadResource(nullptr, resource);
    const DWORD size = SizeofResource(nullptr, resource);
    BYTE* bytes = static_cast<BYTE*>(LockResource(loaded));
    if (!loaded || !bytes || size == 0)
        return nullptr;

    IWICImagingFactory* wic = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWICImagingFactory, (void**)&wic)) || !wic)
        return nullptr;

    IWICStream* stream = nullptr;
    if (FAILED(wic->CreateStream(&stream)) || !stream ||
        FAILED(stream->InitializeFromMemory(bytes, size))) {
        if (stream) stream->Release();
        wic->Release();
        return nullptr;
    }

    IWICBitmapDecoder* decoder = nullptr;
    HRESULT hr = wic->CreateDecoderFromStream(stream, nullptr,
                                              WICDecodeMetadataCacheOnLoad, &decoder);
    stream->Release();
    if (FAILED(hr) || !decoder) {
        wic->Release();
        return nullptr;
    }

    IWICBitmapFrameDecode* frame = nullptr;
    hr = decoder->GetFrame(0, &frame);
    decoder->Release();
    if (FAILED(hr) || !frame) {
        wic->Release();
        return nullptr;
    }

    ID3D11ShaderResourceView* srv = CreateTextureFromWicFrame(wic, frame, device);
    frame->Release();
    wic->Release();
    return srv;
}

static ID3D11ShaderResourceView* TryLoadLogoCandidate(const std::wstring& path, ID3D11Device* device) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY))
        return nullptr;
    return LoadPngTexture(path.c_str(), device);
}

static ID3D11ShaderResourceView* LoadAssetTexture(const wchar_t* fileName,
                                                 ID3D11Device* device) {
    wchar_t exePath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        std::wstring dir(exePath);
        const size_t slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            const std::wstring candidate =
                dir.substr(0, slash + 1) + L"assets\\" + fileName;
            if (auto* srv = TryLoadLogoCandidate(candidate, device))
                return srv;
        }
    }

    wchar_t cwd[MAX_PATH] = {};
    if (GetCurrentDirectoryW(MAX_PATH, cwd)) {
        std::wstring candidate(cwd);
        if (!candidate.empty() && candidate.back() != L'\\' && candidate.back() != L'/')
            candidate += L"\\";
        candidate += L"assets\\";
        candidate += fileName;
        if (auto* srv = TryLoadLogoCandidate(candidate, device))
            return srv;
    }
    return nullptr;
}

static ID3D11ShaderResourceView* LoadLogoTexture(ID3D11Device* device) {
    wchar_t exePath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        std::wstring dir(exePath);
        size_t slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            std::wstring candidate = dir.substr(0, slash + 1) + L"icon.png";
            if (auto* srv = TryLoadLogoCandidate(candidate, device))
                return srv;
        }
    }

    wchar_t cwd[MAX_PATH] = {};
    if (GetCurrentDirectoryW(MAX_PATH, cwd)) {
        std::wstring candidate(cwd);
        if (!candidate.empty() && candidate.back() != L'\\' && candidate.back() != L'/')
            candidate += L"\\";
        candidate += L"icon.png";
        if (auto* srv = TryLoadLogoCandidate(candidate, device))
            return srv;
    }

    return TryLoadLogoCandidate(
        L"C:\\Users\\gusta\\OneDrive\\Desktop\\400ad7f0-8da6-4665-866c-00f11c695cab.png",
        device);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    ApplyProcessHardening();
#ifdef NDEBUG
    if (IsDebuggerAttached())
        return 0;
#endif
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SelfRelocateToTemp()) { CoUninitialize(); return 0; }

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                       hInstance, nullptr, nullptr, nullptr, nullptr,
                       L"rxvscan", nullptr };
    ::RegisterClassExW(&wc);

    g_hWnd = ::CreateWindowExW(0, wc.lpszClassName, L"rxvscan",
                               WS_POPUP, LoadingCardX(), LoadingCardY(),
                               kLoadingCardW, kLoadingCardH,
                               nullptr, nullptr, wc.hInstance, nullptr);
    ApplyRoundedWindow(g_hWnd);


    SetWindowLongW(g_hWnd, GWL_EXSTYLE,
        GetWindowLongW(g_hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(g_hWnd, 0, 255, LWA_ALPHA);
    SetWindowPos(g_hWnd, nullptr, LoadingCardX(), LoadingCardY(), 0, 0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

    if (!CreateDeviceD3D(g_hWnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(g_hWnd, SW_SHOWDEFAULT);
    ::UpdateWindow(g_hWnd);
    std::atomic_bool randomTitleRunning = true;
    std::thread randomTitleThread(RandomizeWindowTitleLoop, std::ref(randomTitleRunning));

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    LoadReadableFont(io);

    ScannerUI::ApplyTheme();

    ImGui_ImplWin32_Init(g_hWnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ID3D11ShaderResourceView* g_logoSrv = LoadLogoTexture(g_pd3dDevice);
    ID3D11ShaderResourceView* g_efiIconSrv =
        LoadPngResource(IDR_PNG_EFI_CHECKER, g_pd3dDevice);
    ID3D11ShaderResourceView* g_emuIconSrv =
        LoadPngResource(IDR_PNG_EMU_CHECKER, g_pd3dDevice);
    ID3D11ShaderResourceView* g_winScanIconSrv =
        LoadPngResource(IDR_PNG_WINSCAN, g_pd3dDevice);
    ID3D11ShaderResourceView* g_kernelScanIconSrv =
        LoadPngResource(IDR_PNG_KERNEL_SCAN, g_pd3dDevice);
    ID3D11ShaderResourceView* g_generalIconSrv =
        LoadPngResource(IDR_PNG_GENERAL, g_pd3dDevice);
    ID3D11ShaderResourceView* g_sysmonIconSrv =
        LoadPngResource(IDR_PNG_SYSMON, g_pd3dDevice);
    ID3D11ShaderResourceView* g_deepScanIconSrv =
        LoadPngResource(IDR_PNG_DEEP_SCAN, g_pd3dDevice);

    ScannerUI::ScanData data = ScannerUI::MakeSampleData();
    {
        CollectSystemOverview(data);
        if (!GetTpm2PublicHash(data.hwid, data.hwidWarning)) {
            data.hwid = "TPM2_PUBLIC_HASH_UNAVAILABLE";
        }
        data.bam.clear();
        data.prefetch.clear();
        data.prefetchHits = 0;
        data.services = CollectServiceStatuses();
        data.sysmonStatus = "Waiting";
        data.sysmonEvents.clear();
        data.sysmonDerivedReady = false;
        data.emulatorChecking = true;
        data.emulatorResult = "Waiting for emulator integrity scan";
        data.emulatorStatus = "Waiting";
        data.emulatorOpenedAt = "-";
        data.emulatorFindings.clear();
        data.genericBypassStatus = "Waiting";
        data.genericBypass.clear();
        data.streamModStatus = "Waiting";
        data.streamModFindings.clear();
        data.remotePortStatus = "Waiting";
        data.remotePortFindings.clear();
        data.efiCheatStatus = "Waiting";
        data.efiCheats.clear();
        data.activePage = 1;
        data.scanProgress = 0.0f;
        data.speedScan = "starting";
        data.terminalLog = { "> opening scanner" };
        data.terminalNotif = 1;
        TryEnableDebugPrivilege();
        data.debugMode = true;
        data.logoTexture = g_logoSrv;
        data.generalIconTexture = g_generalIconSrv;
        data.efiIconTexture = g_efiIconSrv;
        data.emuIconTexture = g_emuIconSrv;
        data.winScanIconTexture = g_winScanIconSrv;
        data.kernelScanIconTexture = g_kernelScanIconSrv;
        data.sysmonIconTexture = g_sysmonIconSrv;
        data.deepScanIconTexture = g_deepScanIconSrv;
    }
    std::mutex dataMutex;
    std::thread scannerThread;

    RuntimeUsageSampler usageSampler;
    ULONGLONG lastUsageSample = 0;
    const ULONGLONG appStartTick = GetTickCount64();
    ULONGLONG loadingIntroStartTick = appStartTick;
    bool loadingStarted = true;
    std::vector<std::thread> commandThreads;
    g_scanFinished = false;
    scannerThread = std::thread(RunScannerAsync, std::ref(data), std::ref(dataMutex));
    HANDLE scannerThreadHandle = reinterpret_cast<HANDLE>(scannerThread.native_handle());
    ApplyBackgroundScanPriority(scannerThreadHandle);
    ScanTier lastAppliedTier = ScanTier::Light;

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight,
                                        DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ULONGLONG nowTick = GetTickCount64();
        const float loadingElapsed = loadingStarted
            ? (float)((nowTick - loadingIntroStartTick) / 1000.0)
            : 0.0f;
        if (loadingStarted)
            ApplyStartupWindowTransform(loadingElapsed);

        if (nowTick - lastUsageSample >= 500) {
            RuntimeUsage usage = usageSampler.Sample();
            g_scanTier = static_cast<int>(usage.tier);
            g_scanSlow = (usage.tier == ScanTier::Overloaded);
            if (usage.tier != lastAppliedTier) {
                SetThreadPriority(scannerThreadHandle,
                    usage.tier == ScanTier::Overloaded ? THREAD_PRIORITY_LOWEST
                                                        : THREAD_PRIORITY_BELOW_NORMAL);
                lastAppliedTier = usage.tier;
            }
            {
                std::lock_guard<std::mutex> lock(dataMutex);
                data.cpu = usage.cpu;
                data.ram = usage.ram;
                data.gpu = usage.gpu;
                if (!g_scanFinished.load()) {
                    data.speedScan = usage.tier == ScanTier::Overloaded ? "slow"
                                    : usage.tier == ScanTier::Busy ? "busy" : "normal";
                }
            }
            lastUsageSample = nowTick;
        }

        std::string commandToRun;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            if (!data.pendingCommand.empty()) {
                commandToRun = data.pendingCommand;
                data.pendingCommand.clear();
                AppendTerminalLine(data, "> running " + commandToRun);
            }
        }
        if (!commandToRun.empty()) {
            commandThreads.erase(
                std::remove_if(commandThreads.begin(), commandThreads.end(),
                    [](std::thread& t) { return !t.joinable(); }),
                commandThreads.end());
            commandThreads.emplace_back(RunTerminalCommandAsync, commandToRun, std::ref(data), std::ref(dataMutex));
            ApplyBackgroundScanPriority(reinterpret_cast<HANDLE>(commandThreads.back().native_handle()));
        }

        const bool overloaded = g_scanSlow.load();
        const bool loadingVisible = ScannerUI::RenderLoadingOverlay(data, loadingElapsed);
        if (!loadingVisible) {
            std::lock_guard<std::mutex> lock(dataMutex);
            ScannerUI::Render(data, nullptr, OnClose);
        }

        ImGui::Render();
        const float clear[4] = { 0.043f, 0.047f, 0.063f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
        if (overloaded)
            Sleep(24);
    }

    auto JoinOrDetach = [](std::thread& t, DWORD ms = 8000) {
        if (!t.joinable()) return;
        if (WaitForSingleObject(reinterpret_cast<HANDLE>(t.native_handle()), ms) == WAIT_OBJECT_0)
            t.join();
        else
            t.detach();
    };

    JoinOrDetach(scannerThread);
    for (auto& thread : commandThreads)
        JoinOrDetach(thread);
    randomTitleRunning = false;
    JoinOrDetach(randomTitleThread, 2000);

    if (g_logoSrv) { g_logoSrv->Release(); g_logoSrv = nullptr; }
    if (g_efiIconSrv) { g_efiIconSrv->Release(); g_efiIconSrv = nullptr; }
    if (g_emuIconSrv) { g_emuIconSrv->Release(); g_emuIconSrv = nullptr; }
    if (g_winScanIconSrv) { g_winScanIconSrv->Release(); g_winScanIconSrv = nullptr; }
    if (g_kernelScanIconSrv) { g_kernelScanIconSrv->Release(); g_kernelScanIconSrv = nullptr; }
    if (g_generalIconSrv) { g_generalIconSrv->Release(); g_generalIconSrv = nullptr; }
    if (g_sysmonIconSrv) { g_sysmonIconSrv->Release(); g_sysmonIconSrv = nullptr; }
    if (g_deepScanIconSrv) { g_deepScanIconSrv->Release(); g_deepScanIconSrv = nullptr; }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(g_hWnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    CoUninitialize();
    SelfDelete();
    return 0;
}




bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createFlags = 0;
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL lvls[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createFlags,
        lvls, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (hr == DXGI_ERROR_UNSUPPORTED)
        hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createFlags,
            lvls, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
            &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (hr != S_OK) return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();        g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

void ApplyRoundedWindow(HWND hWnd) {
    RECT rc = {};
    if (!GetClientRect(hWnd, &rc))
        return;

    const int radius = 18;
    HRGN region = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    if (region && SetWindowRgn(hWnd, region, TRUE) == 0)
        DeleteObject(region);
}




LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_ResizeWidth  = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        ApplyRoundedWindow(hWnd);
        return 0;
    case WM_NCHITTEST: {

        POINT pt = { (LONG)LOWORD(lParam), (LONG)HIWORD(lParam) };
        ScreenToClient(hWnd, &pt);
        RECT rc; GetClientRect(hWnd, &rc);

        if (pt.y >= 0 && pt.y < kTitleBarHeight && pt.x < rc.right - kTitleBarControlsWidth)
            return HTCAPTION;
        return HTCLIENT;
    }
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_QUERYENDSESSION:
        return TRUE;
    case WM_ENDSESSION:
        if (wParam) {
            SelfDelete();
            ::PostQuitMessage(0);
        }
        return 0;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

