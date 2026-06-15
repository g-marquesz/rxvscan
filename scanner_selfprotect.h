#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>

static std::wstring g_tempRunDir;

static bool IsDebuggerAttached() {
    if (IsDebuggerPresent())
        return true;

    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger)
        return true;

    return false;
}

static void ApplyProcessHardening() {
    PROCESS_MITIGATION_DEP_POLICY dep = {};
    dep.Enable = 1;
    dep.Permanent = 1;
    SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep));

    PROCESS_MITIGATION_ASLR_POLICY aslr = {};
    aslr.EnableBottomUpRandomization = 1;
    aslr.EnableForceRelocateImages = 1;
    aslr.EnableHighEntropy = 1;
    aslr.DisallowStrippedImages = 1;
    SetProcessMitigationPolicy(ProcessASLRPolicy, &aslr, sizeof(aslr));

    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handles = {};
    handles.RaiseExceptionOnInvalidHandleReference = 1;
    handles.HandleExceptionsPermanentlyEnabled = 1;
    SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &handles, sizeof(handles));

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensions = {};
    extensions.DisableExtensionPoints = 1;
    SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extensions, sizeof(extensions));

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoad = {};
    imageLoad.NoRemoteImages = 1;
    imageLoad.NoLowMandatoryLabelImages = 1;
    imageLoad.PreferSystem32Images = 1;
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoad, sizeof(imageLoad));
}

static bool IsRunningFromTemp() {
    wchar_t tempPath[MAX_PATH] = {};
    DWORD len = GetTempPathW(MAX_PATH, tempPath);
    if (!len) return false;
    std::wstring temp(tempPath, len);
    if (temp.back() != L'\\') temp += L'\\';

    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring self(selfPath);
    if (self.size() < temp.size()) return false;
    return _wcsnicmp(self.c_str(), temp.c_str(), temp.size()) == 0;
}

static std::wstring GenerateRandomHexName() {
    LARGE_INTEGER qpc = {};
    QueryPerformanceCounter(&qpc);
    ULONGLONG state = (ULONGLONG)qpc.QuadPart ^ GetTickCount64()
                      ^ (ULONGLONG)(ULONG_PTR)GetCurrentProcessId()
                      ^ 0x9E3779B97F4A7C15ULL;
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    wchar_t buf[9];
    swprintf_s(buf, L"%08llx", state & 0xFFFFFFFFULL);
    return std::wstring(buf);
}

static bool SelfRelocateToTemp() {
    if (IsRunningFromTemp()) {
        wchar_t selfPath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        std::wstring self(selfPath);
        size_t slash = self.rfind(L'\\');
        if (slash != std::wstring::npos)
            g_tempRunDir = self.substr(0, slash);
        return false;
    }

    wchar_t tempBase[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tempBase)) return false;
    std::wstring destDir = std::wstring(tempBase) + GenerateRandomHexName();

    if (!CreateDirectoryW(destDir.c_str(), nullptr)) {
        destDir = std::wstring(tempBase) + GenerateRandomHexName();
        if (!CreateDirectoryW(destDir.c_str(), nullptr)) return false;
    }

    wchar_t selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring srcPath(selfPath);
    size_t srcSlash = srcPath.rfind(L'\\');
    std::wstring srcDir = (srcSlash != std::wstring::npos) ? srcPath.substr(0, srcSlash) : L"";
    std::wstring exeName = (srcSlash != std::wstring::npos) ? srcPath.substr(srcSlash + 1) : srcPath;
    std::wstring destPath = destDir + L"\\" + exeName;

    if (!CopyFileW(srcPath.c_str(), destPath.c_str(), FALSE)) {
        RemoveDirectoryW(destDir.c_str());
        return false;
    }

    if (!srcDir.empty()) {
        std::wstring srcIcon = srcDir + L"\\icon.png";
        std::wstring destIcon = destDir + L"\\icon.png";
        CopyFileW(srcIcon.c_str(), destIcon.c_str(), FALSE);
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::wstring cmdLine = L"\"" + destPath + L"\"";
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    if (CreateProcessW(destPath.c_str(), cmdBuf.data(),
                       nullptr, nullptr, FALSE, 0,
                       nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }

    DeleteFileW(destPath.c_str());
    RemoveDirectoryW(destDir.c_str());
    return false;
}

static void SelfDelete() {
    if (g_tempRunDir.empty()) return;

    std::wstring rmCmd = L"cmd.exe /C ping 127.0.0.1 -n 3 > nul & rmdir /S /Q \""
                         + g_tempRunDir + L"\"";
    std::vector<wchar_t> cmdBuf(rmCmd.begin(), rmCmd.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr,
                   FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS,
                   nullptr, nullptr, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);

    g_tempRunDir.clear();
}
