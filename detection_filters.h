#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")
#include <bcrypt.h>
#include <psapi.h>
#include <iomanip>
#include <sstream>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <chrono>
#include <future>
#include <mutex>
#include <optional>
#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

std::wstring DevicePathToDosPath(const std::wstring& path);

namespace DetectionFilter {

constexpr double kPackedEntropy = 7.2;
constexpr double kCodeLow       = 4.5;
constexpr double kCodeHigh      = 7.0;

inline std::wstring UpperW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return (wchar_t)towupper(c); });
    return s;
}

inline std::wstring EnvW(const wchar_t* name) {
    wchar_t buf[1024] = {};
    DWORD n = GetEnvironmentVariableW(name, buf, (DWORD)std::size(buf));
    if (n == 0 || n >= std::size(buf))
        return L"";
    return buf;
}

inline std::wstring BaseName(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

inline std::string EntropyToStr(double e) {
    if (e < 0.0)
        return "n/a";
    char buf[16] = {};
    snprintf(buf, sizeof(buf), "%.2f", e);
    return buf;
}

inline double ShannonEntropy(const unsigned char* data, size_t len) {
    if (!data || len == 0)
        return 0.0;
    size_t freq[256] = {};
    for (size_t i = 0; i < len; ++i)
        ++freq[data[i]];
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i])
            continue;
        double p = (double)freq[i] / (double)len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

inline double FileEntropySample(const std::wstring& path, size_t maxBytes = 256 * 1024) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return -1.0;

    LARGE_INTEGER size = {};
    if (GetFileSizeEx(h, &size) && size.QuadPart > 4096) {
        LARGE_INTEGER off = {};
        off.QuadPart = 1024;
        SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
    }

    std::vector<unsigned char> buf(maxBytes);
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf.data(), (DWORD)buf.size(), &read, nullptr);
    CloseHandle(h);
    if (!ok || read == 0)
        return -1.0;
    return ShannonEntropy(buf.data(), read);
}

inline std::string FindSuspiciousStringInEfi(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return "";

    constexpr size_t kMaxRead = 512 * 1024;
    std::vector<unsigned char> buf(kMaxRead);
    DWORD rd = 0;
    ReadFile(h, buf.data(), (DWORD)kMaxRead, &rd, nullptr);
    CloseHandle(h);
    if (rd == 0)
        return "";

    static const char* kSuspiciousTokens[] = {
        "eac bypass", "battleye bypass", "vanguard bypass", "anti-cheat bypass",
        "anticheat bypass", "kernel hack", "hwid spoof", "cheat engine",
        "cheathappens", "unknowncheats", "triggerbot", "wallhack", "aimbot",
        "no recoil", "bunnyhop", "ring0 exploit", "hypervisor bypass",
        "easyanticheat", "be bypass", "faceit bypass", nullptr
    };

    std::string current;
    current.reserve(256);
    for (DWORD i = 0; i < rd; ++i) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c <= 0x7E) {
            current += (char)c;
        } else {
            if (current.size() >= 8) {

                std::string low = current;
                std::transform(low.begin(), low.end(), low.begin(),
                               [](unsigned char ch) { return (unsigned char)tolower(ch); });
                for (int k = 0; kSuspiciousTokens[k]; ++k) {
                    if (low.find(kSuspiciousTokens[k]) != std::string::npos)
                        return current.size() > 64 ? current.substr(0, 64) + "..." : current;
                }
            }
            current.clear();
        }
    }
    return "";
}

inline double FileEntropyMultiSample(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return -1.0;

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 4096) {
        CloseHandle(h);
        return -1.0;
    }

    constexpr size_t kRegionSize = 64 * 1024;
    std::vector<unsigned char> buf(kRegionSize);
    double maxE = -1.0;

    auto sampleAt = [&](LONGLONG off) -> double {
        LARGE_INTEGER li = {};
        li.QuadPart = off;
        if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN))
            return -1.0;
        DWORD rd = 0;
        if (!ReadFile(h, buf.data(), (DWORD)kRegionSize, &rd, nullptr) || rd == 0)
            return -1.0;
        return ShannonEntropy(buf.data(), rd);
    };

    double e1 = sampleAt(1024);
    if (e1 > maxE) maxE = e1;

    LONGLONG midOff = (size.QuadPart / 2) - (LONGLONG)(kRegionSize / 2);
    if (midOff < 0) midOff = 0;
    double e2 = sampleAt(midOff);
    if (e2 > maxE) maxE = e2;

    LONGLONG tailOff = size.QuadPart - (LONGLONG)kRegionSize;
    if (tailOff < 0) tailOff = 0;
    double e3 = sampleAt(tailOff);
    if (e3 > maxE) maxE = e3;

    CloseHandle(h);
    return maxE;
}

inline double ProcessRegionEntropy(HANDLE process, const void* base, size_t regionSize,
                                   size_t maxBytes = 64 * 1024) {
    size_t toRead = regionSize < maxBytes ? regionSize : maxBytes;
    if (toRead == 0)
        return -1.0;
    std::vector<unsigned char> buf(toRead);
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, base, buf.data(), toRead, &got) || got == 0)
        return -1.0;
    return ShannonEntropy(buf.data(), (size_t)got);
}

inline bool HasPEHeader(HANDLE process, const void* base) {
    unsigned char buf[4096];
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, base, buf, sizeof(buf), &got) || got < 0x40)
        return false;
    if (buf[0] != 'M' || buf[1] != 'Z')
        return false;
    LONG peOffset = *reinterpret_cast<LONG*>(buf + 0x3C);
    if (peOffset <= 0 || (DWORD)peOffset + 4 > (DWORD)got)
        return false;
    return buf[peOffset] == 'P' && buf[peOffset + 1] == 'E' &&
           buf[peOffset + 2] == 0 && buf[peOffset + 3] == 0;
}

inline bool ExportsGraphicsSymbol(const BYTE* peBase, SIZE_T peSize, uintptr_t ) {
    if (!peBase || peSize < 0x40) return false;
    if (peBase[0] != 'M' || peBase[1] != 'Z') return false;
    LONG peOff = *reinterpret_cast<const LONG*>(peBase + 0x3C);
    if (peOff <= 0 || (SIZE_T)peOff + 24 > peSize) return false;
    if (peBase[peOff] != 'P' || peBase[peOff+1] != 'E') return false;

    WORD machine = *reinterpret_cast<const WORD*>(peBase + peOff + 4);
    bool is64 = (machine == 0x8664);
    WORD optSize = *reinterpret_cast<const WORD*>(peBase + peOff + 20);
    DWORD optOff = (DWORD)peOff + 24;

    DWORD expDirRva = 0;
    if (is64 && optOff + 112 <= (DWORD)peSize)
        expDirRva = *reinterpret_cast<const DWORD*>(peBase + optOff + 96);
    else if (!is64 && optOff + 96 <= (DWORD)peSize)
        expDirRva = *reinterpret_cast<const DWORD*>(peBase + optOff + 80);
    if (expDirRva == 0) return false;

    WORD numSec = *reinterpret_cast<const WORD*>(peBase + peOff + 6);
    if (numSec > 96) numSec = 96;
    DWORD secBase = (DWORD)peOff + 24 + optSize;

    auto rvaToOff = [&](DWORD rva) -> DWORD {
        for (WORD si = 0; si < numSec; ++si) {
            DWORD sHdr = secBase + si * 40;
            if (sHdr + 40 > (DWORD)peSize) break;
            DWORD vAddr  = *reinterpret_cast<const DWORD*>(peBase + sHdr + 12);
            DWORD vSize  = *reinterpret_cast<const DWORD*>(peBase + sHdr + 8);
            DWORD rawOff = *reinterpret_cast<const DWORD*>(peBase + sHdr + 20);
            if (rva >= vAddr && rva < vAddr + vSize) {
                DWORD off = rawOff + (rva - vAddr);
                if (off < (DWORD)peSize) return off;
            }
        }
        return 0;
    };

    DWORD expOff = rvaToOff(expDirRva);
    if (expOff + 40 > (DWORD)peSize) return false;

    DWORD numNames = *reinterpret_cast<const DWORD*>(peBase + expOff + 24);
    DWORD nameRva  = *reinterpret_cast<const DWORD*>(peBase + expOff + 32);
    if (numNames == 0 || numNames > 65536) return false;

    DWORD nameArrOff = rvaToOff(nameRva);
    if (nameArrOff == 0) return false;

    static const char* kGfxSymbols[] = {
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

    for (DWORD ni = 0; ni < numNames; ++ni) {
        DWORD rnOff = nameArrOff + ni * 4;
        if (rnOff + 4 > (DWORD)peSize) break;
        DWORD rnRva = *reinterpret_cast<const DWORD*>(peBase + rnOff);
        DWORD fnOff = rvaToOff(rnRva);
        if (fnOff == 0 || fnOff >= (DWORD)peSize) continue;
        const char* name = reinterpret_cast<const char*>(peBase + fnOff);
        SIZE_T maxLen = peSize - fnOff;
        for (int k = 0; kGfxSymbols[k]; ++k) {
            size_t symLen = strlen(kGfxSymbols[k]);
            if (symLen <= maxLen && memcmp(name, kGfxSymbols[k], symLen) == 0 &&
                (fnOff + symLen >= peSize || name[symLen] == '\0'))
                return true;
        }
    }
    return false;
}

inline bool IsValidSyscallStub(const BYTE* bytes, size_t len) {
    if (!bytes || len < 8) return false;

    if (len >= 11 && bytes[0]==0x4C && bytes[1]==0x8B && bytes[2]==0xD1
        && bytes[3]==0xB8 && bytes[6]==0x00 && bytes[7]==0x00
        && bytes[8]==0x0F && bytes[9]==0x05 && bytes[10]==0xC3)
        return true;

    if (len >= 8 && bytes[0]==0xB8 && bytes[3]==0x00 && bytes[4]==0x00
        && bytes[5]==0x0F && bytes[6]==0x05 && bytes[7]==0xC3)
        return true;

    if (len >= 11 && bytes[0]==0x49 && bytes[1]==0x89 && bytes[2]==0xCA
        && bytes[3]==0xB8 && bytes[6]==0x00 && bytes[7]==0x00
        && bytes[8]==0x0F && bytes[9]==0x05 && bytes[10]==0xC3)
        return true;

    if (len >= 13 && bytes[0]==0xB8 && bytes[3]==0x00 && bytes[4]==0x00
        && bytes[5]==0xBA && bytes[6]==0x08 && bytes[7]==0x03
        && bytes[8]==0xFE && bytes[9]==0x7F
        && bytes[10]==0x0F && bytes[11]==0x05 && bytes[12]==0xC3)
        return true;
    return false;
}

struct SystemRoots {
    std::wstring windows, system32, syswow64, winsxs, windirTemp;
    std::wstring programFiles, programFilesX86, programData, packageCache;
    std::wstring localAppData, userTemp, usersRoot, recycleBin;
};

inline const SystemRoots& Roots() {
    static SystemRoots r = [] {
        SystemRoots s;
        wchar_t win[MAX_PATH] = {};
        GetWindowsDirectoryW(win, (UINT)std::size(win));
        s.windows    = UpperW(win);
        s.system32   = s.windows + L"\\SYSTEM32";
        s.syswow64   = s.windows + L"\\SYSWOW64";
        s.winsxs     = s.windows + L"\\WINSXS";
        s.windirTemp = s.windows + L"\\TEMP";

        s.programFiles = UpperW(EnvW(L"ProgramW6432"));
        if (s.programFiles.empty())
            s.programFiles = UpperW(EnvW(L"ProgramFiles"));
        s.programFilesX86 = UpperW(EnvW(L"ProgramFiles(x86)"));
        s.programData = UpperW(EnvW(L"ProgramData"));
        if (s.programData.empty())
            s.programData = L"C:\\PROGRAMDATA";
        s.packageCache = s.programData + L"\\PACKAGE CACHE";

        s.localAppData = UpperW(EnvW(L"LOCALAPPDATA"));

        wchar_t tmp[MAX_PATH] = {};
        GetTempPathW((DWORD)std::size(tmp), tmp);
        s.userTemp = UpperW(tmp);

        if (s.windows.size() >= 2) {
            std::wstring drive = s.windows.substr(0, 2);
            s.usersRoot  = drive + L"\\USERS";
            s.recycleBin = drive + L"\\$RECYCLE.BIN";
        }
        return s;
    }();
    return r;
}

inline bool PathIsUnder(const std::wstring& path, const std::wstring& rootUpper) {
    if (rootUpper.empty() || path.empty())
        return false;
    std::wstring p = UpperW(path);
    std::wstring r = rootUpper;
    if (!r.empty() && r.back() == L'\\')
        r.pop_back();
    if (p.rfind(r, 0) != 0)
        return false;
    return p.size() == r.size() || p[r.size()] == L'\\';
}

enum class PathClass {
    SystemTrusted,
    ProgramFiles,
    TempOrInstaller,
    UserProfile,
    Removable,
    Unmapped,
    Unknown
};

inline PathClass ClassifyPath(const std::wstring& path) {
    if (path.empty())
        return PathClass::Unknown;
    std::wstring up = UpperW(path);

    if (up.rfind(L"\\DEVICE\\", 0) == 0 || up.rfind(L"\\\\?\\GLOBALROOT", 0) == 0)
        return PathClass::Unmapped;

    if (up.rfind(L"\\\\", 0) == 0)
        return PathClass::Removable;

    if (up.size() >= 3 && up[1] == L':' && up[2] == L'\\') {
        wchar_t driveRoot[4] = { up[0], L':', L'\\', L'\0' };
        UINT t = GetDriveTypeW(driveRoot);
        if (t == DRIVE_REMOVABLE || t == DRIVE_REMOTE || t == DRIVE_CDROM)
            return PathClass::Removable;
    }

    const SystemRoots& r = Roots();

    if (PathIsUnder(up, r.userTemp) || PathIsUnder(up, r.windirTemp) ||
        PathIsUnder(up, r.packageCache) || PathIsUnder(up, r.recycleBin) ||
        (!r.localAppData.empty() && PathIsUnder(up, r.localAppData + L"\\TEMP")))
        return PathClass::TempOrInstaller;

    if (PathIsUnder(up, r.system32) || PathIsUnder(up, r.syswow64) || PathIsUnder(up, r.winsxs))
        return PathClass::SystemTrusted;

    if (PathIsUnder(up, r.programFiles) || PathIsUnder(up, r.programFilesX86))
        return PathClass::ProgramFiles;

    if (PathIsUnder(up, r.usersRoot))
        return PathClass::UserProfile;

    if (PathIsUnder(up, r.windows))
        return PathClass::SystemTrusted;

    return PathClass::Unknown;
}

inline bool IsTrustedDir(PathClass c) {
    return c == PathClass::SystemTrusted || c == PathClass::ProgramFiles;
}

inline const char* PathClassName(PathClass c) {
    switch (c) {
    case PathClass::SystemTrusted:  return "SystemTrusted";
    case PathClass::ProgramFiles:   return "ProgramFiles";
    case PathClass::TempOrInstaller: return "TempOrInstaller";
    case PathClass::UserProfile:    return "UserProfile";
    case PathClass::Removable:      return "Removable";
    case PathClass::Unmapped:       return "Unmapped";
    default:                        return "Unknown";
    }
}

inline int SeverityRank(const std::string& s) {
    if (s == "HIGH")   return 0;
    if (s == "MEDIUM") return 1;
    if (s == "FLAG")   return 2;
    if (s == "INFO")   return 3;
    return 4;
}

inline bool SeverityCompare(const std::string& a, const std::string& b) {
    return SeverityRank(a) < SeverityRank(b);
}

inline bool IsNamedLikeGraphicsRuntime(const std::wstring& fileName) {
    std::wstring f = UpperW(fileName);
    static const std::unordered_set<std::wstring> names = {
        L"LIBEGL.DLL", L"LIBGLESV2.DLL", L"LIBGLES_CM.DLL",
        L"D3DCOMPILER_43.DLL", L"D3DCOMPILER_46.DLL", L"D3DCOMPILER_47.DLL",
        L"VK_SWIFTSHADER.DLL", L"LIBVK_SWIFTSHADER.DLL",
        L"SWIFTSHADER_LIBEGL.DLL", L"SWIFTSHADER_LIBGLESV2.DLL",
        L"VULKAN-1.DLL", L"OSMESA.DLL", L"OPENGL32SW.DLL",

        L"NVOGLV32.DLL", L"NVOGLV64.DLL", L"NVOGLSHIM.DLL",
        L"NVD3DUM.DLL", L"NVD3DUMX.DLL", L"NVWGF2UM.DLL", L"NVWGF2UMX.DLL",

        L"ATIG6PXX.DLL", L"ATIG6TAF.DLL", L"ATIOGLXX.DLL",
        L"ATIDXX32.DLL", L"ATIDXX64.DLL",

        L"IG4ICD32.DLL", L"IG4ICD64.DLL",
        L"IGDUMDIM32.DLL", L"IGDUMDIM64.DLL",
        L"IGDUMD32.DLL", L"IGDUMD64.DLL",

        L"D3D9.DLL", L"D3D11.DLL", L"D3D12.DLL", L"DXGI.DLL",
        L"D3D12CORE.DLL", L"D3DSCACHE.DLL",
    };
    if (names.find(f) != names.end())
        return true;
    return f.find(L"SWIFTSHADER") != std::wstring::npos ||
           f.find(L"ANGLE") != std::wstring::npos ||
           f.find(L"NVOG") != std::wstring::npos ||
           f.find(L"NVD3D") != std::wstring::npos ||
           f.find(L"ATIG") != std::wstring::npos;
}

inline bool IsNamedLikeOverlay(const std::wstring& fileName) {
    std::wstring f = UpperW(fileName);
    static const std::unordered_set<std::wstring> names = {
        L"GAMEOVERLAYRENDERER.DLL", L"GAMEOVERLAYRENDERER64.DLL",
        L"DISCORDHOOK.DLL", L"DISCORDHOOK64.DLL",
        L"RTSSHOOKS.DLL", L"RTSSHOOKS64.DLL",
        L"GRAPHICS-HOOK.DLL",
        L"NVCUDA.DLL",
        L"RXOVERLAY.DLL",
    };
    if (names.find(f) != names.end())
        return true;
    return f.find(L"OVERLAY") != std::wstring::npos && (
               f.find(L"GAME") != std::wstring::npos ||
               f.find(L"STEAM") != std::wstring::npos ||
               f.find(L"DISCORD") != std::wstring::npos ||
               f.find(L"NVIDIA") != std::wstring::npos ||
               f.find(L"RADEON") != std::wstring::npos);
}

inline bool IsKnownEmulatorServiceName(const std::wstring& fileName) {
    std::wstring f = UpperW(fileName);
    static const std::unordered_set<std::wstring> names = {
        L"HD-PLAYER.EXE", L"BLUESTACKS.EXE", L"BLUESTACKSSERVICES.EXE", L"BSTKSVC.EXE",
        L"BSTKVMMGR.EXE", L"HD-AGENT.EXE", L"BLUESTACKSHELPER.EXE", L"BGP64.EXE", L"BGP32.EXE",
        L"NOX.EXE", L"NOXVMHANDLE.EXE", L"NOXVMHANDLE64.EXE", L"NOXVM.EXE", L"MULTIPLAYERMANAGER.EXE",
        L"MEMU.EXE", L"MEMUHEADLESS.EXE", L"MEMUSVC.EXE", L"MEMUCONSOLE.EXE",
        L"DNPLAYER.EXE", L"LDVBOXHEADLESS.EXE", L"LD9BOXHEADLESS.EXE", L"DNMULTIPLAYER.EXE",
        L"MUMUPLAYER.EXE", L"MUMUVMMHEADLESS.EXE", L"MUMUEMULATOR.EXE", L"MUMUNXDEVICE.EXE"
    };
    return names.find(f) != names.end();
}

inline bool IsKnownEmulatorRuntime(const std::wstring& exeName) {
    std::wstring f = UpperW(exeName);
    static const std::unordered_set<std::wstring> names = {
        L"HD-PLAYER.EXE", L"BSTKSA.EXE",
        L"NOXVMHANDLE.EXE", L"NOXVMHANDLE64.EXE",
        L"MEMUHEADLESS.EXE",
        L"LDVBOXHEADLESS.EXE", L"LD9BOXHEADLESS.EXE",
        L"MUMUVMMHEADLESS.EXE"
    };
    return names.find(f) != names.end();
}

struct RegionVerdict {
    bool keep = true;
    std::string severity = "FLAG";
    std::string note;
};

inline RegionVerdict ClassifyExecRegion(bool writeExec, size_t size, double entropy,
                                        bool privateMem, bool hasPeHeader = false,
                                        bool isEmulatorProcess = false) {
    RegionVerdict v;
    v.note = "entropy=" + EntropyToStr(entropy) +
             " size=" + std::to_string((unsigned long long)size) +
             (privateMem ? " private" : " mapped");

    if (hasPeHeader && privateMem) {
        v.severity = "HIGH";
        v.note += " | PE header detectado (DLL reflective/injetada)";
        return v;
    }

    if (!privateMem && !hasPeHeader) {
        v.keep = false;
        v.note += " | regiao mapeada sem PE header (descartado)";
        return v;
    }

    if (isEmulatorProcess && privateMem && !hasPeHeader) {
        v.keep = false;
        v.note += writeExec
            ? " | RWX sem PE header em runtime de emulador (JIT, descartado)"
            : " | ART JIT cache (emulator runtime, descartado)";
        return v;
    }

    const size_t kJitMin    = 2ull  * 1024 * 1024;
    const size_t kMinReport = 16ull * 1024;


    if (entropy >= 0.0 && entropy >= kPackedEntropy) {
        v.severity = "HIGH";
        v.note += " | alta entropia (packed/cifrado)";
        return v;
    }

    bool codeLike = entropy >= kCodeLow && entropy <= kCodeHigh;


    if (writeExec) {
        if (privateMem && size >= kJitMin && codeLike) {
            v.severity = "MEDIUM";
            v.note += " | RWX grande estilo cache JIT";
            return v;
        }

        if (size < kMinReport && (entropy < 0.0 || entropy < kCodeLow)) {
            v.keep = false;
            v.note += " | RWX stub muito pequeno sem codigo (descartado)";
            return v;
        }



        if (privateMem && !hasPeHeader && codeLike && size < kJitMin) {
            v.severity = "MEDIUM";
            v.note += " | RWX medio com entropia de codigo (possivel JIT inicial)";
            return v;
        }
        v.severity = "HIGH";
        v.note += " | RWX fora de modulo";
        return v;
    }


    if (privateMem && size >= kJitMin && codeLike) {
        v.keep = false;
        v.note += " | provavel cache JIT (descartado)";
        return v;
    }


    if (size < kMinReport) {
        v.keep = false;
        v.note += " | regiao muito pequena (descartado)";
        return v;
    }



    if (codeLike) {
        v.keep = false;
        v.note += " | RX com entropia normal sem indicador adicional (descartado)";
        return v;
    }


    if (entropy >= 0.0 && entropy < kCodeLow) {
        v.keep = false;
        v.note += " | entropia baixa, nao e codigo (descartado)";
        return v;
    }


    v.keep = false;
    v.note += " | sem indicador conclusivo (descartado)";
    return v;
}

struct EfiPeInfo {
    bool     valid              = false;
    uint16_t subsystem          = 0xFFFF;
    size_t   overlaySize        = 0;
    bool     badSections        = false;
    uint16_t numSections        = 0;
    uint32_t peTimestamp        = 0;
    uint32_t storedChecksum     = 0;

    bool        noRichHeader       = false;
    bool        epHooked           = false;
    bool        injectedSection    = false;
    bool        dataDirOutOfBounds = false;
    std::string epHookDetail;
    std::string injectedSecName;
};

inline bool IsValidEfiSubsystem(uint16_t s) {
    return s >= 10 && s <= 13;
}

inline const char* EfiSubsystemName(uint16_t s) {
    switch (s) {
    case  1: return "NATIVE";
    case  2: return "WIN_GUI";
    case  3: return "WIN_CONSOLE";
    case 10: return "EFI_APP";
    case 11: return "EFI_BOOT_DRV";
    case 12: return "EFI_RT_DRV";
    case 13: return "EFI_ROM";
    default: return "UNKNOWN";
    }
}

inline EfiPeInfo AnalyzeEfiPe(const std::wstring& path) {
    EfiPeInfo info;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return info;

    LARGE_INTEGER fileSize = {};
    GetFileSizeEx(h, &fileSize);

    unsigned char buf[4096] = {};
    DWORD read = 0;
    ReadFile(h, buf, sizeof(buf), &read, nullptr);


    if (read < 0x40 || buf[0] != 'M' || buf[1] != 'Z') {
        CloseHandle(h); return info;
    }

    LONG peOff = *reinterpret_cast<LONG*>(buf + 0x3C);
    if (peOff <= 0 || (DWORD)peOff + 28 > read) {
        CloseHandle(h); return info;
    }
    if (buf[peOff] != 'P' || buf[peOff+1] != 'E' || buf[peOff+2] || buf[peOff+3]) {
        CloseHandle(h); return info;
    }

    info.valid = true;
    info.numSections = *reinterpret_cast<uint16_t*>(buf + peOff + 6);
    info.peTimestamp = *reinterpret_cast<uint32_t*>(buf + peOff + 4);
    uint16_t optSize  = *reinterpret_cast<uint16_t*>(buf + peOff + 20);

    DWORD checksumOff = (DWORD)peOff + 24 + 64;
    if (checksumOff + 4 <= read)
        info.storedChecksum = *reinterpret_cast<uint32_t*>(buf + checksumOff);

    DWORD subsOff = (DWORD)peOff + 24 + 68;
    if (subsOff + 2 <= read)
        info.subsystem = *reinterpret_cast<uint16_t*>(buf + subsOff);





    if ((DWORD)peOff > 0x80) {
        bool foundRich = false;
        for (DWORD ri = 0x40; ri + 4 <= (DWORD)peOff && ri + 4 <= read; ++ri) {
            if (buf[ri]=='R' && buf[ri+1]=='i' && buf[ri+2]=='c' && buf[ri+3]=='h') {
                foundRich = true; break;
            }
        }
        if (!foundRich) info.noRichHeader = true;
    }


    uint32_t entryRVA = 0;
    if ((DWORD)peOff + 44 <= read)
        entryRVA = *reinterpret_cast<uint32_t*>(buf + peOff + 40);


    uint16_t optMagic = 0;
    if ((DWORD)peOff + 26 <= read)
        optMagic = *reinterpret_cast<uint16_t*>(buf + peOff + 24);
    DWORD ddBase = (DWORD)peOff + 24 + (optMagic == 0x20B ? 112u : 96u);
    uint32_t ddRva[2] = {};
    for (int di = 0; di < 2; ++di) {
        DWORD ddOff = ddBase + (DWORD)di * 8;
        if (ddOff + 4 <= read)
            ddRva[di] = *reinterpret_cast<uint32_t*>(buf + ddOff);
    }


    struct SecEntry { uint32_t va, vsz, ptrRaw, sizeRaw; };
    SecEntry sections[96] = {};

    DWORD secTableOff = (DWORD)peOff + 24 + optSize;
    DWORD lastEnd = 0;
    uint16_t numSec = info.numSections < 96 ? info.numSections : 96;

    static const char* kBadNames[] = {
        "packed", "themida", ".vmp", "protect", "petite", "upx", ".ndata", "sforce", nullptr
    };


    static const char* kGoodExecNames[] = {
        ".text", ".ntext", ".code", "init", ".textbss", ".gfids", ".gehcont", nullptr
    };

    for (uint16_t i = 0; i < numSec; ++i) {
        DWORD sOff = secTableOff + i * 40;
        if (sOff + 40 > read)
            break;

        char name[9] = {};
        memcpy(name, buf + sOff, 8);

        uint32_t vsz     = *reinterpret_cast<uint32_t*>(buf + sOff + 8);
        uint32_t va      = *reinterpret_cast<uint32_t*>(buf + sOff + 12);
        uint32_t sizeRaw = *reinterpret_cast<uint32_t*>(buf + sOff + 16);
        uint32_t ptrRaw  = *reinterpret_cast<uint32_t*>(buf + sOff + 20);
        sections[i] = { va, vsz, ptrRaw, sizeRaw };

        if (!info.badSections) {
            for (int j = 0; j < 8 && name[j]; ++j) {
                if ((unsigned char)name[j] > 127) { info.badSections = true; break; }
            }
        }
        if (!info.badSections) {
            char low[9] = {};
            for (int j = 0; j < 8; ++j) low[j] = (char)tolower((unsigned char)name[j]);
            for (int k = 0; kBadNames[k]; ++k) {
                if (strstr(low, kBadNames[k])) { info.badSections = true; break; }
            }
        }

        DWORD ch = *reinterpret_cast<DWORD*>(buf + sOff + 36);
        if ((ch & 0x80000000u) && (ch & 0x20000000u))
            info.badSections = true;


        if (!info.injectedSection && (ch & 0x20000000u) && name[0]) {
            char low[9] = {};
            for (int j = 0; j < 8; ++j) low[j] = (char)tolower((unsigned char)name[j]);
            bool knownExec = false;
            for (int k = 0; kGoodExecNames[k]; ++k) {
                if (strcmp(low, kGoodExecNames[k]) == 0) { knownExec = true; break; }
            }
            if (!knownExec) {
                info.injectedSection = true;
                info.injectedSecName = std::string(name, strnlen(name, 8));
            }
        }

        DWORD end = ptrRaw + sizeRaw;
        if (end > lastEnd) lastEnd = end;
    }

    if (lastEnd > 0 && fileSize.QuadPart > (LONGLONG)lastEnd)
        info.overlaySize = (size_t)(fileSize.QuadPart - lastEnd);


    for (int di = 0; di < 2; ++di) {
        if (ddRva[di] == 0) continue;
        bool inSec = false;
        for (uint16_t i = 0; i < numSec; ++i) {
            uint32_t effSz = sections[i].vsz ? sections[i].vsz : sections[i].sizeRaw;
            if (ddRva[di] >= sections[i].va && ddRva[di] < sections[i].va + effSz) {
                inSec = true; break;
            }
        }
        if (!inSec) { info.dataDirOutOfBounds = true; break; }
    }


    if (entryRVA != 0) {
        DWORD epFileOff = 0;
        for (uint16_t i = 0; i < numSec; ++i) {
            uint32_t effSz = sections[i].vsz ? sections[i].vsz : sections[i].sizeRaw;
            if (entryRVA >= sections[i].va && entryRVA < sections[i].va + effSz) {
                epFileOff = sections[i].ptrRaw + (entryRVA - sections[i].va);
                break;
            }
        }
        if (epFileOff != 0) {
            LARGE_INTEGER li = {}; li.QuadPart = epFileOff;
            uint8_t epBytes[16] = {};
            DWORD epRead = 0;
            if (SetFilePointerEx(h, li, nullptr, FILE_BEGIN))
                ReadFile(h, epBytes, 16, &epRead, nullptr);
            if (epRead >= 2) {
                if (epBytes[0] == 0xE9) {
                    info.epHooked = true; info.epHookDetail = "JMP rel32";
                } else if (epBytes[0] == 0xFF && epBytes[1] == 0x25) {
                    info.epHooked = true; info.epHookDetail = "JMP [RIP+off]";
                } else if (epBytes[0] == 0x48 && epBytes[1] == 0xB8) {
                    info.epHooked = true; info.epHookDetail = "MOV RAX imm64 trampoline";
                } else if (epRead >= 8 &&
                           epBytes[0]==0x90 && epBytes[1]==0x90 && epBytes[2]==0x90 &&
                           epBytes[3]==0x90 && epBytes[4]==0x90 && epBytes[5]==0x90 &&
                           epBytes[6]==0x90 && epBytes[7]==0x90) {
                    info.epHooked = true; info.epHookDetail = "NOP sled";
                } else if (epRead >= 4 &&
                           epBytes[0]==0xCC && epBytes[1]==0xCC &&
                           epBytes[2]==0xCC && epBytes[3]==0xCC) {
                    info.epHooked = true; info.epHookDetail = "INT3 sled";
                }
            }
        }
    }

    CloseHandle(h);
    return info;
}

inline bool CheckPeChecksumMismatch(const std::wstring& path, uint32_t storedChecksum) {
    if (storedChecksum == 0)
        return false;
    DWORD headerSum = 0, computedSum = 0;
    if (MapFileAndCheckSumW(path.c_str(), &headerSum, &computedSum) != CHECKSUM_SUCCESS)
        return false;
    return headerSum != computedSum;
}

inline bool IsEmbeddedSigned(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;



    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fileInfo;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    return status == ERROR_SUCCESS;
}

inline bool IsCatalogSigned(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fileInfo;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID driverAction = DRIVER_ACTION_VERIFY;
    LONG status = WinVerifyTrust(nullptr, &driverAction, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &driverAction, &wd);
    return status == ERROR_SUCCESS;
}

template<typename Func>
static bool RunWithTimeout(Func&& fn, unsigned timeoutMs) {
    std::packaged_task<bool()> task(std::forward<Func>(fn));
    auto future = task.get_future();
    std::thread(std::move(task)).detach();
    if (future.wait_for(std::chrono::milliseconds(timeoutMs)) == std::future_status::ready)
        return future.get();
    return false;
}

inline std::optional<bool> IsTrustedSignedTriState(const std::wstring& path) {
    if (path.empty())
        return false;
    auto p = std::make_shared<std::wstring>(path);
    auto result = std::make_shared<std::atomic<int>>(-1);
    std::packaged_task<bool()> task([p, result]() {
        bool ok = IsEmbeddedSigned(*p) || IsCatalogSigned(*p);
        result->store(ok ? 1 : 0);
        return ok;
    });
    auto future = task.get_future();
    std::thread(std::move(task)).detach();


    if (future.wait_for(std::chrono::milliseconds(8000)) == std::future_status::ready)
        return future.get();
    return std::nullopt;
}

inline bool IsTrustedSigned(const std::wstring& path) {
    auto r = IsTrustedSignedTriState(path);
    return r.value_or(false);
}

inline uint64_t GetFileFingerprint(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA attr = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attr))
        return 0;
    ULARGE_INTEGER size = {};
    size.LowPart  = attr.nFileSizeLow;
    size.HighPart = attr.nFileSizeHigh;
    ULARGE_INTEGER mtime = {};
    mtime.LowPart  = attr.ftLastWriteTime.dwLowDateTime;
    mtime.HighPart = attr.ftLastWriteTime.dwHighDateTime;
    uint64_t h = size.QuadPart;
    h ^= mtime.QuadPart + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
    return h != 0 ? h : 1;
}

namespace detail_sigcache {
    struct Entry { bool value; uint64_t fingerprint; };
    inline std::mutex& Mtx() { static std::mutex m; return m; }
    inline std::unordered_map<std::wstring, Entry>& Map() {
        static std::unordered_map<std::wstring, Entry> c; return c;
    }
}

inline bool IsTrustedSignedCached(const std::wstring& path) {
    if (path.empty())
        return false;
    uint64_t fp = GetFileFingerprint(path);
    if (fp != 0) {
        std::lock_guard<std::mutex> lk(detail_sigcache::Mtx());
        auto it = detail_sigcache::Map().find(path);
        if (it != detail_sigcache::Map().end() && it->second.fingerprint == fp)
            return it->second.value;
    }
    auto tri = IsTrustedSignedTriState(path);
    bool result = tri.value_or(false);
    if (tri.has_value() && fp != 0) {
        std::lock_guard<std::mutex> lk(detail_sigcache::Mtx());
        if (detail_sigcache::Map().size() < 2048)
            detail_sigcache::Map()[path] = { result, fp };
    }
    return result;
}

inline void ClearSignatureCache() {
    std::lock_guard<std::mutex> lk(detail_sigcache::Mtx());
    detail_sigcache::Map().clear();
}

struct AddressModuleTrust {
    bool resolved = false;
    bool signedTrusted = false;
    bool exportsGraphics = false;
    std::wstring path;
};

inline AddressModuleTrust ResolveModuleTrustAtAddress(HANDLE process, uintptr_t addr) {
    AddressModuleTrust result;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(process, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return result;
    if (mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED)
        return result;

    wchar_t devicePath[1024] = {};
    DWORD len = GetMappedFileNameW(process, mbi.AllocationBase, devicePath, (DWORD)std::size(devicePath));
    if (len == 0)
        return result;

    result.path = DevicePathToDosPath(devicePath);
    result.resolved = !result.path.empty();
    if (!result.resolved)
        return result;

    result.signedTrusted = IsTrustedSignedCached(result.path);
    if (result.signedTrusted) {
        BYTE header[4096] = {};
        SIZE_T got = 0;
        if (ReadProcessMemory(process, mbi.AllocationBase, header, sizeof(header), &got) && got >= 0x40)
            result.exportsGraphics = ExportsGraphicsSymbol(header, got, (uintptr_t)mbi.AllocationBase);
    }
    return result;
}

namespace detail_pubcache {
    struct Entry { std::wstring value; uint64_t fingerprint; };
    inline std::mutex& Mtx() { static std::mutex m; return m; }
    inline std::unordered_map<std::wstring, Entry>& Map() {
        static std::unordered_map<std::wstring, Entry> c; return c;
    }
}

inline std::wstring GetSignerCommonNameUpperCached(const std::wstring& path) {
    if (path.empty())
        return L"";
    uint64_t fp = GetFileFingerprint(path);
    if (fp != 0) {
        std::lock_guard<std::mutex> lk(detail_pubcache::Mtx());
        auto it = detail_pubcache::Map().find(path);
        if (it != detail_pubcache::Map().end() && it->second.fingerprint == fp)
            return it->second.value;
    }

    std::wstring name;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                         CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                         CERT_QUERY_FORMAT_FLAG_BINARY,
                         0, &encoding, &contentType, &formatType,
                         &hStore, &hMsg, nullptr)) {
        DWORD sz = 0;
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &sz) && sz > 0) {
            std::vector<uint8_t> buf(sz);
            auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, si, &sz)) {
                CERT_INFO ci = {};
                ci.Issuer       = si->Issuer;
                ci.SerialNumber = si->SerialNumber;
                PCCERT_CONTEXT ctx = CertFindCertificateInStore(
                    hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                    CERT_FIND_SUBJECT_CERT, &ci, nullptr);
                if (ctx) {
                    wchar_t out[512] = {};
                    CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       0, nullptr, out, 512);
                    name = out;
                    CertFreeCertificateContext(ctx);
                }
            }
        }
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
    }
    name = UpperW(name);

    if (fp != 0) {
        std::lock_guard<std::mutex> lk(detail_pubcache::Mtx());
        if (detail_pubcache::Map().size() < 2048)
            detail_pubcache::Map()[path] = { name, fp };
    }
    return name;
}

inline void ClearPublisherCache() {
    std::lock_guard<std::mutex> lk(detail_pubcache::Mtx());
    detail_pubcache::Map().clear();
}

inline bool IsCrashDumpDriverName(const std::wstring& name) {
    std::wstring up = UpperW(BaseName(name));
    if (up.size() >= 5 && up.substr(0, 5) == L"DUMP_")
        return true;
    static const std::unordered_set<std::wstring> kKnownDump = {
        L"DUMPFVE.SYS", L"DUMPSTORPORT.SYS", L"DUMPSD.SYS",
        L"DUMPATA.SYS", L"DUMPDISKDUMP.SYS", L"DUMPNFTS.SYS",
        L"DUMPSMB.SYS", L"DUMPVSTORFL.SYS"
    };
    return kKnownDump.count(up) > 0;
}

inline bool HasRichHeader(const uint8_t* data, size_t sz) {
    if (!data || sz < 0x40) return false;
    LONG peOff = *reinterpret_cast<const LONG*>(data + 0x3C);
    if (peOff <= 0x40 || (size_t)peOff > sz) return false;

    for (size_t i = 0x40; i + 4 <= (size_t)peOff; ++i) {
        if (data[i] == 'R' && data[i+1] == 'i' && data[i+2] == 'c' && data[i+3] == 'h')
            return true;
    }
    return false;
}

inline int CountReadableStrings(const uint8_t* data, size_t sz, size_t minLen = 5) {
    if (!data || sz == 0) return 0;
    int count = 0;
    size_t runLen = 0;
    for (size_t i = 0; i < sz; ++i) {
        uint8_t c = data[i];
        if (c >= 0x20 && c <= 0x7E) {
            ++runLen;
        } else {
            if (runLen >= minLen) ++count;
            runLen = 0;
        }
    }
    if (runLen >= minLen) ++count;
    return count;
}

struct AntiAnalysisProfile {
    bool hasRdtscCheck    = false;
    bool hasCpuidVmCheck  = false;
    bool hasPebDebugCheck = false;
};

inline AntiAnalysisProfile ScanAntiAnalysisPatterns(const uint8_t* data, size_t sz) {
    AntiAnalysisProfile p;
    if (!data || sz < 4) return p;
    for (size_t i = 0; i + 1 < sz; ++i) {
        if (!p.hasRdtscCheck && data[i] == 0x0F && data[i+1] == 0x31)
            p.hasRdtscCheck = true;
        if (!p.hasCpuidVmCheck && data[i] == 0x0F && data[i+1] == 0xA2)
            p.hasCpuidVmCheck = true;



        if (!p.hasPebDebugCheck && i + 6 < sz) {
            if (data[i] == 0x64 && data[i+1] == 0xA1 &&
                data[i+2] == 0x30 && data[i+3] == 0x00)
                p.hasPebDebugCheck = true;
            if (data[i] == 0x65 && data[i+1] == 0x48 && data[i+2] == 0x8B &&
                data[i+3] == 0x04 && data[i+4] == 0x25 &&
                data[i+5] == 0x60 && data[i+6] == 0x00)
                p.hasPebDebugCheck = true;
        }
    }
    return p;
}

inline const wchar_t* const kCheatDomains[] = {

    L"KEYAUTH.WIN",  L"KEYAUTH.ME",  L"KEYAUTH.FUN",
    L"KEYAUTH.ORG",  L"KEYAUTH.APP",

    L"CHEATAUTOMATION.COM", L"UNKNOWNCHEATS.ME", L"MPGH.NET",
    L"GAMEHACKING.ORG",     L"GUIDED-HACKING.COM",
    L"WALLHAX.COM",         L"CHEATER.NINJA",
    L"IWANTCHEATS.NET",     L"AIMJUNKIES.COM",
    L"ELITEPVPERS.COM",     L"HACKFORUMS.NET",

    L"HVPP.IO",         L"RING0LOADER",   L"WTFBYPASS",
    L"FUCKBYPASS",      L"SKIDROW.TO",    L"LC.CX",
    L"LC.WUAZE.COM",    L"BYPASSCHEATS",  L"SPOOFERZONE",

    L"CRACKED.IO",
    nullptr
};

inline bool IsCheatDomain(const std::wstring& upperText) {
    for (int i = 0; kCheatDomains[i]; ++i) {
        if (upperText.find(kCheatDomains[i]) != std::wstring::npos)
            return true;
    }
    return false;
}

inline bool IsFileInWindowsCatalog(const std::wstring& path) {
    HCATADMIN hAdmin = nullptr;
    GUID action = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hAdmin, &action, 0))
        return false;

    bool found = false;
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD hashSize = 0;
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0);
        if (hashSize > 0) {
            std::vector<BYTE> hash(hashSize);
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
                HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(
                    hAdmin, hash.data(), hashSize, 0, nullptr);
                if (hCat) {
                    found = true;
                    CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
                }
            }
        }
        CloseHandle(hFile);
    }
    CryptCATAdminReleaseContext(hAdmin, 0);
    return found;
}

enum class CatalogState {
    Found,
    NotFound,
    Unverifiable
};

inline CatalogState QueryWindowsCatalogState(const std::wstring& path) {
    HCATADMIN hAdmin = nullptr;
    GUID action = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hAdmin, &action, 0))
        return CatalogState::Unverifiable;

    CatalogState state = CatalogState::Unverifiable;
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD hashSize = 0;
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0);
        if (hashSize > 0) {
            std::vector<BYTE> hash(hashSize);
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
                HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(
                    hAdmin, hash.data(), hashSize, 0, nullptr);
                if (hCat) {








                    CATALOG_INFO catInfo = {};
                    catInfo.cbStruct = sizeof(catInfo);
                    if (CryptCATCatalogInfoFromContext(hCat, &catInfo, 0) &&
                        catInfo.wszCatalogFile[0]) {
                        std::wstring catPath = catInfo.wszCatalogFile;
                        bool catTrusted = IsTrustedSignedCached(catPath);
                        std::wstring catCn = GetSignerCommonNameUpperCached(catPath);
                        bool catIsMs = catTrusted &&
                                       catCn.compare(0, 9, L"MICROSOFT") == 0;
                        state = catIsMs ? CatalogState::Found : CatalogState::NotFound;
                    } else {
                        state = CatalogState::Unverifiable;
                    }
                    CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
                } else {
                    state = CatalogState::NotFound;
                }
            }
        }
        CloseHandle(hFile);
    }
    CryptCATAdminReleaseContext(hAdmin, 0);
    return state;
}

inline std::string ComputeFileSha256(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return {};

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        DWORD hashLen = 0, cbResult = 0;
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
            (PUCHAR)&hashLen, sizeof(hashLen), &cbResult, 0);
        if (hashLen == 32) {
            std::vector<BYTE> hashBuf(hashLen);
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
                BYTE block[65536];
                DWORD read = 0;
                while (ReadFile(hFile, block, sizeof(block), &read, nullptr) && read > 0)
                    BCryptHashData(hHash, block, read, 0);
                if (BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0) == 0) {
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (BYTE b : hashBuf)
                        oss << std::setw(2) << (int)b;
                    result = oss.str();
                }
                BCryptDestroyHash(hHash);
            }
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    CloseHandle(hFile);
    return result;
}

inline std::string ComputeBufferSha256(const uint8_t* data, size_t size) {
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        DWORD hashLen = 0, cbResult = 0;
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
            (PUCHAR)&hashLen, sizeof(hashLen), &cbResult, 0);
        if (hashLen == 32) {
            std::vector<BYTE> hashBuf(hashLen);
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
                BCryptHashData(hHash, (PUCHAR)data, (ULONG)size, 0);
                if (BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0) == 0) {
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (BYTE b : hashBuf)
                        oss << std::setw(2) << (int)b;
                    result = oss.str();
                }
                BCryptDestroyHash(hHash);
            }
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return result;
}

struct VerifiedSignerIdentity {
    bool         trusted = false;
    std::wstring cnUpper;
    std::string  rootThumb;
};

inline std::string GetSignerRootThumbprint(const std::wstring& path) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &encoding, &contentType, &formatType,
                          &hStore, &hMsg, nullptr))
        return {};

    std::string rootThumb;
    DWORD sz = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &sz) && sz > 0) {
        std::vector<uint8_t> buf(sz);
        auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, si, &sz)) {
            CERT_INFO ci = {};
            ci.Issuer       = si->Issuer;
            ci.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT leaf = CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &ci, nullptr);
            if (leaf) {
                CERT_CHAIN_PARA chainPara = {};
                chainPara.cbSize = sizeof(chainPara);
                PCCERT_CHAIN_CONTEXT chainCtx = nullptr;
                if (CertGetCertificateChain(nullptr, leaf, nullptr, hStore,
                                            &chainPara, 0, nullptr, &chainCtx)) {
                    if (chainCtx->cChain > 0) {
                        PCERT_SIMPLE_CHAIN sc = chainCtx->rgpChain[0];
                        if (sc && sc->cElement > 0) {
                            PCCERT_CONTEXT root = sc->rgpElement[sc->cElement - 1]->pCertContext;
                            BYTE hash[20] = {}; DWORD hashSz = 20;
                            if (root && CertGetCertificateContextProperty(
                                            root, CERT_HASH_PROP_ID, hash, &hashSz)) {
                                std::ostringstream oss;
                                oss << std::hex << std::setfill('0');
                                for (DWORD i = 0; i < hashSz; ++i)
                                    oss << std::setw(2) << (int)hash[i];
                                rootThumb = oss.str();
                            }
                        }
                    }
                    CertFreeCertificateChain(chainCtx);
                }
                CertFreeCertificateContext(leaf);
            }
        }
    }
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg)   CryptMsgClose(hMsg);
    return rootThumb;
}

namespace detail_identcache {
    struct Entry { VerifiedSignerIdentity value; uint64_t fingerprint; };
    inline std::mutex& Mtx() { static std::mutex m; return m; }
    inline std::unordered_map<std::wstring, Entry>& Map() {
        static std::unordered_map<std::wstring, Entry> c; return c;
    }
}

inline VerifiedSignerIdentity GetVerifiedSignerIdentityCached(const std::wstring& path) {
    VerifiedSignerIdentity id;
    if (path.empty())
        return id;
    uint64_t fp = GetFileFingerprint(path);
    if (fp != 0) {
        std::lock_guard<std::mutex> lk(detail_identcache::Mtx());
        auto it = detail_identcache::Map().find(path);
        if (it != detail_identcache::Map().end() && it->second.fingerprint == fp)
            return it->second.value;
    }
    if (IsTrustedSignedCached(path)) {
        id.trusted   = true;
        id.cnUpper   = GetSignerCommonNameUpperCached(path);
        id.rootThumb = GetSignerRootThumbprint(path);
    }
    if (fp != 0) {
        std::lock_guard<std::mutex> lk(detail_identcache::Mtx());
        if (detail_identcache::Map().size() < 2048)
            detail_identcache::Map()[path] = { id, fp };
    }
    return id;
}

inline void ClearIdentityCache() {
    std::lock_guard<std::mutex> lk(detail_identcache::Mtx());
    detail_identcache::Map().clear();
}

inline bool SamePublisherTrusted(const std::wstring& a, const std::wstring& b) {
    if (a.empty() || b.empty())
        return false;
    VerifiedSignerIdentity ia = GetVerifiedSignerIdentityCached(a);
    VerifiedSignerIdentity ib = GetVerifiedSignerIdentityCached(b);
    if (!ia.trusted || !ib.trusted)
        return false;
    if (ia.cnUpper.empty() || ia.cnUpper != ib.cnUpper)
        return false;


    if (!ia.rootThumb.empty() && !ib.rootThumb.empty() && ia.rootThumb != ib.rootThumb)
        return false;
    return true;
}

inline std::string GetSignerCertThumbprint(const std::wstring& path) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &encoding, &contentType, &formatType,
                          &hStore, &hMsg, nullptr))
        return {};

    std::string thumbprint;
    DWORD sz = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &sz) && sz > 0) {
        std::vector<uint8_t> buf(sz);
        auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, si, &sz)) {
            CERT_INFO ci = {};
            ci.Issuer       = si->Issuer;
            ci.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT ctx = CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &ci, nullptr);
            if (ctx) {
                BYTE hash[20] = {};
                DWORD hashSz = 20;
                if (CertGetCertificateContextProperty(ctx, CERT_HASH_PROP_ID, hash, &hashSz)) {
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (DWORD i = 0; i < hashSz; ++i)
                        oss << std::setw(2) << (int)hash[i];
                    thumbprint = oss.str();
                }
                CertFreeCertificateContext(ctx);
            }
        }
    }
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg)   CryptMsgClose(hMsg);
    return thumbprint;
}

}
