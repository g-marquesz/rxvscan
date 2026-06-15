#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
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
#include <bcrypt.h>
#include <ncrypt.h>

#include "scanner_ui.h"
#include "detection_filters.h"

extern std::atomic_bool g_scanSlow;
extern std::atomic_bool g_scanFinished;

namespace ScanLimits {
    constexpr size_t kMaxBypassFindings    = 160;
    constexpr size_t kMaxSyscallDetections =  32;
    constexpr size_t kMaxSysmemFindings    = 128;
    constexpr DWORD  kEvtNextTimeoutMs     = 4000;
    constexpr DWORD  kProcessScanTimeoutMs = 3000;
    constexpr size_t kSignatureCacheMax    = 2048;
    constexpr size_t kMaxGfxHookFindings  =   24; // cap for VTable/inline hook findings
}

namespace ScanTag {
    constexpr const char* ManualMapping = "MANUALMAPPING";
    constexpr const char* Mapper        = "MAPPER";
    constexpr const char* MemoryInject  = "MEMORY INJECT";
    constexpr const char* ThreadInject  = "THREAD INJECT";
    constexpr const char* MemoryProtect = "MEMORY PROTECT";
    constexpr const char* ThreadProtect = "THREAD PROTECT";
    constexpr const char* GfxHook       = "GFXHOOK";
    constexpr const char* GfxHookThread = "GFXHOOK THREAD";
    constexpr const char* GfxHookMemory = "GFXHOOK MEMORY";
    constexpr const char* ModulePatch   = "MODULE PATCH";   // PE checksum mismatch (binary patching)
    constexpr const char* ModuleAnomaly = "MODULE ANOMALY"; // Rich header ausente / secao packer
    constexpr const char* InjectHandle  = "INJECT HANDLE";  // handle com direitos de injecao
    constexpr const char* Hollowing     = "HOLLOWING";
    constexpr const char* NamedPipe     = "NAMED_PIPE";
    constexpr const char* Lsp           = "LSP";
    constexpr const char* ProcAccess    = "PROC_ACCESS";
    constexpr const char* RemoteThread  = "REMOTETHREAD";
    constexpr const char* CheatDomain   = "CHEAT_DOMAIN";
    constexpr const char* Handle        = "HANDLE";
    constexpr const char* AvExclusion   = "AV_EXCLUSION";
    constexpr const char* AvRemoval     = "AV_REMOVAL";
    constexpr const char* Sysmon        = "SYSMON";
    constexpr const char* EventLog      = "EVENTLOG";
    constexpr const char* Explorer      = "EXPLORER";
}

using NtQuerySystemInformationFn = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = LONG (WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct ModuleRange {
    uintptr_t begin = 0;
    uintptr_t end = 0;
    std::wstring path;
    DWORD protect = 0;
};

struct SystemHandleEntry {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SystemHandleInformationEx {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SystemHandleEntry Handles[1];
};

struct EmulatorRuntimeInfo {
    bool hdPlayerOpen = false;
    std::string openedAt = "-";
};

enum class ProtectedBaselineResult {
    Unchanged,
    FirstObservation,
    Changed,
    StoreTampered,
    WriteFailed
};

std::string WideToUtf8(const std::wstring& text);
std::string TrimAscii(std::string text);
std::string ToLowerAscii(std::string text);
bool HasExecutableExtension(const std::wstring& path);
std::wstring ToUpperInvariant(std::wstring text);
bool IsExecutablePrefetchFile(const std::wstring& text);
bool FileExistsW(const std::wstring& path);
ULONGLONG FileTimeToU64(const FILETIME& ft);
FILETIME GetBootFileTime();
void FileTimeToLocalStrings(const FILETIME& ft, std::string& date, std::string& time);
std::wstring DevicePathToDosPath(const std::wstring& path);
bool IsAuthenticodeSigned(const std::wstring& path);
bool GetTpm2PublicHash(std::string& hashHex, std::string& warning);
void CollectSystemOverview(ScannerUI::ScanData& data);

std::wstring GetWindowsDriveRoot();
std::wstring JoinPathW(const std::wstring& base, const std::wstring& child);
std::vector<std::wstring> CollectEfiSystemPartitionRoots(std::string& coverageStatus);
std::vector<ScannerUI::EfiCheatFinding> CollectBootStorageIntegrityFindings(std::string& coverageStatus);
std::vector<ScannerUI::EfiCheatFinding> CollectMeasuredBootFindings(std::string& coverageStatus);
ProtectedBaselineResult CheckProtectedBootBaseline(const std::string& key,
                                                   const std::string& currentHash,
                                                   std::string& previousHash);
std::vector<ScannerUI::BamEntry> CollectBamDetections();
std::vector<ScannerUI::EfiCheatFinding> CollectEfiCheatFindings(std::string& status);
std::vector<ScannerUI::PrefetchHit> CollectHiddenPrefetchDetections();
std::vector<ScannerUI::PrefetchHit> CollectPrefetchIntegrityFindings();
std::vector<ScannerUI::PrefetchHit> CollectUsnJournalIntegrityFindings(std::string& outStatus, std::string& outDrive);

std::wstring BaseNameFromPath(const std::wstring& path);
std::vector<DWORD> FindEmulatorProcesses();
EmulatorRuntimeInfo CollectEmulatorRuntimeInfo();
bool CollectProcessModules(HANDLE process, std::vector<ModuleRange>& modules);
std::string ProcessName(HANDLE process);
std::string ProcessPathByPid(DWORD pid);
std::wstring ProcessBaseNameByPid(DWORD pid);
std::wstring ProcessImageDirW(HANDLE process);
std::wstring ProcessFullPathW(DWORD pid);
std::vector<ScannerUI::EmulatorFinding> CollectEmulatorIntegrityFindings();
std::vector<ScannerUI::EmulatorFinding> CollectSystemMemoryFindings(std::string& status);

std::wstring ExtractXmlTag(const std::wstring& xml, const std::wstring& tag);
std::wstring ExtractXmlAttribute(const std::wstring& xml, const std::wstring& marker, const std::wstring& attr);
std::wstring ExtractSysmonData(const std::wstring& xml, const std::wstring& name);
bool SysmonSystemTimeToFileTime(const std::wstring& systemTime, FILETIME& out);
bool RenderEventXml(EVT_HANDLE eventHandle, std::wstring& out);
std::string FirstNonEmptyUtf8(std::initializer_list<std::wstring> values);
std::vector<ScannerUI::SysmonEvent> CollectSysmonEvents(std::string& status);
std::vector<ScannerUI::ServiceStatus> CollectServiceStatuses();
bool IsSecureBootEnabled();
bool IsIommuEnabled();

// Returns the AllocationBase addresses of all JMP-hook destinations found in
// graphics API exports for the given process. Used to cross-reference injected
// threads/memory regions against confirmed OpenGL/D3D hook payloads.
std::unordered_set<uintptr_t> CollectGfxHookDestBases(HANDLE process,
                                                       const std::vector<ModuleRange>& modules);

std::vector<ScannerUI::GenericBypassFinding> CollectGenericBypassFindings(std::string& status);
std::vector<ScannerUI::GenericBypassFinding> CollectWfpStreamFilterFindings(std::string& status);
std::vector<ScannerUI::StreamModFinding>     CollectStreamModFindings(std::string& status);
std::vector<ScannerUI::RemotePortFinding>    CollectRemotePortFindings(std::string& status);
bool ExportUsnCsvForCommand(const std::string& command, std::string& message);
void ExportScanReportToZ(ScannerUI::ScanData& data);

std::vector<ScannerUI::KernelDriverFinding> CollectKernelDriverFindings(std::string& status);
std::vector<ScannerUI::RegistryFinding>     CollectRegistryPersistenceFindings(std::string& status);
std::vector<ScannerUI::ClsidFinding>        CollectClsidHijackFindings(std::string& status);
bool                                        CleanClsidFinding(ScannerUI::ClsidFinding& finding);
std::vector<ScannerUI::EmulatorFinding> CollectSuspiciousProcesses(std::string& status);
std::vector<ScannerUI::DriverIntegrityFinding> CollectDriverIntegrityFindings(std::string& status);
std::vector<ScannerUI::KernelAnomalyFinding>   CollectKernelAnomalies(std::string& status);

void AppendTerminalLine(ScannerUI::ScanData& data, const std::string& line);
void RunTerminalCommandAsync(const std::string& command, ScannerUI::ScanData& data, std::mutex& dataMutex);
void RunScannerAsync(ScannerUI::ScanData& data, std::mutex& dataMutex);

// P5 — Timeline correlation across BAM, Prefetch, USN journal, and Sysmon events
std::vector<ScannerUI::TimelineCorrelationFinding>
CollectTimelineCorrelationFindings(
    const std::vector<ScannerUI::BamEntry>& bam,
    const std::vector<ScannerUI::PrefetchHit>& prefetch,
    const std::vector<ScannerUI::SysmonEvent>& sysmonEvents,
    std::string& status);
