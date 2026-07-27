#pragma once
#include "scanner_core.h"

struct RTCoreMemRange {
    uint64_t base;
    uint64_t size;
};

struct HiddenEprocessFinding {
    DWORD pid;
    std::string imageFileName;
    uintptr_t eprocessVirtual;
    uint64_t eprocessPhysical;
    std::string reason;
};

struct RTCoreDriver {
    ~RTCoreDriver();
    bool Load(const std::wstring& driverPath);
    void Unload();
    bool IsLoaded() const { return hDevice != INVALID_HANDLE_VALUE && hDevice != nullptr; }
    bool ReadKernelMemory(uint64_t address, void* buffer, DWORD size);
    std::vector<ScannerUI::KernelAnomalyFinding> VerifyKernelVirtualIntegrity();
    bool ReadPhysicalMemory(uint64_t physAddr, void* buffer, DWORD size);
    bool GetPhysicalMemoryRanges(std::vector<RTCoreMemRange>& ranges);
    bool GetKernelPhysicalBase(uint64_t& kernelPhysBase);
    std::vector<HiddenEprocessFinding> FindHiddenProcesses();
    std::vector<ScannerUI::KernelAnomalyFinding> VerifyKernelIntegrity();
    std::vector<ScannerUI::StreamModFinding> FindStreamModAnomalies();
    std::vector<ScannerUI::EmulatorFinding> ScanHdPlayerPhysicalMemory();
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    std::wstring serviceName;
    SC_HANDLE scmHandle = nullptr;
    SC_HANDLE svcHandle = nullptr;
    bool serviceCreated = false;
    std::wstring stagedDriverPath;
};
