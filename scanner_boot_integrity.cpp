#include "scanner_core.h"

#include <tbs.h>
#include <winioctl.h>
#include <wincrypt.h>

namespace {

constexpr GUID kEfiSystemPartitionGuid = {
    0xc12a7328, 0xf81f, 0x11d2, { 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b }
};

#pragma pack(push, 1)
struct GptHeaderRaw {
    char signature[8];
    uint32_t revision;
    uint32_t headerSize;
    uint32_t headerCrc32;
    uint32_t reserved;
    uint64_t currentLba;
    uint64_t backupLba;
    uint64_t firstUsableLba;
    uint64_t lastUsableLba;
    GUID diskGuid;
    uint64_t partitionEntryLba;
    uint32_t partitionEntryCount;
    uint32_t partitionEntrySize;
    uint32_t partitionEntryArrayCrc32;
};
#pragma pack(pop)

uint32_t Crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

std::wstring TrimVolumeForOpen(std::wstring volume) {
    while (!volume.empty() && (volume.back() == L'\\' || volume.back() == L'/'))
        volume.pop_back();
    return volume;
}

bool ReadAt(HANDLE handle, uint64_t offset, void* buffer, DWORD bytes) {
    LARGE_INTEGER pos = {};
    pos.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN))
        return false;
    DWORD read = 0;
    return ReadFile(handle, buffer, bytes, &read, nullptr) && read == bytes;
}

void StampFinding(ScannerUI::EfiCheatFinding& finding,
                  const char* ruleId,
                  const char* confidence,
                  const char* state = "SUSPICIOUS") {
    finding.ruleId = ruleId;
    finding.source = "raw-disk";
    finding.confidence = confidence;
    finding.evidenceState = state;
}

void AddDiskFinding(std::vector<ScannerUI::EfiCheatFinding>& findings,
                    int disk,
                    const char* severity,
                    const char* ruleId,
                    const char* confidence,
                    const std::string& reason,
                    const std::string& detail,
                    bool suspicious = true) {
    ScannerUI::EfiCheatFinding finding;
    finding.severity = severity;
    finding.path = "\\\\.\\PhysicalDrive" + std::to_string(disk);
    finding.reason = reason;
    finding.detail = detail;
    finding.suspicious = suspicious;
    StampFinding(finding, ruleId, confidence, suspicious ? "SUSPICIOUS" : "INCONCLUSIVE");
    findings.push_back(std::move(finding));
}

bool ValidateGptHeader(HANDLE drive,
                       int disk,
                       uint32_t sectorSize,
                       uint64_t diskSectors,
                       uint64_t headerLba,
                       const char* side,
                       GptHeaderRaw& out,
                       std::vector<ScannerUI::EfiCheatFinding>& findings) {
    std::vector<uint8_t> sector(sectorSize);
    if (!ReadAt(drive, headerLba * sectorSize, sector.data(), sectorSize))
        return false;

    if (sector.size() < sizeof(GptHeaderRaw) ||
        memcmp(sector.data(), "EFI PART", 8) != 0) {
        AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.HEADER_MISSING", "HIGH",
                       std::string(side) + " GPT header missing",
                       "expected signature \"EFI PART\" at LBA " + std::to_string(headerLba));
        return false;
    }

    memcpy(&out, sector.data(), sizeof(out));
    if (out.headerSize < 92 || out.headerSize > sectorSize) {
        AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.HEADER_SIZE", "HIGH",
                       std::string(side) + " GPT header has invalid size",
                       "header_size=" + std::to_string(out.headerSize) +
                       " sector_size=" + std::to_string(sectorSize));
        return false;
    }

    std::vector<uint8_t> header(sector.begin(), sector.begin() + out.headerSize);
    const uint32_t storedCrc = out.headerCrc32;
    memset(header.data() + offsetof(GptHeaderRaw, headerCrc32), 0, sizeof(uint32_t));
    const uint32_t calculatedCrc = Crc32(header.data(), header.size());
    if (storedCrc != calculatedCrc) {
        AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.HEADER_CRC", "HIGH",
                       std::string(side) + " GPT header CRC mismatch",
                       "stored_crc=" + std::to_string(storedCrc) +
                       " calculated_crc=" + std::to_string(calculatedCrc));
    }

    if (out.currentLba != headerLba || out.backupLba >= diskSectors ||
        out.firstUsableLba > out.lastUsableLba ||
        out.lastUsableLba >= diskSectors) {
        AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.HEADER_BOUNDS", "HIGH",
                       std::string(side) + " GPT header contains invalid disk bounds",
                       "current_lba=" + std::to_string(out.currentLba) +
                       " backup_lba=" + std::to_string(out.backupLba) +
                       " disk_sectors=" + std::to_string(diskSectors));
    }

    const uint64_t arrayBytes =
        static_cast<uint64_t>(out.partitionEntryCount) * out.partitionEntrySize;
    constexpr uint64_t kMaxPartitionArrayBytes = 16ull * 1024 * 1024;
    if (out.partitionEntryCount == 0 || out.partitionEntrySize < 128 ||
        arrayBytes > kMaxPartitionArrayBytes ||
        out.partitionEntryLba >= diskSectors ||
        arrayBytes > (diskSectors - out.partitionEntryLba) * sectorSize) {
        AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.TABLE_BOUNDS", "HIGH",
                       std::string(side) + " GPT partition table bounds are invalid",
                       "entries=" + std::to_string(out.partitionEntryCount) +
                       " entry_size=" + std::to_string(out.partitionEntrySize));
        return true;
    }

    std::vector<uint8_t> entries(static_cast<size_t>(arrayBytes));
    if (!ReadAt(drive, out.partitionEntryLba * sectorSize,
                entries.data(), static_cast<DWORD>(entries.size()))) {
        AddDiskFinding(findings, disk, "FLAG", "BOOT.GPT.TABLE_UNREADABLE", "LOW",
                       std::string(side) + " GPT partition table could not be read",
                       "raw disk read failed", false);
        return true;
    }

    const uint32_t entriesCrc = Crc32(entries.data(), entries.size());
    if (entriesCrc != out.partitionEntryArrayCrc32) {
        AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.TABLE_CRC", "HIGH",
                       std::string(side) + " GPT partition table CRC mismatch",
                       "stored_crc=" + std::to_string(out.partitionEntryArrayCrc32) +
                       " calculated_crc=" + std::to_string(entriesCrc));
    }
    return true;
}

bool GuidEqual(const GUID& a, const GUID& b) {
    return InlineIsEqualGUID(a, b) != 0;
}

bool ReadU16(const std::vector<uint8_t>& data, size_t& offset, uint16_t& value) {
    if (offset + sizeof(value) > data.size())
        return false;
    memcpy(&value, data.data() + offset, sizeof(value));
    offset += sizeof(value);
    return true;
}

bool ReadU32(const std::vector<uint8_t>& data, size_t& offset, uint32_t& value) {
    if (offset + sizeof(value) > data.size())
        return false;
    memcpy(&value, data.data() + offset, sizeof(value));
    offset += sizeof(value);
    return true;
}

struct TcgLogSummary {
    bool valid = false;
    bool cryptoAgile = false;
    size_t events = 0;
    size_t efiImageEvents = 0;
    std::string error;
};

TcgLogSummary ParseTcgLog(const std::vector<uint8_t>& log) {
    TcgLogSummary summary;
    constexpr size_t kLegacyHeaderSize = 4 + 4 + 20 + 4;
    if (log.size() < kLegacyHeaderSize) {
        summary.error = "log is shorter than a TCG event header";
        return summary;
    }

    size_t offset = 0;
    uint32_t firstPcr = 0, firstType = 0, firstEventSize = 0;
    if (!ReadU32(log, offset, firstPcr) || !ReadU32(log, offset, firstType)) {
        summary.error = "first event header is truncated";
        return summary;
    }
    offset += 20;
    if (!ReadU32(log, offset, firstEventSize) ||
        firstEventSize > log.size() - offset) {
        summary.error = "first event payload exceeds the log";
        return summary;
    }

    const size_t firstEventOffset = offset;
    const bool isSpecId =
        firstEventSize >= 16 &&
        memcmp(log.data() + firstEventOffset, "Spec ID Event03", 15) == 0;
    ++summary.events;

    if (!isSpecId) {
        offset += firstEventSize;
        while (offset < log.size()) {
            if (log.size() - offset < kLegacyHeaderSize) {
                summary.error = "legacy event header is truncated";
                return summary;
            }
            uint32_t pcr = 0, type = 0, eventSize = 0;
            ReadU32(log, offset, pcr);
            ReadU32(log, offset, type);
            offset += 20;
            ReadU32(log, offset, eventSize);
            if (pcr > 31 || eventSize > log.size() - offset) {
                summary.error = "legacy event contains invalid bounds";
                return summary;
            }
            if (type >= 0x80000003u && type <= 0x80000006u)
                ++summary.efiImageEvents;
            offset += eventSize;
            ++summary.events;
        }
        summary.valid = true;
        return summary;
    }

    summary.cryptoAgile = true;
    std::unordered_map<uint16_t, uint16_t> digestSizes;
    size_t spec = firstEventOffset + 16;
    if (spec + 4 + 4 + 4 > firstEventOffset + firstEventSize) {
        summary.error = "SpecID event is truncated";
        return summary;
    }
    spec += 4; // platformClass
    spec += 4; // minor, major, errata, uintnSize
    uint32_t algorithmCount = 0;
    memcpy(&algorithmCount, log.data() + spec, sizeof(algorithmCount));
    spec += sizeof(algorithmCount);
    if (algorithmCount == 0 || algorithmCount > 32) {
        summary.error = "SpecID algorithm count is invalid";
        return summary;
    }
    for (uint32_t i = 0; i < algorithmCount; ++i) {
        if (spec + 4 > firstEventOffset + firstEventSize) {
            summary.error = "SpecID algorithm table is truncated";
            return summary;
        }
        uint16_t algorithm = 0, digestSize = 0;
        memcpy(&algorithm, log.data() + spec, sizeof(algorithm));
        memcpy(&digestSize, log.data() + spec + 2, sizeof(digestSize));
        spec += 4;
        if (digestSize == 0 || digestSize > 128) {
            summary.error = "SpecID contains an invalid digest size";
            return summary;
        }
        digestSizes[algorithm] = digestSize;
    }

    offset = firstEventOffset + firstEventSize;
    while (offset < log.size()) {
        uint32_t pcr = 0, type = 0, digestCount = 0;
        if (!ReadU32(log, offset, pcr) ||
            !ReadU32(log, offset, type) ||
            !ReadU32(log, offset, digestCount)) {
            summary.error = "event2 header is truncated";
            return summary;
        }
        if (pcr > 31 || digestCount == 0 || digestCount > 32) {
            summary.error = "event2 header contains invalid values";
            return summary;
        }
        for (uint32_t i = 0; i < digestCount; ++i) {
            uint16_t algorithm = 0;
            if (!ReadU16(log, offset, algorithm)) {
                summary.error = "event2 digest algorithm is truncated";
                return summary;
            }
            auto sizeIt = digestSizes.find(algorithm);
            if (sizeIt == digestSizes.end() ||
                sizeIt->second > log.size() - offset) {
                summary.error = "event2 references an unknown or truncated digest";
                return summary;
            }
            offset += sizeIt->second;
        }
        uint32_t eventSize = 0;
        if (!ReadU32(log, offset, eventSize) ||
            eventSize > log.size() - offset) {
            summary.error = "event2 payload exceeds the log";
            return summary;
        }
        if (type >= 0x80000003u && type <= 0x80000006u)
            ++summary.efiImageEvents;
        offset += eventSize;
        ++summary.events;
    }

    summary.valid = summary.events > 1;
    if (!summary.valid)
        summary.error = "log contains no measured boot events";
    return summary;
}

std::wstring ProtectedBaselinePath() {
    wchar_t programData[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(
        L"ProgramData", programData, static_cast<DWORD>(std::size(programData)));
    std::wstring base = (len > 0 && len < std::size(programData))
        ? std::wstring(programData)
        : L"C:\\ProgramData";
    std::wstring dir = base + L"\\rxvscan";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\boot-baseline.dpapi";
}

DATA_BLOB BaselineEntropy() {
    static BYTE entropy[] = {
        'r','x','v','s','c','a','n','-','b','o','o','t','-','v','2'
    };
    DATA_BLOB blob = {};
    blob.pbData = entropy;
    blob.cbData = static_cast<DWORD>(sizeof(entropy));
    return blob;
}

bool LoadProtectedBaseline(std::unordered_map<std::string, std::string>& values,
                           bool& tampered) {
    tampered = false;
    std::wstring path = ProtectedBaselinePath();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 4 * 1024 * 1024) {
        CloseHandle(file);
        tampered = true;
        return false;
    }
    std::vector<BYTE> encrypted(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    bool readOk = ReadFile(file, encrypted.data(),
                           static_cast<DWORD>(encrypted.size()), &read, nullptr) &&
                  read == encrypted.size();
    CloseHandle(file);
    if (!readOk) {
        tampered = true;
        return false;
    }

    DATA_BLOB input = {};
    input.pbData = encrypted.data();
    input.cbData = static_cast<DWORD>(encrypted.size());
    DATA_BLOB output = {};
    DATA_BLOB entropy = BaselineEntropy();
    if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                            &output)) {
        tampered = true;
        return false;
    }

    std::string plain(reinterpret_cast<const char*>(output.pbData), output.cbData);
    LocalFree(output.pbData);
    std::istringstream stream(plain);
    std::string line;
    while (std::getline(stream, line)) {
        size_t tab = line.find('\t');
        if (tab == std::string::npos || tab == 0 || tab + 1 >= line.size()) {
            tampered = true;
            values.clear();
            return false;
        }
        std::string key = line.substr(0, tab);
        std::string hash = line.substr(tab + 1);
        if (hash.size() != 64 ||
            !std::all_of(hash.begin(), hash.end(), [](unsigned char c) {
                return std::isxdigit(c) != 0;
            })) {
            tampered = true;
            values.clear();
            return false;
        }
        values[key] = hash;
    }
    return true;
}

bool SaveProtectedBaseline(const std::unordered_map<std::string, std::string>& values) {
    std::vector<std::pair<std::string, std::string>> sorted(values.begin(), values.end());
    std::sort(sorted.begin(), sorted.end());
    std::ostringstream plain;
    for (const auto& entry : sorted)
        plain << entry.first << '\t' << entry.second << '\n';
    std::string serialized = plain.str();

    DATA_BLOB input = {};
    input.pbData = reinterpret_cast<BYTE*>(serialized.data());
    input.cbData = static_cast<DWORD>(serialized.size());
    DATA_BLOB output = {};
    DATA_BLOB entropy = BaselineEntropy();
    if (!CryptProtectData(&input, L"RXVScan boot baseline", &entropy,
                          nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                          &output))
        return false;

    std::wstring path = ProtectedBaselinePath();
    std::wstring temp = path + L".tmp";
    HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LocalFree(output.pbData);
        return false;
    }
    DWORD written = 0;
    bool ok = WriteFile(file, output.pbData, output.cbData, &written, nullptr) &&
              written == output.cbData && FlushFileBuffers(file);
    CloseHandle(file);
    LocalFree(output.pbData);
    if (!ok) {
        DeleteFileW(temp.c_str());
        return false;
    }
    if (!MoveFileExW(temp.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp.c_str());
        return false;
    }
    return true;
}

} // namespace

std::vector<std::wstring> CollectEfiSystemPartitionRoots(std::string& coverageStatus) {
    std::vector<std::wstring> roots;
    std::unordered_set<std::wstring> seen;
    bool enumFailed = false;
    bool espAccessDenied = false;

    wchar_t volumeName[MAX_PATH] = {};
    HANDLE find = FindFirstVolumeW(volumeName, static_cast<DWORD>(std::size(volumeName)));
    if (find == INVALID_HANDLE_VALUE) {
        coverageStatus = "INCONCLUSIVE: volume enumeration failed";
        return roots;
    }

    do {
        std::wstring root = volumeName;
        std::wstring openPath = TrimVolumeForOpen(root);
        HANDLE volume = CreateFileW(openPath.c_str(), 0,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
        if (volume == INVALID_HANDLE_VALUE)
            continue;

        PARTITION_INFORMATION_EX partition = {};
        DWORD returned = 0;
        const bool gotPartition =
            DeviceIoControl(volume, IOCTL_DISK_GET_PARTITION_INFO_EX,
                            nullptr, 0, &partition, sizeof(partition), &returned, nullptr) != FALSE;
        CloseHandle(volume);
        if (!gotPartition || partition.PartitionStyle != PARTITION_STYLE_GPT ||
            !GuidEqual(partition.Gpt.PartitionType, kEfiSystemPartitionGuid))
            continue;

        DWORD attrs = GetFileAttributesW(root.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            espAccessDenied = true;
            continue;
        }

        std::wstring key = ToUpperInvariant(root);
        if (seen.insert(key).second)
            roots.push_back(root);
    } while (FindNextVolumeW(find, volumeName, static_cast<DWORD>(std::size(volumeName))));

    if (GetLastError() != ERROR_NO_MORE_FILES)
        enumFailed = true;
    FindVolumeClose(find);

    if (enumFailed || espAccessDenied)
        coverageStatus = "INCONCLUSIVE: one or more EFI partitions were inaccessible";
    else if (roots.empty())
        coverageStatus = "INCONCLUSIVE: no EFI System Partition was discovered";
    else
        coverageStatus = "OK";
    return roots;
}

std::vector<ScannerUI::EfiCheatFinding>
CollectBootStorageIntegrityFindings(std::string& coverageStatus) {
    std::vector<ScannerUI::EfiCheatFinding> findings;
    bool sawDisk = false;
    bool accessDenied = false;
    int consecutiveMissing = 0;

    for (int disk = 0; disk < 32 && consecutiveMissing < 8; ++disk) {
        std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(disk);
        HANDLE drive = CreateFileW(path.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (drive == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED)
                accessDenied = true;
            ++consecutiveMissing;
            continue;
        }

        sawDisk = true;
        consecutiveMissing = 0;

        std::vector<uint8_t> geometryBuffer(sizeof(DISK_GEOMETRY_EX) + 256);
        DWORD returned = 0;
        if (!DeviceIoControl(drive, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                             nullptr, 0, geometryBuffer.data(),
                             static_cast<DWORD>(geometryBuffer.size()), &returned, nullptr)) {
            AddDiskFinding(findings, disk, "FLAG", "BOOT.DISK.GEOMETRY_UNAVAILABLE", "LOW",
                           "disk geometry unavailable",
                           "cannot validate GPT bounds", false);
            CloseHandle(drive);
            continue;
        }

        const auto* geometry =
            reinterpret_cast<const DISK_GEOMETRY_EX*>(geometryBuffer.data());
        const uint32_t sectorSize = geometry->Geometry.BytesPerSector;
        const uint64_t diskBytes = static_cast<uint64_t>(geometry->DiskSize.QuadPart);
        if (sectorSize < 512 || sectorSize > 65536 || diskBytes < sectorSize * 3ull) {
            AddDiskFinding(findings, disk, "FLAG", "BOOT.DISK.GEOMETRY_INVALID", "LOW",
                           "disk geometry is outside supported bounds",
                           "sector_size=" + std::to_string(sectorSize), false);
            CloseHandle(drive);
            continue;
        }

        const uint64_t diskSectors = diskBytes / sectorSize;
        std::vector<uint8_t> mbr(sectorSize);
        if (!ReadAt(drive, 0, mbr.data(), sectorSize)) {
            AddDiskFinding(findings, disk, "FLAG", "BOOT.MBR.UNREADABLE", "LOW",
                           "protective MBR could not be read",
                           "raw disk read failed", false);
            CloseHandle(drive);
            continue;
        }

        if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
            AddDiskFinding(findings, disk, "HIGH", "BOOT.MBR.SIGNATURE", "HIGH",
                           "MBR boot signature is missing",
                           "expected 0x55AA at offsets 510-511");
        }

        bool protective = false;
        for (int entry = 0; entry < 4; ++entry) {
            if (mbr[0x1BE + entry * 16 + 4] == 0xEE) {
                protective = true;
                break;
            }
        }

        std::vector<uint8_t> lba1(sectorSize);
        const bool hasPrimarySignature =
            ReadAt(drive, sectorSize, lba1.data(), sectorSize) &&
            memcmp(lba1.data(), "EFI PART", 8) == 0;
        if (!hasPrimarySignature) {
            CloseHandle(drive);
            continue;
        }

        if (!protective) {
            AddDiskFinding(findings, disk, "MEDIUM", "BOOT.MBR.PROTECTIVE_MISSING", "MEDIUM",
                           "GPT disk has no protective MBR entry",
                           "valid GPT signature exists but no partition type 0xEE was found",
                           false);
        }

        GptHeaderRaw primary = {};
        const bool primaryValid =
            ValidateGptHeader(drive, disk, sectorSize, diskSectors, 1,
                              "primary", primary, findings);

        uint64_t backupLba = diskSectors - 1;
        if (primaryValid && primary.backupLba < diskSectors)
            backupLba = primary.backupLba;

        GptHeaderRaw backup = {};
        const bool backupValid =
            ValidateGptHeader(drive, disk, sectorSize, diskSectors, backupLba,
                              "backup", backup, findings);

        if (primaryValid && backupValid) {
            if (primary.backupLba != backup.currentLba ||
                backup.backupLba != primary.currentLba ||
                !GuidEqual(primary.diskGuid, backup.diskGuid) ||
                primary.partitionEntryArrayCrc32 != backup.partitionEntryArrayCrc32) {
                AddDiskFinding(findings, disk, "HIGH", "BOOT.GPT.COPY_MISMATCH", "HIGH",
                               "primary and backup GPT metadata do not match",
                               "disk GUID, reciprocal LBA, or partition-array CRC differs");
            }
        }

        CloseHandle(drive);
    }

    if (!sawDisk)
        coverageStatus = accessDenied ? "ACCESS_DENIED" : "INCONCLUSIVE";
    else if (accessDenied)
        coverageStatus = "PARTIAL";
    else
        coverageStatus = "OK";

    if (accessDenied) {
        AddDiskFinding(findings, -1, "FLAG", "BOOT.DISK.ACCESS_DENIED", "LOW",
                       "one or more physical disks could not be inspected",
                       "run elevated for complete raw-disk coverage", false);
        findings.back().path = "PhysicalDrive::*";
        findings.back().evidenceState = "ACCESS_DENIED";
    }
    return findings;
}

std::vector<ScannerUI::EfiCheatFinding>
CollectMeasuredBootFindings(std::string& coverageStatus) {
    std::vector<ScannerUI::EfiCheatFinding> findings;

    TPM_DEVICE_INFO info = {};
    info.structVersion = 1;
    if (Tbsi_GetDeviceInfo(sizeof(info), &info) != TBS_SUCCESS ||
        info.tpmVersion == TPM_VERSION_UNKNOWN) {
        coverageStatus = "UNAVAILABLE: TPM not present";
        return findings;
    }

    UINT32 logSize = 0;
    Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_BOOT, nullptr, &logSize);
    if (logSize == 0 || logSize > 64u * 1024u * 1024u) {
        coverageStatus = "UNAVAILABLE: SRTM boot log not exposed";
        return findings;
    }

    std::vector<uint8_t> log(logSize);
    TBS_RESULT result =
        Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_BOOT, log.data(), &logSize);
    if (result != TBS_SUCCESS || logSize == 0 || logSize > log.size()) {
        coverageStatus = "INCONCLUSIVE: failed to read SRTM boot log";
        return findings;
    }
    log.resize(logSize);

    TcgLogSummary summary = ParseTcgLog(log);
    if (!summary.valid) {
        ScannerUI::EfiCheatFinding finding;
        finding.severity = "MEDIUM";
        finding.path = "TPM::SRTM_BOOT_LOG";
        finding.reason = "Measured Boot log is structurally inconsistent";
        finding.detail = summary.error + " | bytes=" + std::to_string(log.size());
        finding.ruleId = "BOOT.TPM.LOG_MALFORMED";
        finding.source = "TPM Base Services";
        finding.confidence = "MEDIUM";
        finding.evidenceState = "INCONCLUSIVE";
        finding.suspicious = false;
        findings.push_back(std::move(finding));
        coverageStatus = "INCONCLUSIVE";
        return findings;
    }

    coverageStatus =
        "OK: events=" + std::to_string(summary.events) +
        " efi_images=" + std::to_string(summary.efiImageEvents) +
        " format=" + (summary.cryptoAgile ? std::string("TCG2") : std::string("TCG1.2"));
    return findings;
}

ProtectedBaselineResult CheckProtectedBootBaseline(const std::string& key,
                                                   const std::string& currentHash,
                                                   std::string& previousHash) {
    previousHash.clear();
    if (key.empty() || currentHash.size() != 64)
        return ProtectedBaselineResult::WriteFailed;

    static std::mutex baselineMutex;
    std::lock_guard<std::mutex> lock(baselineMutex);

    std::unordered_map<std::string, std::string> values;
    bool tampered = false;
    if (!LoadProtectedBaseline(values, tampered))
        return tampered ? ProtectedBaselineResult::StoreTampered
                        : ProtectedBaselineResult::WriteFailed;

    auto existing = values.find(key);
    if (existing == values.end()) {
        values[key] = currentHash;
        return SaveProtectedBaseline(values)
            ? ProtectedBaselineResult::FirstObservation
            : ProtectedBaselineResult::WriteFailed;
    }
    if (existing->second == currentHash)
        return ProtectedBaselineResult::Unchanged;

    previousHash = existing->second;
    return ProtectedBaselineResult::Changed;
}
