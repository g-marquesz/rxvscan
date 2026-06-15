#include "scanner_core.h"

struct UsnNameEntry {
    ULONGLONG parent = 0;
    std::wstring name;
};

struct UsnExportOptions {
    std::unordered_set<std::string> includeExtensions;
    std::unordered_set<std::string> ignoreExtensions;
};
static std::string CsvEscape(const std::string& value) {
    bool quote = value.find_first_of(",\"\r\n") != std::string::npos;
    std::string out;
    out.reserve(value.size() + 4);
    if (quote)
        out.push_back('"');
    for (char c : value) {
        if (c == '"')
            out += "\"\"";
        else
            out.push_back(c);
    }
    if (quote)
        out.push_back('"');
    return out;
}

std::string ToLowerAscii(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return text;
}

static std::string NormalizeExtension(std::string ext) {
    ext = ToLowerAscii(ext);
    while (!ext.empty() && (ext.back() == ',' || ext.back() == ';'))
        ext.pop_back();
    if (!ext.empty() && ext.front() != '.')
        ext.insert(ext.begin(), '.');
    return ext;
}

static std::string ExtensionFromName(const std::wstring& name) {
    size_t dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos)
        return {};
    return NormalizeExtension(WideToUtf8(name.substr(dot)));
}

static void AddExtensionList(const std::string& value, std::unordered_set<std::string>& out) {
    std::string current;
    for (char c : value) {
        if (c == ',' || c == ';' || c == '|') {
            std::string ext = NormalizeExtension(current);
            if (!ext.empty() && ext != ".")
                out.insert(ext);
            current.clear();
        } else {
            current.push_back(c);
        }
    }

    std::string ext = NormalizeExtension(current);
    if (!ext.empty() && ext != ".")
        out.insert(ext);
}

static bool MatchesIncludeExtension(const std::string& ext, const UsnExportOptions& options) {
    std::string normalized = NormalizeExtension(ext);
    if (!options.includeExtensions.empty() && options.includeExtensions.find(normalized) == options.includeExtensions.end())
        return false;
    return true;
}

static bool MatchesIgnoreExtension(const std::string& ext, const UsnExportOptions& options) {
    std::string normalized = NormalizeExtension(ext);
    return !options.ignoreExtensions.empty() && options.ignoreExtensions.find(normalized) != options.ignoreExtensions.end();
}

static std::string UsnReasonToString(DWORD reason) {
    struct ReasonName { DWORD bit; const char* name; };
    static const ReasonName names[] = {
        { USN_REASON_DATA_OVERWRITE, "DATA_OVERWRITE" },
        { USN_REASON_DATA_EXTEND, "DATA_EXTEND" },
        { USN_REASON_DATA_TRUNCATION, "DATA_TRUNCATION" },
        { USN_REASON_NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE" },
        { USN_REASON_NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND" },
        { USN_REASON_NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION" },
        { USN_REASON_FILE_CREATE, "FILE_CREATE" },
        { USN_REASON_FILE_DELETE, "FILE_DELETE" },
        { USN_REASON_EA_CHANGE, "EA_CHANGE" },
        { USN_REASON_SECURITY_CHANGE, "SECURITY_CHANGE" },
        { USN_REASON_RENAME_OLD_NAME, "RENAME_OLD_NAME" },
        { USN_REASON_RENAME_NEW_NAME, "RENAME_NEW_NAME" },
        { USN_REASON_INDEXABLE_CHANGE, "INDEXABLE_CHANGE" },
        { USN_REASON_BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE" },
        { USN_REASON_HARD_LINK_CHANGE, "HARD_LINK_CHANGE" },
        { USN_REASON_COMPRESSION_CHANGE, "COMPRESSION_CHANGE" },
        { USN_REASON_ENCRYPTION_CHANGE, "ENCRYPTION_CHANGE" },
        { USN_REASON_OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE" },
        { USN_REASON_REPARSE_POINT_CHANGE, "REPARSE_POINT_CHANGE" },
        { USN_REASON_STREAM_CHANGE, "STREAM_CHANGE" },
        { USN_REASON_TRANSACTED_CHANGE, "TRANSACTED_CHANGE" },
        { USN_REASON_CLOSE, "CLOSE" },
    };

    std::string out;
    for (const auto& item : names) {
        if ((reason & item.bit) == 0)
            continue;
        if (!out.empty())
            out += "|";
        out += item.name;
    }
    return out.empty() ? "0" : out;
}

static std::string FileAttributesToString(DWORD attrs) {
    std::string out;
    auto add = [&](DWORD bit, const char* name) {
        if ((attrs & bit) == 0)
            return;
        if (!out.empty())
            out += "|";
        out += name;
    };
    add(FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY");
    add(FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE");
    add(FILE_ATTRIBUTE_HIDDEN, "HIDDEN");
    add(FILE_ATTRIBUTE_SYSTEM, "SYSTEM");
    add(FILE_ATTRIBUTE_READONLY, "READONLY");
    add(FILE_ATTRIBUTE_TEMPORARY, "TEMPORARY");
    add(FILE_ATTRIBUTE_COMPRESSED, "COMPRESSED");
    add(FILE_ATTRIBUTE_ENCRYPTED, "ENCRYPTED");
    add(FILE_ATTRIBUTE_REPARSE_POINT, "REPARSE_POINT");
    return out.empty() ? "NORMAL" : out;
}

static std::string GetExecutableDirectoryA() {
    char exePath[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return ".";
    std::string dir(exePath);
    size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos)
        dir.resize(slash);
    return dir;
}

static void ParseUsnExtensionFilters(const std::string& filters, UsnExportOptions& options) {
    std::istringstream iss(filters);
    std::string token;
    std::string pendingKey;

    auto apply = [&](const std::string& keyRaw, const std::string& value) {
        std::string key = ToLowerAscii(keyRaw);
        if (key == "ext" || key == "include" || key == "inc" || key == "pull" || key == "only")
            AddExtensionList(value, options.includeExtensions);
        else if (key == "ignore" || key == "exclude" || key == "exc" || key == "skip")
            AddExtensionList(value, options.ignoreExtensions);
    };

    while (iss >> token) {
        size_t colon = token.find(':');
        if (colon != std::string::npos) {
            std::string key = token.substr(0, colon);
            std::string value = token.substr(colon + 1);
            if (value.empty())
                pendingKey = key;
            else
                apply(key, value);
        } else if (!pendingKey.empty()) {
            apply(pendingKey, token);
            pendingKey.clear();
        }
    }
}

static bool ParseUsnCommandRange(const std::string& command, FILETIME& startFt, FILETIME& endFt,
                                 std::string& startLabel, std::string& endLabel,
                                 UsnExportOptions& options) {
    const std::string prefix = "xv!usn";
    if (command.rfind(prefix, 0) != 0)
        return false;

    std::string range = command.substr(prefix.size());
    size_t sep = range.find('a');
    if (sep == std::string::npos)
        sep = range.find('A');
    if (sep == std::string::npos)
        return false;

    auto trim = [](std::string text) {
        while (!text.empty() && std::isspace((unsigned char)text.front()))
            text.erase(text.begin());
        while (!text.empty() && std::isspace((unsigned char)text.back()))
            text.pop_back();
        return text;
    };

    auto firstFilterMarker = [](const std::string& text) {
        std::string lower = ToLowerAscii(text);
        const char* markers[] = {
            " ext:", " include:", " inc:", " pull:", " only:",
            " ignore:", " exclude:", " exc:", " skip:"
        };
        size_t found = std::string::npos;
        for (const char* marker : markers) {
            size_t pos = lower.find(marker);
            if (pos != std::string::npos && (found == std::string::npos || pos < found))
                found = pos;
        }
        return found;
    };

    auto parseDateTime = [](std::string text, SYSTEMTIME baseDate, SYSTEMTIME& out) {
        auto trimInner = [](std::string value) {
            while (!value.empty() && std::isspace((unsigned char)value.front()))
                value.erase(value.begin());
            while (!value.empty() && std::isspace((unsigned char)value.back()))
                value.pop_back();
            return value;
        };

        text = trimInner(text);
        std::replace(text.begin(), text.end(), '_', ' ');
        std::replace(text.begin(), text.end(), 'T', ' ');

        std::string datePart;
        std::string timePart = text;
        size_t space = text.find(' ');
        if (space != std::string::npos) {
            datePart = trimInner(text.substr(0, space));
            timePart = trimInner(text.substr(space + 1));
        }

        int hour = 0, minute = 0, second = 0;
        if (timePart.size() < 5 || timePart[2] != ':')
            return false;
        hour = std::atoi(timePart.substr(0, 2).c_str());
        minute = std::atoi(timePart.substr(3, 2).c_str());
        if (timePart.size() >= 8 && timePart[5] == ':')
            second = std::atoi(timePart.substr(6, 2).c_str());
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59)
            return false;

        out = baseDate;
        out.wHour = (WORD)hour;
        out.wMinute = (WORD)minute;
        out.wSecond = (WORD)second;
        out.wMilliseconds = 0;

        if (!datePart.empty()) {
            char sepChar = datePart.find('/') != std::string::npos ? '/' : '-';
            size_t p1 = datePart.find(sepChar);
            size_t p2 = p1 == std::string::npos ? std::string::npos : datePart.find(sepChar, p1 + 1);
            if (p1 == std::string::npos || p2 == std::string::npos)
                return false;

            int a = std::atoi(datePart.substr(0, p1).c_str());
            int b = std::atoi(datePart.substr(p1 + 1, p2 - p1 - 1).c_str());
            int c = std::atoi(datePart.substr(p2 + 1).c_str());
            if (c < 100)
                c += 2000;

            if (a > 31) {
                out.wYear = (WORD)a;
                out.wMonth = (WORD)b;
                out.wDay = (WORD)c;
            } else {
                out.wDay = (WORD)a;
                out.wMonth = (WORD)b;
                out.wYear = (WORD)c;
            }
        }

        return out.wYear >= 1970 && out.wMonth >= 1 && out.wMonth <= 12 &&
               out.wDay >= 1 && out.wDay <= 31;
    };

    SYSTEMTIME local = {};
    GetLocalTime(&local);

    std::string startText = trim(range.substr(0, sep));
    std::string endText = trim(range.substr(sep + 1));
    size_t filterAt = firstFilterMarker(" " + endText);
    if (filterAt != std::string::npos) {
        filterAt = filterAt == 0 ? 0 : filterAt - 1;
        std::string filterText = trim(endText.substr(filterAt));
        endText = trim(endText.substr(0, filterAt));
        ParseUsnExtensionFilters(filterText, options);
    }

    SYSTEMTIME startLocal = {};
    SYSTEMTIME endLocal = {};
    if (!parseDateTime(startText, local, startLocal) ||
        !parseDateTime(endText, startLocal, endLocal))
        return false;

    SYSTEMTIME utcStart = {};
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &startLocal, &utcStart))
        return false;
    if (!SystemTimeToFileTime(&utcStart, &startFt))
        return false;

    SYSTEMTIME utcEnd = {};
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &endLocal, &utcEnd))
        return false;
    if (!SystemTimeToFileTime(&utcEnd, &endFt))
        return false;

    if (FileTimeToU64(endFt) < FileTimeToU64(startFt)) {
        ULONGLONG endValue = FileTimeToU64(endFt) + 24ULL * 60ULL * 60ULL * 10000000ULL;
        endFt.dwLowDateTime = (DWORD)endValue;
        endFt.dwHighDateTime = (DWORD)(endValue >> 32);
    }

    char startBuf[32] = {};
    char endBuf[32] = {};
    sprintf_s(startBuf, "%04u%02u%02u_%02u%02u%02u",
              startLocal.wYear, startLocal.wMonth, startLocal.wDay,
              startLocal.wHour, startLocal.wMinute, startLocal.wSecond);
    sprintf_s(endBuf, "%04u%02u%02u_%02u%02u%02u",
              endLocal.wYear, endLocal.wMonth, endLocal.wDay,
              endLocal.wHour, endLocal.wMinute, endLocal.wSecond);
    startLabel = startBuf;
    endLabel = endBuf;
    return true;
}

static void BuildUsnNameMap(HANDLE volume, USN nextUsn, std::unordered_map<ULONGLONG, UsnNameEntry>& names) {
    MFT_ENUM_DATA_V0 query = {};
    query.StartFileReferenceNumber = 0;
    query.LowUsn = 0;
    query.HighUsn = nextUsn;

    std::vector<BYTE> buffer(1024 * 1024);
    DWORD bytes = 0;
    while (DeviceIoControl(volume, FSCTL_ENUM_USN_DATA, &query, sizeof(query),
                           buffer.data(), (DWORD)buffer.size(), &bytes, nullptr)) {
        if (bytes <= sizeof(USN))
            break;

        BYTE* cursor = buffer.data() + sizeof(USN);
        BYTE* end = buffer.data() + bytes;
        while (cursor + sizeof(USN_RECORD_V2) <= end) {
            auto* record = reinterpret_cast<USN_RECORD_V2*>(cursor);
            if (record->RecordLength == 0 || cursor + record->RecordLength > end)
                break;

            if (record->MajorVersion == 2 && record->FileNameLength > 0) {
                const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(cursor + record->FileNameOffset);
                std::wstring name(namePtr, record->FileNameLength / sizeof(wchar_t));
                names[(ULONGLONG)record->FileReferenceNumber] = { (ULONGLONG)record->ParentFileReferenceNumber, name };
            }
            cursor += record->RecordLength;
        }

        query.StartFileReferenceNumber = *reinterpret_cast<USN*>(buffer.data());
    }
}

static std::wstring ReconstructUsnPath(ULONGLONG frn, const std::unordered_map<ULONGLONG, UsnNameEntry>& names) {
    std::vector<std::wstring> parts;
    ULONGLONG current = frn;
    for (int depth = 0; depth < 64; ++depth) {
        auto it = names.find(current);
        if (it == names.end() || it->second.name.empty())
            break;
        parts.push_back(it->second.name);
        if (it->second.parent == current || it->second.parent == 0)
            break;
        current = it->second.parent;
    }

    std::wstring path;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!path.empty())
            path += L"\\";
        path += *it;
    }
    return path;
}

bool ExportUsnCsvForCommand(const std::string& command, std::string& message) {
    FILETIME startFt = {}, endFt = {};
    std::string startLabel, endLabel;
    UsnExportOptions options;
    if (!ParseUsnCommandRange(command, startFt, endFt, startLabel, endLabel, options)) {
        message = "invalid command. use xv!usn29/05/2026 04:59a29/05/2026 05:10 ext:.exe,.dll ignore:.tmp";
        return false;
    }

    std::wstring root = GetWindowsDriveRoot();
    wchar_t volumePath[] = { L'\\', L'\\', L'.', L'\\', root[0], L':', L'\0' };
    HANDLE volume = CreateFileW(volumePath, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (volume == INVALID_HANDLE_VALUE) {
        message = "failed to open volume. run as administrator";
        return false;
    }

    USN_JOURNAL_DATA_V0 journal = {};
    DWORD bytes = 0;
    if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &journal, sizeof(journal), &bytes, nullptr)) {
        CloseHandle(volume);
        message = "failed to query USN Journal";
        return false;
    }

    std::unordered_map<ULONGLONG, UsnNameEntry> names;
    BuildUsnNameMap(volume, journal.NextUsn, names);

    std::string outPath = GetExecutableDirectoryA() + "\\usn_" + startLabel + "_" + endLabel + ".csv";
    std::ofstream csv(outPath, std::ios::binary);
    if (!csv) {
        CloseHandle(volume);
        message = "failed to create csv";
        return false;
    }

    csv << "Date,Time,USN,Reason,ReasonHex,Extension,ExtensionIncludeMatch,ExtensionIgnoreMatch,ExtensionFilterHint,FileName,Path,FRN,ParentFRN,Attributes,AttributesHex\n";

    READ_USN_JOURNAL_DATA_V0 readData = {};
    readData.StartUsn = journal.FirstUsn;
    readData.ReasonMask = 0xFFFFFFFF;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout = 0;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = journal.UsnJournalID;

    ULONGLONG startValue = FileTimeToU64(startFt);
    ULONGLONG endValue = FileTimeToU64(endFt);
    std::vector<BYTE> buffer(1024 * 1024);
    size_t written = 0;

    while (readData.StartUsn < journal.NextUsn &&
           DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData),
                           buffer.data(), (DWORD)buffer.size(), &bytes, nullptr)) {
        if (bytes <= sizeof(USN))
            break;

        BYTE* cursor = buffer.data() + sizeof(USN);
        BYTE* end = buffer.data() + bytes;
        while (cursor + sizeof(USN_RECORD_V2) <= end) {
            auto* record = reinterpret_cast<USN_RECORD_V2*>(cursor);
            if (record->RecordLength == 0 || cursor + record->RecordLength > end)
                break;

            if (record->MajorVersion == 2) {
                FILETIME ft = {};
                ft.dwLowDateTime = record->TimeStamp.LowPart;
                ft.dwHighDateTime = record->TimeStamp.HighPart;
                ULONGLONG timeValue = FileTimeToU64(ft);
                if (timeValue >= startValue && timeValue <= endValue) {
                    const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(cursor + record->FileNameOffset);
                    std::wstring name(namePtr, record->FileNameLength / sizeof(wchar_t));
                    std::string extension = ExtensionFromName(name);
                    bool includeMatch = MatchesIncludeExtension(extension, options);
                    bool ignoreMatch = MatchesIgnoreExtension(extension, options);
                    std::string filterHint = ignoreMatch ? "IGNORE_MATCH" : (includeMatch ? "INCLUDE_MATCH" : "OUTSIDE_INCLUDE");
                    std::wstring path = ReconstructUsnPath((ULONGLONG)record->FileReferenceNumber, names);
                    std::string date, time;
                    FileTimeToLocalStrings(ft, date, time);

                    csv << CsvEscape(date) << ','
                        << CsvEscape(time) << ','
                        << record->Usn << ','
                        << CsvEscape(UsnReasonToString(record->Reason)) << ','
                        << "0x" << std::hex << std::uppercase << record->Reason << std::dec << ','
                        << CsvEscape(extension) << ','
                        << (includeMatch ? "yes" : "no") << ','
                        << (ignoreMatch ? "yes" : "no") << ','
                        << CsvEscape(filterHint) << ','
                        << CsvEscape(WideToUtf8(name)) << ','
                        << CsvEscape(WideToUtf8(path)) << ','
                        << (ULONGLONG)record->FileReferenceNumber << ','
                        << (ULONGLONG)record->ParentFileReferenceNumber << ','
                        << CsvEscape(FileAttributesToString(record->FileAttributes)) << ','
                        << "0x" << std::hex << std::uppercase << record->FileAttributes << std::dec << "\n";
                    ++written;
                }
            }

            cursor += record->RecordLength;
        }

        USN nextUsn = *reinterpret_cast<USN*>(buffer.data());
        if (nextUsn <= readData.StartUsn)
            break;
        readData.StartUsn = nextUsn;
    }

    CloseHandle(volume);
    message = "USN csv generated: " + outPath + " (" + std::to_string((int)written) + " rows)";

    return true;
}
