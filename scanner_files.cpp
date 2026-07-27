#include "scanner_core.h"
#pragma comment(lib, "crypt32.lib")

static void CollectBamFromKey(HKEY root, const wchar_t* subkey, const FILETIME& bootTime,
                              std::vector<ScannerUI::BamEntry>& out) {
    HKEY usersKey = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &usersKey) != ERROR_SUCCESS)
        return;

    DWORD subkeyCount = 0;
    RegQueryInfoKeyW(usersKey, nullptr, nullptr, nullptr, &subkeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    for (DWORD i = 0; i < subkeyCount; ++i) {
        wchar_t sidName[256] = {};
        DWORD sidLen = (DWORD)std::size(sidName);
        if (RegEnumKeyExW(usersKey, i, sidName, &sidLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            continue;

        HKEY sidKey = nullptr;
        if (RegOpenKeyExW(usersKey, sidName, 0, KEY_READ | KEY_WOW64_64KEY, &sidKey) != ERROR_SUCCESS)
            continue;

        DWORD valueCount = 0;
        RegQueryInfoKeyW(sidKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, nullptr, nullptr, nullptr, nullptr);

        for (DWORD v = 0; v < valueCount; ++v) {
            wchar_t valueName[32768] = {};
            DWORD valueNameLen = (DWORD)std::size(valueName);
            BYTE data[64] = {};
            DWORD dataSize = sizeof(data);
            DWORD type = 0;
            if (RegEnumValueW(sidKey, v, valueName, &valueNameLen, nullptr, &type, data, &dataSize) != ERROR_SUCCESS)
                continue;
            if (type != REG_BINARY || dataSize < sizeof(FILETIME))
                continue;

            std::wstring path = DevicePathToDosPath(valueName);
            if (!HasExecutableExtension(path))
                continue;

            FILETIME lastRun = {};
            memcpy(&lastRun, data, sizeof(FILETIME));

            bool exists = FileExistsW(path);
            DetectionFilter::PathClass cls = DetectionFilter::ClassifyPath(path);
            std::string reason;
            std::string note;

            if (!exists) {
                if (FileTimeToU64(lastRun) < FileTimeToU64(bootTime))
                    continue;


                if (cls == DetectionFilter::PathClass::TempOrInstaller ||
                    cls == DetectionFilter::PathClass::Removable ||
                    cls == DetectionFilter::PathClass::Unmapped)
                    continue;
                reason = "DELETED";
                note = "removed after boot";
            } else {
                // Check for file replacement: BAM recorded an earlier run,
                // but the file on disk was written after that run timestamp.
                WIN32_FILE_ATTRIBUTE_DATA fad = {};
                bool gotAttribs = GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad) != 0;
                if (gotAttribs) {
                    ULONGLONG lastWrite = FileTimeToU64(fad.ftLastWriteTime);
                    ULONGLONG bamTs     = FileTimeToU64(lastRun);
                    // Require at least 6 hours delta to avoid false positives from
                    // Windows Update or app auto-updates touching the file shortly after run.
                    constexpr ULONGLONG k6Hours = 6ULL * 60 * 60 * 10000000ULL;
                    if (bamTs > 0 && lastWrite > bamTs && (lastWrite - bamTs) > k6Hours) {
                        // File on disk is significantly newer than BAM-recorded execution.
                        // Skip if the replacement file is Authenticode-signed — this covers
                        // legitimate software updates (Steam, Epic, game launchers, etc.).
                        if (DetectionFilter::IsTrustedSignedCached(path))
                            continue;
                        reason = "REPLACED";
                        note = "file modified after BAM-recorded execution";
                        ScannerUI::BamEntry entry;
                        FileTimeToLocalStrings(lastRun, entry.date, entry.time);
                        entry.path = WideToUtf8(path);
                        entry.reason = reason;
                        entry.detail = note;
                        entry.suspicious = true;
                        entry.pathClass = DetectionFilter::PathClassName(cls);
                        out.push_back(entry);
                        continue;
                    }
                }

                if (IsAuthenticodeSigned(path))
                    continue;

                // Use multi-sample entropy for files > 512 KB for better accuracy
                LONGLONG fileSize = 0;
                if (gotAttribs) {
                    fileSize = ((LONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
                }
                double entropy = (fileSize > 512 * 1024)
                    ? DetectionFilter::FileEntropyMultiSample(path)
                    : DetectionFilter::FileEntropySample(path);
                bool packed = entropy >= DetectionFilter::kPackedEntropy;

                bool userProfileUnsigned = (cls == DetectionFilter::PathClass::UserProfile);
                if (DetectionFilter::IsTrustedDir(cls) && !packed) {
                    // Unsigned & not catalog-signed inside System32/Program Files is unusual
                    // (genuine Windows/vendor binaries are always signed or cataloged), but
                    // low-entropy/unpacked third-party DLLs do exist there. Surface at low
                    // severity instead of dropping it — a malicious binary placed here with
                    // admin rights must not vanish from the report entirely.
                    ScannerUI::BamEntry entry;
                    FileTimeToLocalStrings(lastRun, entry.date, entry.time);
                    entry.path = WideToUtf8(path);
                    entry.reason = "UNSIGNED_TRUSTED_PATH";
                    entry.detail = "unsigned & not in Windows catalog, located in trusted dir | entropy "
                                  + DetectionFilter::EntropyToStr(entropy);
                    entry.suspicious = false;
                    entry.pathClass = DetectionFilter::PathClassName(cls);
                    out.push_back(entry);
                    continue;
                }
                // Unsigned files in UserProfile are common (indie games, dev tools, launchers).
                // Only flag if packed OR entropy is meaningfully elevated (>= 5.5).
                constexpr double kUserProfileMinEntropy = 5.5;
                if (userProfileUnsigned && !packed && entropy < kUserProfileMinEntropy)
                    continue;
                reason = "UNSIGNED";
                note = "entropy " + DetectionFilter::EntropyToStr(entropy);
                if (packed)
                    note += " (packed)";
                if (userProfileUnsigned)
                    note += " | user-profile path";
            }

            ScannerUI::BamEntry entry;
            FileTimeToLocalStrings(lastRun, entry.date, entry.time);
            entry.path = WideToUtf8(path);
            entry.reason = reason;
            entry.detail = note;
            entry.suspicious = true;
            entry.pathClass = DetectionFilter::PathClassName(cls);
            out.push_back(entry);
        }

        RegCloseKey(sidKey);
    }

    RegCloseKey(usersKey);
}




static std::unordered_set<std::wstring> CollectShimcacheEntries() {
    std::unordered_set<std::wstring> paths;
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                      0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return paths;

    DWORD dataSize = 0;
    RegQueryValueExW(h, L"AppCompatCache", nullptr, nullptr, nullptr, &dataSize);
    if (dataSize == 0) { RegCloseKey(h); return paths; }

    std::vector<uint8_t> buf(dataSize);
    if (RegQueryValueExW(h, L"AppCompatCache", nullptr, nullptr, buf.data(), &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(h);
        return paths;
    }
    RegCloseKey(h);





    size_t i = 0;
    while (i + 4 < buf.size()) {

        if (buf[i + 1] == 0 && buf[i] >= 'A' && buf[i] <= 'Z' &&
            i + 3 < buf.size() && buf[i + 2] == ':' && buf[i + 3] == 0) {

            const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buf.data() + i);
            size_t maxChars = (buf.size() - i) / sizeof(wchar_t);
            size_t len = 0;
            while (len < maxChars && ptr[len]) ++len;
            if (len >= 6 && len < 512) {
                std::wstring entry(ptr, len);
                paths.insert(ToUpperInvariant(entry));
            }
            i += (len + 1) * sizeof(wchar_t);
            continue;
        }
        ++i;
    }
    return paths;
}

std::vector<ScannerUI::BamEntry> CollectBamDetections() {
    std::vector<ScannerUI::BamEntry> entries;
    FILETIME bootTime = GetBootFileTime();
    CollectBamFromKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", bootTime, entries);
    CollectBamFromKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings", bootTime, entries);



    auto shimcache = CollectShimcacheEntries();
    if (!shimcache.empty()) {
        for (auto& e : entries) {
            if (e.reason == "DELETED") {
                std::wstring pathW = std::wstring(e.path.begin(), e.path.end());
                std::wstring up = ToUpperInvariant(pathW);
                if (shimcache.count(up)) {
                    e.detail += " | shimcache=confirmed";
                    e.suspicious = true;
                }
            }
        }
    }

    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        if (a.date != b.date) return a.date > b.date;
        return a.time > b.time;
    });
    return entries;
}

struct PrefetchSourceEntry {
    std::wstring file;
    FILETIME time = {};
};

struct UsnNameEntry {
    ULONGLONG parent = 0;
    std::wstring name;
};

struct UsnExportOptions {
    std::unordered_set<std::string> includeExtensions;
    std::unordered_set<std::string> ignoreExtensions;
};

std::wstring GetWindowsDriveRoot() {
    wchar_t windowsDir[MAX_PATH] = {};
    UINT len = GetWindowsDirectoryW(windowsDir, (UINT)std::size(windowsDir));
    if (len >= 2 && windowsDir[1] == L':') {
        wchar_t root[] = { windowsDir[0], L':', L'\\', L'\0' };
        return root;
    }
    return L"C:\\";
}

std::wstring JoinPathW(const std::wstring& base, const std::wstring& child) {
    if (base.empty())
        return child;
    wchar_t last = base.back();
    if (last == L'\\' || last == L'/')
        return base + child;
    return base + L"\\" + child;
}

static bool HasEfiExtension(const std::wstring& path) {
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos)
        return false;
    std::wstring ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return ext == L".efi";
}

static bool ContainsAnyToken(const std::wstring& text, std::initializer_list<const wchar_t*> tokens) {
    std::wstring upper = ToUpperInvariant(text);
    for (const wchar_t* token : tokens) {
        if (upper.find(token) != std::wstring::npos)
            return true;
    }
    return false;
}

// Like ContainsAnyToken but requires each token to be bounded by a non-alpha character
// (dot, dash, underscore, start/end of string). Use for short ambiguous tokens.
static bool ContainsWholeWordToken(const std::wstring& text, std::initializer_list<const wchar_t*> tokens) {
    std::wstring upper = ToUpperInvariant(text);
    for (const wchar_t* token : tokens) {
        size_t tlen = wcslen(token);
        size_t pos = 0;
        while ((pos = upper.find(token, pos)) != std::wstring::npos) {
            bool leftOk  = (pos == 0) || !iswalpha(upper[pos - 1]);
            bool rightOk = (pos + tlen >= upper.size()) || !iswalpha(upper[pos + tlen]);
            if (leftOk && rightOk)
                return true;
            pos += tlen;
        }
    }
    return false;
}

static bool IsCommonSignedEfiPath(const std::wstring& path) {
    std::wstring upper = ToUpperInvariant(path);
    return upper.find(L"\\EFI\\MICROSOFT\\") != std::wstring::npos ||
           upper.find(L"\\EFI\\BOOT\\") != std::wstring::npos ||
           upper.find(L"\\EFI\\OEM\\") != std::wstring::npos ||
           upper.find(L"\\EFI\\TOOLS\\") != std::wstring::npos;
}

struct EfiFileCandidate {
    std::wstring path;
    WIN32_FIND_DATAW data = {};
};

static void CollectEfiFilesRecursive(const std::wstring& dir, std::vector<EfiFileCandidate>& out,
                                     bool& accessIssue, int depth = 0) {
    if (depth > 7)
        return;

    std::wstring search = JoinPathW(dir, L"*");
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(search.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
            accessIssue = true;
        return;
    }

    do {
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..")
            continue;

        std::wstring full = JoinPathW(dir, name);
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
                CollectEfiFilesRecursive(full, out, accessIssue, depth + 1);
            continue;
        }

        if (HasEfiExtension(name)) {
            out.push_back({ full, data });
        } else if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            // Bug 4 fix: bootkits podem usar extensoes nao-.efi (.bin, .dat, sem extensao)
            // para escapar da varredura por extensao. Incluir qualquer arquivo no ESP cujos
            // 2 primeiros bytes sejam 'MZ' — o magic number de PE executaveis.
            // Extensoes Windows padrao (.dll, .mui, .sys, etc.) sao arquivos de suporte do
            // Windows no ESP — nao sao UEFI executaveis e nunca sao usadas por bootkits.
            {
                std::wstring nameUpper = ToUpperInvariant(name);
                auto dot = nameUpper.rfind(L'.');
                if (dot != std::wstring::npos) {
                    static const std::unordered_set<std::wstring> kWinExts = {
                        L".DLL", L".MUI", L".SYS", L".EXE", L".DRV", L".CPL", L".OCX"
                    };
                    if (kWinExts.count(nameUpper.substr(dot)))
                        continue;
                }
            }
            uint64_t sz = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
            if (sz >= 2) {
                HANDLE hf = CreateFileW(full.c_str(), GENERIC_READ,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, 0, nullptr);
                if (hf != INVALID_HANDLE_VALUE) {
                    BYTE magic[2] = {};
                    DWORD rd = 0;
                    if (ReadFile(hf, magic, 2, &rd, nullptr) && rd == 2 &&
                        magic[0] == 'M' && magic[1] == 'Z')
                        out.push_back({ full, data });
                    CloseHandle(hf);
                }
            }
        }
    } while (FindNextFileW(find, &data));

    FindClose(find);
}

static void AddEfiRootIfPresent(const std::wstring& root, std::vector<std::wstring>& roots,
                                std::unordered_set<std::wstring>& seen) {
    std::wstring efiRoot = JoinPathW(root, L"EFI");
    DWORD attrs = GetFileAttributesW(efiRoot.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return;

    std::wstring key = ToUpperInvariant(efiRoot);
    if (seen.insert(key).second)
        roots.push_back(efiRoot);
}

// Returns the path of fileName inside C:\Windows\Boot\EFI (where bcdboot stages
// bootmgfw.efi/bootmgr.efi/memtest.efi before copying them to the EFI System
// Partition), or empty if no such reference file exists. Most ESP candidates
// (vendor/shim/grub/dual-boot files) simply have no counterpart here, so callers
// only pay for a hash comparison when a real reference is found.
static std::wstring FindWindowsBootEfiReference(const std::wstring& fileName) {
    std::wstring refDir  = JoinPathW(JoinPathW(JoinPathW(GetWindowsDriveRoot(), L"Windows"), L"Boot"), L"EFI");
    std::wstring refPath = JoinPathW(refDir, fileName);
    DWORD attrs = GetFileAttributesW(refPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return L"";
    return refPath;
}

static std::vector<std::wstring> CollectEfiRoots(bool& accessIssue) {
    std::vector<std::wstring> roots;
    std::unordered_set<std::wstring> seen;

    std::string espCoverage;
    for (const auto& root : CollectEfiSystemPartitionRoots(espCoverage)) {
        AddEfiRootIfPresent(root, roots, seen);
    }
    if (espCoverage != "OK")
        accessIssue = true;

    AddEfiRootIfPresent(GetWindowsDriveRoot(), roots, seen);

    DWORD drives = GetLogicalDrives();
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        if ((drives & (1 << (letter - L'A'))) == 0)
            continue;
        wchar_t driveRoot[] = { letter, L':', L'\\', L'\0' };
        AddEfiRootIfPresent(driveRoot, roots, seen);
    }

    wchar_t volumeName[MAX_PATH] = {};
    HANDLE find = FindFirstVolumeW(volumeName, (DWORD)std::size(volumeName));
    if (find == INVALID_HANDLE_VALUE) {
        accessIssue = true;
        return roots;
    }

    do {
        AddEfiRootIfPresent(volumeName, roots, seen);
    } while (FindNextVolumeW(find, volumeName, (DWORD)std::size(volumeName)));

    FindVolumeClose(find);
    return roots;
}




static std::wstring GetSignerCommonName(const std::wstring& path) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &encoding, &contentType, &formatType,
                          &hStore, &hMsg, nullptr))
        return L"";

    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
    if (signerInfoSize == 0) {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return L"";
    }

    std::vector<uint8_t> siBuf(signerInfoSize);
    auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(siBuf.data());
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, si, &signerInfoSize);

    CERT_INFO ci = {};
    ci.Issuer       = si->Issuer;
    ci.SerialNumber = si->SerialNumber;

    PCCERT_CONTEXT ctx = CertFindCertificateInStore(
        hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_CERT, &ci, nullptr);

    std::wstring name;
    if (ctx) {
        wchar_t buf[512] = {};
        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf, 512);
        name = buf;
        CertFreeCertificateContext(ctx);
    }

    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);
    return name;
}






static void CollectBootIntegrityFindings(std::vector<ScannerUI::EfiCheatFinding>& out) {
    std::vector<std::wstring> efiBootDirs;
    DWORD drives = GetLogicalDrives();
    for (wchar_t L = L'A'; L <= L'Z'; ++L) {
        if (!(drives & (1u << (L - L'A'))))
            continue;
        wchar_t dr[] = { L, L':', L'\\', L'\0' };
        std::wstring candidate = JoinPathW(JoinPathW(JoinPathW(std::wstring(dr), L"EFI"), L"Microsoft"), L"Boot");
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
            efiBootDirs.push_back(candidate);
    }

    wchar_t volName[MAX_PATH] = {};
    HANDLE vfind = FindFirstVolumeW(volName, (DWORD)std::size(volName));
    if (vfind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring candidate = JoinPathW(JoinPathW(JoinPathW(std::wstring(volName), L"EFI"), L"Microsoft"), L"Boot");
            if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
                efiBootDirs.push_back(candidate);
        } while (FindNextVolumeW(vfind, volName, (DWORD)std::size(volName)));
        FindVolumeClose(vfind);
    }

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);



    // Bug 3 fix: bootx64.efi e o fallback universal do UEFI firmware e alvo
    // frequente de bootkits (ex: BlackLotus). Adicionar a verificacao de signer.
    static const wchar_t* kCheckIssuer[] = { L"bootmgfw.efi", L"bootx64.efi", nullptr };

    for (const auto& efiDir : efiBootDirs) {
        for (int i = 0; kCheckIssuer[i]; ++i) {
            std::wstring efiFile = JoinPathW(efiDir, kCheckIssuer[i]);
            if (GetFileAttributesW(efiFile.c_str()) == INVALID_FILE_ATTRIBUTES)
                continue;


            // Bug 1 fix: arquivo de boot nao-assinado e um indicador critico.
            // Anteriormente o continue aqui fazia o scanner ignorar silenciosamente
            // uma substituicao nao-assinada do bootmgfw.efi — o caso mais comum de bootkit.
            if (!IsAuthenticodeSigned(efiFile)) {
                ScannerUI::EfiCheatFinding f;
                f.date = date;
                f.time = timeStr;
                f.severity = "HIGH";
                f.path = WideToUtf8(efiFile);
                f.reason = "Windows boot manager nao assinado (possivel bootkit)";
                f.detail = "arquivo=" + WideToUtf8(kCheckIssuer[i]) +
                           " | signed=no | o boot manager da Microsoft e sempre assinado";
                f.suspicious = true;
                out.push_back(f);
                continue;
            }

            std::wstring signer = GetSignerCommonName(efiFile);
            if (signer.empty())
                continue;

            std::wstring signerUpper = ToUpperInvariant(signer);

            static const wchar_t* kKnownLegitSigners[] = {
                L"MICROSOFT", L"CANONICAL", L"RED HAT", L"REDHAT", L"FEDORA",
                L"SUSE", L"NOVELL", L"SHIM", L"GRUB", L"DEBIAN",
                L"HP", L"HEWLETT", L"DELL", L"LENOVO", L"ASUS", L"ACER",
                L"INTEL", L"AMD", L"INSYDE", L"AMI", L"PHOENIX",
                nullptr
            };
            bool isKnownSigner = false;
            for (int k = 0; kKnownLegitSigners[k]; ++k) {
                if (signerUpper.find(kKnownLegitSigners[k]) != std::wstring::npos) {
                    isKnownSigner = true;
                    break;
                }
            }

            if (!isKnownSigner) {
                ScannerUI::EfiCheatFinding f;
                f.date = date;
                f.time = timeStr;
                f.severity = "MEDIUM";
                f.path = WideToUtf8(efiFile);
                f.reason = "Windows boot manager assinado por certificado nao reconhecido";
                f.detail = "signer=" + WideToUtf8(signer) + " | esperado=Microsoft ou OEM conhecido";
                f.suspicious = true;
                out.push_back(f);
            }
        }
    }
}

static void CollectBcdIntegrityFindings(
    const std::vector<std::wstring>& roots,
    std::vector<ScannerUI::EfiCheatFinding>& out) {
    std::unordered_set<std::wstring> seen;
    for (const auto& root : roots) {
        std::wstring bootDir =
            JoinPathW(JoinPathW(JoinPathW(root, L"EFI"), L"Microsoft"), L"Boot");
        DWORD bootAttrs = GetFileAttributesW(bootDir.c_str());
        if (bootAttrs == INVALID_FILE_ATTRIBUTES ||
            (bootAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
            continue;

        std::wstring bcd = JoinPathW(bootDir, L"BCD");
        std::wstring key = ToUpperInvariant(bcd);
        if (!seen.insert(key).second)
            continue;

        HANDLE file = CreateFileW(bcd.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            ScannerUI::EfiCheatFinding finding;
            finding.severity = "MEDIUM";
            finding.path = WideToUtf8(bcd);
            finding.reason = "Windows EFI directory has no readable BCD store";
            finding.detail = "win32_error=" + std::to_string(GetLastError());
            finding.ruleId = "BOOT.BCD.UNREADABLE";
            finding.source = "EFI filesystem";
            finding.confidence = "MEDIUM";
            finding.evidenceState = "INCONCLUSIVE";
            finding.suspicious = false;
            out.push_back(std::move(finding));
            continue;
        }

        LARGE_INTEGER size = {};
        uint8_t header[4] = {};
        DWORD read = 0;
        bool headerOk = GetFileSizeEx(file, &size) &&
                        ReadFile(file, header, sizeof(header), &read, nullptr) &&
                        read == sizeof(header) &&
                        memcmp(header, "regf", 4) == 0 &&
                        size.QuadPart >= 4096 &&
                        size.QuadPart <= 64ll * 1024 * 1024;
        CloseHandle(file);
        if (!headerOk) {
            ScannerUI::EfiCheatFinding finding;
            finding.severity = "HIGH";
            finding.path = WideToUtf8(bcd);
            finding.reason = "BCD store has an invalid registry-hive structure";
            finding.detail = "expected regf header and size between 4 KiB and 64 MiB";
            finding.ruleId = "BOOT.BCD.INVALID_HIVE";
            finding.source = "EFI filesystem";
            finding.confidence = "HIGH";
            finding.evidenceState = "SUSPICIOUS";
            finding.suspicious = true;
            out.push_back(std::move(finding));
            continue;
        }

        HKEY hive = nullptr;
        LONG loadStatus = RegLoadAppKeyW(bcd.c_str(), &hive, KEY_READ, 0, 0);
        if (loadStatus != ERROR_SUCCESS) {
            ScannerUI::EfiCheatFinding finding;
            finding.severity = "FLAG";
            finding.path = WideToUtf8(bcd);
            finding.reason = "BCD header is valid but logical contents could not be inspected";
            finding.detail = "RegLoadAppKey status=" + std::to_string(loadStatus);
            finding.ruleId = "BOOT.BCD.LOGICAL_CHECK_UNAVAILABLE";
            finding.source = "BCD registry hive";
            finding.confidence = "LOW";
            finding.evidenceState = "INCONCLUSIVE";
            finding.suspicious = false;
            out.push_back(std::move(finding));
            continue;
        }

        HKEY objects = nullptr;
        DWORD objectCount = 0;
        bool objectsOk =
            RegOpenKeyExW(hive, L"Objects", 0, KEY_READ, &objects) == ERROR_SUCCESS;
        if (objectsOk) {
            RegQueryInfoKeyW(objects, nullptr, nullptr, nullptr, &objectCount,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
            RegCloseKey(objects);
        }
        RegCloseKey(hive);
        if (!objectsOk || objectCount == 0) {
            ScannerUI::EfiCheatFinding finding;
            finding.severity = "HIGH";
            finding.path = WideToUtf8(bcd);
            finding.reason = "BCD store contains no boot objects";
            finding.detail = "Objects key missing or empty";
            finding.ruleId = "BOOT.BCD.EMPTY_OBJECTS";
            finding.source = "BCD registry hive";
            finding.confidence = "HIGH";
            finding.evidenceState = "SUSPICIOUS";
            finding.suspicious = true;
            out.push_back(std::move(finding));
        }
    }
}




static std::wstring ParseBootEntryFilePath(const uint8_t* buf, DWORD bufLen) {
    if (bufLen < 6)
        return L"";


    const wchar_t* desc = reinterpret_cast<const wchar_t*>(buf + 6);
    size_t maxDescChars = (bufLen - 6) / sizeof(wchar_t);
    size_t descLen = 0;
    while (descLen < maxDescChars && desc[descLen])
        ++descLen;


    size_t pathListOff = 6 + (descLen + 1) * sizeof(wchar_t);
    if (pathListOff >= bufLen)
        return L"";

    size_t pos = pathListOff;
    while (pos + 4 <= bufLen) {
        uint8_t nodeType    = buf[pos];
        uint8_t nodeSubType = buf[pos + 1];
        uint16_t nodeLen    = *reinterpret_cast<const uint16_t*>(buf + pos + 2);

        if (nodeLen < 4 || pos + nodeLen > (size_t)bufLen)
            break;
        if (nodeType == 0x7F && nodeSubType == 0xFF)
            break;


        if (nodeType == 4 && nodeSubType == 4 && nodeLen > 4) {
            size_t dataChars = (nodeLen - 4) / sizeof(wchar_t);
            const wchar_t* pathData = reinterpret_cast<const wchar_t*>(buf + pos + 4);
            size_t pathLen = 0;
            while (pathLen < dataChars && pathData[pathLen])
                ++pathLen;
            return std::wstring(pathData, pathLen);
        }
        pos += nodeLen;
    }
    return L"";
}


// Returns markers like "[PXE-IPv4]", "[HTTP-Boot:http://...]", "[MAC:aabbccddeeff]"
// for any Messaging device path nodes (type 0x03) found in the EFI_LOAD_OPTION buffer.
// An empty return means no network boot nodes were detected.
static std::wstring ParseBootEntryNetworkPath(const uint8_t* buf, DWORD bufLen) {
    if (bufLen < 6) return L"";

    const wchar_t* desc = reinterpret_cast<const wchar_t*>(buf + 6);
    size_t maxDescChars = (bufLen - 6) / sizeof(wchar_t);
    size_t descLen = 0;
    while (descLen < maxDescChars && desc[descLen]) ++descLen;

    size_t pathListOff = 6 + (descLen + 1) * sizeof(wchar_t);
    if (pathListOff >= (size_t)bufLen) return L"";

    std::wstring result;
    size_t pos = pathListOff;
    while (pos + 4 <= (size_t)bufLen) {
        uint8_t  nodeType    = buf[pos];
        uint8_t  nodeSubType = buf[pos + 1];
        uint16_t nodeLen     = *reinterpret_cast<const uint16_t*>(buf + pos + 2);

        if (nodeLen < 4 || pos + nodeLen > (size_t)bufLen) break;
        if (nodeType == 0x7F && nodeSubType == 0xFF) break;

        if (nodeType == 0x03) {
            std::wstring nodeDesc;
            if (nodeSubType == 0x0C) {
                nodeDesc = L"[PXE-IPv4]";
            } else if (nodeSubType == 0x0D) {
                nodeDesc = L"[PXE-IPv6]";
            } else if (nodeSubType == 0x0B && nodeLen >= 10) {
                // MAC Address: 32-byte padded field at offset +4; first 6 bytes are Ethernet MAC
                nodeDesc = L"[MAC:";
                wchar_t hex[3];
                for (int b = 0; b < 6; ++b) {
                    swprintf_s(hex, _countof(hex), L"%02x", buf[pos + 4 + b]);
                    nodeDesc += hex;
                }
                nodeDesc += L"]";
            } else if (nodeSubType == 0x18) {
                // URI Device Path: ASCII URI string after 4-byte header
                nodeDesc = L"[HTTP-Boot";
                if (nodeLen > 4) {
                    std::string uri(reinterpret_cast<const char*>(buf + pos + 4), nodeLen - 4);
                    while (!uri.empty() && uri.back() == '\0') uri.pop_back();
                    if (!uri.empty()) {
                        nodeDesc += L":";
                        nodeDesc += std::wstring(uri.begin(), uri.end());
                    }
                }
                nodeDesc += L"]";
            }
            if (!nodeDesc.empty()) {
                if (!result.empty()) result += L"+";
                result += nodeDesc;
            }
        }

        pos += nodeLen;
    }
    return result;
}

static bool IsKnownDualBootPath(const std::wstring& path) {
    std::wstring up = ToUpperInvariant(path);
    static const wchar_t* kKnown[] = {
        L"\\EFI\\UBUNTU\\", L"\\EFI\\FEDORA\\", L"\\EFI\\ARCH\\",
        L"\\EFI\\MANJARO\\", L"\\EFI\\OPENSUSE\\", L"\\EFI\\REFIND\\",
        L"\\EFI\\CLOVER\\", L"\\EFI\\OC\\", L"\\EFI\\KALI\\",
        L"\\EFI\\POP_OS\\", L"\\EFI\\DEBIAN\\", L"\\EFI\\LINPUS\\",
        L"\\EFI\\ENDLESS\\", L"\\EFI\\ZORIN\\", L"\\EFI\\MINT\\",
        nullptr
    };
    for (int i = 0; kKnown[i]; ++i)
        if (up.find(kKnown[i]) != std::wstring::npos)
            return true;
    return false;
}

static bool IsKnownWindowsBootPath(std::wstring path) {
    for (auto& c : path)
        if (c == L'/') c = L'\\';
    std::wstring up = ToUpperInvariant(path);
    return up == L"\\EFI\\MICROSOFT\\BOOT\\BOOTMGFW.EFI" ||
           up == L"\\EFI\\BOOT\\BOOTX64.EFI" ||
           up.find(L"\\EFI\\MICROSOFT\\") != std::wstring::npos;
}



static void EnableFirmwareEnvPrivilege() {
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        if (LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &tp.Privileges[0].Luid)) {
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(tok);
    }
}

bool IsSecureBootEnabled() {
    EnableFirmwareEnvPrivilege();

    uint8_t val = 0;
    DWORD rd = GetFirmwareEnvironmentVariableW(
        L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &val, 1);
    if (rd == 1 && val == 1)
        return true;
    if (rd == 1 && val == 0)
        return false;

    // Firmware variable inacessivel (sem privilegio/BIOS legada) — fallback ao registro
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD enabled = 0, sz = sizeof(enabled), type = 0;
        bool ok = RegQueryValueExW(hKey, L"UEFISecureBootEnabled", nullptr, &type,
                                    (LPBYTE)&enabled, &sz) == ERROR_SUCCESS;
        RegCloseKey(hKey);
        if (ok)
            return enabled != 0;
    }
    return false;
}

bool IsIommuEnabled() {
    // Presenca da tabela ACPI DMAR (Intel VT-d) ou IVRS (AMD-Vi) indica que o
    // IOMMU esta habilitado na firmware e exposto ao SO.
    const DWORD kDmar = ('D') | ('M' << 8) | ('A' << 16) | ('R' << 24);
    const DWORD kIvrs = ('I') | ('V' << 8) | ('R' << 16) | ('S' << 24);
    if (GetSystemFirmwareTable('ACPI', kDmar, nullptr, 0) > 0) return true;
    if (GetSystemFirmwareTable('ACPI', kIvrs, nullptr, 0) > 0) return true;
    return false;
}




static void CollectNvramBootEntries(std::vector<ScannerUI::EfiCheatFinding>& out) {
    const wchar_t* kEfiGuid = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

    // Privilegio SE_SYSTEM_ENVIRONMENT_NAME e necessario para ler variaveis UEFI;
    // habilitamos aqui pois IsSecureBootEnabled so e chamada depois das leituras abaixo.
    EnableFirmwareEnvPrivilege();

    uint16_t bootOrder[128] = {};
    DWORD bootOrderBytes = GetFirmwareEnvironmentVariableW(
        L"BootOrder", kEfiGuid, bootOrder, (DWORD)sizeof(bootOrder));
    if (bootOrderBytes == 0)
        return;


    bool secureBoot = IsSecureBootEnabled();

    size_t numEntries = bootOrderBytes / sizeof(uint16_t);
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    // Check BootNext: one-shot boot override used by bootkits to persist across reboots
    {
        uint16_t bootNextId = 0;
        DWORD bnRead = GetFirmwareEnvironmentVariableW(L"BootNext", kEfiGuid,
                                                       &bootNextId, sizeof(bootNextId));
        if (bnRead == sizeof(bootNextId)) {
            wchar_t bnVarName[16] = {};
            swprintf_s(bnVarName, _countof(bnVarName), L"Boot%04X", (unsigned)bootNextId);
            uint8_t bnBuf[2048] = {};
            DWORD bnOptRead = GetFirmwareEnvironmentVariableW(bnVarName, kEfiGuid,
                                                              bnBuf, (DWORD)sizeof(bnBuf));
            if (bnOptRead >= 6) {
                std::wstring bnPath    = ParseBootEntryFilePath(bnBuf, bnOptRead);
                std::wstring bnNetPath = ParseBootEntryNetworkPath(bnBuf, bnOptRead);

                if (!bnNetPath.empty()) {
                    ScannerUI::EfiCheatFinding f;
                    f.date = date; f.time = timeStr;
                    f.severity = "FLAG";
                    f.path = "NVRAM::BootNext";
                    f.reason = "BootNext override loads from network";
                    f.detail = "var=" + WideToUtf8(bnVarName) + " | network=" + WideToUtf8(bnNetPath);
                    if (!bnPath.empty()) f.detail += " | file=" + WideToUtf8(bnPath);
                    f.ruleId = "BOOT.NVRAM.BOOTNEXT_NETWORK";
                    f.source = "UEFI NVRAM";
                    f.confidence = "LOW";
                    f.evidenceState = "REVIEW";
                    f.suspicious = false;
                    out.push_back(f);
                } else {
                bool nonStd = !bnPath.empty() && !IsKnownWindowsBootPath(bnPath)
                              && !IsKnownDualBootPath(bnPath);
                if (nonStd) {
                    const wchar_t* descPtr = reinterpret_cast<const wchar_t*>(bnBuf + 6);
                    size_t maxLen = (bnOptRead - 6) / sizeof(wchar_t);
                    size_t descLen = 0;
                    while (descLen < maxLen && descPtr[descLen]) ++descLen;
                    ScannerUI::EfiCheatFinding f;
                    f.date = date; f.time = timeStr;
                    f.severity = "MEDIUM";
                    f.path = "NVRAM::BootNext";
                    f.reason = "BootNext points to an unclassified EFI path";
                    f.detail = "var=" + WideToUtf8(bnVarName) + " | next_path=" + WideToUtf8(bnPath);
                    if (descLen > 0)
                        f.detail += " | desc=" + WideToUtf8(std::wstring(descPtr, descLen));
                    f.ruleId = "BOOT.NVRAM.BOOTNEXT_UNCLASSIFIED";
                    f.source = "UEFI NVRAM";
                    f.confidence = "LOW";
                    f.evidenceState = "REVIEW";
                    f.suspicious = false;
                    out.push_back(f);
                }
                }
            }
        }
    }

    for (size_t i = 0; i < numEntries; ++i) {
        wchar_t varName[16] = {};
        swprintf_s(varName, _countof(varName), L"Boot%04X", (unsigned)bootOrder[i]);

        uint8_t optBuf[2048] = {};
        DWORD optRead = GetFirmwareEnvironmentVariableW(varName, kEfiGuid, optBuf, (DWORD)sizeof(optBuf));
        if (optRead < 6)
            continue;


        const wchar_t* descPtr = reinterpret_cast<const wchar_t*>(optBuf + 6);
        size_t maxLen = (optRead - 6) / sizeof(wchar_t);
        size_t descLen = 0;
        while (descLen < maxLen && descPtr[descLen])
            ++descLen;
        std::wstring description(descPtr, descLen);


        std::wstring filePath = ParseBootEntryFilePath(optBuf, optRead);

        // Network boot detection — PXE/HTTP Boot device path nodes indicate OS loaded from network
        {
            std::wstring netPath = ParseBootEntryNetworkPath(optBuf, optRead);
            if (!netPath.empty()) {
                ScannerUI::EfiCheatFinding f;
                f.date = date; f.time = timeStr;
                f.severity = "FLAG";
                f.path = "NVRAM::" + WideToUtf8(varName);
                f.reason = "UEFI boot entry uses PXE/HTTP Boot";
                f.detail = "var=" + WideToUtf8(varName)
                         + " | network=" + WideToUtf8(netPath)
                         + " | desc=" + WideToUtf8(description);
                if (!filePath.empty()) f.detail += " | file=" + WideToUtf8(filePath);
                f.ruleId = "BOOT.NVRAM.NETWORK_ENTRY";
                f.source = "UEFI NVRAM";
                f.confidence = "LOW";
                f.evidenceState = "REVIEW";
                f.suspicious = false;
                out.push_back(f);
                continue;
            }
        }

        bool riskyDesc = ContainsAnyToken(description, {
            L"CHEAT", L"BYPASS", L"SPOOF", L"SPOOFER", L"HWID", L"MAPPER", L"BOOTKIT",
            L"BLACKLOTUS", L"INJECT", L"HYPERVISOR",
            L"AIMBOT", L"RAGE", L"TRIGGERBOT",
            L"VANGUARD", L"FACEIT", L"BATTLEYE",
            L"RING0", L"ROOTKIT", L"KDRIVER", L"DRVMAP", L"BLACKOUT", L"NIGHTSTALKER"
        }) || ContainsWholeWordToken(description, {
            L"HOOK", L"SHADOW", L"GHOST", L"PHANTOM", L"SILENT", L"EAC", L"VAC"
        });

        if (riskyDesc) {
            ScannerUI::EfiCheatFinding f;
            f.date = date; f.time = timeStr;
            f.severity = "HIGH";
            f.path = "NVRAM::" + WideToUtf8(varName);
            f.reason = "suspicious UEFI NVRAM boot entry";
            f.detail = "var=" + WideToUtf8(varName) + " | desc=" + WideToUtf8(description);
            if (!filePath.empty())
                f.detail += " | path=" + WideToUtf8(filePath);
            f.suspicious = true;
            out.push_back(f);
            continue;
        }


        bool isFirst = (i == 0);
        bool nonStandardPath = !filePath.empty() && !IsKnownWindowsBootPath(filePath);

        if (isFirst && nonStandardPath && !IsKnownDualBootPath(filePath)) {
            ScannerUI::EfiCheatFinding f;
            f.date = date; f.time = timeStr;
            f.severity = "MEDIUM";
            f.path = "NVRAM::" + WideToUtf8(varName);
            f.reason = "first boot priority uses an unclassified EFI path";
            f.detail = "var=" + WideToUtf8(varName) + " | first_path=" + WideToUtf8(filePath) +
                       " | desc=" + WideToUtf8(description);
            f.ruleId = "BOOT.NVRAM.FIRST_UNCLASSIFIED";
            f.source = "UEFI NVRAM";
            f.confidence = "LOW";
            f.evidenceState = "REVIEW";
            f.suspicious = false;
            out.push_back(f);
        } else if (!isFirst && nonStandardPath) {

            bool riskyPath = ContainsAnyToken(filePath, {
                L"CHEAT", L"BYPASS", L"HACK", L"INJECT", L"BOOTKIT", L"LOADER",
                L"GHOST", L"SHADOW", L"PHANTOM", L"ROOTKIT"
            });
            if (riskyPath) {
                ScannerUI::EfiCheatFinding f;
                f.date = date; f.time = timeStr;
                f.severity = "MEDIUM";
                f.path = "NVRAM::" + WideToUtf8(varName);
                f.reason = "unexpected boot entry with suspicious path";
                f.detail = "var=" + WideToUtf8(varName) + " | path=" + WideToUtf8(filePath) +
                           " | desc=" + WideToUtf8(description);
                f.suspicious = true;
                out.push_back(f);
            }
        }
    }


    if (!secureBoot) {
        ScannerUI::EfiCheatFinding f;
        f.date = date; f.time = timeStr;
        f.severity = "FLAG";
        f.path = "NVRAM::SecureBoot";
        f.reason = "Secure Boot disabled";
        f.detail = "secure_boot=off | unsigned EFI loaders can execute without restriction";
        f.ruleId = "BOOT.SECURE_BOOT.DISABLED";
        f.source = "UEFI NVRAM/registry";
        f.confidence = "HIGH";
        f.evidenceState = "CONFIGURATION";
        f.suspicious = false;
        out.push_back(f);
    }
}

// ─── Secure Boot key stores: comparacao com as chaves de fabrica da placa-mae ───
//
// Bypass comum: manter o Secure Boot LIGADO mas registrar uma PK/KEK/db propria e
// assinar o bootkit com ela — os checks de "Secure Boot ativo" continuam verdes
// enquanto o firmware confia em codigo do atacante. O firmware expoe as chaves de
// fabrica nas variaveis somente-leitura PKDefault/KEKDefault/dbDefault/dbxDefault;
// qualquer entrada atual fora desses defaults (e fora dos certs que a Microsoft
// adiciona legitimamente via Windows Update) indica chave alterada.

static const wchar_t* kEfiGlobalGuid   = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
static const wchar_t* kEfiImageSecGuid = L"{d719b2cb-3d3a-4596-a3bc-dad00e67656f}";

struct EfiSigEntry {
    bool        isX509 = false;
    std::string sha256;   // hex do payload (DER do cert ou hash revogado)
    std::string cn;       // subject CN quando X.509
};

static std::string ToUpperAscii(const std::string& s) {
    std::string up = s;
    for (auto& c : up)
        c = (char)toupper((unsigned char)c);
    return up;
}

static std::vector<uint8_t> ReadUefiVariable(const wchar_t* name, const wchar_t* guid,
                                             bool& readable) {
    readable = false;
    DWORD cap = 4096;
    for (;;) {
        std::vector<uint8_t> buf(cap);
        DWORD rd = GetFirmwareEnvironmentVariableW(name, guid, buf.data(), cap);
        if (rd > 0) {
            readable = true;
            buf.resize(rd);
            return buf;
        }
        // dbx atualizado pelo Windows Update passa de 100 KB — cresce ate 1 MB
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cap < (1u << 20)) {
            cap *= 2;
            continue;
        }
        return {};
    }
}

static std::vector<EfiSigEntry> ParseEfiSignatureLists(const std::vector<uint8_t>& buf) {
    static const GUID kCertX509 =
        { 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };

    std::vector<EfiSigEntry> entries;
    const size_t total = buf.size();
    // EFI_SIGNATURE_LIST: GUID(16) + ListSize(4) + HeaderSize(4) + SignatureSize(4)
    constexpr size_t kListHdr   = 28;
    constexpr size_t kOwnerGuid = 16; // EFI_SIGNATURE_DATA comeca com o GUID SignatureOwner
    size_t pos = 0;
    while (pos + kListHdr <= total) {
        GUID type = {};
        uint32_t listSize = 0, headerSize = 0, sigSize = 0;
        memcpy(&type,       buf.data() + pos,      sizeof(GUID));
        memcpy(&listSize,   buf.data() + pos + 16, sizeof(uint32_t));
        memcpy(&headerSize, buf.data() + pos + 20, sizeof(uint32_t));
        memcpy(&sigSize,    buf.data() + pos + 24, sizeof(uint32_t));

        // Campos de tamanho vem da NVRAM e podem estar corrompidos — nunca ler alem do buffer
        if (listSize < kListHdr || listSize > total - pos ||
            headerSize > listSize - kListHdr || sigSize <= kOwnerGuid)
            break;

        size_t dataPos = pos + kListHdr + headerSize;
        size_t listEnd = pos + listSize;
        while (dataPos + sigSize <= listEnd) {
            const uint8_t* payload = buf.data() + dataPos + kOwnerGuid;
            size_t payloadLen = sigSize - kOwnerGuid;

            EfiSigEntry e;
            e.isX509 = IsEqualGUID(type, kCertX509) != FALSE;
            e.sha256 = DetectionFilter::ComputeBufferSha256(payload, payloadLen);
            if (e.isX509) {
                PCCERT_CONTEXT ctx = CertCreateCertificateContext(
                    X509_ASN_ENCODING, payload, (DWORD)payloadLen);
                if (ctx) {
                    wchar_t nb[512] = {};
                    CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nb, 512);
                    e.cn = WideToUtf8(nb);
                    CertFreeCertificateContext(ctx);
                }
            }
            entries.push_back(std::move(e));
            dataPos += sigSize;
        }
        pos += listSize;
    }
    return entries;
}

static bool IsMicrosoftSecureBootCn(const std::string& cn) {
    // Certs que o Windows Update adiciona legitimamente ao KEK/db — nao podem alertar
    // mesmo quando ausentes dos defaults de fabrica (placas antigas nao os incluem).
    static const char* kMsCns[] = {
        "MICROSOFT WINDOWS PRODUCTION PCA 2011",
        "MICROSOFT CORPORATION UEFI CA 2011",
        "WINDOWS UEFI CA 2023",
        "MICROSOFT UEFI CA 2023",
        "MICROSOFT OPTION ROM UEFI CA 2023",
        "MICROSOFT CORPORATION KEK CA 2011",
        "MICROSOFT CORPORATION KEK 2K CA 2023",
        nullptr
    };
    std::string up = ToUpperAscii(cn);
    for (int i = 0; kMsCns[i]; ++i)
        if (up == kMsCns[i])
            return true;
    return false;
}

static bool IsKnownOemSecureBootCn(const std::string& cn) {
    // Fabricantes que legitimamente aparecem no db de fabrica (fallback quando a
    // placa nao expoe dbDefault). Tokens de substring — manter especificos o
    // suficiente para nao casar com nomes de cert arbitrarios.
    static const char* kOemTokens[] = {
        "MICROSOFT", "CANONICAL", "ASUSTEK", "GIGABYTE", "MICRO-STAR", "ASROCK",
        "DELL", "HEWLETT-PACKARD", "HP INC", "LENOVO", "ACER",
        "AMERICAN MEGATRENDS", "INSYDE", "PHOENIX TECHNOLOGIES",
        "TOSHIBA", "SAMSUNG", "FUJITSU", "PANASONIC", "INTEL", "NVIDIA",
        "RED HAT", "SUSE", "DEBIAN", "FRAMEWORK COMPUTER",
        nullptr
    };
    std::string up = ToUpperAscii(cn);
    for (int i = 0; kOemTokens[i]; ++i)
        if (up.find(kOemTokens[i]) != std::string::npos)
            return true;
    return false;
}

static void CollectSecureBootKeyFindings(std::vector<ScannerUI::EfiCheatFinding>& out) {
    EnableFirmwareEnvPrivilege();

    bool pkOk = false, kekOk = false, dbOk = false, dbxOk = false;
    bool pkDefOk = false, kekDefOk = false, dbDefOk = false, dbxDefOk = false;
    auto pkBuf   = ReadUefiVariable(L"PK",         kEfiGlobalGuid,   pkOk);
    auto kekBuf  = ReadUefiVariable(L"KEK",        kEfiGlobalGuid,   kekOk);
    auto dbBuf   = ReadUefiVariable(L"db",         kEfiImageSecGuid, dbOk);
    auto dbxBuf  = ReadUefiVariable(L"dbx",        kEfiImageSecGuid, dbxOk);
    // Nota (UEFI spec, Globally Defined Variables): TODAS as *Default vivem sob
    // EFI_GLOBAL_VARIABLE — inclusive dbDefault/dbxDefault, ao contrario de db/dbx.
    auto pkDef   = ReadUefiVariable(L"PKDefault",  kEfiGlobalGuid, pkDefOk);
    auto kekDef  = ReadUefiVariable(L"KEKDefault", kEfiGlobalGuid, kekDefOk);
    auto dbDef   = ReadUefiVariable(L"dbDefault",  kEfiGlobalGuid, dbDefOk);
    auto dbxDef  = ReadUefiVariable(L"dbxDefault", kEfiGlobalGuid, dbxDefOk);

    // BIOS legada ou NVRAM inacessivel (sem privilegio): nenhum store legivel — sem base
    if (!pkOk && !kekOk && !dbOk && !dbxOk)
        return;

    bool secureBoot = IsSecureBootEnabled();

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    auto emit = [&](const char* sev, const char* store, const std::string& reason,
                    const std::string& detail, const char* ruleId, const char* confidence,
                    const char* evidenceState, bool suspicious) {
        ScannerUI::EfiCheatFinding f;
        f.date = date; f.time = timeStr;
        f.severity = sev;
        f.path = std::string("NVRAM::") + store;
        f.reason = reason;
        f.detail = detail;
        f.ruleId = ruleId;
        f.source = "UEFI NVRAM (Secure Boot keys)";
        f.confidence = confidence;
        f.evidenceState = evidenceState;
        f.suspicious = suspicious;
        out.push_back(f);
    };

    auto describeEntries = [](const std::vector<EfiSigEntry>& list) {
        std::string s;
        size_t shown = 0;
        for (const auto& e : list) {
            if (shown++ == 6) { s += ";..."; break; }
            if (!s.empty()) s += ";";
            s += e.cn.empty() ? e.sha256.substr(0, 16) : e.cn;
        }
        return s.empty() ? std::string("(vazio)") : s;
    };

    // Entradas de `cur` ausentes de `def` (por hash SHA-256 do payload)
    auto entriesNotIn = [](const std::vector<EfiSigEntry>& cur,
                           const std::vector<EfiSigEntry>& def,
                           bool skipMicrosoft) {
        std::unordered_set<std::string> defSet;
        for (const auto& e : def) defSet.insert(e.sha256);
        std::vector<EfiSigEntry> extra;
        for (const auto& e : cur) {
            if (defSet.count(e.sha256)) continue;
            if (skipMicrosoft && IsMicrosoftSecureBootCn(e.cn)) continue;
            extra.push_back(e);
        }
        return extra;
    };

    auto pkCur     = ParseEfiSignatureLists(pkBuf);
    auto kekCur    = ParseEfiSignatureLists(kekBuf);
    auto dbCur     = ParseEfiSignatureLists(dbBuf);
    auto dbxCur    = ParseEfiSignatureLists(dbxBuf);
    auto pkDefEnt  = ParseEfiSignatureLists(pkDef);
    auto kekDefEnt = ParseEfiSignatureLists(kekDef);
    auto dbDefEnt  = ParseEfiSignatureLists(dbDef);
    auto dbxDefEnt = ParseEfiSignatureLists(dbxDef);

    // ── PK de teste (PKfail): chave "DO NOT TRUST/SHIP" de firmware de referencia AMI
    //    deixada em producao — a chave privada vazou e assina qualquer coisa
    for (const auto& e : pkCur) {
        std::string up = ToUpperAscii(e.cn);
        if (up.find("DO NOT TRUST") != std::string::npos ||
            up.find("DO NOT SHIP")  != std::string::npos) {
            emit("HIGH", "SecureBoot::PK",
                 "Platform Key is a leaked firmware test key (PKfail)",
                 "pk_cn=" + e.cn + " | pk_sha256=" + e.sha256.substr(0, 16) +
                 " | private key is public — anyone can sign Secure Boot payloads",
                 "BOOT.SECURE_BOOT.TEST_PK", "HIGH", "SUSPICIOUS", true);
        }
    }

    // ── PK vs PKDefault: a Platform Key de fabrica da placa-mae
    if (pkOk && pkDefOk && !pkDefEnt.empty() && !pkCur.empty()) {
        auto extra   = entriesNotIn(pkCur, pkDefEnt, false);
        auto missing = entriesNotIn(pkDefEnt, pkCur, false);
        if (!extra.empty() || !missing.empty()) {
            emit("HIGH", "SecureBoot::PK",
                 "Platform Key differs from motherboard factory default",
                 "pk=" + describeEntries(pkCur) + " | pk_default=" + describeEntries(pkDefEnt) +
                 " | custom PK allows enrolling attacker KEK/db keys",
                 "BOOT.SECURE_BOOT.PK_MODIFIED", "HIGH", "SUSPICIOUS", true);
        }
    }

    // ── KEK vs KEKDefault
    if (kekOk && kekDefOk && !kekDefEnt.empty()) {
        auto extra = entriesNotIn(kekCur, kekDefEnt, /*skipMicrosoft=*/true);
        if (!extra.empty()) {
            emit("HIGH", "SecureBoot::KEK",
                 "KEK contains keys absent from motherboard factory default",
                 "kek_extra=" + describeEntries(extra) +
                 " | kek_default=" + describeEntries(kekDefEnt) +
                 " | rogue KEK can push signing certs into db",
                 "BOOT.SECURE_BOOT.KEK_MODIFIED", "HIGH", "SUSPICIOUS", true);
        }
    }

    // ── db vs dbDefault: cert extra no db assina EFI que passa no Secure Boot
    if (dbOk && dbDefOk && !dbDefEnt.empty()) {
        auto extra = entriesNotIn(dbCur, dbDefEnt, /*skipMicrosoft=*/true);
        if (!extra.empty()) {
            emit("HIGH", "SecureBoot::db",
                 "Secure Boot db contains certs absent from motherboard factory default",
                 "db_extra=" + describeEntries(extra) +
                 " | a custom db cert signs EFI loaders that pass Secure Boot",
                 "BOOT.SECURE_BOOT.DB_CUSTOM_CERT", "HIGH", "SUSPICIOUS", true);
        }
    } else if (dbOk && !dbDefOk) {
        // Fallback: placa nao expoe dbDefault — sem diff possivel, checa apenas CNs
        // desconhecidos (OEMs incluem certs extras de fabrica, dai confianca baixa)
        std::vector<EfiSigEntry> unknown;
        for (const auto& e : dbCur) {
            if (!e.isX509) continue;
            if (e.cn.empty() || IsMicrosoftSecureBootCn(e.cn) || IsKnownOemSecureBootCn(e.cn))
                continue;
            unknown.push_back(e);
        }
        if (!unknown.empty()) {
            emit("MEDIUM", "SecureBoot::db",
                 "Secure Boot db contains unrecognized signing certs",
                 "db_unknown=" + describeEntries(unknown) +
                 " | factory defaults (dbDefault) not exposed by firmware — manual review",
                 "BOOT.SECURE_BOOT.DB_UNKNOWN_CERT", "LOW", "REVIEW", false);
        }
    }

    // ── dbx vs dbxDefault: rollback da lista de revogacao reabilita loaders
    //    vulneraveis ja revogados (tecnica BlackLotus)
    if (dbxDefOk && !dbxDefEnt.empty()) {
        auto missing = dbxOk ? entriesNotIn(dbxDefEnt, dbxCur, false) : dbxDefEnt;
        if (!missing.empty()) {
            char cnt[64] = {};
            snprintf(cnt, sizeof(cnt), "revoked_entries_removed=%zu/%zu",
                     missing.size(), dbxDefEnt.size());
            emit("MEDIUM", "SecureBoot::dbx",
                 "Secure Boot revocation list (dbx) rolled back below factory default",
                 std::string(cnt) + " | removed=" + describeEntries(missing) +
                 " | rollback re-enables revoked vulnerable bootloaders",
                 "BOOT.SECURE_BOOT.DBX_ROLLBACK", "MEDIUM", "SUSPICIOUS", true);
        }
    }

    // ── SetupMode/AuditMode: chaves podem ser trocadas sem autenticacao
    {
        uint8_t setupMode = 0, auditMode = 0;
        bool smOk = false, amOk = false;
        auto sm = ReadUefiVariable(L"SetupMode", kEfiGlobalGuid, smOk);
        if (smOk && !sm.empty()) setupMode = sm[0];
        auto am = ReadUefiVariable(L"AuditMode", kEfiGlobalGuid, amOk);
        if (amOk && !am.empty()) auditMode = am[0];

        if (secureBoot && (setupMode == 1 || auditMode == 1)) {
            emit("HIGH", "SecureBoot::SetupMode",
                 "firmware in Setup/Audit mode with Secure Boot reported active",
                 std::string("setup_mode=") + (setupMode == 1 ? "1" : "0") +
                 " | audit_mode=" + (auditMode == 1 ? "1" : "0") +
                 " | keys can be replaced without authentication",
                 "BOOT.SECURE_BOOT.SETUP_MODE", "HIGH", "SUSPICIOUS", true);
        }
    }

    // ── PK ausente com Secure Boot supostamente ativo: estado inconsistente
    if (secureBoot && (!pkOk || pkCur.empty())) {
        emit("MEDIUM", "SecureBoot::PK",
             "Secure Boot reported active but no Platform Key enrolled",
             std::string("pk_present=") + (pkOk ? "yes(empty)" : "no") +
             " | without a PK the key hierarchy is not anchored",
             "BOOT.SECURE_BOOT.PK_MISSING", "MEDIUM", "REVIEW", false);
    }
}

struct MsEfiExpectedPath {
    const wchar_t* nameUpper;
    const wchar_t* expectedFragment; // nullptr = file should never appear on the ESP
};

static const MsEfiExpectedPath kMsEfiExpectedPaths[] = {
    { L"BOOTMGFW.EFI",  L"\\EFI\\MICROSOFT\\BOOT\\" },
    { L"BOOTX64.EFI",   L"\\EFI\\BOOT\\"            },
    { L"WINLOAD.EFI",   nullptr                      },
    { L"WINRESUME.EFI", nullptr                      },
    { L"BOOTMGR.EFI",   L"\\EFI\\MICROSOFT\\BOOT\\" },
    { nullptr,          nullptr                      }
};

static bool IsMasqueradingMsEfi(const std::wstring& fileName, const std::wstring& fullPath) {
    std::wstring nameUp = ToUpperInvariant(fileName);
    std::wstring pathUp = ToUpperInvariant(fullPath);
    for (int i = 0; kMsEfiExpectedPaths[i].nameUpper; ++i) {
        if (nameUp != kMsEfiExpectedPaths[i].nameUpper)
            continue;
        const wchar_t* expected = kMsEfiExpectedPaths[i].expectedFragment;
        if (expected == nullptr)
            return true;
        if (pathUp.find(expected) == std::wstring::npos)
            return true;
        return false;
    }
    return false;
}

// Reads the stored SHA-256 of filePath from HKCU\SOFTWARE\rxvscan\EfiBaseline.
// If the stored hash differs from currentHash, returns the previous hash (change detected).
// On first run or when unchanged, stores/updates the hash and returns empty string.
// Force-writes newHash as the accepted baseline. Called when a critical boot file has changed
// but is still validly MS-signed (Windows Update scenario) — prevents the stale registry entry
// from triggering HIGH findings on every subsequent scan.
static void AcceptEfiNewHash(const std::wstring& filePath, const std::string& newHash) {
    std::string key = WideToUtf8(filePath);
    for (char& c : key) if (c == '\\') c = '/';
    HKEY hKey = nullptr;
    RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rxvscan\\EfiBaseline",
                    0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (hKey) {
        RegSetValueExA(hKey, key.c_str(), 0, REG_SZ,
            (const BYTE*)newHash.c_str(), (DWORD)newHash.size() + 1);
        RegCloseKey(hKey);
    }
}

// MBR sector SHA-256 baseline helpers. Registry key: HKCU\SOFTWARE\rxvscan\MbrBaseline.
// Value name: "PhysicalDrive0", "PhysicalDrive1", etc.
static std::string CheckMbrHashBaseline(int driveIndex, const std::string& currentHash) {
    std::string key = "PhysicalDrive" + std::to_string(driveIndex);
    HKEY hKey = nullptr;
    std::string storedHash;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rxvscan\\MbrBaseline",
                      0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rxvscan\\MbrBaseline",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &hKey, nullptr);
    if (hKey) {
        char buf[128] = {}; DWORD sz = sizeof(buf);
        if (RegGetValueA(hKey, nullptr, key.c_str(), RRF_RT_REG_SZ, nullptr, buf, &sz) == ERROR_SUCCESS)
            storedHash = buf;
        if (storedHash.empty() || storedHash == currentHash)
            RegSetValueExA(hKey, key.c_str(), 0, REG_SZ,
                (const BYTE*)currentHash.c_str(), (DWORD)currentHash.size() + 1);
        RegCloseKey(hKey);
    }
    return (storedHash.empty() || storedHash == currentHash) ? "" : storedHash;
}

static void AcceptMbrNewHash(int driveIndex, const std::string& newHash) {
    std::string key = "PhysicalDrive" + std::to_string(driveIndex);
    HKEY hKey = nullptr;
    RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rxvscan\\MbrBaseline",
                    0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (hKey) {
        RegSetValueExA(hKey, key.c_str(), 0, REG_SZ,
            (const BYTE*)newHash.c_str(), (DWORD)newHash.size() + 1);
        RegCloseKey(hKey);
    }
}

static std::string CheckEfiHashBaseline(const std::wstring& filePath, const std::string& currentHash) {
    std::string key = WideToUtf8(filePath);
    for (char& c : key) if (c == '\\') c = '/';

    HKEY hKey = nullptr;
    std::string storedHash;

    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rxvscan\\EfiBaseline",
                      0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\rxvscan\\EfiBaseline",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &hKey, nullptr);
    }

    if (hKey) {
        char buf[128] = {};
        DWORD sz = sizeof(buf);
        if (RegGetValueA(hKey, nullptr, key.c_str(), RRF_RT_REG_SZ, nullptr, buf, &sz) == ERROR_SUCCESS)
            storedHash = buf;

        if (storedHash.empty() || storedHash == currentHash)
            RegSetValueExA(hKey, key.c_str(), 0, REG_SZ,
                (const BYTE*)currentHash.c_str(), (DWORD)currentHash.size() + 1);

        RegCloseKey(hKey);
    }

    return (storedHash.empty() || storedHash == currentHash) ? "" : storedHash;
}

// Reads the first 512 bytes (Sector 0) from each physical drive and checks:
//   1. Boot signature at bytes [510-511] must be 0x55 0xAA.
//   2. On UEFI systems, partition entry type at offset 0x1BE+4 must be 0xEE (GPT Protective).
//   3. SHA-256 baseline stored in HKCU\SOFTWARE\rxvscan\MbrBaseline — flags on change.
static void CollectMbrIntegrityFindings(std::vector<ScannerUI::EfiCheatFinding>& findings) {
    FIRMWARE_TYPE fwType = FirmwareTypeUnknown;
    GetFirmwareType(&fwType);
    const bool isUefi = (fwType == FirmwareTypeUefi);

    for (int i = 0; i < 4; ++i) {
        std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
        HANDLE hDrive = CreateFileW(drivePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDrive == INVALID_HANDLE_VALUE)
            break; // drives are numbered contiguously; first failure means no more drives

        uint8_t sector[512] = {};
        DWORD bytesRead = 0;
        bool readOk = ReadFile(hDrive, sector, sizeof(sector), &bytesRead, nullptr) &&
                      bytesRead == 512;
        CloseHandle(hDrive);

        if (!readOk)
            continue;

        std::string driveName = "\\\\.\\PhysicalDrive" + std::to_string(i) + " [MBR]";

        // Check 1: boot signature
        if (sector[510] != 0x55 || sector[511] != 0xAA) {
            ScannerUI::EfiCheatFinding f;
            f.severity  = "HIGH";
            f.path      = driveName;
            f.reason    = "MBR boot signature missing or corrupted";
            f.detail    = "Expected 0x55AA at sector offset 510 — found 0x"
                          + [&]{ char b[8]{}; snprintf(b, sizeof(b), "%02X%02X", sector[510], sector[511]); return std::string(b); }();
            f.suspicious = true;
            findings.push_back(f);
        }

        // Check 2: on UEFI systems the protective MBR must have partition type 0xEE
        if (isUefi) {
            // Partition table starts at 0x1BE; type byte is at offset +4 within the entry
            uint8_t partType = sector[0x1BE + 4];
            if (partType != 0xEE) {
                ScannerUI::EfiCheatFinding f;
                f.severity  = "HIGH";
                f.path      = driveName;
                f.reason    = "Unexpected MBR partition type on UEFI system";
                f.detail    = "Expected GPT Protective (0xEE) at partition entry 0 — found 0x"
                              + [&]{ char b[4]{}; snprintf(b, sizeof(b), "%02X", partType); return std::string(b); }()
                              + " | possible MBR bootkit replacing protective record";
                f.suspicious = true;
                findings.push_back(f);
            }
        }

        // Check 3: SHA-256 baseline change detection
        std::string currentHash = DetectionFilter::ComputeBufferSha256(sector, 512);
        if (!currentHash.empty()) {
            std::string prevHash = CheckMbrHashBaseline(i, currentHash);
            if (!prevHash.empty()) {
                ScannerUI::EfiCheatFinding f;
                f.severity  = "HIGH";
                f.path      = driveName;
                f.reason    = "MBR sector modified since last scan";
                f.detail    = "SHA256 of Sector 0 changed"
                              " | prev=" + prevHash.substr(0, 16) + "..."
                              " | curr=" + currentHash.substr(0, 16) + "...";
                f.suspicious = true;
                findings.push_back(f);
            }
        }
    }
}

std::vector<ScannerUI::EfiCheatFinding> CollectEfiCheatFindings(std::string& status) {
    bool accessIssue = false;
    std::vector<std::wstring> roots = CollectEfiRoots(accessIssue);
    std::vector<EfiFileCandidate> files;
    for (const auto& root : roots)
        CollectEfiFilesRecursive(root, files, accessIssue);

    FILETIME bootTime = GetBootFileTime();
    ULONGLONG bootValue = FileTimeToU64(bootTime);
    std::vector<ScannerUI::EfiCheatFinding> findings;
    std::unordered_set<std::wstring> seenFiles;

    for (const auto& candidate : files) {
        std::wstring key = ToUpperInvariant(candidate.path);
        if (!seenFiles.insert(key).second)
            continue;

        const std::wstring fileName = DetectionFilter::BaseName(candidate.path);

        if (IsMasqueradingMsEfi(fileName, candidate.path)) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI masquerading as Windows boot file";
            f.detail = "name=" + WideToUtf8(fileName) +
                       " | unexpected_path=" + WideToUtf8(candidate.path);
            f.suspicious = true;
            findings.push_back(f);
            continue;
        }

        bool signedOk = IsAuthenticodeSigned(candidate.path);
        bool riskyName = ContainsAnyToken(fileName, {
            L"CHEAT", L"BYPASS", L"SPOOF", L"SPOOFER", L"HWID", L"MAPPER", L"BOOTKIT",
            L"BLACKLOTUS", L"INJECT", L"HYPERVISOR",
            L"AIMBOT", L"RAGE", L"TRIGGERBOT",
            L"VANGUARD", L"FACEIT", L"BATTLEYE",
            L"RING0", L"ROOTKIT", L"KDRIVER", L"DRVMAP", L"BLACKOUT", L"NIGHTSTALKER"
        }) || ContainsWholeWordToken(fileName, {
            L"HOOK", L"SHADOW", L"GHOST", L"PHANTOM", L"SILENT", L"EAC", L"VAC"
        });
        bool standardPath = IsCommonSignedEfiPath(candidate.path);
        bool modifiedAfterBoot = FileTimeToU64(candidate.data.ftLastWriteTime) > bootValue;
        double entropy = DetectionFilter::FileEntropyMultiSample(candidate.path);
        bool packed = entropy >= DetectionFilter::kPackedEntropy;

        uint64_t fileSize = ((uint64_t)candidate.data.nFileSizeHigh << 32) | candidate.data.nFileSizeLow;
        bool tinyFile = fileSize < 4096 && !signedOk;

        DetectionFilter::EfiPeInfo peInfo = DetectionFilter::AnalyzeEfiPe(candidate.path);


        bool badSubsystem = peInfo.valid && !signedOk && !DetectionFilter::IsValidEfiSubsystem(peInfo.subsystem);

        bool badSections  = peInfo.badSections && !signedOk;

        // Detect binary patching: compare stored PE checksum against computed value.
        // Extended to all EFI files regardless of path — not just standard paths.
        bool checksumMismatch = peInfo.valid &&
                                DetectionFilter::CheckPeChecksumMismatch(candidate.path, peInfo.storedChecksum);

        // Content-integrity checks for critical Windows EFI boot files.
        // These catch in-place binary modification even when the Authenticode signature
        // wrapper is still present (signer's wrapper untouched, payload bytes patched).
        static const std::unordered_set<std::wstring> kCriticalBootNames = {
            L"BOOTMGFW.EFI", L"WINLOAD.EFI", L"BOOTX64.EFI", L"BOOTMGR.EFI"
        };
        // Known Microsoft EFI certificate SHA-1 thumbprints (lowercase hex).
        static const std::unordered_set<std::string> kMsEfiThumbprints = {
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d", // Microsoft Windows Production PCA 2011
            "13adb9056804f03cc1aa0779eb1d43ebe52a6a3d", // Microsoft Corporation UEFI CA 2011
            "b3772e76f1d8c4e8d62d3af5e6e91ffed5c2f8fb", // Microsoft UEFI CA 2023
            "46def63b5ce1890208cfabff48de43f0e7b74c5b", // Microsoft Windows PCA 2010
        };

        // pinMsThumbprint: only the 4 Microsoft critical boot names — these MUST chain
        // to one of the pinned MS EFI certs. criticalWindowsEfi keeps the old meaning
        // (severity gates and the "critical" classification for findings).
        const std::wstring fileNameUpper = ToUpperInvariant(fileName);
        const std::wstring candidatePathUpper = ToUpperInvariant(candidate.path);
        bool criticalWindowsEfi = kCriticalBootNames.count(fileNameUpper) > 0;
        // The fallback \EFI\BOOT\BOOTX64.EFI may legitimately be shim/grub from
        // Canonical, Red Hat or another trusted UEFI vendor. Microsoft pinning is
        // only valid for Microsoft's own boot directory and manager filenames.
        bool pinMsThumbprint =
            candidatePathUpper.find(L"\\EFI\\MICROSOFT\\") != std::wstring::npos ||
            fileNameUpper == L"BOOTMGFW.EFI" ||
            fileNameUpper == L"BOOTMGR.EFI";
        // enforceHashBaseline: any .EFI sitting under an \EFI\ directory (ESP, mounted
        // ESP, shadow ESP). Catches in-place modification of vendor/shim/grub/memtest
        // files — they have no MS thumbprint to pin but should still be byte-stable
        // between scans. First scan records the baseline silently; later scans flag
        // any change once and refresh the baseline so legit vendor updates do not loop.
        bool enforceHashBaseline = ToUpperInvariant(candidate.path).find(L"\\EFI\\")
                                   != std::wstring::npos;
        // For signed non-critical files the Authenticode signature is the authoritative integrity
        // check — some vendor signing toolchains never update the PE CheckSum field, so mismatch
        // alone on a properly-signed file is a toolchain artifact, not evidence of patching.
        // The PE CheckSum field is not an Authenticode integrity primitive. Some
        // legitimate EFI toolchains leave it stale, so it is only actionable when
        // the file also fails trust verification.
        bool checksumMismatchSevere = checksumMismatch && !signedOk;
        bool catalogMismatch    = false;
        bool hashChanged        = false;
        bool thumbprintMismatch = false;
        std::string prevHash, currentHash;

        std::string efiThumb;
        bool pinnedMsThumb = false;
        if (pinMsThumbprint) {
            if (signedOk) {
                efiThumb = DetectionFilter::GetSignerCertThumbprint(candidate.path);
                pinnedMsThumb = !efiThumb.empty() && kMsEfiThumbprints.count(efiThumb) > 0;
                thumbprintMismatch = !efiThumb.empty() && !pinnedMsThumb;
                // Fallback: if leaf cert not in the hardcoded list but the full chain is
                // trust-verified (signedOk=true) and the signer CN starts with "MICROSOFT",
                // accept as legitimate. WinVerifyTrust chain validation prevents CN spoofing,
                // and prefix match (vs. substring) blocks contrived names like "Microsofty".
                if (thumbprintMismatch) {
                    auto id = DetectionFilter::GetVerifiedSignerIdentityCached(candidate.path);
                    if (id.trusted && id.cnUpper.compare(0, 9, L"MICROSOFT") == 0) {
                        pinnedMsThumb = true;
                        thumbprintMismatch = false;
                    }
                }
            }
        }

        if (enforceHashBaseline) {
            // Catalog check is tri-state. Only assert a mismatch when the catalog
            // subsystem actually worked AND reported the hash absent. "Unverifiable"
            // (service/hash failure) must NOT flag a legitimate file. A file that is
            // genuinely embedded-signed by a pinned Microsoft EFI cert is authentic
            // even when absent from .cat catalogs, so it is never a catalog mismatch.
            // QueryWindowsCatalogState itself was hardened to require an MS-signed .cat
            // for a Found verdict, closing the CatRoot poisoning gap.
            DetectionFilter::CatalogState catState =
                DetectionFilter::QueryWindowsCatalogState(candidate.path);
            catalogMismatch = (catState == DetectionFilter::CatalogState::NotFound) &&
                              !pinnedMsThumb && pinMsThumbprint;

            currentHash = DetectionFilter::ComputeFileSha256(candidate.path);
            ProtectedBaselineResult baselineResult =
                ProtectedBaselineResult::WriteFailed;
            if (!currentHash.empty()) {
                std::string baselineKey =
                    "EFI:" + WideToUtf8(ToUpperInvariant(candidate.path));
                baselineResult =
                    CheckProtectedBootBaseline(baselineKey, currentHash, prevHash);
            }
            hashChanged = baselineResult == ProtectedBaselineResult::Changed;

            // Windows Update path: pinned MS-signed file rotates — silently accept.
            // Vendor EFI path (signed non-MS or unsigned): keep the finding so the user
            // is alerted, but refresh the baseline so routine updates do not loop the
            // alert. An attacker who replaces shim.efi/grub.efi/etc. produces exactly
            // one finding; failing to investigate is the user's responsibility.
            if (baselineResult == ProtectedBaselineResult::StoreTampered) {
                ScannerUI::EfiCheatFinding baselineFinding;
                baselineFinding.severity = "MEDIUM";
                baselineFinding.path = "ProgramData::rxvscan\\boot-baseline.dpapi";
                baselineFinding.reason = "protected boot baseline could not be authenticated";
                baselineFinding.detail = "DPAPI validation failed; baseline was not replaced";
                baselineFinding.ruleId = "BOOT.BASELINE.TAMPERED";
                baselineFinding.source = "DPAPI machine baseline";
                baselineFinding.confidence = "MEDIUM";
                baselineFinding.evidenceState = "INCONCLUSIVE";
                baselineFinding.suspicious = false;
                findings.push_back(std::move(baselineFinding));
            }
        }

        // Cross-location integrity: compare this file's hash against the reference
        // copy Windows itself keeps in C:\Windows\Boot\EFI (staged there by bcdboot
        // before being written to the ESP). Unlike the baseline check above (which
        // only notices a change between two scans), this catches tampering that was
        // already present the very first time the tool ever runs on the machine.
        bool bootRefMismatch = false;
        std::wstring bootRefPath;
        std::string bootRefHash, bootEspHash;
        {
            std::wstring refPath = FindWindowsBootEfiReference(fileName);
            if (!refPath.empty()) {
                std::string espHash = currentHash.empty()
                    ? DetectionFilter::ComputeFileSha256(candidate.path)
                    : currentHash;
                std::string refHash = DetectionFilter::ComputeFileSha256(refPath);
                if (!espHash.empty() && !refHash.empty() && espHash != refHash) {
                    bootRefMismatch = true;
                    bootRefPath = refPath;
                    bootEspHash = espHash;
                    bootRefHash = refHash;
                }
            }
        }

        std::string suspiciousStr;
        if (!signedOk)
            suspiciousStr = DetectionFilter::FindSuspiciousStringInEfi(candidate.path);
        bool hasEmbeddedCheatStr = !suspiciousStr.empty();


        // ── Bootloader hook detection ────────────────────────────────────────
        // Checked before allClear so patched-but-still-Authenticode-signed files are caught.
        // Pushed without 'continue' — multiple distinct hook findings per file are possible.
        if (peInfo.epHooked && !signedOk) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "MEDIUM";
            f.path = WideToUtf8(candidate.path);
            f.reason = "untrusted EFI begins with a trampoline-like pattern";
            f.detail = "pattern=" + peInfo.epHookDetail +
                       " | this opcode is supporting evidence, not proof of a hook";
            f.ruleId = "BOOT.EFI.UNTRUSTED_TRAMPOLINE";
            f.source = "EFI PE parser";
            f.confidence = "LOW";
            f.evidenceState = "REVIEW";
            f.suspicious = true;
            findings.push_back(f);
        }
        // The executable-section-name whitelist is intentionally small, so legitimate
        // signed EFI binaries (memtest.efi, vendor EFI tools, EDK2 builds) routinely
        // contain section names outside it (.itext/.crt/_TEXT/etc). Gate by !signedOk:
        // an Authenticode-trusted chain authenticates the section layout, and any real
        // injection on a signed binary would have broken the signature already.
        if (peInfo.injectedSection && !signedOk) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = criticalWindowsEfi ? "HIGH" : "MEDIUM";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI has injected executable section";
            f.detail = "section=" + peInfo.injectedSecName;
            f.suspicious = true;
            findings.push_back(f);
        }
        // Removed: Rich-header-absent finding on signed Microsoft EFI.
        // Microsoft strips Rich headers from many production-signed EFI binaries
        // (including bootmgfw.efi on recent Windows builds), so absence is not a
        // reliable patcher indicator — it produced FPs on legit boot files.
        if (peInfo.dataDirOutOfBounds) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "PE DataDirectory points outside declared sections (tampered header)";
            f.detail = "Import or Export directory RVA falls outside all section ranges";
            f.suspicious = true;
            findings.push_back(f);
        }

        // Bug 2 fix: remover "|| standardPath" — arquivos EFI em caminhos padrao
        // NUNCA sao modificados durante a sessao ativa de forma legitima. O Windows Update
        // modifica bootmgfw.efi antes do reboot, entao apos o boot modifiedAfterBoot=false.
        // modifiedAfterBoot=true em caminho padrao = bootkit modificou o arquivo em runtime.
        // hookAnomaly: structural signs of binary patching that survive Authenticode
        // wrapping. injectedSection contributes only when !signedOk (see comment above);
        // noRichHeader was removed because Microsoft ships legit EFI binaries without it.
        bool hookAnomaly = (peInfo.epHooked && !signedOk) || peInfo.dataDirOutOfBounds ||
                           (peInfo.injectedSection && !signedOk);
        bool allClear = signedOk && !badSections && !badSubsystem && !checksumMismatchSevere &&
                        !catalogMismatch && !hashChanged && !thumbprintMismatch &&
                        !hookAnomaly && !bootRefMismatch;
        if (allClear)
            continue;

        if (bootRefMismatch) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI da particao de boot diverge da copia de referencia em C:\\Windows\\Boot\\EFI";
            f.detail = "esp_sha256=" + bootEspHash + " | reference_sha256=" + bootRefHash +
                       " | reference_path=" + WideToUtf8(bootRefPath);
            f.ruleId = "BOOT.EFI.ESP_C_MISMATCH";
            f.source = "ESP vs C:\\Windows\\Boot\\EFI";
            f.confidence = "HIGH";
            f.evidenceState = "SUSPICIOUS";
            f.suspicious = true;
            findings.push_back(std::move(f));
            continue;
        }

        if (checksumMismatchSevere) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI binary modified (PE checksum mismatch)";
            f.detail = "signed=" + std::string(signedOk ? "yes" : "no") +
                       " | stored_checksum=0x" + [&]{ char b[12]{}; snprintf(b, sizeof(b), "%08X", peInfo.storedChecksum); return std::string(b); }() +
                       " | file=" + WideToUtf8(candidate.path);
            f.suspicious = true;
            findings.push_back(f);
            continue;
        }

        if (catalogMismatch) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI catalog mismatch (content modified)";
            f.detail = "Windows EFI file not found in any system .cat catalog — binary content may have been patched"
                       " | signed=" + std::string(signedOk ? "yes" : "no");
            f.suspicious = true;
            findings.push_back(f);
            continue;
        }

        if (hashChanged) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = signedOk ? "MEDIUM" : "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI hash changed since last scan";
            f.detail = "SHA256 changed since previous scan"
                       " | prev=" + prevHash.substr(0, 16) + "..."
                       " | curr=" + currentHash.substr(0, 16) + "..."
                       " | trusted_signature=" + (signedOk ? std::string("yes") : std::string("no"));
            f.ruleId = "BOOT.EFI.BASELINE_CHANGED";
            f.source = "protected-content baseline";
            f.confidence = signedOk ? "MEDIUM" : "HIGH";
            f.evidenceState = signedOk ? "REVIEW" : "SUSPICIOUS";
            f.suspicious = !signedOk;
            findings.push_back(f);
            continue;
        }

        if (thumbprintMismatch) {
            ScannerUI::EfiCheatFinding f;
            FileTimeToLocalStrings(candidate.data.ftLastWriteTime, f.date, f.time);
            f.severity = "HIGH";
            f.path = WideToUtf8(candidate.path);
            f.reason = "EFI signed with unrecognized Microsoft certificate";
            f.detail = "Windows boot file signed but certificate thumbprint does not match known Microsoft EFI certs"
                       " — possible forged CN or re-signed binary";
            f.suspicious = true;
            findings.push_back(f);
            continue;
        }

        std::string reason;
        std::string severity = "MEDIUM";
        bool highIndicator = packed || riskyName || badSubsystem ||
                             tinyFile || badSections || hasEmbeddedCheatStr;

        if (!signedOk && highIndicator) {
            severity = "HIGH";
            if (hasEmbeddedCheatStr)
                reason = "unsigned EFI with embedded cheat strings";
            else if (badSubsystem)
                reason = "non-EFI PE subsystem (possible malicious loader)";
            else if (tinyFile)
                reason = "unsigned stub EFI (possible dropper)";
            else if (badSections)
                reason = "unsigned EFI with packer sections";
            else
                reason = "unsigned EFI loader";
        } else if (!signedOk) {
            reason = standardPath ? "unsigned standard boot path" : "unsigned non-standard EFI";
        } else if (modifiedAfterBoot) {
            severity = "FLAG";
            reason = standardPath ? "trusted EFI timestamp changed after boot" :
                                    "trusted non-standard EFI timestamp changed after boot";
        } else if (riskyName) {
            reason = "cheat-like EFI filename";
        } else {
            // Reached here with signedOk=true, !modifiedAfterBoot, !riskyName, but allClear
            // turned out false from some structural check that has already pushed its own
            // dedicated finding (epHooked, dataDirOutOfBounds, etc). Emitting another
            // generic "EFI requires review" on top is duplicate noise — skip.
            continue;
        }

        std::string detail = std::string("signed=") + (signedOk ? "yes" : "no") +
                             " | entropy=" + DetectionFilter::EntropyToStr(entropy) +
                             " | after-boot=" + (modifiedAfterBoot ? "yes" : "no");
        if (peInfo.valid) {
            detail += std::string(" | subsystem=") + std::to_string(peInfo.subsystem) +
                      "(" + DetectionFilter::EfiSubsystemName(peInfo.subsystem) + ")";
        }
        if (peInfo.overlaySize > 0) {
            char buf[32] = {};
            snprintf(buf, sizeof(buf), " | overlay=%zuB", peInfo.overlaySize);
            detail += buf;
        }
        if (tinyFile) {
            char buf[32] = {};
            snprintf(buf, sizeof(buf), " | size=%zuB", (size_t)fileSize);
            detail += buf;
        }
        if (hasEmbeddedCheatStr)
            detail += " | embedded=\"" + suspiciousStr + "\"";

        ScannerUI::EfiCheatFinding finding;
        FileTimeToLocalStrings(candidate.data.ftLastWriteTime, finding.date, finding.time);
        finding.severity = severity;
        finding.path = WideToUtf8(candidate.path);
        finding.reason = reason;
        finding.detail = detail;
        finding.ruleId = modifiedAfterBoot && signedOk
            ? "BOOT.EFI.TIMESTAMP_AFTER_BOOT"
            : "BOOT.EFI.UNTRUSTED_IMAGE";
        finding.source = "EFI filesystem";
        finding.confidence = modifiedAfterBoot && signedOk ? "LOW" : "MEDIUM";
        finding.evidenceState = modifiedAfterBoot && signedOk ? "REVIEW" : "SUSPICIOUS";
        finding.suspicious = !signedOk || riskyName || badSubsystem || tinyFile;
        findings.push_back(finding);
    }

    CollectBootIntegrityFindings(findings);
    CollectBcdIntegrityFindings(roots, findings);
    CollectNvramBootEntries(findings);
    CollectSecureBootKeyFindings(findings);
    std::string storageCoverage;
    auto storageFindings = CollectBootStorageIntegrityFindings(storageCoverage);
    findings.insert(findings.end(),
                    std::make_move_iterator(storageFindings.begin()),
                    std::make_move_iterator(storageFindings.end()));
    std::string measuredBootCoverage;
    auto measuredBootFindings = CollectMeasuredBootFindings(measuredBootCoverage);
    findings.insert(findings.end(),
                    std::make_move_iterator(measuredBootFindings.begin()),
                    std::make_move_iterator(measuredBootFindings.end()));

    for (auto& finding : findings) {
        if (finding.ruleId.empty())
            finding.ruleId = "BOOT.LEGACY_RULE";
        if (finding.source.empty())
            finding.source = "EFI/NVRAM";
        if (finding.confidence.empty())
            finding.confidence = finding.suspicious ? "MEDIUM" : "LOW";
        if (finding.evidenceState.empty())
            finding.evidenceState = finding.suspicious ? "SUSPICIOUS" : "REVIEW";
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        auto rank = [](const std::string& severity) {
            if (severity == "HIGH") return 0;
            if (severity == "MEDIUM") return 1;
            if (severity == "FLAG") return 2;
            return 3;
        };
        if (a.severity != b.severity)
            return rank(a.severity) < rank(b.severity);
        if (a.date != b.date)
            return a.date > b.date;
        return a.time > b.time;
    });

    bool hasSuspicious = false;
    bool hasReview = false;
    for (const auto& finding : findings) {
        hasSuspicious = hasSuspicious || finding.suspicious;
        hasReview = hasReview || !finding.suspicious;
    }

    if (hasSuspicious)
        status = "DETECTED";
    else if (hasReview || roots.empty() || accessIssue || storageCoverage != "OK" ||
             measuredBootCoverage.rfind("INCONCLUSIVE", 0) == 0)
        status = "REVIEW";
    else
        status = "OK";
    return findings;
}

static void CollectPrefetchFilesOnDisk(std::unordered_map<std::wstring, PrefetchSourceEntry>& out) {
    wchar_t windowsDir[MAX_PATH] = {};
    UINT len = GetWindowsDirectoryW(windowsDir, (UINT)std::size(windowsDir));
    if (len == 0 || len >= std::size(windowsDir))
        return;

    std::wstring search = std::wstring(windowsDir) + L"\\Prefetch\\*.pf";
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(search.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE)
        return;

    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            continue;

        std::wstring file = data.cFileName;
        if (!IsExecutablePrefetchFile(file))
            continue;

        std::wstring key = ToUpperInvariant(file);
        out[key] = { file, data.ftLastWriteTime };
    } while (FindNextFileW(find, &data));

    FindClose(find);
}

// Reads the USN change journal (FSCTL_READ_USN_JOURNAL) looking for .pf files that were
// CREATED (execution happened) but are no longer on disk (deleted = anti-forensic wipe).
// Returns the set of deleted .pf names with their timestamps and the create→delete delta.
struct DeletedPrefetchRecord {
    std::wstring name;
    FILETIME     deleteTime = {};
    FILETIME     createTime = {};   // zero if create record not visible in journal
};

static std::vector<DeletedPrefetchRecord>
CollectDeletedPrefetchFromChangeJournal(DWORD& outDeleteCount)
{
    outDeleteCount = 0;
    std::vector<DeletedPrefetchRecord> result;

    std::wstring root = GetWindowsDriveRoot();
    wchar_t volumePath[] = { L'\\', L'\\', L'.', L'\\', root[0], L':', L'\0' };
    HANDLE volume = CreateFileW(volumePath, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (volume == INVALID_HANDLE_VALUE)
        return result;

    USN_JOURNAL_DATA_V0 journal = {};
    DWORD bytes = 0;
    if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                         &journal, sizeof(journal), &bytes, nullptr)) {
        CloseHandle(volume);
        return result;
    }

    // Approximate boot time: current time minus uptime
    FILETIME bootTime = {};
    {
        ULONGLONG uptimeMs = GetTickCount64();
        FILETIME now = {};
        GetSystemTimeAsFileTime(&now);
        ULONGLONG nowU = FileTimeToU64(now);
        ULONGLONG bootU = nowU > uptimeMs * 10000ULL ? nowU - uptimeMs * 10000ULL : 0;
        bootTime.dwLowDateTime  = (DWORD)(bootU & 0xFFFFFFFF);
        bootTime.dwHighDateTime = (DWORD)(bootU >> 32);
    }

    // First pass: collect CREATE and DELETE records for .pf files since boot
    std::unordered_map<std::wstring, FILETIME> createTimes;
    std::unordered_map<std::wstring, FILETIME> deleteTimes;

    READ_USN_JOURNAL_DATA_V0 readData = {};
    readData.StartUsn        = journal.FirstUsn;
    readData.ReasonMask      = USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE
                             | USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout          = 0;
    readData.BytesToWaitFor   = 0;
    readData.UsnJournalID     = journal.UsnJournalID;

    std::vector<BYTE> buffer(1024 * 1024);
    while (readData.StartUsn < journal.NextUsn &&
           DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL,
                           &readData, sizeof(readData),
                           buffer.data(), (DWORD)buffer.size(), &bytes, nullptr)) {
        if (bytes <= sizeof(USN)) break;

        BYTE* cursor = buffer.data() + sizeof(USN);
        BYTE* end    = buffer.data() + bytes;
        while (cursor + sizeof(USN_RECORD_V2) <= end) {
            auto* rec = reinterpret_cast<USN_RECORD_V2*>(cursor);
            if (rec->RecordLength == 0 || cursor + rec->RecordLength > end) break;

            if (rec->MajorVersion == 2 && rec->FileNameLength > 0) {
                FILETIME ft = {};
                ft.dwLowDateTime  = rec->TimeStamp.LowPart;
                ft.dwHighDateTime = rec->TimeStamp.HighPart;

                // Only consider events that happened since boot
                if (FileTimeToU64(ft) >= FileTimeToU64(bootTime)) {
                    const wchar_t* namePtr =
                        reinterpret_cast<const wchar_t*>(cursor + rec->FileNameOffset);
                    std::wstring name(namePtr, rec->FileNameLength / sizeof(wchar_t));
                    std::wstring key = ToUpperInvariant(name);

                    if (IsExecutablePrefetchFile(name)) {
                        DWORD reason = rec->Reason;
                        if (reason & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME)) {
                            deleteTimes[key] = ft;
                            ++outDeleteCount;
                        }
                        if (reason & (USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW_NAME)) {
                            // Only store if not already recorded (keep earliest)
                            if (createTimes.find(key) == createTimes.end())
                                createTimes[key] = ft;
                        }
                    }
                }
            }
            cursor += rec->RecordLength;
        }

        USN nextUsn = *reinterpret_cast<USN*>(buffer.data());
        if (nextUsn <= readData.StartUsn) break;
        readData.StartUsn = nextUsn;
    }
    CloseHandle(volume);

    // Build Prefetch directory path for on-disk check
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring prefDir = std::wstring(winDir) + L"\\Prefetch\\";

    // Cross-reference: deleted .pf that no longer exist on disk = anti-forensic wipe
    for (const auto& kv : deleteTimes) {
        const std::wstring& key = kv.first;
        // Find the original-case name (from deleteTimes key, which is uppercase)
        // We use the key directly for disk check since it's uppercase and Windows is case-insensitive
        if (FileExistsW(prefDir + key))
            continue;  // Still on disk — file was renamed or temporarily deleted, skip

        DeletedPrefetchRecord rec;
        // Recover original-case name from createTimes if available
        auto cit = createTimes.find(key);
        rec.name       = (cit != createTimes.end()) ? key : key;
        rec.deleteTime = kv.second;
        rec.createTime = (cit != createTimes.end()) ? cit->second : FILETIME{};
        result.push_back(rec);
    }

    return result;
}

std::vector<ScannerUI::PrefetchHit> CollectHiddenPrefetchDetections() {
    DWORD deleteCount = 0;
    auto deleted = CollectDeletedPrefetchFromChangeJournal(deleteCount);

    struct HiddenPrefetch {
        ScannerUI::PrefetchHit hit;
        ULONGLONG order = 0;
    };

    std::vector<HiddenPrefetch> hidden;
    constexpr ULONGLONG kWiperThresholdSec = 120ULL;  // < 2 min create→delete = active wiper
    constexpr ULONGLONG kSecToInterval     = 10000000ULL;

    for (const auto& rec : deleted) {
        ULONGLONG delU = FileTimeToU64(rec.deleteTime);
        ULONGLONG crtU = FileTimeToU64(rec.createTime);

        bool isWiper = crtU > 0 && delU > crtU &&
                       (delU - crtU) < kWiperThresholdSec * kSecToInterval;

        ScannerUI::PrefetchHit hit;
        FileTimeToLocalStrings(rec.deleteTime, hit.date, hit.time);
        hit.file = WideToUtf8(rec.name);

        if (isWiper) {
            ULONGLONG deltaSec = (delU - crtU) / kSecToInterval;
            hit.severity = "HIGH";
            hit.alias    = "Wiper de Prefetch ativo";
            hit.note     = "Arquivo .pf criado e apagado em " + std::to_string(deltaSec) +
                           "s (possivel wiper em execucao)";
        } else {
            hit.severity = "HIDDEN";
            hit.alias    = "Prefetch apagado apos execucao";
            hit.note     = "Arquivo executado (registro no journal) mas .pf removido do disco";
        }

        hidden.push_back({ hit, delU });
    }

    std::sort(hidden.begin(), hidden.end(), [](const auto& a, const auto& b) {
        return a.order > b.order;
    });

    std::vector<ScannerUI::PrefetchHit> out;
    out.reserve(hidden.size());
    for (const auto& item : hidden)
        out.push_back(item.hit);

    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// USN Journal integrity: detects anti-forensic manipulation of the journal
// itself (size reduction, wipe+recreate, entry gaps, abnormal configuration).
// ─────────────────────────────────────────────────────────────────────────────

std::vector<ScannerUI::PrefetchHit> CollectUsnJournalIntegrityFindings(
    std::string& outStatus, std::string& outDrive)
{
    std::vector<ScannerUI::PrefetchHit> findings;

    // Open the system volume — same pattern as CollectDeletedPrefetchFromChangeJournal
    std::wstring root = GetWindowsDriveRoot();
    if (root.empty()) {
        outStatus = "NTFS: erro ao abrir volume";
        outDrive  = "-";
        return findings;
    }
    wchar_t volumePath[] = { L'\\', L'\\', L'.', L'\\', root[0], L':', L'\0' };
    HANDLE hVol = CreateFileW(volumePath, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol == INVALID_HANDLE_VALUE) {
        outStatus = "NTFS: OK | Journal: acesso negado";
        outDrive  = WideToUtf8(root) + " [sem acesso]";
        return findings;
    }

    // Query journal metadata
    USN_JOURNAL_DATA_V0 jd = {};
    DWORD bytes = 0;
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL,
                         nullptr, 0, &jd, sizeof(jd), &bytes, nullptr)) {
        CloseHandle(hVol);
        outStatus = "NTFS: OK | Journal: desabilitado ou nao disponivel";
        outDrive  = WideToUtf8(root) + " [NTFS] - Journal ausente";
        return findings;
    }

    DWORD uptimeMin = (DWORD)(GetTickCount64() / 60000);

    std::string nowDate, nowTime;
    FILETIME nowFt = {};
    GetSystemTimeAsFileTime(&nowFt);
    FileTimeToLocalStrings(nowFt, nowDate, nowTime);

    auto addAnomaly = [&](const std::string& tag, const std::string& detail,
                          const std::string& sev) {
        ScannerUI::PrefetchHit h;
        h.date     = nowDate;
        h.time     = nowTime;
        h.severity = sev;
        h.alias    = tag;
        h.file     = WideToUtf8(root);
        h.note     = detail;
        findings.push_back(h);
    };

    // ── Detecção 1: MaximumSize reduzido ─────────────────────────────────────
    constexpr DWORDLONG k8MB  =  8ULL * 1024 * 1024;
    constexpr DWORDLONG k32MB = 32ULL * 1024 * 1024;
    if (jd.MaximumSize < k8MB) {
        char buf[64];
        snprintf(buf, sizeof(buf), "MaximumSize=%.1f MB (esperado >=32MB)",
                 (double)jd.MaximumSize / (1024.0 * 1024.0));
        addAnomaly("USN_JOURNAL_REDUZIDO",
                   std::string(buf) + " — janela forense gravemente reduzida", "HIGH");
    } else if (jd.MaximumSize < k32MB) {
        char buf[64];
        snprintf(buf, sizeof(buf), "MaximumSize=%.1f MB (padrao Windows: >=32MB)",
                 (double)jd.MaximumSize / (1024.0 * 1024.0));
        addAnomaly("USN_JOURNAL_PEQUENO",
                   std::string(buf) + " — historico forense abaixo do padrao", "MEDIUM");
    }

    // ── Detecção 2: AllocationDelta anormal ──────────────────────────────────
    constexpr DWORDLONG k512KB = 512ULL * 1024;
    if (jd.AllocationDelta > 0 && jd.AllocationDelta < k512KB) {
        char buf[64];
        snprintf(buf, sizeof(buf), "AllocationDelta=%llu KB (padrao: ~2MB)",
                 (unsigned long long)jd.AllocationDelta / 1024);
        addAnomaly("USN_ALLOCATION_DELTA",
                   std::string(buf) + " — pode retardar o crescimento do journal", "MEDIUM");
    }

    // ── Detecção 3: NextUsn quase zero (journal recreado muito recentemente) ─
    if (jd.NextUsn < 65536 && uptimeMin > 10) {
        char buf[64];
        snprintf(buf, sizeof(buf), "NextUsn=%llu (uptime=%u min)",
                 (unsigned long long)jd.NextUsn, uptimeMin);
        addAnomaly("USN_NEXTUSN_ZERO",
                   std::string(buf) + " — journal com sequencia quase zero: recreado recentemente", "HIGH");
    }

    // ── Detecção 4: Janela legivel muito pequena (wipe recente) ──────────────
    if (jd.MaximumSize > 0 && jd.NextUsn > jd.LowestValidUsn) {
        DWORDLONG readable = jd.NextUsn - jd.LowestValidUsn;
        int pct = (int)((readable * 100ULL) / jd.MaximumSize);
        if (pct < 3 && uptimeMin > 30) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                     "janela legivel=%llu KB (%d%% do MaximumSize) com uptime=%u min",
                     (unsigned long long)readable / 1024, pct, uptimeMin);
            addAnomaly("USN_JANELA_MINIMA",
                       std::string(buf) + " — possivel limpeza recente do journal", "HIGH");
        } else if (pct < 10 && uptimeMin > 60) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                     "janela legivel=%llu KB (%d%% do MaximumSize) com uptime=%u min",
                     (unsigned long long)readable / 1024, pct, uptimeMin);
            addAnomaly("USN_HISTORICO_BAIXO",
                       std::string(buf) + " — historico do journal abaixo do esperado", "MEDIUM");
        }
    }

    // ── Detecção 4b: Journal recriado desde o boot (primeiro entry > boot) ───
    if (jd.LowestValidUsn < jd.NextUsn) {
        READ_USN_JOURNAL_DATA_V0 readFirst = {};
        readFirst.StartUsn     = jd.LowestValidUsn;
        readFirst.ReasonMask   = MAXDWORD;
        readFirst.UsnJournalID = jd.UsnJournalID;

        std::vector<BYTE> fbuf(4096);
        DWORD fbytes = 0;
        if (DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL,
                            &readFirst, sizeof(readFirst),
                            fbuf.data(), (DWORD)fbuf.size(), &fbytes, nullptr)
            && fbytes > (DWORD)sizeof(USN)) {
            BYTE* cursor = fbuf.data() + sizeof(USN);
            BYTE* fend   = fbuf.data() + fbytes;
            if (cursor + sizeof(USN_RECORD_V2) <= fend) {
                auto* rec = reinterpret_cast<const USN_RECORD_V2*>(cursor);
                if (rec->RecordLength > 0 && rec->MajorVersion == 2) {
                    FILETIME firstEntryFt = {};
                    firstEntryFt.dwLowDateTime  = rec->TimeStamp.LowPart;
                    firstEntryFt.dwHighDateTime = rec->TimeStamp.HighPart;

                    // Compare to boot time
                    FILETIME bootTime = GetBootFileTime();
                    ULONGLONG firstU = FileTimeToU64(firstEntryFt);
                    ULONGLONG bootU  = FileTimeToU64(bootTime);

                    // Format first entry timestamp for UI display
                    std::string feDate, feTime;
                    FileTimeToLocalStrings(firstEntryFt, feDate, feTime);
                    outDrive = WideToUtf8(root) + " [NTFS] - Ativo | First Entry: " + feDate + " " + feTime;

                    if (firstU > bootU && bootU > 0) {
                        std::string bootDate, bootTimeStr;
                        FileTimeToLocalStrings(bootTime, bootDate, bootTimeStr);
                        addAnomaly("USN_RECREADO_NO_BOOT",
                                   "Journal recriado durante sessao atual | boot=" +
                                   bootDate + " " + bootTimeStr +
                                   " | primeiro_entry=" + feDate + " " + feTime +
                                   " — evidencias pre-recriacao apagadas", "HIGH");
                    }
                }
            }
        }
    }

    // ── Detecção 5: Gaps de sequência USN (entradas deletadas do $J) ─────────
    if (jd.NextUsn > jd.LowestValidUsn) {
        constexpr DWORDLONG kSampleWindow = 512ULL * 1024; // últimos 512KB
        READ_USN_JOURNAL_DATA_V0 readGap = {};
        readGap.StartUsn = (static_cast<DWORDLONG>(jd.NextUsn) >
                            static_cast<DWORDLONG>(jd.LowestValidUsn) + kSampleWindow)
                           ? jd.NextUsn - kSampleWindow
                           : jd.LowestValidUsn;
        readGap.ReasonMask   = MAXDWORD;
        readGap.UsnJournalID = jd.UsnJournalID;

        std::vector<BYTE> gbuf(128 * 1024);
        DWORD gbytes = 0;
        DWORDLONG totalGap = 0;
        USN expectedUsn = readGap.StartUsn;
        bool firstRecord = true;

        while (readGap.StartUsn < jd.NextUsn &&
               DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL,
                               &readGap, sizeof(readGap),
                               gbuf.data(), (DWORD)gbuf.size(), &gbytes, nullptr)) {
            if (gbytes <= (DWORD)sizeof(USN)) break;
            BYTE* cursor = gbuf.data() + sizeof(USN);
            BYTE* gend   = gbuf.data() + gbytes;
            while (cursor + sizeof(USN_RECORD_V2) <= gend) {
                auto* rec = reinterpret_cast<const USN_RECORD_V2*>(cursor);
                if (rec->RecordLength == 0 || cursor + rec->RecordLength > gend) break;
                if (rec->MajorVersion == 2) {
                    if (!firstRecord && rec->Usn > expectedUsn) {
                        DWORDLONG gap = (DWORDLONG)(rec->Usn - expectedUsn);
                        // Gaps < 8 bytes are alignment padding (normal)
                        if (gap > 8) totalGap += gap;
                    }
                    firstRecord = false;
                    expectedUsn = rec->Usn + ((rec->RecordLength + 7) & ~7ULL);
                }
                cursor += rec->RecordLength;
            }
            USN nextUsn = *reinterpret_cast<const USN*>(gbuf.data());
            if (nextUsn <= readGap.StartUsn) break;
            readGap.StartUsn = nextUsn;
        }

        constexpr DWORDLONG kGapThreshold = 64ULL * 1024; // 64KB de entradas ausentes
        if (totalGap > kGapThreshold) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                     "gaps totais=%.1f KB na janela dos ultimos 512KB do journal",
                     (double)totalGap / 1024.0);
            addAnomaly("USN_GAPS_DETECTADOS",
                       std::string(buf) + " — entradas ausentes do $J (possivel rootkit ou edicao direta)", "HIGH");
        }
    }

    CloseHandle(hVol);

    // Build status and drive strings if not set yet (first entry detection above sets outDrive)
    bool hasHigh = false;
    for (const auto& f : findings)
        if (f.severity == "HIGH") { hasHigh = true; break; }

    outStatus = findings.empty()
        ? "NTFS: OK | Journal: OK"
        : (hasHigh ? "NTFS: OK | Journal: ANOMALIA DETECTADA" : "NTFS: OK | Journal: REVISAO");

    if (outDrive.empty())
        outDrive = WideToUtf8(root) + " [NTFS] - Ativo | Journal ID: " +
                   [&]() {
                       char buf[32];
                       snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)jd.UsnJournalID);
                       return std::string(buf);
                   }();

    return findings;
}

// ─────────────────────────────────────────────────────────────────────────────
// Prefetch subsystem integrity checks: detect registry disabling, directory
// tampering (reparse point), mass deletion, and active wipers.
// ─────────────────────────────────────────────────────────────────────────────

std::vector<ScannerUI::PrefetchHit> CollectPrefetchIntegrityFindings() {
    std::vector<ScannerUI::PrefetchHit> out;

    std::string nowDate, nowTime;
    FILETIME nowFt = {};
    GetSystemTimeAsFileTime(&nowFt);
    FileTimeToLocalStrings(nowFt, nowDate, nowTime);

    auto addHit = [&](const std::string& sev, const std::string& alias,
                      const std::string& file, const std::string& note) {
        ScannerUI::PrefetchHit h;
        h.date = nowDate; h.time = nowTime;
        h.severity = sev; h.alias = alias;
        h.file = file;    h.note  = note;
        out.push_back(std::move(h));
    };

    // Check 1 — EnablePrefetcher registry value
    // 0=off, 1=boot only, 2=app only, 3=both (normal Windows default)
    {
        DWORD val = 3;
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager"
                L"\\Memory Management\\PrefetchParameters",
                0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(val), type = 0;
            RegQueryValueExW(hKey, L"EnablePrefetcher", nullptr, &type,
                             reinterpret_cast<LPBYTE>(&val), &sz);
            RegCloseKey(hKey);
        }
        if (val == 0)
            addHit("HIGH", "Prefetch desabilitado no registro",
                   "EnablePrefetcher=0",
                   "Prefetch completamente desativado — tecnica anti-forense comum");
        else if (val == 1)
            addHit("MEDIUM", "Prefetch parcialmente desabilitado",
                   "EnablePrefetcher=1",
                   "Apenas boot Prefetch ativo — execucoes de apps nao sao registradas");
    }

    // Check 2 — Prefetch directory reparse point (junction / symlink)
    {
        wchar_t winDir[MAX_PATH] = {};
        GetWindowsDirectoryW(winDir, MAX_PATH);
        std::wstring prefDir = std::wstring(winDir) + L"\\Prefetch";
        DWORD attrs = GetFileAttributesW(prefDir.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
            addHit("HIGH", "Diretorio Prefetch e um ponto de juncao/symlink",
                   WideToUtf8(prefDir),
                   "C:\\Windows\\Prefetch redirecionado — possivelmente ocultando execucoes");
    }

    // Check 3 — Mass .pf deletion detected via change journal (reuse deleteCount)
    {
        DWORD deleteCount = 0;
        CollectDeletedPrefetchFromChangeJournal(deleteCount);
        if (deleteCount > 15)
            addHit("HIGH", "Remocao em massa de arquivos Prefetch",
                   std::to_string(deleteCount) + " arquivos .pf deletados",
                   "Alto volume de delecoes de .pf desde o boot — possivel wiper");
    }

    // Check 4 — SysMain (Superfetch) service stopped or disabled
    {
        SC_HANDLE sc = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (sc) {
            SC_HANDLE svc = OpenService(sc, L"SysMain",
                                        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
            if (svc) {
                SERVICE_STATUS_PROCESS ssp = {};
                DWORD needed = 0;
                QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                     reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

                DWORD confSize = 0;
                QueryServiceConfigW(svc, nullptr, 0, &confSize);
                DWORD startType = SERVICE_AUTO_START;
                if (confSize > 0) {
                    std::vector<BYTE> buf(confSize);
                    auto* conf = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
                    if (QueryServiceConfigW(svc, conf, confSize, &confSize))
                        startType = conf->dwStartType;
                }

                bool stopped  = ssp.dwCurrentState == SERVICE_STOPPED;
                bool disabled = startType == SERVICE_DISABLED;

                if (disabled)
                    addHit("HIGH", "Servico SysMain (Prefetch) desabilitado",
                           "SysMain", "Superfetch/Prefetch permanentemente desabilitado no SCM");
                else if (stopped)
                    addHit("MEDIUM", "Servico SysMain (Prefetch) parado",
                           "SysMain", "Superfetch parado — novos arquivos .pf nao serao gerados");

                CloseServiceHandle(svc);
            }
            CloseServiceHandle(sc);
        }
    }

    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// P5 — Timeline correlation: cross-reference BAM × Prefetch × USN journal
// Detects anti-forensics artifacts that only appear when sources are compared.
// ─────────────────────────────────────────────────────────────────────────────

std::vector<ScannerUI::TimelineCorrelationFinding>
CollectTimelineCorrelationFindings(
    const std::vector<ScannerUI::BamEntry>& bam,
    const std::vector<ScannerUI::PrefetchHit>& prefetch,
    const std::vector<ScannerUI::SysmonEvent>& sysmonEvents,
    std::string& status)
{
    std::vector<ScannerUI::TimelineCorrelationFinding> findings;

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    std::string date, timeStr;
    FileTimeToLocalStrings(now, date, timeStr);

    // Build a set of paths that appear in USN (prefetch cross-reference)
    // PrefetchHit entries with "Registro USN sem Prefetch atual" = has USN
    std::unordered_set<std::wstring> usnKnownPaths;
    for (const auto& ph : prefetch) {
        if (ph.alias.find("USN") != std::string::npos || ph.note.find("USN") != std::string::npos) {
            std::wstring wpath(ph.file.begin(), ph.file.end());
            usnKnownPaths.insert(ToUpperInvariant(wpath));
        }
    }

    // Build a set of prefetch-on-disk basenames (no-USN entries)
    std::unordered_set<std::wstring> prefetchOnDiskNoUsn;
    for (const auto& ph : prefetch) {
        if (ph.alias == "Prefetch ausente no USN Journal") {
            std::wstring wfile(ph.file.begin(), ph.file.end());
            prefetchOnDiskNoUsn.insert(ToUpperInvariant(wfile));
        }
    }

    // Collect Sysmon EventID 1102 (log cleared) timestamps for correlation
    // Store as YYYYMMDDHHMMSS strings for proximity comparison
    std::vector<std::string> logClearedTimes;
    for (const auto& ev : sysmonEvents) {
        if (ev.eventId == 1102 || ev.eventId == 104)
            logClearedTimes.push_back(ev.date + ev.time);
    }

    // Rule — BATCH_TIMESTAMP_WIPE: 3+ BAM entries with "00:00:00" timestamp
    {
        int wipedCount = 0;
        for (const auto& entry : bam) {
            if (entry.time == "00:00:00")
                ++wipedCount;
        }
        if (wipedCount >= 3) {
            ScannerUI::TimelineCorrelationFinding f;
            f.date      = date;
            f.time      = timeStr;
            f.severity  = "HIGH";
            f.path      = "(multiple)";
            f.reason    = "batch-timestamp-wipe";
            f.detail    = std::to_string(wipedCount) + " BAM entries have zeroed timestamps (00:00:00) — batch forensic wipe detected";
            f.suspicious = true;
            findings.push_back(f);
        }
    }

    // Rule 1 + TRIPLE_WIPE: BAM entry + no USN + optionally no prefetch
    for (const auto& entry : bam) {
        if (entry.reason != "DELETED" && entry.reason != "UNSIGNED")
            continue;
        std::wstring wpath(entry.path.begin(), entry.path.end());
        std::wstring wpathUp = ToUpperInvariant(wpath);

        // Wiped timestamp: time part is exactly "00:00:00"
        if (entry.time == "00:00:00") {
            ScannerUI::TimelineCorrelationFinding f;
            f.date      = entry.date;
            f.time      = entry.time;
            f.severity  = "HIGH";
            f.path      = entry.path;
            f.reason    = "wiped-timestamp";
            f.detail    = "BAM timestamp is exactly midnight — timestamp deliberately zeroed";
            f.suspicious = true;
            findings.push_back(f);
            continue;
        }

        bool noUsn = (entry.reason == "DELETED" && usnKnownPaths.find(wpathUp) == usnKnownPaths.end());
        if (!noUsn)
            continue;

        // Check if a matching prefetch-no-USN entry also exists for this exe name
        std::wstring baseNameUp = ToUpperInvariant(DetectionFilter::BaseName(wpath));
        // Prefetch filename format: EXECNAME-XXXXXXXX.pf
        bool tripleWipe = false;
        for (const auto& pfKey : prefetchOnDiskNoUsn) {
            if (pfKey.rfind(baseNameUp, 0) == 0) {
                tripleWipe = true;
                break;
            }
        }

        if (tripleWipe) {
            ScannerUI::TimelineCorrelationFinding f;
            f.date      = entry.date;
            f.time      = entry.time;
            f.severity  = "HIGH";
            f.path      = entry.path;
            f.reason    = "triple-wipe";
            f.detail    = "BAM executed + prefetch exists without USN + no USN record — coordinated anti-forensic wipe (highest confidence)";
            f.suspicious = true;
            findings.push_back(f);
        } else {
            ScannerUI::TimelineCorrelationFinding f;
            f.date      = entry.date;
            f.time      = entry.time;
            f.severity  = "HIGH";
            f.path      = entry.path;
            f.reason    = "bam-no-usn";
            f.detail    = "file executed post-boot (BAM) but has no USN journal record and no longer exists — execution tracks wiped";
            f.suspicious = true;

            // Check if a log-clear event happened within 1 hour of this BAM entry
            if (!logClearedTimes.empty()) {
                std::string bamDt = entry.date + entry.time;
                for (const auto& clearDt : logClearedTimes) {
                    // Simple lexicographic proximity check on YYYY-MM-DDHH:MM:SS
                    // An exact string match of date is sufficient to flag same-day correlation
                    if (!clearDt.empty() && clearDt.substr(0, 10) == bamDt.substr(0, 10)) {
                        f.detail += " | LOG_CLEARED_NEAR_EXECUTION (EventID 1102/104 same day)";
                        break;
                    }
                }
            }

            findings.push_back(f);
        }
    }

    // Rule 2: Prefetch entries referencing DLLs that no longer exist at path
    // PrefetchHit with "Prefetch ausente no USN Journal" = disk file exists but no USN
    for (const auto& ph : prefetch) {
        if (ph.alias != "Prefetch ausente no USN Journal")
            continue;
        ScannerUI::TimelineCorrelationFinding f;
        f.date      = ph.date;
        f.time      = ph.time;
        f.severity  = "MEDIUM";
        f.path      = ph.file;
        f.reason    = "prefetch-no-usn";
        f.detail    = "prefetch file exists on disk but has no USN journal record — prefetch may have been manually placed";
        f.suspicious = true;
        findings.push_back(f);
    }

    std::sort(findings.begin(), findings.end(), [](const auto& a, const auto& b) {
        return DetectionFilter::SeverityRank(a.severity) < DetectionFilter::SeverityRank(b.severity);
    });

    status = findings.empty() ? "OK" : "DETECTED";
    return findings;
}
