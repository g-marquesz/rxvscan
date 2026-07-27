#include "scanner_core.h"

// Detectores do DeepScan entram aqui como funcoes Scan*(std::vector<ScannerUI::DeepScanFinding>&)
// e sao chamados em sequencia dentro de CollectDeepScanFindings, no mesmo padrao de
// scanner_stream_mods.cpp / scanner_generic_bypass.cpp.

// ============================================================================
// PLScan — deteccao de payload/shellcode injetado em memoria de processos.
// ============================================================================

static std::string HexAddress(uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << value;
    return oss.str();
}

static void AddDeepScanFinding(std::vector<ScannerUI::DeepScanFinding>& out,
                                const std::string& type,
                                const std::string& process, const std::string& target,
                                const std::string& detail, const std::string& severity) {
    if (out.size() >= ScanLimits::kMaxDeepScanFindings) return;
    ScannerUI::DeepScanFinding finding;
    finding.type = type;
    finding.process = process;
    finding.target = target;
    finding.detail = detail;
    finding.severity = severity;
    out.push_back(std::move(finding));
}

// Boot time cacheado (nao muda durante um scan) - usado pelo LXAScan e pelo
// HJCScan para nao reportar arquivos antigos (de antes do boot atual): um
// arquivo que ja estava la antes desta sessao ligar e um sinal bem mais fraco
// do que um tocado durante a sessao atual. Mesmo padrao "modifiedAfterBoot"
// ja usado em varios pontos do projeto (ex. scanner_files.cpp:1638).
static ULONGLONG DeepScanBootTimeU64() {
    static const ULONGLONG bootValue = FileTimeToU64(GetBootFileTime());
    return bootValue;
}

static bool IsAfterBoot(const FILETIME& fileTime) {
    return FileTimeToU64(fileTime) > DeepScanBootTimeU64();
}

static bool IsExecProtect(DWORD protect) {
    DWORD base = protect & 0xff;
    return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWriteExecProtect(DWORD protect) {
    DWORD base = protect & 0xff;
    return base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

// So regioes privadas (nao mapeadas de arquivo/modulo) e executaveis interessam ao PLScan:
// shellcode/payload injetado precisa ser executavel para rodar, e codigo legitimo de DLL
// mora em MEM_IMAGE (ja coberto por outros topicos). Isso reduz custo (pula a maior parte
// do espaco de enderecos) e ruido (heap/stack normais nunca sao PAGE_EXECUTE*).
static bool IsPrivateExecRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    return mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsExecProtect(mbi.Protect);
}

static bool IsAnonymousMappedExecRegion(HANDLE process,
                                        const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_MAPPED ||
        !IsExecProtect(mbi.Protect))
        return false;

    wchar_t mappedPath[MAX_PATH * 2] = {};
    DWORD length = GetMappedFileNameW(process, mbi.BaseAddress, mappedPath,
                                      (DWORD)std::size(mappedPath));
    return length == 0;
}

static bool IsAddrInModules(uintptr_t addr, const std::vector<ModuleRange>& modules) {
    for (const auto& m : modules)
        if (addr >= m.begin && addr < m.end)
            return true;
    return false;
}

static const ModuleRange* FindModuleContaining(uintptr_t addr, const std::vector<ModuleRange>& modules) {
    for (const auto& m : modules)
        if (addr >= m.begin && addr < m.end)
            return &m;
    return nullptr;
}

namespace {

struct BytePattern {
    const char* name;
    std::vector<int> bytes; // -1 = wildcard byte
    // Padroes "fracos" aparecem em codigo legitimo compilado/JIT (cookie de
    // stack /GS, acesso a TLS, exception handling, engines JIT V8/CLR/HotSpot,
    // runtimes .NET NativeAOT/Rust com syscall direto) - sozinhos (sem string
    // corroborando) so devem contar quando a regiao tem entropia de codigo.
    bool weak = false;
};

const std::vector<BytePattern>& ShellcodePatterns() {
    static const std::vector<BytePattern> patterns = {
        {"PEB access (fs:[0x30], mov eax)",  {0x64, 0xA1, 0x30, 0x00, 0x00, 0x00}, true},
        {"PEB access (fs:[0x30], mov ecx)",  {0x64, 0x8B, 0x0D, 0x30, 0x00, 0x00, 0x00}, true},
        {"PEB access (gs:[0x60], x64)",      {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}, true},
        {"Egghunter (NtDisplayString tag)",  {0x66, 0x81, 0xCA, 0xFF, 0x0F}, false},
        {"Direct syscall stub (mov r10,rcx;mov eax,imm)", {0x4C, 0x8B, 0xD1, 0xB8, -1, -1, 0x00, 0x00}, true},
    };
    return patterns;
}

struct StringNeedle {
    const char* text;
};

// Marcadores de alto sinal: qualquer ocorrencia isolada ja e suspeita o bastante.
const std::vector<StringNeedle>& HighSignalStrings() {
    static const std::vector<StringNeedle> needles = {
        {"WinExec"}, {"ShellExecuteA"}, {"ShellExecuteW"},
        {"VirtualAllocEx"}, {"WriteProcessMemory"},
        {"CreateRemoteThread"}, {"NtCreateThreadEx"},
        {"cmd.exe /c"},
        {"Cobalt Strike"}, {"meterpreter"}, {"donut"},
    };
    return needles;
}

} // namespace

static bool ContainsAscii(const unsigned char* data, size_t len, const char* needle) {
    size_t nlen = std::strlen(needle);
    if (nlen == 0 || nlen > len) return false;
    const unsigned char* nbeg = reinterpret_cast<const unsigned char*>(needle);
    return std::search(data, data + len, nbeg, nbeg + nlen) != data + len;
}

// Busca por padroes de bytes de shellcode conhecidos. A comparacao usa
// `i + pattern.size() <= len` (soma) em vez de `i <= len - pattern.size()` (subtracao)
// para nao estourar quando len < pattern.size() (size_t e sem sinal).
static bool ScanBytePatterns(const unsigned char* data, size_t len, std::string& matchedName, bool& matchedWeak) {
    for (const auto& pattern : ShellcodePatterns()) {
        size_t plen = pattern.bytes.size();
        if (plen == 0 || plen > len) continue;
        for (size_t i = 0; i + plen <= len; ++i) {
            bool match = true;
            for (size_t j = 0; j < plen; ++j) {
                int want = pattern.bytes[j];
                if (want >= 0 && data[i + j] != static_cast<unsigned char>(want)) {
                    match = false;
                    break;
                }
            }
            if (match) {
                matchedName = pattern.name;
                matchedWeak = pattern.weak;
                return true;
            }
        }
    }
    return false;
}

// Strings fracas ("payload", "execute", "run") geram falso positivo em quase qualquer
// binario. Em vez disso: marcadores de alto sinal isolados, ou pares que so fazem sentido
// juntos (LoadLibrary+GetProcAddress = resolucao dinamica de API; powershell+-enc = comando
// codificado em base64, tecnica classica de stager).
static bool ScanStrings(const unsigned char* data, size_t len, std::string& matchedName) {
    for (const auto& needle : HighSignalStrings()) {
        if (ContainsAscii(data, len, needle.text)) {
            matchedName = needle.text;
            return true;
        }
    }

    bool hasLoadLibrary = ContainsAscii(data, len, "LoadLibraryA") ||
                          ContainsAscii(data, len, "LoadLibraryW");
    bool hasGetProcAddress = ContainsAscii(data, len, "GetProcAddress");
    if (hasLoadLibrary && hasGetProcAddress) {
        matchedName = "LoadLibrary + GetProcAddress (resolucao dinamica de API)";
        return true;
    }

    bool hasPowershell = ContainsAscii(data, len, "powershell");
    bool hasEncodedCmd = ContainsAscii(data, len, "-enc") ||
                          ContainsAscii(data, len, "-EncodedCommand");
    if (hasPowershell && hasEncodedCmd) {
        matchedName = "powershell -enc (comando codificado)";
        return true;
    }

    return false;
}

// Uma passada por ciclo de scan (chamada de CollectDeepScanFindings, disparada pelo
// scanner_runner.cpp) — sem thread/loop proprio. Enumera processos, restringe a varredura
// a regioes privadas executaveis (onde shellcode injetado precisa viver para rodar) e
// classifica em cascata: PE header reflectivo > entropia (pega payload empacotado/cifrado
// que assinatura estatica nunca pegaria) > assinaturas de bytes/strings.
//
// Sem filtro de "arquivo antigo antes do boot" (diferente do LXAScan/HJCScan):
// nao ha arquivo em disco aqui, so memoria de processos VIVOS agora - um
// processo nao sobrevive a um reboot, entao todo processo enumerado abaixo
// ja e, por definicao, posterior ao boot atual. Nao existe achado "antigo"
// pra excluir.
static void ScanInjectedPayloads(std::vector<ScannerUI::DeepScanFinding>& out) {
    DWORD ownPid = GetCurrentProcessId();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    size_t paceCounter = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;

            DWORD pid = entry.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == ownPid) continue;

            // Sem gate por pasta/assinatura do processo hospedeiro: a assinatura do
            // CONTAINER nao valida o que foi injetado dentro dele (payload injetado
            // nao tem e nao pode ter assinatura propria), e "esta em Program Files"
            // e 100% controlavel pelo atacante. Mesma razao pela qual HJCScan/TRHScan
            // ja nao pulam processo algum - atacante injeta de proposito em processos
            // confiaveis pra se esconder. A discriminacao de falso-positivo fica
            // inteiramente por conteudo via ClassifyExecRegion (entropia/tamanho) abaixo.
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process) continue;

            std::vector<ModuleRange> modules;
            if (!CollectProcessModules(process, modules)) {
                CloseHandle(process);
                continue;
            }

            std::string procName = WideToUtf8(entry.szExeFile) + " [" + std::to_string(pid) + "]";

            // Cap por processo: um unico processo ruidoso (muitas regioes
            // legitimas que escapam do ClassifyExecRegion) nao pode consumir
            // sozinho todo o orcamento global de achados antes de outros
            // processos serem sequer olhados. Nao depende de identidade do
            // processo - aplica-se igualmente a qualquer um.
            constexpr size_t kMaxFindingsPerProcess = 8;
            const size_t outSizeAtProcessStart = out.size();

            uintptr_t maxModuleEnd = 0;
            for (const auto& m : modules)
                if (m.end > maxModuleEnd) maxModuleEnd = m.end;
            constexpr uintptr_t kMinScan  = 2ULL * 1024 * 1024 * 1024;  // 2 GB floor
            constexpr uintptr_t kHeadroom = 512ULL * 1024 * 1024;       // 512 MB acima dos modulos
            const uintptr_t kScanLimit = (maxModuleEnd + kHeadroom > kMinScan)
                                          ? (maxModuleEnd + kHeadroom) : kMinScan;

            constexpr size_t kMaxRegionRead = 256 * 1024; // cap por regiao (o exemplo original lia RegionSize inteiro, sem limite)
            constexpr size_t kChunk = 64 * 1024;

            uintptr_t address = 0;
            MEMORY_BASIC_INFORMATION mbi = {};
            std::unordered_set<uintptr_t> seenAllocBases;

            while (address < kScanLimit &&
                   VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                MaybePaceIteration(paceCounter, 6);

                uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                uintptr_t end = base + mbi.RegionSize;
                if (end <= address) break; // regiao invalida/zerada: nao trava o laco

                if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;
                if (out.size() - outSizeAtProcessStart >= kMaxFindingsPerProcess) break;

                const bool privateExec = IsPrivateExecRegion(mbi);
                const bool anonymousMappedExec = IsAnonymousMappedExecRegion(process, mbi);
                if ((!privateExec && !anonymousMappedExec) || IsAddrInModules(base, modules)) {
                    address = end;
                    continue;
                }

                uintptr_t allocBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
                if (mbi.AllocationBase && !seenAllocBases.insert(allocBase).second) {
                    address = end; // ja processamos esta alocacao (regiao vizinha da mesma reserva)
                    continue;
                }

                size_t toRead = static_cast<size_t>(mbi.RegionSize) < kMaxRegionRead
                                 ? static_cast<size_t>(mbi.RegionSize) : kMaxRegionRead;
                std::vector<unsigned char> buf(toRead);
                size_t got = 0;
                for (size_t off = 0; off < toRead; off += kChunk) {
                    size_t chunkLen = (std::min)(kChunk, toRead - off);
                    SIZE_T chunkGot = 0;
                    if (!ReadProcessMemory(process, reinterpret_cast<const BYTE*>(mbi.BaseAddress) + off,
                                            buf.data() + off, chunkLen, &chunkGot))
                        break;
                    got += chunkGot;
                    if (chunkGot < chunkLen) break; // leitura parcial: nao escaneia alem do que foi lido de fato
                }
                if (got == 0) {
                    address = end;
                    continue;
                }

                std::string addrHex = HexAddress(base);

                bool hasPe = DetectionFilter::HasPEHeader(process, mbi.BaseAddress);
                if (hasPe) {
                    AddDeepScanFinding(out, "PLSCAN", procName, addrHex,
                        anonymousMappedExec
                            ? "PE header em memoria mapeada anonima executavel (DLL reflective/manual-mapped)"
                            : "PE header em memoria privada executavel (DLL reflective/manual-mapped)",
                        "HIGH");
                    address = end;
                    continue;
                }

                double entropy = DetectionFilter::ShannonEntropy(buf.data(), got);
                bool writeExec = IsWriteExecProtect(mbi.Protect);
                DetectionFilter::RegionVerdict verdict = DetectionFilter::ClassifyExecRegion(
                    writeExec, static_cast<size_t>(mbi.RegionSize), entropy,
                    /*privateMem*/ true, /*hasPeHeader*/ false);
                if (verdict.keep) {
                    AddDeepScanFinding(out, "PLSCAN", procName, addrHex, verdict.note, verdict.severity);
                    address = end;
                    continue;
                }

                std::string patternName;
                std::string stringName;
                bool patternWeak = false;
                bool patternHit = ScanBytePatterns(buf.data(), got, patternName, patternWeak);
                bool stringHit = ScanStrings(buf.data(), got, stringName);

                bool codeLike = entropy >= DetectionFilter::kCodeLow && entropy <= DetectionFilter::kCodeHigh;
                // Padrao fraco sozinho (sem string corroborando) so conta se a
                // regiao tiver entropia de codigo E tamanho razoavel (>= 4KB,
                // uma pagina) - caso contrario e mais provavel coincidencia de
                // bytes numa regiao que nao parece codigo de verdade, ou um
                // trampolim minusculo tipo Detours (o unico jeito de uma
                // regiao pequena chegar aqui e via o descarte de "RWX pequeno
                // sem entropia de codigo" do ClassifyExecRegion), do que um
                // sinal real de shellcode.
                if (patternHit && patternWeak && !stringHit && (!codeLike || got < 4096))
                    patternHit = false;

                if (patternHit && stringHit) {
                    AddDeepScanFinding(out, "PLSCAN", procName, addrHex,
                        "Padrao de shellcode (" + patternName + ") + string suspeita (" + stringName + ")",
                        "HIGH");
                } else if (patternHit || stringHit) {
                    // Sinal isolado numa regiao de baixa entropia (nao parece
                    // codigo) e mais fraco ainda - rebaixa um degrau em vez de
                    // descartar, mantendo visibilidade sem inflar severidade.
                    std::string severity = (entropy >= 0.0 && entropy < DetectionFilter::kCodeLow)
                        ? "FLAG" : "MEDIUM";
                    if (patternHit) {
                        AddDeepScanFinding(out, "PLSCAN", procName, addrHex,
                            "Padrao de shellcode: " + patternName, severity);
                    } else {
                        AddDeepScanFinding(out, "PLSCAN", procName, addrHex,
                            "String suspeita em memoria executavel: " + stringName, severity);
                    }
                }

                address = end;
            }

            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

// ============================================================================
// HJCScan — deteccao de DLL hijacking (search-order/sideloading) e API
// hooking em modulos legitimamente carregados.
//
// Nao reimplementa deteccao de "reflective loader": um modulo obtido via
// CollectProcessModules/EnumProcessModules ja esta registrado no loader do
// Windows e por definicao sempre comeca com um header PE valido — reflective
// loading de verdade nunca aparece nessa lista (o proprio nome da tecnica vem
// de nao se registrar no loader). Quem cobre isso de verdade e o branch
// HasPEHeader em memoria privada do PLScan (acima); adulteracao de um modulo
// ja carregado (checksum disco vs. memoria) ja e coberta por
// ScanLoadedModuleAnomalies em scanner_processes.cpp. Portar aqui uma
// checagem de "o modulo comeca com MZ/PE" seria ruido puro (dispara em 100%
// dos modulos carregados) ou duplicacao do que ja existe.
// ============================================================================

namespace {

// DLLs classicas usadas como alvo de search-order hijacking / DLL planting —
// arquivos do Windows que nunca sao legitimamente redistribuidos ao lado de
// um executavel de terceiros (lista pode crescer).
const wchar_t* const kHijackableDlls[] = {
    L"VERSION.DLL", L"DWMAPI.DLL", L"UXTHEME.DLL", L"CRYPTBASE.DLL",
    L"PROPSYS.DLL", L"UALAPI.DLL", L"PROFAPI.DLL", L"SECUR32.DLL",
    L"WTSAPI32.DLL", L"WINMM.DLL", L"DBGHELP.DLL", L"WININET.DLL",
    L"URLMON.DLL", L"USERENV.DLL", L"NETAPI32.DLL", L"IPHLPAPI.DLL",
    L"DNSAPI.DLL", L"WINSPOOL.DRV",
    nullptr
};

bool MatchesHijackableList(const std::wstring& upperName) {
    for (int i = 0; kHijackableDlls[i]; ++i)
        if (upperName == kHijackableDlls[i])
            return true;
    return false;
}

struct HookApiTarget {
    const wchar_t* moduleName;
    const char* apiName;
};

// Alvos classicos de API hooking (do exemplo original) — sempre resolvidos
// contra kernel32/kernelbase/user32/ntdll, nunca DLLs de terceiros.
const HookApiTarget kHookTargets[] = {
    {L"kernel32.dll", "CreateProcessA"},
    {L"kernel32.dll", "CreateProcessW"},
    {L"kernel32.dll", "LoadLibraryA"},
    {L"kernel32.dll", "LoadLibraryW"},
    {L"kernel32.dll", "GetProcAddress"},
    {L"user32.dll",   "SetWindowsHookExA"},
    {L"user32.dll",   "SetWindowsHookExW"},
};

const wchar_t* const kHookCandidateModules[] = {
    L"KERNEL32.DLL", L"KERNELBASE.DLL", L"USER32.DLL", L"NTDLL.DLL", nullptr
};

} // namespace

// Normaliza via GetFinalPathNameByHandleW antes de comparar - fecha a via de
// disfarce por truque de path do NTFS (espaco/ponto no final de um nome de
// pasta, nome curto 8.3) que pode fazer um caminho PARECER System32 sem ser,
// deixando um sideload passar como "sistema" e ser ignorado por engano.
static bool HjcIsSystemPath(const std::wstring& path) {
    const auto& r = DetectionFilter::Roots();

    std::wstring normalized = path;
    HANDLE hFile = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        wchar_t buf[MAX_PATH * 2] = {};
        DWORD len = GetFinalPathNameByHandleW(hFile, buf, (DWORD)std::size(buf), FILE_NAME_NORMALIZED);
        CloseHandle(hFile);
        if (len > 0 && len < std::size(buf)) {
            std::wstring norm = buf;
            if (norm.rfind(L"\\\\?\\", 0) == 0) norm = norm.substr(4); // remove o prefixo de path estendido
            normalized = norm;
        }
    }

    std::wstring up = DetectionFilter::UpperW(normalized);
    return DetectionFilter::PathIsUnder(up, r.system32) ||
           DetectionFilter::PathIsUnder(up, r.syswow64) ||
           DetectionFilter::PathIsUnder(up, r.winsxs);
}

// Reaproveita DetectionFilter::AnalyzeEfiPe (parser PE generico apesar do
// nome - funciona em qualquer arquivo PE, nao so .efi) + CheckPeChecksumMismatch
// pra detectar arquivo alterado depois de compilado/assinado - sinal de
// integridade que nenhuma pasta ou nome consegue disfarçar.
static bool HjcHasChecksumMismatch(const std::wstring& path) {
    DetectionFilter::EfiPeInfo info = DetectionFilter::AnalyzeEfiPe(path);
    if (!info.valid || info.storedChecksum == 0) return false;
    return DetectionFilter::CheckPeChecksumMismatch(path, info.storedChecksum);
}

// Entropia do arquivo (nao da memoria carregada) de uma DLL - mesmo estilo de
// leitura capada ja usado em EhkReadPeSections, para reusar ShannonEntropy
// como corroboracao do tier "nao assinado": uma DLL nao assinada de baixa
// entropia (utilitario antigo comum) e sinal mais fraco do que uma nao
// assinada E empacotada/ofuscada. Retorna -1.0 em caso de falha de leitura.
static double HjcFileEntropy(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return -1.0;

    LARGE_INTEGER size64 = {};
    if (!GetFileSizeEx(hFile, &size64) || size64.QuadPart <= 0) {
        CloseHandle(hFile);
        return -1.0;
    }
    constexpr DWORD kMaxRead = 4 * 1024 * 1024;
    DWORD toRead = size64.QuadPart < (LONGLONG)kMaxRead ? (DWORD)size64.QuadPart : kMaxRead;

    std::vector<BYTE> buf(toRead);
    DWORD got = 0;
    bool ok = ReadFile(hFile, buf.data(), toRead, &got, nullptr) && got > 0;
    CloseHandle(hFile);
    if (!ok) return -1.0;

    return DetectionFilter::ShannonEntropy(buf.data(), got);
}

// So considera uma DLL se o arquivo foi tocado durante a sessao atual
// (pos-boot) - uma DLL classica de sideloading que ja estava la antes desta
// sessao ligar e um sinal bem mais fraco (ou completamente irrelevante para
// uma ameaca ativa) do que uma escrita/plantada recentemente.
static bool HjcFileIsAfterBoot(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return true; // nao foi possivel checar - nao descarta por causa disso
    return IsAfterBoot(fad.ftLastWriteTime);
}

// Sub-detector A: DLL search-order hijacking / sideloading. Reaproveita a
// mesma cascata de decisao ja validada em producao por
// ScanDuplicateGraphicsModules (scanner_generic_bypass.cpp), generalizada
// para todos os processos e uma lista de DLLs classicas de sideloading
// (nao-graficas). Sem gate de "processo confiavel": hijacking existe
// justamente para atacar hosts assinados/confiaveis.
static void ScanDllSideloading(const std::string& procName,
                                const std::wstring& exePathW, const std::wstring& exeDir,
                                const std::vector<ModuleRange>& modules,
                                std::vector<ScannerUI::DeepScanFinding>& out) {
    std::unordered_map<std::wstring, std::vector<const ModuleRange*>> byName;
    for (const auto& m : modules) {
        if (m.path.empty()) continue;
        std::wstring upName = DetectionFilter::UpperW(BaseNameFromPath(m.path));
        byName[upName].push_back(&m);
    }

    for (const auto& kv : byName) {
        if (out.size() >= ScanLimits::kMaxDeepScanFindings) return;
        if (!MatchesHijackableList(kv.first)) continue;

        const ModuleRange* m = kv.second.front();
        if (HjcIsSystemPath(m->path)) continue;
        if (!HjcFileIsAfterBoot(m->path)) continue; // arquivo antigo (de antes do boot atual) - ignora

        bool sideBySide = !exeDir.empty() &&
            DetectionFilter::PathIsUnder(DetectionFilter::UpperW(m->path), DetectionFilter::UpperW(exeDir));
        bool signedMod = DetectionFilter::IsTrustedSignedCached(m->path);
        bool samePub   = signedMod && DetectionFilter::SamePublisherTrusted(m->path, exePathW);

        if (samePub) continue; // DLL legitimamente distribuida pelo mesmo publisher do host

        // Severidade nunca depende de pasta/nome - so de conteudo (entropia,
        // integridade do PE) e assinatura (propriedade criptografica do
        // proprio arquivo, mantida como sinal por decisao explicita, ao
        // contrario de "esta em Program Files" que o atacante controla de graca).
        double fileEntropy = HjcFileEntropy(m->path);
        bool packedLike = fileEntropy >= DetectionFilter::kCodeHigh;
        bool tampered = HjcHasChecksumMismatch(m->path);
        // A signed DLL from another publisher is not enough to prove a hijack:
        // applications commonly ship signed runtimes beside their executable.
        // Keep it only when the file also has a concrete integrity signal.
        if (signedMod && !tampered)
            continue;
        if (!sideBySide && !packedLike && !tampered)
            continue;

        std::string severity;
        if (packedLike || tampered) {
            severity = "HIGH"; // empacotada/adulterada - nenhuma assinatura muda isso
        } else {
            severity = sideBySide ? "MEDIUM" : "FLAG";
        }

        std::string entropyNote = fileEntropy >= 0.0
            ? " | entropia=" + DetectionFilter::EntropyToStr(fileEntropy) : "";
        std::string tamperNote = tampered
            ? " | checksum PE nao bate (alterado apos compilacao/assinatura)" : "";

        std::string detail = "DLL classica de sideloading fora do System32/SysWOW64/WinSxS: " +
                             WideToUtf8(kv.first) +
                             " | path=" + WideToUtf8(m->path) +
                             " | signed=" + (signedMod ? "yes" : "no") +
                             (sideBySide ? " | lado-a-lado com o exe" : "") +
                             entropyNote + tamperNote;
        AddDeepScanFinding(out, "HJCSCAN", procName, WideToUtf8(m->path), detail, severity);
    }

    // DLL da lista presente no diretorio do exe mas ainda nao carregada — hijack preparado/staged.
    if (!exeDir.empty()) {
        for (int i = 0; kHijackableDlls[i]; ++i) {
            if (out.size() >= ScanLimits::kMaxDeepScanFindings) return;
            std::wstring candidate = exeDir + L"\\" + kHijackableDlls[i];
            if (!FileExistsW(candidate)) continue;
            if (!HjcFileIsAfterBoot(candidate)) continue; // arquivo antigo (de antes do boot atual) - ignora

            auto it = byName.find(kHijackableDlls[i]);
            if (it != byName.end()) {
                bool already = false;
                for (const auto* m : it->second) {
                    if (DetectionFilter::UpperW(m->path) == DetectionFilter::UpperW(candidate)) {
                        already = true;
                        break;
                    }
                }
                if (already) continue;
            }

            bool signedFile = DetectionFilter::IsTrustedSignedCached(candidate);
            bool samePub    = signedFile && DetectionFilter::SamePublisherTrusted(candidate, exePathW);
            if (samePub) continue;

            bool tampered = HjcHasChecksumMismatch(candidate);
            if (signedFile && !tampered)
                continue;

            std::string severity;
            std::string entropyNote;
            if (!signedFile) {
                double fileEntropy = HjcFileEntropy(candidate);
                bool packedLike = fileEntropy >= DetectionFilter::kCodeHigh;
                severity = packedLike ? "HIGH" : "MEDIUM";
                if (fileEntropy >= 0.0)
                    entropyNote = " | entropia=" + DetectionFilter::EntropyToStr(fileEntropy);
            } else {
                severity = "HIGH";
                entropyNote = " | checksum PE nao bate (alterado apos compilacao/assinatura)";
            }

            std::string detail = "arquivo classico de sideloading lado-a-lado com o exe (hijack preparado): " +
                                 WideToUtf8(kHijackableDlls[i]) +
                                 " | path=" + WideToUtf8(candidate) +
                                 " | signed=" + (signedFile ? "yes" : "no") +
                                 entropyNote;
            AddDeepScanFinding(out, "HJCSCAN", procName, WideToUtf8(candidate), detail, severity);
        }
    }
}

// Resolve o endereco local (no proprio processo do scanner) de uma API alvo e
// o offset a partir da base do modulo que REALMENTE a contem. Necessario
// porque varios exports de kernel32.dll sao forwarders para kernelbase.dll
// desde o Windows 7 — GetProcAddress segue o forwarder e retorna um endereco
// dentro de kernelbase.dll, nao de kernel32.dll. O offset base->export e fixo
// pelo layout do arquivo e independe de ASLR (que randomiza so a base).
static bool ResolveLocalExportOffset(const wchar_t* moduleName, const char* apiName,
                                      std::wstring& containingModuleUpperName,
                                      uintptr_t& offset, size_t& moduleSizeOfImage) {
    HMODULE hMod = GetModuleHandleW(moduleName);
    if (!hMod) return false;
    FARPROC proc = GetProcAddress(hMod, apiName);
    if (!proc) return false;
    uintptr_t procAddr = reinterpret_cast<uintptr_t>(proc);

    for (int i = 0; kHookCandidateModules[i]; ++i) {
        HMODULE hCandidate = GetModuleHandleW(kHookCandidateModules[i]);
        if (!hCandidate) continue;
        MODULEINFO info = {};
        if (!GetModuleInformation(GetCurrentProcess(), hCandidate, &info, sizeof(info)))
            continue;
        uintptr_t base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
        uintptr_t end = base + info.SizeOfImage;
        if (procAddr >= base && procAddr < end) {
            containingModuleUpperName = kHookCandidateModules[i];
            offset = procAddr - base;
            moduleSizeOfImage = info.SizeOfImage;
            return true;
        }
    }
    return false; // endereco fora de todos os candidatos: nao arrisca
}

// Sub-detector B: API hooking em exports criticos de kernel32/kernelbase/
// user32/ntdll. Traduz o endereco local (resolvido via GetProcAddress) para
// o processo remoto usando o mesmo offset relativo a base do modulo — valido
// porque esses arquivos sao identicos byte-a-byte entre processos na mesma
// maquina/build. Escopo estrito a esses 4 modulos: para DLLs de terceiros a
// premissa de arquivo identico local/remoto nao vale.
static void ScanApiHooking(HANDLE process, const std::string& procName,
                            const std::vector<ModuleRange>& modules,
                            std::vector<ScannerUI::DeepScanFinding>& out) {
    size_t hookedApiCount = 0;
    size_t suspiciousHookCount = 0;

    for (const auto& target : kHookTargets) {
        if (out.size() >= ScanLimits::kMaxDeepScanFindings) return;

        std::wstring containingModule;
        uintptr_t offset = 0;
        size_t localSize = 0;
        if (!ResolveLocalExportOffset(target.moduleName, target.apiName, containingModule, offset, localSize))
            continue;

        const ModuleRange* remoteModule = nullptr;
        for (const auto& m : modules) {
            if (m.path.empty()) continue;
            if (DetectionFilter::UpperW(BaseNameFromPath(m.path)) == containingModule) {
                remoteModule = &m;
                break;
            }
        }
        if (!remoteModule) continue;

        // Build diferente no alvo (ex.: WOW64) teria layout diferente — offset
        // local nao seria valido ali. Descarta em vez de arriscar um veredito errado.
        size_t remoteSize = static_cast<size_t>(remoteModule->end - remoteModule->begin);
        if (remoteSize != localSize) continue;

        uintptr_t remoteFuncAddr = remoteModule->begin + offset;

        unsigned char prologue[16] = {};
        SIZE_T got = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(remoteFuncAddr), prologue, sizeof(prologue), &got) ||
            got < 6)
            continue;

        uintptr_t hookTarget = 0;
        if (prologue[0] == 0xE9) { // JMP rel32
            INT32 rel = 0;
            memcpy(&rel, prologue + 1, sizeof(rel));
            hookTarget = remoteFuncAddr + 5 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
        } else if (prologue[0] == 0xEB && got >= 2) { // JMP rel8
            const INT8 rel = static_cast<INT8>(prologue[1]);
            hookTarget = remoteFuncAddr + 2 + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
        } else if (prologue[0] == 0xFF && prologue[1] == 0x25 && got >= 6) { // JMP [rip+disp32], x64
            INT32 disp = 0;
            memcpy(&disp, prologue + 2, sizeof(disp));
            uintptr_t slot = remoteFuncAddr + 6 + static_cast<uintptr_t>(static_cast<intptr_t>(disp));
            uintptr_t indirectTarget = 0;
            SIZE_T got2 = 0;
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(slot), &indirectTarget, sizeof(indirectTarget), &got2) ||
                got2 < sizeof(indirectTarget))
                continue;
            hookTarget = indirectTarget;
        } else if (got >= 12 && prologue[0] == 0x48 && prologue[1] == 0xB8 &&
                   prologue[10] == 0xFF && prologue[11] == 0xE0) { // MOV RAX,imm64; JMP RAX
            memcpy(&hookTarget, prologue + 2, sizeof(hookTarget));
        } else if (got >= 13 && prologue[0] == 0x49 && prologue[1] == 0xBB &&
                   prologue[10] == 0x41 && prologue[11] == 0xFF && prologue[12] == 0xE3) { // MOV R11,imm64; JMP R11
            memcpy(&hookTarget, prologue + 2, sizeof(hookTarget));
        } else if (got >= 6 && prologue[0] == 0x68 && prologue[5] == 0xC3) { // PUSH imm32; RET
            DWORD target32 = 0;
            memcpy(&target32, prologue + 1, sizeof(target32));
            hookTarget = target32;
        } else if (got >= 7 && prologue[0] == 0xB8 &&
                   prologue[5] == 0xFF && prologue[6] == 0xE0) { // MOV EAX,imm32; JMP EAX
            DWORD target32 = 0;
            memcpy(&target32, prologue + 1, sizeof(target32));
            hookTarget = target32;
        } else {
            continue; // sem prologo de jmp/call: funcao nao hookeada
        }

        if (hookTarget == 0)
            continue;

        ++hookedApiCount;

        const ModuleRange* targetModule = FindModuleContaining(hookTarget, modules);
        std::string detail = "Export " + std::string(target.apiName) + " de " + WideToUtf8(containingModule) +
                             " redirecionado para " + HexAddress(hookTarget);
        std::string severity;

        if (targetModule) {
            // Hook redirecionando para dentro de um modulo assinado/confiavel
            // (ex.: a propria DLL de um EDR/AV hookando sua propria API) e um
            // sinal bem mais fraco do que redirecionar para um modulo
            // desconhecido/nao assinado.
            bool targetSigned = DetectionFilter::IsTrustedSignedCached(targetModule->path);
            severity = targetSigned ? "FLAG" : "MEDIUM";
            if (!targetSigned)
                ++suspiciousHookCount;
            detail += " (dentro de " + WideToUtf8(BaseNameFromPath(targetModule->path)) +
                      ", assinado=" + (targetSigned ? "yes" : "no") + ")";
        } else {
            // Fora de qualquer modulo: pode ser um stub de shellcode real, mas
            // tambem e exatamente o perfil de um trampolim Detours legitimo
            // (EDR/AV, overlay de jogo/captura, RTSS, etc.). Usa tamanho da
            // regiao + entropia para diferenciar: trampolim pequeno e nao
            // empacotado fica MEDIUM; regiao grande ou com entropia de
            // packer/shellcode mantem HIGH.
            MEMORY_BASIC_INFORMATION targetMbi = {};
            bool smallCleanTrampoline = false;
            if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(hookTarget), &targetMbi, sizeof(targetMbi)) == sizeof(targetMbi) &&
                targetMbi.State == MEM_COMMIT && targetMbi.RegionSize <= 4096) {
                constexpr size_t kSampleSize = 512;
                unsigned char sample[kSampleSize] = {};
                SIZE_T sampleGot = 0;
                size_t toRead = (std::min)((size_t)targetMbi.RegionSize, kSampleSize);
                if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(hookTarget), sample, toRead, &sampleGot) &&
                    sampleGot > 0) {
                    double targetEntropy = DetectionFilter::ShannonEntropy(sample, sampleGot);
                    if (targetEntropy < DetectionFilter::kPackedEntropy)
                        smallCleanTrampoline = true;
                }
            }
            severity = smallCleanTrampoline ? "MEDIUM" : "HIGH";
            if (!smallCleanTrampoline)
                ++suspiciousHookCount;
            detail += smallCleanTrampoline
                ? " (memoria privada, trampolim pequeno nao empacotado - possivel hook legitimo tipo Detours)"
                : " (memoria privada/desconhecida)";
        }

        AddDeepScanFinding(out, "HJCSCAN", procName, target.apiName, detail, severity);
    }

    // Hooks de EDR/AV frequentemente cobrem varias APIs, mas terminam em um
    // modulo assinado. So agrega HIGH quando pelo menos dois destinos sao
    // realmente nao confiaveis/privados; quantidade isolada nao e evidencia.
    if (suspiciousHookCount >= 2) {
        AddDeepScanFinding(out, "HJCSCAN", procName, "multiple-apis",
            std::to_string(hookedApiCount) + " exports redirecionados; " +
            std::to_string(suspiciousHookCount) +
            " destinos nao assinados ou em memoria privada", "HIGH");
    }
}

// Uma passada por ciclo de scan, mesmo esqueleto de ScanInjectedPayloads
// (Toolhelp32Snapshot, fallback de dois niveis no OpenProcess,
// CollectProcessModules) — mas SEM o gate de "processo confiavel" do PLScan:
// DLL hijacking e API hooking existem justamente para atacar processos
// assinados/confiaveis e herdar sua confianca.
static void ScanDllHijacking(std::vector<ScannerUI::DeepScanFinding>& out) {
    DWORD ownPid = GetCurrentProcessId();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    size_t paceCounter = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;

            DWORD pid = entry.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == ownPid) continue;

            MaybePaceIteration(paceCounter, 4);

            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process) continue;

            std::vector<ModuleRange> modules;
            if (!CollectProcessModules(process, modules)) {
                CloseHandle(process);
                continue;
            }

            std::string procName = WideToUtf8(entry.szExeFile) + " [" + std::to_string(pid) + "]";
            std::wstring exePathW = ProcessFullPathW(pid);
            std::wstring exeDir = ProcessImageDirW(process);

            ScanDllSideloading(procName, exePathW, exeDir, modules, out);
            ScanApiHooking(process, procName, modules, out);

            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

// ============================================================================
// EHKScan — hooks em secoes PE de bootloaders EFI, assinatura/hash e baseline
// de PCR do TPM 2.0.
// ============================================================================

// Helpers locais (mirror de scanner_platform.cpp - static/arquivo local,
// mesma convencao ja usada no PLScan/HJCScan: nao compartilhado via header).
static uint16_t EhkReadBe16(const BYTE* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t EhkReadBe32(const BYTE* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void EhkWriteBe32(BYTE* p, uint32_t value) {
    p[0] = (BYTE)(value >> 24);
    p[1] = (BYTE)(value >> 16);
    p[2] = (BYTE)(value >> 8);
    p[3] = (BYTE)value;
}

static void EhkAppendBe16(std::vector<BYTE>& out, uint16_t value) {
    out.push_back((BYTE)(value >> 8));
    out.push_back((BYTE)value);
}

static void EhkAppendBe32(std::vector<BYTE>& out, uint32_t value) {
    out.push_back((BYTE)(value >> 24));
    out.push_back((BYTE)(value >> 16));
    out.push_back((BYTE)(value >> 8));
    out.push_back((BYTE)value);
}

static std::string EhkBytesToHex(const BYTE* data, size_t size) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

static bool EhkSha256Hex(const BYTE* data, size_t size, std::string& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD cbData = 0;
    std::vector<BYTE> object;
    std::array<BYTE, 32> digest = {};

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;

    bool ok = false;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                          sizeof(objectSize), &cbData, 0) == 0) {
        object.resize(objectSize);
        if (BCryptCreateHash(alg, &hash, object.data(), objectSize, nullptr, 0, 0) == 0) {
            if (BCryptHashData(hash, const_cast<PUCHAR>(data), (ULONG)size, 0) == 0 &&
                BCryptFinishHash(hash, digest.data(), (ULONG)digest.size(), 0) == 0) {
                out = EhkBytesToHex(digest.data(), digest.size());
                ok = true;
            }
        }
    }

    if (hash)
        BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

struct EhkPeSection {
    std::string name;
    uint32_t va = 0, vsize = 0, ptrRaw = 0, sizeRaw = 0, characteristics = 0;
};

// Le o arquivo inteiro (cap ~8MB) e faz parsing manual do header DOS/PE/tabela
// de secoes - mesmo layout ja usado e validado em ScanNtdllStubIntegrity
// (scanner_generic_bypass.cpp) e em DetectionFilter::AnalyzeEfiPe: peOffset em
// 0x3C, numSec em peOff+6, optSize em peOff+20, tabela de secoes em
// peOff+24+optSize, entradas de 40 bytes. AnalyzeEfiPe nao expoe os bytes das
// secoes ao chamador (so flags resumo) - por isso este leitor proprio.
static bool EhkReadPeSections(const std::wstring& path, std::vector<BYTE>& fileBytes,
                               std::vector<EhkPeSection>& sections, uint32_t& entryRVA) {
    entryRVA = 0;
    sections.clear();
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size64 = {};
    if (!GetFileSizeEx(hFile, &size64) || size64.QuadPart <= 0) {
        CloseHandle(hFile);
        return false;
    }
    constexpr DWORD kMaxRead = 8 * 1024 * 1024;
    DWORD toRead = size64.QuadPart < (LONGLONG)kMaxRead ? (DWORD)size64.QuadPart : kMaxRead;

    fileBytes.assign(toRead, 0);
    DWORD got = 0;
    bool ok = ReadFile(hFile, fileBytes.data(), toRead, &got, nullptr) && got > 0;
    CloseHandle(hFile);
    if (!ok) return false;
    fileBytes.resize(got);

    const BYTE* buf = fileBytes.data();
    if (got < 0x40 || buf[0] != 'M' || buf[1] != 'Z') return false;

    LONG peOff = *reinterpret_cast<const LONG*>(buf + 0x3C);
    if (peOff <= 0 || (DWORD)peOff + 24 > got) return false;
    if (buf[peOff] != 'P' || buf[peOff + 1] != 'E' || buf[peOff + 2] || buf[peOff + 3]) return false;

    uint16_t numSec  = *reinterpret_cast<const uint16_t*>(buf + peOff + 6);
    uint16_t optSize = *reinterpret_cast<const uint16_t*>(buf + peOff + 20);
    if ((DWORD)peOff + 44 <= got)
        entryRVA = *reinterpret_cast<const uint32_t*>(buf + peOff + 40);

    if (numSec > 96) numSec = 96; // mesmo teto defensivo do AnalyzeEfiPe

    DWORD secTableOff = (DWORD)peOff + 24 + optSize;
    sections.reserve(numSec);
    for (uint16_t i = 0; i < numSec; ++i) {
        DWORD sOff = secTableOff + (DWORD)i * 40;
        if (sOff + 40 > got) break;

        char name[9] = {};
        memcpy(name, buf + sOff, 8);

        EhkPeSection sec;
        sec.name            = std::string(name, strnlen(name, 8));
        sec.vsize           = *reinterpret_cast<const uint32_t*>(buf + sOff + 8);
        sec.va              = *reinterpret_cast<const uint32_t*>(buf + sOff + 12);
        sec.sizeRaw         = *reinterpret_cast<const uint32_t*>(buf + sOff + 16);
        sec.ptrRaw          = *reinterpret_cast<const uint32_t*>(buf + sOff + 20);
        sec.characteristics = *reinterpret_cast<const uint32_t*>(buf + sOff + 36);
        sections.push_back(std::move(sec));
    }
    return true;
}

static bool EhkRvaInsideAnySection(uint32_t rva, const std::vector<EhkPeSection>& sections) {
    for (const auto& s : sections) {
        uint32_t effSz = s.vsize ? s.vsize : s.sizeRaw;
        if (rva >= s.va && rva < s.va + effSz)
            return true;
    }
    return false;
}

// Resolve o RVA de destino de um JMP de 5 bytes (E9 rel32) ou 6 bytes
// (FF 25 disp32, x64) lido do INICIO de uma secao no arquivo em disco (nao de
// memoria remota como no PLScan/HJCScan). Para FF25 o disp aponta para um slot
// de IAT que so contem o ponteiro final quando a imagem esta carregada em
// memoria - no arquivo usamos o proprio RVA do slot como "destino" do teste:
// um slot legitimo de IAT fica dentro de uma secao de dados conhecida; um
// slot fora de qualquer secao do arquivo ja e o sinal de hook.
static bool EhkResolveJumpTargetRVA(const BYTE* data, size_t len, uint32_t selfRVA, uint32_t& targetRVA) {
    if (len >= 5 && data[0] == 0xE9) {
        int32_t rel = *reinterpret_cast<const int32_t*>(data + 1);
        targetRVA = (uint32_t)((int64_t)selfRVA + 5 + rel);
        return true;
    }
    if (len >= 6 && data[0] == 0xFF && data[1] == 0x25) {
        int32_t disp = *reinterpret_cast<const int32_t*>(data + 2);
        targetRVA = (uint32_t)((int64_t)selfRVA + 6 + disp);
        return true;
    }
    return false;
}

// Rebaixa um degrau de severidade quando o arquivo e assinado - um .efi
// legitimamente assinado e um sinal isolado (NOP-sled/jump/entropia) juntos
// sao muito menos indicativos de bootkit do que o mesmo sinal num arquivo
// sem assinatura. Nao suprime a finding, so tempera a severidade.
static std::string EhkDowngradeIfSigned(const std::string& severity, bool signedFile) {
    if (!signedFile) return severity;
    if (severity == "HIGH") return "MEDIUM";
    if (severity == "MEDIUM") return "FLAG";
    return severity;
}

// Parte 1: hooks em secoes PE. Reusa DetectionFilter::AnalyzeEfiPe (ja
// existente) para os sinais de entry-point/estrutura sem duplicar a logica
// dela, e adiciona o que nao existe em nenhum lugar do projeto: escanear o
// CORPO das secoes executaveis. Restrito ao INICIO de cada secao (nao a
// secao inteira) - o mesmo motivo do PLScan/HJCScan: E8/FF25 sozinhos
// aparecem centenas de vezes em qualquer binario compilado normal; uma
// secao/funcao legitima nunca COMECA com esse padrao, e padding de
// alinhamento fica no FIM da secao, nao no inicio. So marca HIGH quando o
// destino do jump e resolvido E cai fora de qualquer secao da propria
// imagem (mesma ideia do IsAddrInModules do HJCScan, aplicada as secoes de
// um unico arquivo EFI). Entropia (igual em espirito ao PLScan) e status de
// assinatura reduzem o falso positivo: sinal isolado num arquivo assinado
// vira severidade mais baixa em vez de HIGH direto.
static void ScanEfiSectionHooks(const std::wstring& path, const std::string& fileLabel,
                                 const std::vector<BYTE>& fileBytes,
                                 const std::vector<EhkPeSection>& sections,
                                 uint32_t entryRVA, bool signedFile,
                                 std::vector<ScannerUI::DeepScanFinding>& out) {
    constexpr uint32_t kMinSectionSize = 32; // piso para descartar stubs/reserva sem conteudo real

    DetectionFilter::EfiPeInfo pe = DetectionFilter::AnalyzeEfiPe(path);
    if (pe.valid) {
        if (pe.epHooked) {
            // So reporta se a secao que contem o entry point tiver conteudo
            // de verdade (nao uma secao degenerada/quase vazia, onde um match
            // de padrao e provavelmente coincidencia).
            bool entrySectionMeaningful = false;
            for (const auto& s : sections) {
                uint32_t effSz = s.vsize ? s.vsize : s.sizeRaw;
                if (entryRVA >= s.va && entryRVA < s.va + effSz && s.sizeRaw >= kMinSectionSize) {
                    entrySectionMeaningful = true;
                    break;
                }
            }
            if (entrySectionMeaningful) {
                AddDeepScanFinding(out, "EHKSCAN", fileLabel, "entry-point",
                    "Entry point do EFI com padrao de hook: " + pe.epHookDetail,
                    EhkDowngradeIfSigned("MEDIUM", signedFile));
            }
        }
        if (pe.injectedSection) {
            AddDeepScanFinding(out, "EHKSCAN", fileLabel, pe.injectedSecName,
                "Secao executavel fora da whitelist MSVC/EDK2: " + pe.injectedSecName,
                EhkDowngradeIfSigned("MEDIUM", signedFile));
        }
        if (pe.dataDirOutOfBounds) {
            AddDeepScanFinding(out, "EHKSCAN", fileLabel, "data-directory",
                "Import/Export DataDirectory aponta fora de qualquer secao (RVA invalido)",
                EhkDowngradeIfSigned("MEDIUM", signedFile));
        }
    }

    constexpr size_t kMaxEntropyWindow = 64 * 1024;

    for (const auto& sec : sections) {
        if (!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (sec.ptrRaw == 0 || sec.sizeRaw < kMinSectionSize) continue;
        if ((uint64_t)sec.ptrRaw + 16 > fileBytes.size()) continue;

        const BYTE* start = fileBytes.data() + sec.ptrRaw;
        size_t avail = fileBytes.size() - sec.ptrRaw;

        // Entropia do corpo da secao (ate 64 KB) - sinal independente do
        // NOP-sled/jump: uma secao "executavel" com entropia de dado
        // empacotado/cifrado e suspeita por si so, igual ao PLScan em
        // memoria de processo.
        size_t entropyLen = avail < kMaxEntropyWindow ? avail : kMaxEntropyWindow;
        double entropy = DetectionFilter::ShannonEntropy(start, entropyLen);
        if (entropy >= DetectionFilter::kPackedEntropy) {
            AddDeepScanFinding(out, "EHKSCAN", fileLabel, sec.name,
                "Secao executavel " + sec.name + " com entropia alta (" +
                DetectionFilter::EntropyToStr(entropy) + ") - possivelmente empacotada/cifrada",
                EhkDowngradeIfSigned("HIGH", signedFile));
        }

        size_t window = avail < 16 ? avail : 16;

        size_t nopRun = 0;
        for (size_t i = 0; i < window && start[i] == 0x90; ++i) nopRun++;
        if (nopRun >= 8) {
            AddDeepScanFinding(out, "EHKSCAN", fileLabel, sec.name,
                "NOP sled no inicio da secao executavel " + sec.name +
                " (" + std::to_string(nopRun) + " bytes)",
                EhkDowngradeIfSigned("MEDIUM", signedFile));
            continue;
        }

        uint32_t targetRVA = 0;
        if (EhkResolveJumpTargetRVA(start, window, sec.va, targetRVA)) {
            if (!EhkRvaInsideAnySection(targetRVA, sections)) {
                AddDeepScanFinding(out, "EHKSCAN", fileLabel, sec.name,
                    "Jump no inicio da secao " + sec.name + " aponta para fora de "
                    "qualquer secao da imagem (RVA destino=" + HexAddress(targetRVA) + ")",
                    EhkDowngradeIfSigned("HIGH", signedFile));
            }
        }
    }
}

// Parte 2: assinatura + hash. Reusa as mesmas primitivas globais ja usadas
// pela pagina EFI Cheat Detect (IsAuthenticodeSigned/CheckProtectedBootBaseline)
// em vez de reimplementar verificacao de assinatura/hash do zero - aqui e so
// um sinal mais leve e proprio do DeepScan, com chave de baseline propria
// ("EHKSCAN.HASH:") para nao colidir com a baseline da pagina EFI Cheat
// Detect ("EFI:"). signedFile/fileEntropy vem do orquestrador (evita
// recomputar assinatura/entropia, ja feitas para a Parte 1).
static void ScanEfiSignatureAndHash(const std::wstring& path, const std::string& fileLabel,
                                     const std::vector<BYTE>& fileBytes,
                                     bool signedFile, double fileEntropy,
                                     std::vector<ScannerUI::DeepScanFinding>& out) {
    if (!signedFile) {
        // Bootloaders sem assinatura sao comuns em dual-boot e ferramentas de
        // manutencao. A ausencia de assinatura isolada fica em FLAG; a
        // entropia alta ainda sobe para HIGH.
        bool packedLike = fileEntropy >= DetectionFilter::kCodeHigh;
        // A ausencia isolada de assinatura e comum em dual-boot e nao
        // constitui evidencia suficiente para criar um card.
        if (packedLike) {
            std::string severity = "HIGH";
            std::string detail = "Bootloader EFI sem assinatura Authenticode valida";
            if (fileEntropy >= 0.0)
                detail += " | entropia=" + DetectionFilter::EntropyToStr(fileEntropy);
            AddDeepScanFinding(out, "EHKSCAN", fileLabel, "signature", detail, severity);
        }
    }

    if (fileBytes.empty()) return;

    std::string hashHex;
    if (!EhkSha256Hex(fileBytes.data(), fileBytes.size(), hashHex)) return;

    std::string prevHash;
    std::string key = "EHKSCAN.HASH:" + WideToUtf8(ToUpperInvariant(path));
    ProtectedBaselineResult result = CheckProtectedBootBaseline(key, hashHex, prevHash);
    if (result == ProtectedBaselineResult::Changed) {
        // Se a versao NOVA esta assinada, e mais consistente com uma
        // atualizacao legitima do bootloader do que com um bootkit trocando
        // o arquivo - mesma excecao ja usada pela pagina EFI Cheat Detect
        // para rotacao de arquivos assinados.
        std::string severity = signedFile ? "MEDIUM" : "HIGH";
        std::string detail = "Hash SHA-256 do bootloader mudou desde a ultima observacao (" +
            prevHash.substr(0, 12) + "... -> " + hashHex.substr(0, 12) + "...)";
        if (signedFile) detail += " | nova versao assinada: possivel atualizacao legitima";
        AddDeepScanFinding(out, "EHKSCAN", fileLabel, "hash", detail, severity);
    } else if (result == ProtectedBaselineResult::StoreTampered) {
        AddDeepScanFinding(out, "EHKSCAN", fileLabel, "hash-baseline",
            "Baseline protegido de hash nao pode ser autenticado (DPAPI)", "MEDIUM");
    }
}

// Parte 3: PCR do TPM 2.0. Monta e submete um TPM2_PCR_Read cru via TBS
// (TPM_CC_PCR_Read = 0x0000017E), no mesmo padrao ja usado e testado por
// ReadTpm2PublicArea (scanner_platform.cpp): tag sem sessao (0x8001), sem
// campo parameterSize na resposta, corpo comecando no offset 10. Le os PCRs
// 0 (CRTM/BIOS), 2 (option ROM), 4 (boot manager/MBR) e 7 (politica Secure
// Boot) no banco SHA256. Falha fechada em qualquer anomalia: nunca le fora
// dos limites do buffer de resposta, nunca reporta valor incerto.
static bool EhkReadTpm2PcrValues(TBS_HCONTEXT context, const std::vector<uint32_t>& pcrIndices,
                                  std::vector<std::pair<uint32_t, std::array<BYTE, 32>>>& outValues) {
    outValues.clear();
    if (pcrIndices.empty()) return false;

    BYTE pcrSelect[3] = { 0, 0, 0 };
    for (uint32_t idx : pcrIndices) {
        if (idx >= 24) return false;
        pcrSelect[idx / 8] |= (BYTE)(1u << (idx % 8));
    }

    std::vector<BYTE> command;
    EhkAppendBe16(command, 0x8001);      // tag: TPM_ST_NO_SESSIONS
    EhkAppendBe32(command, 0);           // commandSize (corrigido abaixo)
    EhkAppendBe32(command, 0x0000017E);  // TPM_CC_PCR_Read
    EhkAppendBe32(command, 1);           // TPML_PCR_SELECTION.count = 1 banco
    EhkAppendBe16(command, 0x000B);      // TPM_ALG_SHA256
    command.push_back(3);                // sizeofSelect (cobre PCR 0-23)
    command.push_back(pcrSelect[0]);
    command.push_back(pcrSelect[1]);
    command.push_back(pcrSelect[2]);
    EhkWriteBe32(command.data() + 2, (uint32_t)command.size());

    std::vector<BYTE> response(4096);
    UINT32 responseSize = (UINT32)response.size();
    TBS_RESULT result = Tbsip_Submit_Command(context,
                                             TBS_COMMAND_LOCALITY_ZERO,
                                             TBS_COMMAND_PRIORITY_NORMAL,
                                             command.data(), (UINT32)command.size(),
                                             response.data(), &responseSize);
    if (result != TBS_SUCCESS || responseSize < 10) return false;

    const BYTE* r = response.data();
    if (EhkReadBe32(r + 6) != 0) return false; // responseCode != TPM_RC_SUCCESS

    size_t off = 10;
    if (off + 4 > responseSize) return false;
    off += 4; // pcrUpdateCounter (nao usado)

    if (off + 4 > responseSize) return false;
    uint32_t selCount = EhkReadBe32(r + off); off += 4;
    if (selCount != 1) return false; // so pedimos 1 selecao (banco SHA256)

    if (off + 2 + 1 > responseSize) return false;
    uint16_t hashAlg = EhkReadBe16(r + off); off += 2;
    BYTE sizeofSelect = r[off]; off += 1;
    if (hashAlg != 0x000B || sizeofSelect != 3) return false;
    if (off + sizeofSelect > responseSize) return false;

    BYTE returnedSelect[3] = {};
    memcpy(returnedSelect, r + off, 3);
    off += sizeofSelect;

    // Se o TPM devolveu um subconjunto dos PCRs pedidos (permitido pela
    // spec), trata como leitura indisponivel em vez de arriscar um baseline
    // que oscila entre conjunto completo/parcial.
    if (memcmp(returnedSelect, pcrSelect, 3) != 0) return false;

    // A ordem dos digests em pcrValues corresponde a ordem crescente dos bits
    // marcados em pcrSelectionOut (invariante da especificacao TPM2) - nao
    // assume a ordem {0,2,4,7} pedida.
    std::vector<uint32_t> expectedIndices;
    for (uint32_t idx = 0; idx < 24; ++idx)
        if (returnedSelect[idx / 8] & (1u << (idx % 8)))
            expectedIndices.push_back(idx);

    if (off + 4 > responseSize) return false;
    uint32_t digestCount = EhkReadBe32(r + off); off += 4;
    if (digestCount == 0 || digestCount != expectedIndices.size()) return false;

    for (uint32_t i = 0; i < digestCount; ++i) {
        if (off + 2 > responseSize) return false;
        uint16_t digestSize = EhkReadBe16(r + off); off += 2;
        if (digestSize != 32 || off + digestSize > responseSize) return false;

        std::array<BYTE, 32> digest{};
        memcpy(digest.data(), r + off, 32);
        off += digestSize;

        outValues.push_back({ expectedIndices[i], digest });
    }

    return !outValues.empty();
}

// corroboratingEfiSignal = true se algum achado EHKSCAN com severidade HIGH
// ja foi adicionado a out nesta mesma passada (por ScanEfiSectionHooks/
// ScanEfiSignatureAndHash, de qualquer .efi). Drift de PCR sozinho e comum
// por motivos benignos (atualizacao de firmware/BIOS, politica Secure
// Boot/dbx, atualizacao do boot manager) - so vale HIGH quando corroborado
// por outro sinal HIGH do mesmo scan; sozinho fica MEDIUM.
static void ScanTpmPcrBaseline(std::vector<ScannerUI::DeepScanFinding>& out, bool corroboratingEfiSignal) {
    TPM_DEVICE_INFO info = {};
    info.structVersion = 1;
    if (Tbsi_GetDeviceInfo(sizeof(info), &info) != TBS_SUCCESS ||
        info.tpmVersion == TPM_VERSION_UNKNOWN)
        return; // sem TPM 2.0: nada a verificar, sem finding

    TBS_CONTEXT_PARAMS2 params = {};
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.requestRaw = 1;
    params.includeTpm20 = 1;

    TBS_HCONTEXT context = nullptr;
    if (Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&params), &context) != TBS_SUCCESS)
        return;

    std::vector<std::pair<uint32_t, std::array<BYTE, 32>>> pcrValues;
    bool ok = EhkReadTpm2PcrValues(context, { 0, 2, 4, 7 }, pcrValues);
    Tbsip_Context_Close(context);
    if (!ok || pcrValues.empty()) return;

    std::vector<BYTE> composite;
    for (const auto& pv : pcrValues) {
        composite.push_back((BYTE)pv.first);
        composite.insert(composite.end(), pv.second.begin(), pv.second.end());
    }
    composite.push_back((BYTE)pcrValues.size());

    std::string currentHash;
    if (!EhkSha256Hex(composite.data(), composite.size(), currentHash)) return;

    std::string prevHash;
    ProtectedBaselineResult result = CheckProtectedBootBaseline("EHKSCAN.PCR", currentHash, prevHash);
    if (result == ProtectedBaselineResult::Changed) {
        std::string severity = corroboratingEfiSignal ? "HIGH" : "MEDIUM";
        std::string detail = "PCRs de boot (0,2,4,7) mudaram desde a ultima observacao";
        detail += corroboratingEfiSignal
            ? " | corroborado por outro achado HIGH do EHKScan nesta mesma passada"
            : " | sem outro sinal suspeito neste scan - costuma ser atualizacao de "
              "firmware/BIOS ou politica Secure Boot/dbx";
        AddDeepScanFinding(out, "EHKSCAN", "System", "TPM PCR", detail, severity);
    } else if (result == ProtectedBaselineResult::StoreTampered) {
        AddDeepScanFinding(out, "EHKSCAN", "System", "TPM PCR baseline",
            "Baseline protegido de PCR nao pode ser autenticado (DPAPI)", "MEDIUM");
    }
}

// Descoberta de .efi: reusa CollectEfiSystemPartitionRoots (ja global) para as
// raizes da ESP, com um walker recursivo pequeno e proprio aqui (nao reusa
// CollectEfiRoots/CollectEfiFilesRecursive de scanner_files.cpp, que sao
// static/locais e muito mais elaborados - a sofisticacao de evasao por
// extensao deles ja e coberta pela pagina EFI Cheat Detect).
static void EhkCollectEfiFiles(const std::wstring& dir, std::vector<std::wstring>& out, int depth = 0) {
    if (depth > 6 || out.size() >= 64) return;

    std::wstring search = JoinPathW(dir, L"*");
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(search.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        if (out.size() >= 64) break;
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;

        std::wstring full = JoinPathW(dir, name);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                EhkCollectEfiFiles(full, out, depth + 1);
            continue;
        }

        size_t dot = name.find_last_of(L'.');
        if (dot == std::wstring::npos) continue;
        std::wstring ext = ToUpperInvariant(name.substr(dot));
        if (ext == L".EFI")
            out.push_back(full);
    } while (FindNextFileW(find, &data));

    FindClose(find);
}

static void ScanEfiHooks(std::vector<ScannerUI::DeepScanFinding>& out) {
    std::string coverageStatus;
    std::vector<std::wstring> espRoots = CollectEfiSystemPartitionRoots(coverageStatus);

    std::vector<std::wstring> efiFiles;
    for (const auto& root : espRoots) {
        if (efiFiles.size() >= 64) break;
        std::wstring efiDir = JoinPathW(root, L"EFI");
        DWORD attrs = GetFileAttributesW(efiDir.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
        EhkCollectEfiFiles(efiDir, efiFiles, 0);
    }

    bool anyHighFinding = false;
    for (const auto& efiPath : efiFiles) {
        if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;

        std::vector<BYTE> fileBytes;
        std::vector<EhkPeSection> sections;
        uint32_t entryRVA = 0;
        if (!EhkReadPeSections(efiPath, fileBytes, sections, entryRVA))
            continue;

        std::string fileLabel = WideToUtf8(BaseNameFromPath(efiPath));
        bool signedFile = DetectionFilter::IsTrustedSignedCached(efiPath);
        double fileEntropy = DetectionFilter::ShannonEntropy(fileBytes.data(), fileBytes.size());

        size_t before = out.size();
        ScanEfiSectionHooks(efiPath, fileLabel, fileBytes, sections, entryRVA, signedFile, out);
        ScanEfiSignatureAndHash(efiPath, fileLabel, fileBytes, signedFile, fileEntropy, out);
        for (size_t i = before; i < out.size(); ++i) {
            if (out[i].severity == "HIGH") { anyHighFinding = true; break; }
        }
    }

    // PCRs sao globais da maquina, nao por arquivo - uma unica chamada.
    ScanTpmPcrBaseline(out, anyHighFinding);
}

// ============================================================================
// LXAScan — payloads disfarcados em diretorios temporarios. Malware droppers
// classicamente largam o payload em %TEMP%/C:\Windows\Temp com extensao
// "de dado" (.dat/.tmp/.bin/etc) e/ou nome puramente numerico para escapar
// de varreduras ingenuas por extensao. Classificacao por conteudo (header PE
// + entropia), sem rastreio de mudanca ao longo do tempo: o mecanismo de
// baseline DPAPI ja usado no EHKScan (CheckProtectedBootBaseline) faz um
// ciclo completo de abrir+descriptografar o arquivo de baseline a cada
// chamada, aceitavel para meia duzia de arquivos .efi/PCR mas caro demais
// para as dezenas de candidatos que o LXAScan pode encontrar em %TEMP% por
// scan - decisao consciente de escopo, nao um descuido.
// ============================================================================

namespace {

// Blocklist (nao allowlist) de proposito: uma lista pequena de extensoes
// "suspeitas" deixaria QUALQUER extensao fora dela (.docx, .csv, .xml, ou
// qualquer coisa nao prevista) evadir o LXAScan de graca, nao importa o
// conteudo - exatamente o disfarce por nome/extensao que nao pode funcionar.
// Em vez disso, bloqueia so um punhado de formatos definitivamente inertes
// (imagem/fonte/estilo - nunca carregam payload executavel na pratica) e
// trata TODO O RESTO como candidato; a classificacao por conteudo (header PE
// + entropia) e quem decide severidade, entao um arquivo genuinamente inerte
// que virou candidato nao sobe de FLAG por falta de sinal.
const wchar_t* const kLxaInertExtensions[] = {
    L".JPG", L".JPEG", L".PNG", L".GIF", L".BMP", L".ICO", L".SVG",
    L".WOFF", L".WOFF2", L".TTF", L".CSS", L".MAP",
    nullptr
};

bool LxaIsInertExtension(const std::wstring& upperExt) {
    for (int i = 0; kLxaInertExtensions[i]; ++i)
        if (upperExt == kLxaInertExtensions[i])
            return true;
    return false;
}

bool LxaIsExpectedPeExtension(const std::wstring& upperExt) {
    static const wchar_t* const extensions[] = {
        L".EXE", L".DLL", L".COM", L".SCR", L".CPL", L".OCX", L".SYS", L".EFI", nullptr
    };
    for (int i = 0; extensions[i]; ++i)
        if (upperExt == extensions[i])
            return true;
    return false;
}

bool LxaHasKnownDataMagic(const BYTE* data, size_t len) {
    if (len >= 4 && data[0] == 'P' && data[1] == 'K' &&
        ((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6) ||
         (data[2] == 7 && data[3] == 8)))
        return true; // ZIP/JAR/Office package
    if (len >= 6 && memcmp(data, "7z\xBC\xAF\x27\x1C", 6) == 0) return true;
    if (len >= 4 && memcmp(data, "Rar!", 4) == 0) return true;
    if (len >= 4 && memcmp(data, "MSCF", 4) == 0) return true;
    if (len >= 2 && data[0] == 0x1F && data[1] == 0x8B) return true;
    if (len >= 5 && memcmp(data, "%PDF-", 5) == 0) return true;
    return false;
}

bool LxaIsNumericFilenameStem(const std::wstring& stem) {
    if (stem.empty()) return false;
    for (wchar_t c : stem)
        if (!iswdigit(c))
            return false;
    return true;
}

// MZ + assinatura PE\0\0 no e_lfanew - versao leve do mesmo check ja usado
// em EhkReadPeSections/AnalyzeEfiPe, sem tabela de secoes (aqui so precisa
// responder "isso e um executavel disfarcado de dado?").
bool LxaLooksLikePe(const BYTE* data, size_t len) {
    if (len < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;
    LONG peOff = *reinterpret_cast<const LONG*>(data + 0x3C);
    if (peOff <= 0 || (DWORD)peOff + 4 > (DWORD)len) return false;
    return data[peOff] == 'P' && data[peOff + 1] == 'E' && data[peOff + 2] == 0 && data[peOff + 3] == 0;
}

} // namespace

static void LxaCollectCandidates(const std::wstring& dir, std::vector<std::wstring>& out, int depth = 0) {
    if (depth > 3 || out.size() >= 200) return;

    std::wstring search = JoinPathW(dir, L"*");
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(search.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        if (out.size() >= 200) break;
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;

        std::wstring full = JoinPathW(dir, name);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                LxaCollectCandidates(full, out, depth + 1);
            continue;
        }

        size_t dot = name.find_last_of(L'.');
        std::wstring ext = dot == std::wstring::npos ? L"" : ToUpperInvariant(name.substr(dot));

        if (!ext.empty() && LxaIsInertExtension(ext)) continue; // formato definitivamente inerte - nunca candidato

        uint64_t sz = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
        if (sz < 64 || sz > 50ull * 1024 * 1024) continue; // muito pequeno (sem conteudo) ou grande demais (cache legitimo)

        // So captura arquivo tocado durante a sessao atual (pos-boot) - um
        // .dat/.tmp/.bin que ja estava em Temp antes desta sessao ligar quase
        // certamente nao e um payload recem-derrubado.
        if (!IsAfterBoot(data.ftLastWriteTime)) continue;

        out.push_back(full);
    } while (FindNextFileW(find, &data));

    FindClose(find);
}

static void ScanTempDroppedFiles(std::vector<ScannerUI::DeepScanFinding>& out) {
    const auto& r = DetectionFilter::Roots();
    std::vector<std::wstring> dirs;
    if (!r.userTemp.empty())   dirs.push_back(r.userTemp);
    if (!r.windirTemp.empty()) dirs.push_back(r.windirTemp);

    std::vector<std::wstring> candidates;
    for (const auto& d : dirs) {
        if (candidates.size() >= 200) break;
        LxaCollectCandidates(d, candidates, 0);
    }

    for (const auto& path : candidates) {
        if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;

        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        constexpr DWORD kMaxRead = 64 * 1024;
        std::vector<BYTE> buf(kMaxRead);
        LARGE_INTEGER fileSize = {};
        GetFileSizeEx(hFile, &fileSize);
        DWORD got = 0;
        bool ok = ReadFile(hFile, buf.data(), kMaxRead, &got, nullptr);
        CloseHandle(hFile);
        if (!ok || got == 0) continue;

        std::wstring name = BaseNameFromPath(path);
        size_t dot = name.find_last_of(L'.');
        std::wstring stem = dot == std::wstring::npos ? name : name.substr(0, dot);
        std::wstring ext  = dot == std::wstring::npos ? L"" : ToUpperInvariant(name.substr(dot));
        bool numericName = LxaIsNumericFilenameStem(stem);

        bool looksLikePe = LxaLooksLikePe(buf.data(), got);
        bool expectedPeExtension = LxaIsExpectedPeExtension(ext);
        bool knownDataFormat = LxaHasKnownDataMagic(buf.data(), got);
        double entropy = DetectionFilter::ShannonEntropy(buf.data(), got);
        bool packedLike = entropy >= DetectionFilter::kPackedEntropy;

        std::string severity;
        std::string reason;
        if (looksLikePe) {
            const bool signedFile = DetectionFilter::IsTrustedSignedCached(path);
            if (!expectedPeExtension) {
                severity = signedFile ? "MEDIUM" : "HIGH";
                reason = "arquivo PE disfarcado com extensao " +
                         (ext.empty() ? std::string("(sem extensao)") : WideToUtf8(ext)) +
                         " | signed=" + (signedFile ? std::string("yes") : std::string("no"));
            } else if (!signedFile && packedLike) {
                severity = "MEDIUM";
                reason = "PE nao assinado e empacotado criado em diretorio temporario";
            } else {
                continue; // instalador/updater comum sem evidencia adicional
            }
        } else if (!knownDataFormat && packedLike && numericName) {
            severity = "MEDIUM";
            reason = "nome de arquivo numerico (padrao de dropper) + conteudo de alta entropia (empacotado/cifrado)";
        } else {
            continue; // nome, local ou entropia isolados nao provam payload
        }

        std::string detail = reason +
                             " | path=" + WideToUtf8(path) +
                             " | entropia=" + DetectionFilter::EntropyToStr(entropy) +
                             " | size=" + std::to_string(fileSize.QuadPart);
        if (severity == "HIGH") {
            std::string hashHex = DetectionFilter::ComputeFileSha256(path);
            if (!hashHex.empty())
                detail += " | sha256=" + hashHex;
        }

        AddDeepScanFinding(out, "LXASCAN", "System", WideToUtf8(path), detail, severity);
    }
}

// ============================================================================
// TRHScan — thread hijacking via contexto de threads suspensas. Diferente do
// ScanThreadStartAddresses (scanner_processes.cpp), que so olha o ENDERECO DE
// INICIO de cada thread (propriedade estatica, fixada na criacao), o TRHScan
// olha o RIP/EIP ATUAL de threads SUSPENSAS - o padrao classico de thread
// hijacking: em vez de CreateRemoteThread (muito monitorado), o atacante
// suspende uma thread ja existente, reescreve o contexto via SetThreadContext
// (RIP apontando pro shellcode) e retoma - ou deixa suspensa como backdoor
// dormente. Nenhum codigo no projeto ja usa GetThreadContext/SuspendThread/
// cntSuspendCount - esse sinal e genuinamente novo, nao duplica nada.
//
// Sem gate de "processo confiavel": mesma razao do HJCScan - thread hijacking
// mira processos confiaveis justamente pra se esconder.
// ============================================================================

// So chega aqui quando o RIP/EIP da thread suspensa cai FORA de qualquer
// modulo carregado - a esmagadora maioria das threads suspensas (pool de
// threads, pausa de GC, bloqueada num syscall) tem RIP dentro de ntdll.dll/
// runtime e nunca chega neste ponto, entao a cascata abaixo ja opera sobre um
// sinal razoavelmente raro.
static void ClassifySuspendedThreadRip(HANDLE process, DWORD tid,
                                        const std::string& procName, uintptr_t rip,
                                        std::vector<ScannerUI::DeepScanFinding>& out) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(rip), &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT)
        return;

    constexpr size_t kSampleSize = 4096;
    unsigned char sample[kSampleSize] = {};
    SIZE_T got = 0;
    ReadProcessMemory(process, mbi.BaseAddress, sample, kSampleSize, &got);

    bool hasPe = DetectionFilter::HasPEHeader(process, mbi.BaseAddress);
    double entropy = got > 0 ? DetectionFilter::ShannonEntropy(sample, got) : -1.0;
    bool execProtect = IsExecProtect(mbi.Protect);
    bool codeLike = entropy >= DetectionFilter::kCodeLow && entropy <= DetectionFilter::kCodeHigh;

    std::string severity;
    std::string reason;
    if (hasPe) {
        severity = "HIGH";
        reason = "RIP dentro de PE header em memoria privada (DLL reflective/manual-mapped)";
    } else if (entropy >= DetectionFilter::kPackedEntropy) {
        severity = "HIGH";
        reason = "RIP em memoria de alta entropia (possivelmente empacotada/cifrada)";
    } else if (!execProtect) {
        severity = "HIGH";
        reason = "RIP fora de qualquer modulo em memoria SEM permissao de execucao - "
                 "uma thread nunca chega la sozinha, contexto foi reescrito manualmente";
    } else if (codeLike) {
        severity = "MEDIUM";
        reason = "RIP em memoria privada executavel fora de qualquer modulo (perfil de thread hijacking)";
    } else {
        return; // RIP isolado fora de modulo ocorre em estados transitórios de threads.
    }

    std::string detail = reason + " | rip=" + HexAddress(rip) +
                         " | tid=" + std::to_string(tid) +
                         " | protect=" + std::to_string(mbi.Protect) +
                         (entropy >= 0.0 ? " | entropia=" + DetectionFilter::EntropyToStr(entropy) : "");
    AddDeepScanFinding(out, "TRHSCAN", procName, HexAddress(rip), detail, severity);
}

static void ScanProcessSuspendedThreads(DWORD pid, const std::string& procName, HANDLE process,
                                         const std::vector<ModuleRange>& modules, bool isWow64,
                                         std::vector<ScannerUI::DeepScanFinding>& out) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32 = {};
    te32.dwSize = sizeof(te32);
    size_t paceCounter = 0;

    if (Thread32First(snapshot, &te32)) {
        do {
            if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;
            if (te32.th32OwnerProcessID != pid) continue;

            MaybePaceIteration(paceCounter, 4);

            // THREADENTRY32 nao carrega contagem de suspensao (o sample original
            // usava um campo "cntSuspendCount" que nao existe na struct real do
            // Windows) - a unica forma documentada de consultar isso sem efeito
            // colateral permanente e o round-trip SuspendThread/ResumeThread ja
            // usado por ferramentas como Process Explorer/Process Hacker:
            // SuspendThread incrementa e devolve a contagem ANTERIOR a nossa
            // chamada; ResumeThread desfaz imediatamente so o nosso incremento,
            // restaurando o estado original (suspensa continua suspensa, rodando
            // volta a rodar).
            HANDLE hThread = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE, te32.th32ThreadID);
            if (!hThread) continue;

            DWORD prevSuspendCount = SuspendThread(hThread);
            if (prevSuspendCount == (DWORD)-1) {
                CloseHandle(hThread);
                continue;
            }
            bool wasAlreadySuspended = prevSuspendCount > 0;

            uintptr_t rip = 0;
            bool ok = false;
            if (wasAlreadySuspended) {
                // A thread esta suspensa agora (seja pela nossa chamada ou porque
                // ja estava) - GetThreadContext exige a thread suspensa para dado
                // consistente, entao e seguro ler aqui.
                if (isWow64) {
                    WOW64_CONTEXT wowCtx = {};
                    wowCtx.ContextFlags = WOW64_CONTEXT_CONTROL;
                    if (Wow64GetThreadContext(hThread, &wowCtx)) {
                        rip = wowCtx.Eip;
                        ok = true;
                    }
                } else {
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(hThread, &ctx)) {
                        rip = ctx.Rip;
                        ok = true;
                    }
                }
            }

            ResumeThread(hThread); // desfaz so o nosso incremento
            CloseHandle(hThread);

            if (!wasAlreadySuspended || !ok || rip == 0) continue;

            if (IsAddrInModules(rip, modules)) continue; // suspensa normal, RIP em codigo legitimo

            ClassifySuspendedThreadRip(process, te32.th32ThreadID, procName, rip, out);
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);
}

static void ScanSuspendedThreads(std::vector<ScannerUI::DeepScanFinding>& out) {
    DWORD ownPid = GetCurrentProcessId();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (out.size() >= ScanLimits::kMaxDeepScanFindings) break;

            DWORD pid = entry.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == ownPid) continue;

            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process)
                process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!process) continue;

            std::vector<ModuleRange> modules;
            if (!CollectProcessModules(process, modules)) {
                CloseHandle(process);
                continue;
            }

            BOOL isWow64 = FALSE;
            IsWow64Process(process, &isWow64); // falha -> trata como processo nativo (caso mais comum)

            std::string procName = WideToUtf8(entry.szExeFile) + " [" + std::to_string(pid) + "]";
            ScanProcessSuspendedThreads(pid, procName, process, modules, isWow64 != FALSE, out);

            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

std::vector<ScannerUI::DeepScanFinding> CollectDeepScanFindings(std::string& status) {
    std::vector<ScannerUI::DeepScanFinding> plFindings;
    std::vector<ScannerUI::DeepScanFinding> hjcFindings;
    std::vector<ScannerUI::DeepScanFinding> ehkFindings;
    std::vector<ScannerUI::DeepScanFinding> lxaFindings;
    std::vector<ScannerUI::DeepScanFinding> trhFindings;

    // Cada topico recebe seu proprio orcamento durante a coleta. Assim um
    // processo com muitas regioes RWX nao impede EFI/TPM ou threads de rodar.
    ScanInjectedPayloads(plFindings);
    ScanDllHijacking(hjcFindings);
    ScanEfiHooks(ehkFindings);
    ScanTempDroppedFiles(lxaFindings);
    ScanSuspendedThreads(trhFindings);

    std::array<std::vector<ScannerUI::DeepScanFinding>*, 5> topics = {
        &plFindings, &hjcFindings, &ehkFindings, &lxaFindings, &trhFindings
    };
    auto severityRank = [](const ScannerUI::DeepScanFinding& finding) {
        return finding.severity == "HIGH" ? 0 : finding.severity == "MEDIUM" ? 1 : 2;
    };
    for (auto* topic : topics) {
        std::stable_sort(topic->begin(), topic->end(), [&](const auto& a, const auto& b) {
            return severityRank(a) < severityRank(b);
        });
    }

    std::vector<ScannerUI::DeepScanFinding> findings;
    findings.reserve(ScanLimits::kMaxDeepScanFindings);
    std::unordered_map<std::string, size_t> seen;
    auto appendUnique = [&](const ScannerUI::DeepScanFinding& finding) {
        const std::string key = finding.type + "\n" + finding.process + "\n" + finding.target;
        auto existing = seen.find(key);
        if (existing != seen.end()) {
            auto& merged = findings[existing->second];
            if (severityRank(finding) < severityRank(merged))
                merged.severity = finding.severity;
            if (merged.detail.find(finding.detail) == std::string::npos)
                merged.detail += " | " + finding.detail;
            return;
        }
        if (findings.size() < ScanLimits::kMaxDeepScanFindings) {
            seen.emplace(key, findings.size());
            findings.push_back(finding);
        }
    };

    constexpr size_t kPerTopicReserve = 8;
    for (auto* topic : topics) {
        const size_t count = (std::min)(kPerTopicReserve, topic->size());
        for (size_t i = 0; i < count; ++i)
            appendUnique((*topic)[i]);
    }

    std::vector<const ScannerUI::DeepScanFinding*> remainder;
    for (auto* topic : topics) {
        for (size_t i = (std::min)(kPerTopicReserve, topic->size()); i < topic->size(); ++i)
            remainder.push_back(&(*topic)[i]);
    }
    std::stable_sort(remainder.begin(), remainder.end(), [&](const auto* a, const auto* b) {
        return severityRank(*a) < severityRank(*b);
    });
    for (const auto* finding : remainder) {
        if (findings.size() >= ScanLimits::kMaxDeepScanFindings)
            break;
        appendUnique(*finding);
    }

    if (findings.empty()) {
        status = "OK";
    } else {
        bool hasHigh = false;
        for (const auto& f : findings)
            if (f.severity == "HIGH") { hasHigh = true; break; }
        status = hasHigh ? "DETECTED" : "REVIEW";
    }
    return findings;
}
