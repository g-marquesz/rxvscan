#pragma once

#include <unordered_map>
#include "scanner_ui.h"
#include <string>

namespace ScannerUpload {

struct Config {
    std::wstring apiKey;
    std::wstring endpoint;
    bool valid = false;
};

Config LoadConfigFromRegistry();
bool SaveConfigToRegistry(const Config& cfg);

std::string BuildScanJson(const ScannerUI::ScanData& data,
                          const std::string& clientScanId,
                          const std::string& startedAt,
                          const std::string& status,
                          const std::string& stage,
                          float progress);

bool PostScanResults(const ScannerUI::ScanData& data,
                     const Config& cfg,
                     const std::string& clientScanId,
                     const std::string& startedAt,
                     const std::string& status,
                     const std::string& stage,
                     float progress,
                     bool persistOnFailure,
                     std::string& outError);

bool TryUploadSnapshot(const ScannerUI::ScanData& data,
                       const std::string& clientScanId,
                       const std::string& startedAt,
                       const std::string& status,
                       const std::string& stage,
                       float progress,
                       bool persistOnFailure,
                       std::string& outMessage);

struct BlacklistHit {
    bool blacklisted = false;
    std::string title;
    std::string summary;
    std::string severity;     // "low"|"medium"|"high"|"critical"
    std::string exposedId;
    std::string createdAt;
    std::string error;        // se !blacklisted e !error.empty() → falha de rede/config
};

// Consulta /api/blacklist/check?hwid=... no servidor configurado.
// Devolve hit.blacklisted = true se o HWID aparece na lista de exposeds.
BlacklistHit CheckHwidBlacklist(const std::string& hwidUtf8);

}
