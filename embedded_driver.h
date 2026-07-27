#pragma once

#include <windows.h>
#include <string>

bool ExtractEmbeddedDriverResource(WORD resourceId,
                                   const char* expectedSha256,
                                   const wchar_t* fileStem,
                                   std::wstring& outPath,
                                   std::string& status);
bool DeleteEmbeddedDriverFile(std::wstring& path);

class XvKernelDriver {
public:
    ~XvKernelDriver();

    bool Load();
    bool Unload();
    bool IsLoaded() const {
        return device_ != nullptr && device_ != INVALID_HANDLE_VALUE;
    }
    const std::string& Status() const { return status_; }

private:
    HANDLE device_ = INVALID_HANDLE_VALUE;
    SC_HANDLE scm_ = nullptr;
    SC_HANDLE service_ = nullptr;
    bool serviceCreated_ = false;
    std::wstring serviceName_;
    std::wstring tempPath_;
    std::string status_;
};
