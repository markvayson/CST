#include "WinRARUtils.h"
#include <wininet.h>
#include <urlmon.h>
#include <shellapi.h>
#include <regex>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

// Retrieves installed WinRAR version from Registry with registry fallback
bool GetWinRARVersion(std::wstring& outVersion) {
    HKEY hKey = NULL;

    // Check HKLM (64-bit and 32-bit) & HKCU
    struct RegTarget {
        HKEY root;
        const wchar_t* path;
        REGSAM sam;
    } targets[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WinRAR", KEY_READ | KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WinRAR", KEY_READ | KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\WinRAR", KEY_READ },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinRAR archiver", KEY_READ },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinRAR archiver", KEY_READ },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinRAR archiver", KEY_READ }
    };

    for (const auto& target : targets) {
        if (RegOpenKeyExW(target.root, target.path, 0, target.sam, &hKey) == ERROR_SUCCESS) {
            wchar_t verBuffer[128] = { 0 };
            DWORD dataSize = sizeof(verBuffer);
            DWORD dataType = 0;

            // Try "Version" key first, then "DisplayVersion" for Uninstall entries
            if (RegQueryValueExW(hKey, L"Version", NULL, &dataType, (LPBYTE)verBuffer, &dataSize) == ERROR_SUCCESS ||
                RegQueryValueExW(hKey, L"DisplayVersion", NULL, &dataType, (LPBYTE)verBuffer, &dataSize) == ERROR_SUCCESS) {

                RegCloseKey(hKey);
                if (dataType == REG_SZ || dataType == REG_EXPAND_SZ) {
                    outVersion = verBuffer;
                    return true;
                }
            }
            RegCloseKey(hKey);
        }
    }

    return false;
}

// Dynamic Download & Silent Installation with Registry Verification Retry
void InstallLatestWinRAR() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string installerPath = std::string(tempPath) + "winrar_setup.exe";

    std::wstring latestVer = GetLatestWinRARVersionOnline();
    std::string downloadUrl = "https://www.rarlab.com/rar/winrar-x64-723.exe"; // Fallback default

    if (!latestVer.empty()) {
        int major = 0, minor = 0;
        swscanf_s(latestVer.c_str(), L"%d.%d", &major, &minor);
        if (major > 0 && minor >= 0) {
            char urlBuf[256];
            snprintf(urlBuf, sizeof(urlBuf), "https://www.rarlab.com/rar/winrar-x64-%d%02d.exe", major, minor);
            downloadUrl = urlBuf;
        }
    }

    HRESULT hr = URLDownloadToFileA(NULL, downloadUrl.c_str(), installerPath.c_str(), 0, NULL);
    if (SUCCEEDED(hr)) {
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = "runas";
        sei.lpFile = installerPath.c_str();
        sei.lpParameters = "/S";
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExA(&sei) && sei.hProcess) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
        }
    }

    // Polling retry loop: Wait up to 5 seconds for registry to register the newly installed version
    std::wstring verifiedVer;
    for (int i = 0; i < 10; ++i) {
        Sleep(500);
        if (GetWinRARVersion(verifiedVer)) {
            break;
        }
    }
}

// Fetch highest version string from RARLab download page
std::wstring GetLatestWinRARVersionOnline() {
    HINTERNET hInternet = ::InternetOpenW(L"CSCsecure/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return L"";

    // Download download.htm first as it lists the latest full binaries
    HINTERNET hConnect = ::InternetOpenUrlW(hInternet, L"https://www.rarlab.com/download.htm", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        // Fallback to news page if download page is unreachable
        hConnect = ::InternetOpenUrlW(hInternet, L"https://www.rarlab.com/rarnew.htm", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    }

    if (!hConnect) {
        ::InternetCloseHandle(hInternet);
        return L"";
    }

    char buffer[8192];
    DWORD bytesRead = 0;
    std::string htmlContent;
    while (::InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        htmlContent += buffer;
    }

    ::InternetCloseHandle(hConnect);
    ::InternetCloseHandle(hInternet);

    int maxMajor = 0, maxMinor = 0;
    std::string highestVerStr = "";

    // Pattern 1: match installer filename like winrar-x64-723.exe
    std::regex fileRegex("winrar-x64-([0-9])([0-9]{2})\\.exe", std::regex_constants::icase);
    auto file_begin = std::sregex_iterator(htmlContent.begin(), htmlContent.end(), fileRegex);
    auto file_end = std::sregex_iterator();
    for (std::sregex_iterator i = file_begin; i != file_end; ++i) {
        std::smatch match = *i;
        int major = std::atoi(match[1].str().c_str());
        int minor = std::atoi(match[2].str().c_str());
        if (major > maxMajor || (major == maxMajor && minor > maxMinor)) {
            maxMajor = major;
            maxMinor = minor;
            highestVerStr = match[1].str() + "." + match[2].str();
        }
    }

    // Pattern 2: match standard text tags e.g. "WinRAR 7.23"
    std::regex verRegex("WinRAR\\s+([0-9]+)\\.([0-9]+)", std::regex_constants::icase);
    auto words_begin = std::sregex_iterator(htmlContent.begin(), htmlContent.end(), verRegex);
    auto words_end = std::sregex_iterator();
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::smatch match = *i;
        int major = std::atoi(match[1].str().c_str());
        int minor = std::atoi(match[2].str().c_str());
        if (major > maxMajor || (major == maxMajor && minor > maxMinor)) {
            maxMajor = major;
            maxMinor = minor;
            highestVerStr = match[1].str() + "." + match[2].str();
        }
    }

    if (!highestVerStr.empty()) {
        return std::wstring(highestVerStr.begin(), highestVerStr.end());
    }

    return L"";
}

// Version comparison
bool IsVersionOlder(const std::wstring& installed, const std::wstring& latest) {
    if (latest.empty() || installed.empty()) return false;

    int instMajor = 0, instMinor = 0, latMajor = 0, latMinor = 0;
    swscanf_s(installed.c_str(), L"%d.%d", &instMajor, &instMinor);
    swscanf_s(latest.c_str(), L"%d.%d", &latMajor, &latMinor);

    if (instMajor < latMajor) return true;
    if (instMajor == latMajor && instMinor < latMinor) return true;
    return false;
}
