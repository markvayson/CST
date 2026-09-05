#include "WinRARUtils.h"
#include "CSCsecure.h"
#include <wininet.h>
#include <urlmon.h>
#include <shellapi.h>
#include <regex>
#include <thread>


#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

bool GetWinRARVersion(std::wstring& outVersion) {
    HKEY hKey;
    const wchar_t* regPath = L"SOFTWARE\\WinRAR";
    HKEY rootKeys[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    for (HKEY hRoot : rootKeys) {
        // Check 64-bit Registry View
        if (RegOpenKeyExW(hRoot, regPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            wchar_t verBuf[64] = { 0 };
            DWORD dwSize = sizeof(verBuf);
            if (RegQueryValueExW(hKey, L"Version", NULL, NULL, (LPBYTE)verBuf, &dwSize) == ERROR_SUCCESS) {
                outVersion = verBuf;
                RegCloseKey(hKey);
                return true;
            }
            RegCloseKey(hKey);
        }

        // Check 32-bit/Standard Registry View
        if (RegOpenKeyExW(hRoot, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t verBuf[64] = { 0 };
            DWORD dwSize = sizeof(verBuf);
            if (RegQueryValueExW(hKey, L"Version", NULL, NULL, (LPBYTE)verBuf, &dwSize) == ERROR_SUCCESS) {
                outVersion = verBuf;
                RegCloseKey(hKey);
                return true;
            }
            RegCloseKey(hKey);
        }
    }

    // Fallback: Check standard Uninstall keys if SOFTWARE\WinRAR isn't populated
    const wchar_t* uninstallPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinRAR archiver";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, uninstallPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t verBuf[64] = { 0 };
        DWORD dwSize = sizeof(verBuf);
        if (RegQueryValueExW(hKey, L"DisplayVersion", NULL, NULL, (LPBYTE)verBuf, &dwSize) == ERROR_SUCCESS) {
            outVersion = verBuf;
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }

    outVersion = L"";
    return false;
}

bool IsVersionOlder(const std::wstring& installed, const std::wstring& latest) {
    int instMaj = 0, instMin = 0;
    int latMaj = 0, latMin = 0;
    swscanf_s(installed.c_str(), L"%d.%d", &instMaj, &instMin);
    swscanf_s(latest.c_str(), L"%d.%d", &latMaj, &latMin);

    if (instMaj < latMaj) return true;
    if (instMaj == latMaj && instMin < latMin) return true;
    return false;
}

std::wstring GetLatestWinRARVersionOnline() {
    HINTERNET hInternet = InternetOpenW(L"WinRARChecker", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return L"7.23";

    HINTERNET hConnect = InternetOpenUrlW(hInternet, L"https://www.rarlab.com/download.htm", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return L"7.23";
    }

    char buffer[4096];
    DWORD bytesRead = 0;
    std::string html;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        html += buffer;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    std::regex reg("winrar-x64-(\\d)(\\d{2})\\.exe");
    std::smatch match;
    if (std::regex_search(html, match, reg) && match.size() > 2) {
        std::string maj = match[1].str();
        std::string min = match[2].str();
        std::string fullVer = maj + "." + min;
        return std::wstring(fullVer.begin(), fullVer.end());
    }

    return L"7.23";
}

std::wstring GetAppDirectory() {
    wchar_t szPath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(szPath, L'\\');
    if (lastSlash) {
        *lastSlash = L'\0';
    }
    return std::wstring(szPath);
}

bool IsFileDownloadedToday(const std::wstring& filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fileData = { 0 };
    if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileData)) {
        return false;
    }

    FILETIME ftLocal;
    SYSTEMTIME stFileTime, stCurrentTime;
    FileTimeToLocalFileTime(&fileData.ftLastWriteTime, &ftLocal);
    FileTimeToSystemTime(&ftLocal, &stFileTime);
    GetLocalTime(&stCurrentTime);

    return (stFileTime.wYear == stCurrentTime.wYear &&
        stFileTime.wMonth == stCurrentTime.wMonth &&
        stFileTime.wDay == stCurrentTime.wDay);
}

// Finds any existing installer matching winrar-x64-*.exe in app directory
std::wstring FindExistingWinRARInstaller(const std::wstring& directory) {
    std::wstring searchPattern = directory + L"\\winrar-x64-*.exe";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        std::wstring fileName = findData.cFileName;
        FindClose(hFind);
        return directory + L"\\" + fileName;
    }
    return L"";
}



void InstallLatestWinRAR() {
    std::wstring appDir = GetAppDirectory();
    std::wstring latestVer = GetLatestWinRARVersionOnline();

    // Construct real executable filename (e.g. winrar-x64-723.exe)
    std::wstring actualFileName = L"winrar-x64-723.exe";
    if (!latestVer.empty()) {
        int major = 0, minor = 0;
        swscanf_s(latestVer.c_str(), L"%d.%d", &major, &minor);
        if (major > 0 && minor >= 0) {
            wchar_t buf[128];
            swprintf_s(buf, 128, L"winrar-x64-%d%02d.exe", major, minor);
            actualFileName = buf;
        }
    }

    std::wstring serverSetupPath = appDir + L"\\" + actualFileName;
    std::wstring existingInstaller = FindExistingWinRARInstaller(appDir);
    if (!existingInstaller.empty()) {
        serverSetupPath = existingInstaller;
    }

    wchar_t tempPathBuf[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempPathBuf);
    std::wstring localTempSetupPath = std::wstring(tempPathBuf) + actualFileName;

    bool needDownload = true;

    if (GetFileAttributesW(serverSetupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (IsFileDownloadedToday(serverSetupPath)) {
            needDownload = false;
        }
    }

    if (needDownload) {
        std::wstring downloadUrl = L"https://www.rarlab.com/rar/" + actualFileName;

        HRESULT hr = URLDownloadToFileW(NULL, downloadUrl.c_str(), serverSetupPath.c_str(), 0, NULL);
        if (FAILED(hr)) {
            if (GetFileAttributesW(serverSetupPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                URLDownloadToFileW(NULL, downloadUrl.c_str(), localTempSetupPath.c_str(), 0, NULL);
            }
        }
    }

    if (GetFileAttributesW(serverSetupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        CopyFileW(serverSetupPath.c_str(), localTempSetupPath.c_str(), FALSE);
    }

    if (GetFileAttributesW(localTempSetupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.cbSize = sizeof(sei);
        sei.lpVerb = L"runas";
        sei.lpFile = localTempSetupPath.c_str();
        sei.lpParameters = L"/S";
        sei.nShow = SW_HIDE;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExW(&sei) && sei.hProcess) {
            WaitForSingleObject(sei.hProcess, INFINITE);
            CloseHandle(sei.hProcess);
        }
    }

    // Verify registry installation for up to 5 seconds
    std::wstring verifiedVer;
    for (int i = 0; i < 10; ++i) {
        Sleep(500);
        if (GetWinRARVersion(verifiedVer)) {
            break;
        }
    }
}








