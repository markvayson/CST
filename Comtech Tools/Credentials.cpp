#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <string>
#include <vector>

#include "Credentials.h"

#pragma comment(lib, "shlwapi.lib")

namespace {

bool IsDriveReady(const std::wstring& drivePath) {
    UINT type = GetDriveTypeW(drivePath.c_str());
    if (type == DRIVE_NO_ROOT_DIR || type == DRIVE_UNKNOWN) return false;

    // Check if disk media is accessible and mounted
    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    if (GetDiskFreeSpaceExW(drivePath.c_str(), &freeBytes, &totalBytes, &totalFree)) {
        return true;
    }

    // Fallback check for fixed drives
    if (type == DRIVE_FIXED) {
        DWORD attrs = GetFileAttributesW(drivePath.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES);
    }

    return false;
}

std::wstring UrlEncodeLocation(const std::wstring& path) {
    std::wstring encoded;
    for (wchar_t ch : path) {
        if (ch == L':') encoded += L"%3A";
        else if (ch == L'\\') encoded += L"%5C";
        else if (ch == L'/') encoded += L"%5C";
        else encoded += ch;
    }
    return encoded;
}

std::wstring BuildSearchMsUrl(const std::wstring& rawDrivePath, const std::wstring& query) {
    // For C: drive, constrain search root to C:\Users
    std::wstring locationPath = rawDrivePath;
    if (_wcsicmp(rawDrivePath.c_str(), L"C:\\") == 0) {
        locationPath = L"C:\\Users";
    }

    std::wstring encodedLocation = UrlEncodeLocation(locationPath);

    std::wstring encodedQuery;
    for (wchar_t ch : query) {
        if (ch == L' ') encodedQuery += L"%20";
        else encodedQuery += ch;
    }

    return L"search-ms:query=" + encodedQuery + L"&crumb=location:" + encodedLocation;
}

} // namespace

void ExecuteCredentialsSearch() {
    HRESULT hrCom = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    std::vector<std::wstring> readyDrives;
    DWORD driveMask = GetLogicalDrives();

    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        if ((driveMask & (1u << (letter - L'A'))) == 0) continue;

        std::wstring drivePath = std::wstring(1, letter) + L":\\";
        if (IsDriveReady(drivePath)) {
            readyDrives.push_back(drivePath);
        }
    }

    const std::wstring searchQuery = L"pass OR key OR any";

    // Launch Windows Explorer performing search for "pass OR key OR any" on each drive
    for (size_t i = 0; i < readyDrives.size(); ++i) {
        std::wstring searchUrl = BuildSearchMsUrl(readyDrives[i], searchQuery);
        ShellExecuteW(NULL, L"open", searchUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
        if (i + 1 < readyDrives.size()) {
            Sleep(250); // Brief pause to allow Explorer to process each search request
        }
    }

    if (SUCCEEDED(hrCom)) {
        CoUninitialize();
    }
}