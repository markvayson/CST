#include "BrowserAccount.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>

// Native Win32 function to terminate processes by executable name
static void TerminateProcessesByName(const std::vector<std::wstring>& processNames) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring currentExe = pe.szExeFile;

            // Check if the current process matches any in our target list (case-insensitive)
            for (const auto& target : processNames) {
                if (_wcsicmp(currentExe.c_str(), target.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess != NULL) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

bool IsBrowserAccountLocked() {
    HKEY hKey;
    DWORD edgeVal = 1, chromeVal = 1, braveVal = 1, firefoxAccounts = 0;
    DWORD edgeSync = 0, chromeSync = 0, braveSync = 0;

    auto ReadDWORD = [](const char* subkey, const char* valueName, DWORD& outVal) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD dwSize = sizeof(DWORD); // Reset dwSize before every query
            RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)&outVal, &dwSize);
            RegCloseKey(hKey);
        }
        };

    ReadDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "BrowserSignin", edgeVal);
    ReadDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "SyncDisabled", edgeSync);

    ReadDWORD("SOFTWARE\\Policies\\Google\\Chrome", "BrowserSignin", chromeVal);
    ReadDWORD("SOFTWARE\\Policies\\Google\\Chrome", "SyncDisabled", chromeSync);

    ReadDWORD("SOFTWARE\\Policies\\BraveSoftware\\Brave", "BrowserSignin", braveVal);
    ReadDWORD("SOFTWARE\\Policies\\BraveSoftware\\Brave", "SyncDisabled", braveSync);

    ReadDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "DisableFirefoxAccounts", firefoxAccounts);

    return (edgeVal == 0 && chromeVal == 0 && braveVal == 0 && firefoxAccounts == 1 &&
        edgeSync == 1 && chromeSync == 1 && braveSync == 1);
}

void ConfigureBrowserAccountLock(bool lockAccounts) {
    DWORD signinVal = lockAccounts ? 0 : 1;
    DWORD syncVal = lockAccounts ? 1 : 0;
    DWORD ffAccountVal = lockAccounts ? 1 : 0;

    auto WriteDWORD = [](const char* subkey, const char* valueName, DWORD val) {
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, valueName, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
            RegCloseKey(hKey);
        }
        };

    WriteDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "BrowserSignin", signinVal);
    WriteDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "SyncDisabled", syncVal);

    WriteDWORD("SOFTWARE\\Policies\\Google\\Chrome", "BrowserSignin", signinVal);
    WriteDWORD("SOFTWARE\\Policies\\Google\\Chrome", "SyncDisabled", syncVal);

    WriteDWORD("SOFTWARE\\Policies\\BraveSoftware\\Brave", "BrowserSignin", signinVal);
    WriteDWORD("SOFTWARE\\Policies\\BraveSoftware\\Brave", "SyncDisabled", syncVal);

    WriteDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "DisableFirefoxAccounts", ffAccountVal);

    if (lockAccounts) {
        std::vector<std::wstring> browsersToKill = {
            L"msedge.exe", L"chrome.exe", L"firefox.exe",
            L"brave.exe", L"opera.exe", L"vivaldi.exe"
        };
        TerminateProcessesByName(browsersToKill);
    }
}