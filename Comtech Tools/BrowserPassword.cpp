#include "BrowserPassword.h"
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <fstream>


void KillProcessByName(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

void KillBrowserProcesses() {
    KillProcessByName(L"chrome.exe");
    KillProcessByName(L"msedge.exe");
    KillProcessByName(L"brave.exe");
    KillProcessByName(L"firefox.exe");
}

static bool ReadPolicyDWORD(const char* subkey, const char* valueName, DWORD& outVal) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwType = REG_DWORD;
        DWORD dwSize = sizeof(DWORD);
        LONG result = RegQueryValueExA(hKey, valueName, NULL, &dwType, (LPBYTE)&outVal, &dwSize);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS && dwType == REG_DWORD);
    }
    return false;
}

static bool WritePolicyDWORD(const char* subkey, const char* valueName, DWORD val) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        LONG result = RegSetValueExA(hKey, valueName, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }
    return false;
}

static bool WritePolicyString(const char* subkey, const char* valueName, const char* val) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        LONG result = RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)val, (DWORD)(strlen(val) + 1));
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }
    return false;
}

// Checks if browser password saving is locked via Registry Group Policies
bool IsBrowserPasswordLocked() {
    DWORD edgeVal = 1, chromeVal = 1;
    bool edgeSet = ReadPolicyDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "PasswordManagerEnabled", edgeVal);
    bool chromeSet = ReadPolicyDWORD("SOFTWARE\\Policies\\Google\\Chrome", "PasswordManagerEnabled", chromeVal);

    // Locked if PasswordManagerEnabled is explicitly set to 0
    if ((edgeSet && edgeVal == 0) || (chromeSet && chromeVal == 0)) {
        return true;
    }
    return false;
}

// Checks if browser credential files (e.g., SQLite 'Login Data' or 'logins.json') exist on disk
bool AreBrowserCredentialsPresent() {
    char localAppData[MAX_PATH];
    char appData[MAX_PATH];

    bool foundCredentials = false;

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        std::vector<std::string> targetFiles = {
            std::string(localAppData) + "\\Google\\Chrome\\User Data\\Default\\Login Data",
            std::string(localAppData) + "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
            std::string(localAppData) + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
        };

        for (const auto& path : targetFiles) {
            DWORD dwAttrib = GetFileAttributesA(path.c_str());
            if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
                // Verify file is not empty
                std::ifstream file(path, std::ios::binary | std::ios::ate);
                if (file.is_open() && file.tellg() > 0) {
                    foundCredentials = true;
                    break;
                }
            }
        }
    }

    return foundCredentials;
}





void PurgeAllUsersBrowserCredentials() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Users\\*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {

            std::string baseUserPath = std::string("C:\\Users\\") + findData.cFileName + "\\AppData\\Local";

            std::vector<std::string> browserDataPaths = {
                baseUserPath + "\\Google\\Chrome\\User Data\\",
                baseUserPath + "\\Microsoft\\Edge\\User Data\\",
                baseUserPath + "\\BraveSoftware\\Brave-Browser\\User Data\\"
            };

            for (const auto& basePath : browserDataPaths) {
                // Purge Default profile
                DeleteFileA((basePath + "Default\\Login Data").c_str());

                // Purge Profile 1 through Profile 10
                for (int i = 1; i <= 10; ++i) {
                    std::string profilePath = basePath + "Profile " + std::to_string(i) + "\\Login Data";
                    DeleteFileA(profilePath.c_str());
                }
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

// Enforces or disables browser password manager policies
void ConfigureBrowserPasswordLock(bool lockPasswords) {
    DWORD passVal = lockPasswords ? 0 : 1;

    // 1. Lock saving/autofilling of new passwords
    WritePolicyDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\Google\\Chrome", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\BraveSoftware\\Brave", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "OfferToSaveLogins", passVal);

    // 2. Force automated native deletion of pre-existing saved passwords
    if (lockPasswords) {
        WritePolicyString("SOFTWARE\\Policies\\Microsoft\\Edge\\ClearBrowsingDataOnExitList", "1", "password_signin");
        WritePolicyString("SOFTWARE\\Policies\\Google\\Chrome\\ClearBrowsingDataOnExitList", "1", "password_signin");
        WritePolicyString("SOFTWARE\\Policies\\BraveSoftware\\Brave\\ClearBrowsingDataOnExitList", "1", "password_signin");
        WritePolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "DisablePasswordManager", 1);


        KillBrowserProcesses();
        PurgeAllUsersBrowserCredentials();
    }
}