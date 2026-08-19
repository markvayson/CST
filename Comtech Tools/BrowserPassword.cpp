#include "BrowserPassword.h"
#include <windows.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <fstream>

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



// Safely deletes browser password credential databases across user profiles
void PurgeBrowserCredentialDatabases() {
    char localAppData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        std::vector<std::string> targetFiles = {
            std::string(localAppData) + "\\Google\\Chrome\\User Data\\Default\\Login Data",
            std::string(localAppData) + "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
            std::string(localAppData) + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
        };

        for (const auto& path : targetFiles) {
            DeleteFileA(path.c_str());
        }
    }
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

        PurgeBrowserCredentialDatabases();
    }
}