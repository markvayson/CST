#include "BrowserPassword.h"
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <algorithm>

namespace {

bool IsProcessRunning(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    bool running = false;
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                running = true;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return running;
}

void KillProcessByName(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    WaitForSingleObject(hProcess, 2000);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

void KillBrowserProcesses() {
    const wchar_t* processes[] = {
        L"chrome.exe", L"msedge.exe", L"brave.exe", L"firefox.exe",
        L"opera.exe", L"vivaldi.exe", L"chromium.exe"
    };

    for (const auto* proc : processes) {
        KillProcessByName(proc);
    }

    // Give the OS a moment to release file locks
    for (int i = 0; i < 20; ++i) {
        bool anyRunning = false;
        for (const auto* proc : processes) {
            if (IsProcessRunning(proc)) { anyRunning = true; break; }
        }
        if (!anyRunning) break;
        Sleep(100);
        for (const auto* proc : processes) {
            KillProcessByName(proc);
        }
    }
    Sleep(300);
}

bool ReadPolicyDWORD(const char* subkey, const char* valueName, DWORD& outVal) {
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

bool WritePolicyDWORD(const char* subkey, const char* valueName, DWORD val) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        LONG result = RegSetValueExA(hKey, valueName, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }
    return false;
}

bool WritePolicyString(const char* subkey, const char* valueName, const char* val) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        LONG result = RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)val, (DWORD)(strlen(val) + 1));
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }
    return false;
}

bool DeletePolicyValue(const char* subkey, const char* valueName) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        LONG result = RegDeleteValueA(hKey, valueName);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
    }
    return true; // key absent => nothing to delete
}

bool IsPasswordManagerDisabledPolicy(const char* subkey) {
    DWORD val = 1;
    return ReadPolicyDWORD(subkey, "PasswordManagerEnabled", val) && val == 0;
}

bool FileExists(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool DeleteFileWithRetry(const std::string& path) {
    if (!FileExists(path)) return true;
    for (int i = 0; i < 5; ++i) {
        if (DeleteFileA(path.c_str())) return true;
        // Try to clear read-only/hidden attributes that may block deletion
        SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        Sleep(150);
    }
    return !FileExists(path);
}

std::vector<std::string> EnumerateUserRoots() {
    std::vector<std::string> roots;
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Users\\*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) return roots;

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            std::string name = findData.cFileName;
            // Skip common non-profile junction/system folders
            if (_stricmp(name.c_str(), "All Users") == 0 ||
                _stricmp(name.c_str(), "Default User") == 0) {
                continue;
            }
            roots.push_back(std::string("C:\\Users\\") + name);
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return roots;
}

std::vector<std::string> EnumerateChromiumProfiles(const std::string& userDataDir) {
    std::vector<std::string> profiles;
    std::string pattern = userDataDir + "*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return profiles;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        std::string name = fd.cFileName;
        if (name == "Default" || name.rfind("Profile ", 0) == 0 || name.rfind("Guest Profile", 0) == 0) {
            profiles.push_back(userDataDir + name + "\\");
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return profiles;
}

std::vector<std::string> EnumerateFirefoxProfiles(const std::string& profilesDir) {
    std::vector<std::string> profiles;
    std::string pattern = profilesDir + "*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return profiles;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        profiles.push_back(profilesDir + fd.cFileName + "\\");
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return profiles;
}

std::vector<std::string> GetChromiumUserDataDirs(const std::string& localAppData) {
    return {
        localAppData + "\\Google\\Chrome\\User Data\\",
        localAppData + "\\Microsoft\\Edge\\User Data\\",
        localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\",
        localAppData + "\\Vivaldi\\User Data\\",
        localAppData + "\\Chromium\\User Data\\",
        localAppData + "\\Opera Software\\Opera Stable\\",
        localAppData + "\\Opera Software\\Opera GX Stable\\"
    };
}

bool PurgeChromiumProfile(const std::string& profilePath) {
    bool ok = true;
    const char* files[] = {
        "Login Data", "Login Data-journal", "Login Data For Account", "Login Data For Account-journal"
    };
    for (const auto* f : files) {
        ok &= DeleteFileWithRetry(profilePath + f);
    }
    return ok;
}

bool HasChromiumCredentials(const std::string& profilePath) {
    const char* files[] = { "Login Data", "Login Data For Account" };
    for (const auto* f : files) {
        if (FileExists(profilePath + f)) return true;
    }
    return false;
}

bool PurgeFirefoxProfile(const std::string& profilePath) {
    bool ok = true;
    const char* files[] = { "logins.json", "key4.db", "signons.sqlite", "logins-backup.json" };
    for (const auto* f : files) {
        ok &= DeleteFileWithRetry(profilePath + f);
    }
    return ok;
}

bool HasFirefoxCredentials(const std::string& profilePath) {
    return FileExists(profilePath + "logins.json") || FileExists(profilePath + "signons.sqlite");
}

void PurgeAllUsersBrowserCredentials() {
    auto userRoots = EnumerateUserRoots();
    for (const auto& userRoot : userRoots) {
        std::string localAppData = userRoot + "\\AppData\\Local";
        std::string roamingAppData = userRoot + "\\AppData\\Roaming";

        for (const auto& userDataDir : GetChromiumUserDataDirs(localAppData)) {
            auto profiles = EnumerateChromiumProfiles(userDataDir);
            // Opera Stable/GX store profile files directly in the base dir (no Default subprofile in same way)
            if (userDataDir.find("Opera Software") != std::string::npos) {
                profiles.push_back(userDataDir);
            }
            for (const auto& profile : profiles) {
                PurgeChromiumProfile(profile);
            }
        }

        std::vector<std::string> firefoxProfileRoots = {
            roamingAppData + "\\Mozilla\\Firefox\\Profiles\\",
            localAppData + "\\Mozilla\\Firefox\\Profiles\\"
        };
        for (const auto& root : firefoxProfileRoots) {
            for (const auto& profile : EnumerateFirefoxProfiles(root)) {
                PurgeFirefoxProfile(profile);
            }
        }
    }
}

} // namespace

// Checks if browser password saving is locked via Registry Group Policies
bool IsBrowserPasswordLocked() {
    bool edge = IsPasswordManagerDisabledPolicy("SOFTWARE\\Policies\\Microsoft\\Edge");
    bool chrome = IsPasswordManagerDisabledPolicy("SOFTWARE\\Policies\\Google\\Chrome");
    bool brave = IsPasswordManagerDisabledPolicy("SOFTWARE\\Policies\\BraveSoftware\\Brave");

    DWORD ffMgr = 1, ffOffer = 1, ffDisable = 0;
    bool ffMgrSet = ReadPolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "PasswordManagerEnabled", ffMgr);
    bool ffOfferSet = ReadPolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "OfferToSaveLogins", ffOffer);
    bool ffDisableSet = ReadPolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "DisablePasswordManager", ffDisable);
    bool firefox = (ffMgrSet && ffMgr == 0) || (ffOfferSet && ffOffer == 0) || (ffDisableSet && ffDisable == 1);

    // Consider locked when all major Chromium browsers and Firefox are locked by policy
    return edge && chrome && brave && firefox;
}

// Checks if browser credential files exist on disk for any user/profile
bool AreBrowserCredentialsPresent() {
    auto userRoots = EnumerateUserRoots();
    for (const auto& userRoot : userRoots) {
        std::string localAppData = userRoot + "\\AppData\\Local";
        std::string roamingAppData = userRoot + "\\AppData\\Roaming";

        for (const auto& userDataDir : GetChromiumUserDataDirs(localAppData)) {
            auto profiles = EnumerateChromiumProfiles(userDataDir);
            if (userDataDir.find("Opera Software") != std::string::npos) {
                profiles.push_back(userDataDir);
            }
            for (const auto& profile : profiles) {
                if (HasChromiumCredentials(profile)) return true;
            }
        }

        std::vector<std::string> firefoxProfileRoots = {
            roamingAppData + "\\Mozilla\\Firefox\\Profiles\\",
            localAppData + "\\Mozilla\\Firefox\\Profiles\\"
        };
        for (const auto& root : firefoxProfileRoots) {
            for (const auto& profile : EnumerateFirefoxProfiles(root)) {
                if (HasFirefoxCredentials(profile)) return true;
            }
        }
    }
    return false;
}

// Enforces or disables browser password manager policies
void ConfigureBrowserPasswordLock(bool lockPasswords) {
    DWORD passVal = lockPasswords ? 0 : 1;

    // Lock/unlock saving and autofill of passwords
    WritePolicyDWORD("SOFTWARE\\Policies\\Microsoft\\Edge", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\Google\\Chrome", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\BraveSoftware\\Brave", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "PasswordManagerEnabled", passVal);
    WritePolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "OfferToSaveLogins", passVal);

    if (lockPasswords) {
        // Configure browsers to clear passwords on exit as an extra safeguard
        WritePolicyString("SOFTWARE\\Policies\\Microsoft\\Edge\\ClearBrowsingDataOnExitList", "1", "password_signin");
        WritePolicyString("SOFTWARE\\Policies\\Google\\Chrome\\ClearBrowsingDataOnExitList", "1", "password_signin");
        WritePolicyString("SOFTWARE\\Policies\\BraveSoftware\\Brave\\ClearBrowsingDataOnExitList", "1", "password_signin");
        WritePolicyDWORD("SOFTWARE\\Policies\\Mozilla\\Firefox", "DisablePasswordManager", 1);

        // Stop browsers, purge credential stores for all users/profiles, and retry once
        KillBrowserProcesses();
        PurgeAllUsersBrowserCredentials();

        if (AreBrowserCredentialsPresent()) {
            KillBrowserProcesses();
            PurgeAllUsersBrowserCredentials();
        }
    } else {
        // Remove forced clear-on-exit password entries and Firefox hard-disable on unlock
        DeletePolicyValue("SOFTWARE\\Policies\\Microsoft\\Edge\\ClearBrowsingDataOnExitList", "1");
        DeletePolicyValue("SOFTWARE\\Policies\\Google\\Chrome\\ClearBrowsingDataOnExitList", "1");
        DeletePolicyValue("SOFTWARE\\Policies\\BraveSoftware\\Brave\\ClearBrowsingDataOnExitList", "1");
        DeletePolicyValue("SOFTWARE\\Policies\\Mozilla\\Firefox", "DisablePasswordManager");
    }
}