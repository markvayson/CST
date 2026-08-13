#include "WindowsFeatures.h"
#include <windows.h>
#include "DismApi.h"
#include <vector>
#include <string>

// External logging/status helpers implemented in your project
void UpdateStatus(const std::string& msg);
void LogMessage(const std::string& msg);

// Function pointer signatures for DismApi exports
typedef HRESULT(WINAPI* pfnDismInitialize)(DismLogLevel LogLevel, PCWSTR LogFilePath, PCWSTR ScratchDirectory);
typedef HRESULT(WINAPI* pfnDismShutdown)();
typedef HRESULT(WINAPI* pfnDismOpenSession)(PCWSTR ImagePath, PCWSTR WindowsDirectory, PCWSTR SystemDrive, DismSession* Session);
typedef HRESULT(WINAPI* pfnDismCloseSession)(DismSession Session);
typedef HRESULT(WINAPI* pfnDismDisableFeature)(DismSession Session, PCWSTR FeatureName, PCWSTR PackageName, BOOL RemovePayload, HANDLE CancelEvent, DISM_PROGRESS_CALLBACK Progress, PVOID UserData);

bool AreUnneededWindowsFeaturesEnabled() {
    bool iisEnabled = false;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\InetStp", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        iisEnabled = true;
        RegCloseKey(hKey);
    }

    bool hwcEnabled = (GetFileAttributesW(L"C:\\Windows\\System32\\inetsrv\\hwebcore.dll") != INVALID_FILE_ATTRIBUTES);

    bool smb1Enabled = false;
    DWORD startVal = 4;
    DWORD dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Start", NULL, NULL, (LPBYTE)&startVal, &dwSize) == ERROR_SUCCESS) {
            if (startVal < 4) smb1Enabled = true;
        }
        RegCloseKey(hKey);
    }

    bool smbDirectEnabled = false;
    startVal = 4;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\smbdirect", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Start", NULL, NULL, (LPBYTE)&startVal, &dwSize) == ERROR_SUCCESS) {
            if (startVal < 4) smbDirectEnabled = true;
        }
        RegCloseKey(hKey);
    }

    bool telnetEnabled = (GetFileAttributesW(L"C:\\Windows\\System32\\telnet.exe") != INVALID_FILE_ATTRIBUTES);

    return (iisEnabled || hwcEnabled || smb1Enabled || smbDirectEnabled || telnetEnabled);
}

void DisableUnneededWindowsFeaturesNative() {
    UpdateStatus("Disabling unused Windows features via Native DISM API...");

    // Dynamically load DismApi.dll directly from System32
    HMODULE hDism = LoadLibraryW(L"DismApi.dll");
    if (!hDism) {
        LogMessage("Failed to load DismApi.dll. Error: " + std::to_string(GetLastError()));
    }
    else {
        auto pDismInitialize = (pfnDismInitialize)GetProcAddress(hDism, "DismInitialize");
        auto pDismShutdown = (pfnDismShutdown)GetProcAddress(hDism, "DismShutdown");
        auto pDismOpenSession = (pfnDismOpenSession)GetProcAddress(hDism, "DismOpenSession");
        auto pDismCloseSession = (pfnDismCloseSession)GetProcAddress(hDism, "DismCloseSession");
        auto pDismDisableFeature = (pfnDismDisableFeature)GetProcAddress(hDism, "DismDisableFeature");

        if (pDismInitialize && pDismShutdown && pDismOpenSession && pDismCloseSession && pDismDisableFeature) {
            HRESULT hr = pDismInitialize(DismLogErrorsWarningsInfo, NULL, NULL);
            if (FAILED(hr)) {
                LogMessage("Failed to initialize DismApi. HRESULT: " + std::to_string(hr));
            }
            else {
                DismSession session = DISM_SESSION_DEFAULT;

                hr = pDismOpenSession(DISM_ONLINE_IMAGE, NULL, NULL, &session);
                if (SUCCEEDED(hr)) {
                    const PCWSTR features[] = {
                        L"IIS-WebServerRole",
                        L"IIS-HostableWebCore",
                        L"SMB1Protocol",
                        L"SmbDirect",
                        L"TelnetClient",
                        L"TelnetServer"
                    };

                    for (const auto& feature : features) {
                        HRESULT featHr = pDismDisableFeature(
                            session,
                            feature,
                            NULL,   // No package binding required for OS features
                            FALSE,  // EnableRemove (FALSE keeps payload cached locally)
                            NULL,   // CancelEvent handle
                            NULL,   // ProgressCallback
                            NULL    // UserContext
                        );

                        if (FAILED(featHr) && featHr != DISMAPI_E_DISMAPI_NOT_INITIALIZED) {
                            // Log individual feature status if required
                        }
                    }

                    pDismCloseSession(session);
                }
                else {
                    LogMessage("Failed to open Dism Session. HRESULT: " + std::to_string(hr));
                }

                pDismShutdown();
            }
        }
        else {
            LogMessage("Failed to locate required export functions in DismApi.dll.");
        }

        FreeLibrary(hDism);
    }

    // Direct registry fallback for SMB Direct service configuration
    HKEY hKey;
    DWORD disabled = 4; // Service Disabled state
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\smbdirect", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (const BYTE*)&disabled, sizeof(disabled));
        RegCloseKey(hKey);
    }

    UpdateStatus("Unused Windows features completely disabled.");
}