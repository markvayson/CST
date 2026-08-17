#include "WindowsFeatures.h"
#include <windows.h>
#include <string>

void UpdateStatus(const std::string& msg);

// Helper to disable service auto-start state instantly (0ms)
static void FastDisableService(const char* serviceName) {
    HKEY hKey;
    std::string keyPath = std::string("SYSTEM\\CurrentControlSet\\Services\\") + serviceName;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD disabled = 4; // 4 = SERVICE_DISABLED
        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (const BYTE*)&disabled, sizeof(disabled));
        RegCloseKey(hKey);
    }
}

bool AreUnneededWindowsFeaturesEnabled() {
    HKEY hKey;
    const char* services[] = { "W3SVC", "TlntSvr", "mrxsmb10", "smbdirect" };

    for (const char* service : services) {
        std::string keyPath = std::string("SYSTEM\\CurrentControlSet\\Services\\") + service;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD startVal = 4;
            DWORD dwSize = sizeof(DWORD);
            if (RegQueryValueExA(hKey, "Start", NULL, NULL, (LPBYTE)&startVal, &dwSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                if (startVal < 4) return true; // Enabled/Insecure
            }
            else {
                RegCloseKey(hKey);
            }
        }
    }
    return false;
}

void DisableUnneededWindowsFeaturesNative() {
    UpdateStatus("Applying ADHICS v2 feature hardening rules...");

    // 1. Instantly disable target services in registry (0ms execution time)
    FastDisableService("mrxsmb10");
    FastDisableService("smbdirect");
    FastDisableService("W3SVC");
    FastDisableService("WAS");

    // 2. Run PowerShell in background to uncheck controls natively in Windows
    wchar_t params[] = L"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "
        L"Start-Job -ScriptBlock { "
        L"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol, SmbDirect, TelnetClient, IIS-WebServerRole -NoRestart "
        L"}";

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;

    ShellExecuteExW(&sei);

    UpdateStatus("Unused Windows features disabled successfully.");
}