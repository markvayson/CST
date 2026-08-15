#include "SmbProtocol.h"
#include <windows.h>

// Forward declaration for helper function defined in main or service file
bool RestartWin32Service(const char* serviceName);

bool IsSMBv1Disabled() {
    HKEY hKey;
    DWORD smb1 = 1, dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SMB1", NULL, NULL, (LPBYTE)&smb1, &dwSize);
        RegCloseKey(hKey);
    }
    return (smb1 == 0);
}

void ConfigureSMB(bool harden) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD dwSmb1 = harden ? 0 : 1;
        DWORD dwSmb2 = 1;
        RegSetValueExA(hKey, "SMB1", 0, REG_DWORD, (const BYTE*)&dwSmb1, sizeof(dwSmb1));
        RegSetValueExA(hKey, "SMB2", 0, REG_DWORD, (const BYTE*)&dwSmb2, sizeof(dwSmb2));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD dwStart = harden ? 4 : 2;
        RegSetValueExA(hKey, "Start", 0, REG_DWORD, (const BYTE*)&dwStart, sizeof(dwStart));
        RegCloseKey(hKey);
    }
    RestartWin32Service("LanmanServer");
}