#include "NetworkSecPolicies.h"

bool IsNetworkSecPoliciesHardened() {
    HKEY hKey;
    DWORD dwSize = sizeof(DWORD);
    DWORD lmCompat = 0, serverReq = 0, clientReq = 0;
    DWORD restrictAnon = 0, restrictSam = 0, ldapSigning = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "LmCompatibilityLevel", NULL, NULL, (LPBYTE)&lmCompat, &dwSize);
        RegQueryValueExA(hKey, "RestrictAnonymous", NULL, NULL, (LPBYTE)&restrictAnon, &dwSize);
        RegQueryValueExA(hKey, "RestrictAnonymousSAM", NULL, NULL, (LPBYTE)&restrictSam, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "RequireSecuritySignature", NULL, NULL, (LPBYTE)&serverReq, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "RequireSecuritySignature", NULL, NULL, (LPBYTE)&clientReq, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LDAP", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "LDAPClientIntegrity", NULL, NULL, (LPBYTE)&ldapSigning, &dwSize);
        RegCloseKey(hKey);
    }

    return (lmCompat == 5 && serverReq == 1 && clientReq == 1 &&
        restrictAnon >= 1 && restrictSam >= 1 && ldapSigning >= 2);
}

void ConfigureNetworkSecPolicies(bool harden) {
    HKEY hKey;
    DWORD lmCompat = harden ? 5 : 0;
    DWORD sigEnabled = harden ? 1 : 0;
    DWORD sigRequired = harden ? 1 : 0;
    DWORD restrictVal = harden ? 1 : 0;
    DWORD ldapVal = harden ? 2 : 0;

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "LmCompatibilityLevel", 0, REG_DWORD, (const BYTE*)&lmCompat, sizeof(lmCompat));
        RegSetValueExA(hKey, "RestrictAnonymous", 0, REG_DWORD, (const BYTE*)&restrictVal, sizeof(restrictVal));
        RegSetValueExA(hKey, "RestrictAnonymousSAM", 0, REG_DWORD, (const BYTE*)&restrictVal, sizeof(restrictVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigEnabled, sizeof(sigEnabled));
        RegSetValueExA(hKey, "RequireSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigRequired, sizeof(sigRequired));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigEnabled, sizeof(sigEnabled));
        RegSetValueExA(hKey, "RequireSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigRequired, sizeof(sigRequired));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LDAP", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "LDAPClientIntegrity", 0, REG_DWORD, (const BYTE*)&ldapVal, sizeof(ldapVal));
        RegCloseKey(hKey);
    }
}