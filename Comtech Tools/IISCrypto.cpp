#include "IISCrypto.h"
#include "Resource.h"
#include <vector>

bool CheckSchannelKeyDisabled(const char* subKey) {
    HKEY hKey;
    DWORD enabled = 1;
    DWORD dwSize = sizeof(DWORD);
    char fullPath[512];

    snprintf(fullPath, sizeof(fullPath), "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\%s", subKey);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&enabled, &dwSize) != ERROR_SUCCESS) {
            enabled = 1;
        }
        RegCloseKey(hKey);
    }
    return (enabled == 0);
}
// IISCrypto.cpp

bool DoesSystemMatchCustomTemplate() {
    // 1. Verify strict protocols are explicitly disabled in registry
    bool protocolsOk = CheckSchannelKeyDisabled("Protocols\\SSL 2.0\\Server") &&
        CheckSchannelKeyDisabled("Protocols\\SSL 2.0\\Client") &&
        CheckSchannelKeyDisabled("Protocols\\SSL 3.0\\Server") &&
        CheckSchannelKeyDisabled("Protocols\\SSL 3.0\\Client") &&
        CheckSchannelKeyDisabled("Protocols\\TLS 1.0\\Server") &&
        CheckSchannelKeyDisabled("Protocols\\TLS 1.0\\Client") &&
        CheckSchannelKeyDisabled("Protocols\\TLS 1.1\\Server") &&
        CheckSchannelKeyDisabled("Protocols\\TLS 1.1\\Client");

    // 2. Verify weak ciphers and hashes are disabled
    bool ciphersOk = CheckSchannelKeyDisabled("Ciphers\\RC4 128/128") &&
        CheckSchannelKeyDisabled("Ciphers\\NULL") &&
        CheckSchannelKeyDisabled("Ciphers\\DES 56/56") &&
        CheckSchannelKeyDisabled("Hashes\\MD5");

    // Return true ONLY if every requirement defined in your template is met
    return protocolsOk && ciphersOk;
}

bool IsSslTlsHardened() {
    // Returns true (Secured) only if all template conditions match
    return DoesSystemMatchCustomTemplate();
}

bool ExtractResourceToFile(int resourceID, const std::wstring& outputPath) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(resourceID), RT_RCDATA);
    if (!hRes) return false;

    HGLOBAL hMem = LoadResource(hModule, hRes);
    if (!hMem) return false;

    DWORD fileSize = SizeofResource(hModule, hRes);
    LPVOID pData = LockResource(hMem);
    if (!pData || fileSize == 0) return false;

    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten = 0;
    WriteFile(hFile, pData, fileSize, &bytesWritten, NULL);
    CloseHandle(hFile);

    return true;
}

bool RunEmbeddedIISCrypto(bool useCustomTemplate) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::wstring exePath = std::wstring(tempPath) + L"IISCryptoCli_Temp.exe";
    std::wstring tplPath = std::wstring(tempPath) + L"CustomHardening.ictpl";

    if (!ExtractResourceToFile(IDR_IISCRYPTOCLI, exePath)) return false;

    std::wstring commandLine = L"\"" + exePath + L"\" ";
    if (useCustomTemplate) {
        if (!ExtractResourceToFile(IDR_CUSTOMTEMPLATE, tplPath)) {
            DeleteFileW(exePath.c_str());
            return false;
        }
        commandLine += L"/template \"" + tplPath + L"\"";
    }
    else {
        commandLine += L"/template default";
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    BOOL success = CreateProcessW(NULL, &commandLine[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DeleteFileW(exePath.c_str());
    if (useCustomTemplate) {
        DeleteFileW(tplPath.c_str());
    }

    return success;
}

bool LaunchIISCryptoGUI() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::wstring exePath = std::wstring(tempPath) + L"IISCrypto.exe";

    // Extract the GUI binary from resources (e.g., IDR_IISCRYPTOGUI)
    if (ExtractResourceToFile(IDR_IISCRYPTOGUI, exePath)) {
        HINSTANCE hInst = ShellExecuteW(NULL, L"runas", exePath.c_str(), NULL, NULL, SW_SHOWNORMAL);
        return (INT_PTR)hInst > 32;
    }
    return false;
}

void ConfigureSslTlsIISCrypto(bool harden) {
    if (harden) {
        RunEmbeddedIISCrypto(true);
    }
    else {
        // Instead of applying default CLI template/reverting, launch the GUI app
        LaunchIISCryptoGUI();
    }
}