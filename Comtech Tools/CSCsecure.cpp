#define WIN32_LEAN_AND_MEAN
#include "CSCsecure.h"
#include "ConfirmDialog.h"
#include <windows.h>
#include <commctrl.h>
#include <setupapi.h>
#include <devguid.h>
#include <userenv.h>
#include <cfgmgr32.h>
#include <winspool.h>
#include <lm.h>
#include <stdio.h>
#include <time.h>
#include <string>


#include <vector>
#include <regex>
#include <fstream>
#include <iostream>
#include "Resource.h"
#include <sstream>
#include <d2d1.h>
#include <dwmapi.h> 
#include "Inventory.h"
#include "version.h"
#include "SearchPass.h"
#include "Theme.h"
#include <thread>
#include "Sidebar.h"

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "dwmapi.lib") 
#pragma comment(lib, "version.lib")
#pragma comment(lib, "userenv.lib")

std::string g_appProductName = "";
std::string g_appVersion = "";


// Retrieves a StringFileInfo entry from VS_VERSION_INFO in resources
std::string GetFileVersionValue(const char* valueName) {
    char szPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, szPath, MAX_PATH)) return "";

    DWORD dwDummy = 0;
    DWORD dwSize = GetFileVersionInfoSizeA(szPath, &dwDummy);
    if (dwSize == 0) return "";

    std::vector<BYTE> data(dwSize);
    if (!GetFileVersionInfoA(szPath, 0, dwSize, data.data())) return "";

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *pTranslate = nullptr;
    UINT cbTranslate = 0;

    char subBlock[256];
    if (VerQueryValueA(data.data(), "\\VarFileInfo\\Translation", (LPVOID*)&pTranslate, &cbTranslate) && cbTranslate >= sizeof(LANGANDCODEPAGE)) {
        snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%04x%04x\\%s",
            pTranslate[0].wLanguage, pTranslate[0].wCodePage, valueName);
    }
    else {
        snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\040904b0\\%s", valueName);
    }

    LPVOID lpBuffer = NULL;
    UINT len = 0;
    if (VerQueryValueA(data.data(), subBlock, &lpBuffer, &len) && lpBuffer && len > 0) {
        return std::string(static_cast<char*>(lpBuffer));
    }

    return "";
}

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1
#define DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 19
#endif

#ifndef DPC_ENABLE
#define DPC_ENABLE 0x00000001
#endif
#ifndef DPC_DISABLE
#define DPC_DISABLE 0x00000002
#endif
#ifndef DCPC_GLOBAL
#define DCPC_GLOBAL 0x00000001
#endif

template <class T> void SafeRelease(T** ppT) {
    if (*ppT) {
        (*ppT)->Release();
        *ppT = NULL;
    }
}

#ifndef IDR_IISCRYPTOCLI
#define IDR_IISCRYPTOCLI 101
#endif

#ifndef IDI_ICON1
#define IDI_ICON1 102
#endif

// Control & Menu IDs
#define ID_BTN_SECURE_ALL    1003
#define ID_LOG_EDIT          1005
#define ID_BTN_MENU          1006
#define ID_HARD_BASE         2000
#ifndef IDM_ABOUT
#define IDM_ABOUT            3002
#endif
#define IDM_SEARCHPASS       3003
#define IDM_WINUPDATE        3004
#define IDM_INVENTORY        3005

HWND g_hMainWnd = NULL;
HWND g_hLogWnd = NULL;
HWND g_hLogEdit = NULL;

// Execution State & Live Feedback Message
std::string g_statusText = "";
bool g_isExecuting = false;
std::vector<std::string> g_logMemory;


// Metric Counts 
int g_totalControls = 10;
int g_secureCount = 0;
int g_attentionCount = 0;
int g_insecureCount = 0;

int g_hardStates[10] = { 2, 2, 2, 1, 1, 1, 2, 2, 2, 2 };


struct HardeningRow {
    const char* name;
    std::string liveInfo;
    std::string statusLabel;
    const char* actionLabel;
    wchar_t iconGlyph;
    HWND hBtnAction;
};

// Row Definitions with Segoe MDL2 Icon Codes
HardeningRow g_hardRows[10] = {
    {"Bluetooth Adapter", "Auditing...", "Auditing...", "Disable", L'\xE702', NULL},
    {"Wi-Fi Network Adapter", "Auditing...", "Auditing...", "Disable", L'\xE701', NULL},
    {"SMB Server Protocols", "Auditing...", "Auditing...", "Secure", L'\xE839', NULL},
    {"Shared Network Printers", "Auditing...", "Auditing...", "Secure", L'\xE749', NULL},
    {"Shared Network Folders / Files", "Auditing...", "Auditing...", "Secure", L'\xE8B7', NULL},
    {"SSL / TLS & Ciphers", "Auditing...", "Auditing...", "Secure", L'\xE72E', NULL},
    {"Browser Account Login", "Auditing...", "Auditing...", "Lock", L'\xE77B', NULL},
    {"Browser Password Lock", "Auditing...", "Auditing...", "Lock", L'\xE890', NULL},
    {"Local User Accounts", "Auditing...", "Auditing...", "Secure", L'\xE716', NULL},
    {"Network Security Policies", "Auditing...", "Auditing...", "Secure", L'\xE912', NULL}
};

struct PrinterStatus {
    std::string name;
    std::string shareName;
    bool isShared = false;
};

std::vector<PrinterStatus> g_printerList;

void LogMessage(const std::string& msg);
void UpdateStatus(const std::string& msg);
bool RestartWin32Service(const char* serviceName);
void UnshareAllPrinters();

void LoadVersionInfoFromResource() {
    std::string name = GetFileVersionValue("ProductName");
    std::string ver = GetFileVersionValue("ProductVersion");
    std::string desc = GetFileVersionValue("FileDescription");

    if (!name.empty()) g_appProductName = name;
    if (!ver.empty()) g_appVersion = ver;
}




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

std::string GetLocalUserAccountsInfo(int& outUserCount, bool& outAllDisabled, bool& outAllPasswordsExpire) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    outUserCount = 0;
    outAllDisabled = true;
    outAllPasswordsExpire = true;
    std::vector<std::string> activeUsers;

    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            if (_stricmp(userName.c_str(), "Mark") == 0) continue;

            outUserCount++;

            if ((pBuf[i].usri1_flags & UF_ACCOUNTDISABLE) == 0) {
                outAllDisabled = false;
                activeUsers.push_back(userName);
            }
            if (pBuf[i].usri1_flags & UF_DONT_EXPIRE_PASSWD) {
                outAllPasswordsExpire = false;
            }
        }
        NetApiBufferFree(pBuf);
    }

    if (outUserCount == 0) return "No local user accounts detected.";

    std::string baseMsg;
    if (outAllDisabled) {
        baseMsg = "Non-essential user accounts are disabled.";
    }
    else if (activeUsers.size() == 1) {
        baseMsg = activeUsers[0] + " account is currently active.";
    }
    else {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s and %d other accounts are active.", activeUsers[0].c_str(), (int)(activeUsers.size() - 1));
        baseMsg = std::string(buf);
    }

    if (!outAllPasswordsExpire) {
        if (outAllDisabled) return "Accounts disabled, but 'Password never expires' is enabled.";
        return baseMsg + " (Pass never expires is ticked).";
    }
    return baseMsg;
}

void ConfigureLocalUsers(bool disableAccounts) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            if (_stricmp(userName.c_str(), "Mark") == 0) continue;

            USER_INFO_1008 ui1008;
            DWORD dwParmErr = 0;

            ui1008.usri1008_flags = pBuf[i].usri1_flags;
            if (disableAccounts) {
                ui1008.usri1008_flags |= UF_ACCOUNTDISABLE;
                ui1008.usri1008_flags &= ~UF_DONT_EXPIRE_PASSWD;
            }
            else {
                ui1008.usri1008_flags &= ~UF_ACCOUNTDISABLE;
            }
            NetUserSetInfo(NULL, wUserName.c_str(), 1008, (LPBYTE)&ui1008, &dwParmErr);
        }
        NetApiBufferFree(pBuf);
    }
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

void LogMessage(const std::string& msg) {
    time_t rawtime;
    struct tm timeinfo;
    char timeBuffer[64];

    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);
    strftime(timeBuffer, sizeof(timeBuffer), "[%Y-%m-%d %H:%M:%S] ", &timeinfo);

    std::string formattedLog = std::string(timeBuffer) + msg;
    g_logMemory.push_back(formattedLog);

    std::ofstream logFile("FastSystemSecurity.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << formattedLog << std::endl;
        logFile.close();
    }

    if (g_hLogEdit && IsWindow(g_hLogEdit)) {
        std::string fullLogText = "";
        for (const auto& line : g_logMemory) {
            fullLogText += line + "\r\n";
        }
        SetWindowTextA(g_hLogEdit, fullLogText.c_str());
        SendMessageA(g_hLogEdit, EM_SETSEL, (WPARAM)fullLogText.length(), (LPARAM)fullLogText.length());
        SendMessageA(g_hLogEdit, EM_SCROLLCARET, 0, 0);
    }
}

void UpdateStatus(const std::string& msg) {
    g_statusText = msg;
    LogMessage(msg);
    if (g_hMainWnd) {
        RedrawWindow(g_hMainWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    }
}

LRESULT CALLBACK LogWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        g_hLogEdit = CreateWindowExA(0, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, 0, rc.right, rc.bottom, hwnd, (HMENU)(UINT_PTR)ID_LOG_EDIT, NULL, NULL);

        SendMessageA(g_hLogEdit, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);
        std::string fullLogText = "";
        for (const auto& line : g_logMemory) fullLogText += line + "\r\n";
        SetWindowTextA(g_hLogEdit, fullLogText.c_str());
        break;
    }
    case WM_SIZE:
        MoveWindow(g_hLogEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        g_hLogWnd = NULL;
        g_hLogEdit = NULL;
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ShowLogWindow(HWND hParent) {
    if (g_hLogWnd) {
        SetForegroundWindow(g_hLogWnd);
        return;
    }
    const char LOG_CLASS[] = "SecurityToolLogViewer";
    WNDCLASS wc = {};
    wc.lpfnWndProc = LogWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = LOG_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    g_hLogWnd = CreateWindowExA(0, LOG_CLASS, "Execution Logs - CSCsecure",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 700, 450, hParent, NULL, GetModuleHandle(NULL), NULL);
}

void RunSilentCmd(const char* cmd) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char fullCmd[1024];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", cmd);

    if (CreateProcessA(NULL, fullCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        while (WaitForSingleObject(pi.hProcess, 50) == WAIT_TIMEOUT) {
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

std::vector<PrinterStatus> GetSystemPrintersInfo() {
    std::vector<PrinterStatus> printerList;
    DWORD cbNeeded = 0, cReturned = 0;

    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, NULL, 0, &cbNeeded, &cReturned);
    if (cbNeeded == 0) return printerList;

    std::vector<BYTE> buffer(cbNeeded);
    if (EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, buffer.data(), cbNeeded, &cbNeeded, &cReturned)) {
        PRINTER_INFO_2A* pPrinterInfo = reinterpret_cast<PRINTER_INFO_2A*>(buffer.data());

        for (DWORD i = 0; i < cReturned; i++) {
            PrinterStatus status;
            status.name = pPrinterInfo[i].pPrinterName ? pPrinterInfo[i].pPrinterName : "Unknown Printer";
            status.isShared = (pPrinterInfo[i].Attributes & PRINTER_ATTRIBUTE_SHARED) != 0;
            status.shareName = (status.isShared && pPrinterInfo[i].pShareName) ? pPrinterInfo[i].pShareName : "";
            printerList.push_back(status);
        }
    }
    return printerList;
}

void SetSpoolerClientConnectionsPolicy(bool disableConnections) {
    HKEY hKey;
    LPCWSTR subKey = L"Software\\Policies\\Microsoft\\Windows NT\\Printers";

    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (status == ERROR_SUCCESS) {
        if (disableConnections) {
            DWORD value = 2;
            RegSetValueExW(hKey, L"RegisterSpoolerRemoteRpcEndPoint", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
            LogMessage("Policy 'Allow Print Spooler to accept client connections' set to Disabled.");
        }
        else {
            RegDeleteValueW(hKey, L"RegisterSpoolerRemoteRpcEndPoint");
            LogMessage("Policy 'Allow Print Spooler to accept client connections' reverted to Not Configured.");
        }
        RegCloseKey(hKey);
    }
    else {
        LogMessage("Failed to open or create registry key for Printer policies. Run as Administrator.");
        return;
    }

    LogMessage("Refreshing machine policy natively...");
    RefreshPolicyEx(TRUE, RP_FORCE);

    LogMessage("Restarting Print Spooler service natively...");
    if (RestartWin32Service("Spooler")) {
        LogMessage("Spooler client connection policy applied successfully.");
    }
    else {
        LogMessage("Failed to restart Spooler service natively.");
    }
}

void OnLockdownPrintersButtonClicked() {
    UnshareAllPrinters();
    SetSpoolerClientConnectionsPolicy(true);
}

void OnRevertPrintersButtonClicked() {
    SetSpoolerClientConnectionsPolicy(false);
}

void UnshareAllPrinters() {
    DWORD cbNeeded = 0, cReturned = 0;
    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, NULL, 0, &cbNeeded, &cReturned);
    if (cbNeeded == 0) return;

    std::vector<BYTE> buffer(cbNeeded);
    if (EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, buffer.data(), cbNeeded, &cbNeeded, &cReturned)) {
        PRINTER_INFO_2A* pPrinterInfo = reinterpret_cast<PRINTER_INFO_2A*>(buffer.data());

        for (DWORD i = 0; i < cReturned; i++) {
            if (pPrinterInfo[i].Attributes & PRINTER_ATTRIBUTE_SHARED) {
                HANDLE hPrinter = NULL;
                PRINTER_DEFAULTSA pd = { NULL, NULL, PRINTER_ACCESS_ADMINISTER };

                if (OpenPrinterA(pPrinterInfo[i].pPrinterName, &hPrinter, &pd)) {
                    pPrinterInfo[i].Attributes &= ~PRINTER_ATTRIBUTE_SHARED;
                    pPrinterInfo[i].pDevMode = NULL;
                    pPrinterInfo[i].pSecurityDescriptor = NULL;

                    if (!SetPrinterA(hPrinter, 2, (LPBYTE)&pPrinterInfo[i], 0)) {
                        DWORD err = GetLastError();
                        LogMessage("Failed to unshare printer: " + std::string(pPrinterInfo[i].pPrinterName) + " Error code: " + std::to_string(err));
                    }
                    else {
                        LogMessage("Successfully unshared printer: " + std::string(pPrinterInfo[i].pPrinterName));
                    }
                    ClosePrinter(hPrinter);
                }
                else {
                    DWORD err = GetLastError();
                    LogMessage("Failed to open printer: " + std::string(pPrinterInfo[i].pPrinterName) + " Error code: " + std::to_string(err));
                }
            }
        }
    }
}

bool GetSystemSharedFoldersInfo(std::string& outShareNames) {
    PSHARE_INFO_1 pBuf = NULL, pTmpBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS res;
    bool foundUserShare = false;
    outShareNames = "";

    do {
        res = NetShareEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            pTmpBuf = pBuf;
            for (DWORD i = 0; i < entriesRead; i++) {
                if ((pTmpBuf->shi1_type & STYPE_MASK) == STYPE_DISKTREE) {
                    std::wstring wShareName = pTmpBuf->shi1_netname;
                    if (!wShareName.empty() && wShareName.back() != L'$') {
                        foundUserShare = true;
                        char nameA[256] = { 0 };
                        WideCharToMultiByte(CP_ACP, 0, wShareName.c_str(), -1, nameA, sizeof(nameA), NULL, NULL);
                        if (!outShareNames.empty()) outShareNames += ", ";
                        outShareNames += nameA;
                    }
                }
                pTmpBuf++;
            }
            NetApiBufferFree(pBuf);
        }
    } while (res == ERROR_MORE_DATA);
    return foundUserShare;
}

void UnshareAllFolders() {
    PSHARE_INFO_1 pBuf = NULL, pTmpBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS res;

    do {
        res = NetShareEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            pTmpBuf = pBuf;
            for (DWORD i = 0; i < entriesRead; i++) {
                if ((pTmpBuf->shi1_type & STYPE_MASK) == STYPE_DISKTREE) {
                    std::wstring wShareName = pTmpBuf->shi1_netname;
                    if (!wShareName.empty() && wShareName.back() != L'$') {
                        DWORD delRes = NetShareDel(NULL, (LMSTR)wShareName.c_str(), 0);

                        char nameA[256] = { 0 };
                        WideCharToMultiByte(CP_ACP, 0, wShareName.c_str(), -1, nameA, sizeof(nameA), NULL, NULL);

                        if (delRes == NERR_Success) {
                            LogMessage("Successfully unshared folder: " + std::string(nameA));
                        }
                        else {
                            LogMessage("Failed to unshare folder: " + std::string(nameA) + " Error code: " + std::to_string(delRes));
                        }
                    }
                }
                pTmpBuf++;
            }
            NetApiBufferFree(pBuf);
        }
    } while (res == ERROR_MORE_DATA);
}

bool IsBluetoothEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_BLUETOOTH, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    bool anyEnabled = false, foundRadio = false;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        ULONG status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, devInfoData.DevInst, 0) == CR_SUCCESS) {
            foundRadio = true;
            if (problem != CM_PROB_DISABLED) {
                anyEnabled = true;
                break;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return foundRadio ? anyEnabled : false;
}

bool IsWifiAdapterEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    bool foundPhysicalWifi = false, wifiEnabled = false;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        char friendlyName[256] = { 0 };
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName, sizeof(friendlyName), NULL)) {
            if ((strstr(friendlyName, "Wi-Fi") || strstr(friendlyName, "Wireless") || strstr(friendlyName, "WLAN") || strstr(friendlyName, "802.11")) &&
                !strstr(friendlyName, "Virtual") && !strstr(friendlyName, "Direct") && !strstr(friendlyName, "Hosted")) {

                foundPhysicalWifi = true;
                ULONG status = 0, problem = 0;
                if (CM_Get_DevNode_Status(&status, &problem, devInfoData.DevInst, 0) == CR_SUCCESS) {
                    if (problem != CM_PROB_DISABLED) {
                        wifiEnabled = true;
                        break;
                    }
                }
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return foundPhysicalWifi ? wifiEnabled : false;
}

bool IsSpoolerClientConnectionsDisabled() {
    HKEY hKey;
    DWORD value = 0;
    DWORD dwSize = sizeof(DWORD);
    LPCWSTR subKey = L"Software\\Policies\\Microsoft\\Windows NT\\Printers";

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"RegisterSpoolerRemoteRpcEndPoint", NULL, NULL, (LPBYTE)&value, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value == 2);
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool IsSMBv1Disabled() {
    HKEY hKey;
    DWORD smb1 = 1, dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SMB1", NULL, NULL, (LPBYTE)&smb1, &dwSize);
        RegCloseKey(hKey);
    }
    return (smb1 == 0);
}

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

bool IsSslTlsHardened() {
    bool noTls10 = CheckSchannelKeyDisabled("Protocols\\TLS 1.0\\Server");
    bool noTls11 = CheckSchannelKeyDisabled("Protocols\\TLS 1.1\\Server");
    bool noSsl30 = CheckSchannelKeyDisabled("Protocols\\SSL 3.0\\Server");

    bool noRc4 = CheckSchannelKeyDisabled("Ciphers\\RC4 128/128");
    bool noNull = CheckSchannelKeyDisabled("Ciphers\\NULL");
    bool noDes = CheckSchannelKeyDisabled("Ciphers\\DES 56/56");

    bool noMd5 = CheckSchannelKeyDisabled("Hashes\\MD5");

    return (noTls10 && noTls11 && noSsl30 && noRc4 && noNull && noDes && noMd5);
}

bool IsBrowserAccountLocked() {
    HKEY hKey;
    DWORD dwSize = sizeof(DWORD);
    DWORD edgeVal = 1, chromeVal = 1, braveVal = 1, firefoxAccounts = 0;
    DWORD edgeSync = 0, chromeSync = 0, braveSync = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "BrowserSignin", NULL, NULL, (LPBYTE)&edgeVal, &dwSize);
        RegQueryValueExA(hKey, "SyncDisabled", NULL, NULL, (LPBYTE)&edgeSync, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Google\\Chrome", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "BrowserSignin", NULL, NULL, (LPBYTE)&chromeVal, &dwSize);
        RegQueryValueExA(hKey, "SyncDisabled", NULL, NULL, (LPBYTE)&chromeSync, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\BraveSoftware\\Brave", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "BrowserSignin", NULL, NULL, (LPBYTE)&braveVal, &dwSize);
        RegQueryValueExA(hKey, "SyncDisabled", NULL, NULL, (LPBYTE)&braveSync, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Mozilla\\Firefox", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "DisableFirefoxAccounts", NULL, NULL, (LPBYTE)&firefoxAccounts, &dwSize);
        RegCloseKey(hKey);
    }

    return (edgeVal == 0 && chromeVal == 0 && braveVal == 0 && firefoxAccounts == 1 &&
        edgeSync == 1 && chromeSync == 1 && braveSync == 1);
}

bool IsBrowserPasswordLocked() {
    HKEY hKey;
    DWORD dwSize = sizeof(DWORD);
    DWORD edgeVal = 1, chromeVal = 1, braveVal = 1, firefoxVal = 1;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "PasswordManagerEnabled", NULL, NULL, (LPBYTE)&edgeVal, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Google\\Chrome", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "PasswordManagerEnabled", NULL, NULL, (LPBYTE)&chromeVal, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\BraveSoftware\\Brave", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "PasswordManagerEnabled", NULL, NULL, (LPBYTE)&braveVal, &dwSize);
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Mozilla\\Firefox", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "PasswordManagerEnabled", NULL, NULL, (LPBYTE)&firefoxVal, &dwSize);
        RegCloseKey(hKey);
    }

    return (edgeVal == 0 && chromeVal == 0 && braveVal == 0 && firefoxVal == 0);
}

void ConfigureBrowserAccountLock(bool lockAccounts) {
    HKEY hKey;
    DWORD signinVal = lockAccounts ? 0 : 1;
    DWORD syncVal = lockAccounts ? 1 : 0;
    DWORD ffAccountVal = lockAccounts ? 1 : 0;

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "BrowserSignin", 0, REG_DWORD, (const BYTE*)&signinVal, sizeof(signinVal));
        RegSetValueExA(hKey, "SyncDisabled", 0, REG_DWORD, (const BYTE*)&syncVal, sizeof(syncVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Google\\Chrome", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "BrowserSignin", 0, REG_DWORD, (const BYTE*)&signinVal, sizeof(signinVal));
        RegSetValueExA(hKey, "SyncDisabled", 0, REG_DWORD, (const BYTE*)&syncVal, sizeof(syncVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\BraveSoftware\\Brave", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "BrowserSignin", 0, REG_DWORD, (const BYTE*)&signinVal, sizeof(signinVal));
        RegSetValueExA(hKey, "SyncDisabled", 0, REG_DWORD, (const BYTE*)&syncVal, sizeof(syncVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Mozilla\\Firefox", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "DisableFirefoxAccounts", 0, REG_DWORD, (const BYTE*)&ffAccountVal, sizeof(ffAccountVal));
        RegCloseKey(hKey);
    }
    if (lockAccounts) {
        RunSilentCmd("taskkill /F /IM msedge.exe /IM chrome.exe /IM firefox.exe /IM brave.exe /IM opera.exe /IM vivaldi.exe /T >nul 2>&1");
    }
}

void ConfigureBrowserPasswordLock(bool lockPasswords) {
    HKEY hKey;
    DWORD passVal = lockPasswords ? 0 : 1;
    DWORD ffOfferVal = lockPasswords ? 0 : 1;

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Edge", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "PasswordManagerEnabled", 0, REG_DWORD, (const BYTE*)&passVal, sizeof(passVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Google\\Chrome", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "PasswordManagerEnabled", 0, REG_DWORD, (const BYTE*)&passVal, sizeof(passVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\BraveSoftware\\Brave", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "PasswordManagerEnabled", 0, REG_DWORD, (const BYTE*)&passVal, sizeof(passVal));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Mozilla\\Firefox", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "PasswordManagerEnabled", 0, REG_DWORD, (const BYTE*)&passVal, sizeof(passVal));
        RegSetValueExA(hKey, "OfferToSaveLogins", 0, REG_DWORD, (const BYTE*)&ffOfferVal, sizeof(ffOfferVal));
        RegCloseKey(hKey);
    }
    if (lockPasswords) {
        RunSilentCmd("taskkill /F /IM msedge.exe /IM chrome.exe /IM firefox.exe /IM brave.exe /IM opera.exe /IM vivaldi.exe /T >nul 2>&1");
    }
}

void SetBluetoothDeviceState(bool enable) {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_BLUETOOTH, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
            SP_PROPCHANGE_PARAMS pcp;
            pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
            pcp.StateChange = enable ? DPC_ENABLE : DPC_DISABLE;
            pcp.Scope = DCPC_GLOBAL;
            pcp.HwProfile = 0;

            if (SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &pcp.ClassInstallHeader, sizeof(pcp))) {
                SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
}
void SetWifiDeviceState(bool enable) {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
            char friendlyName[256] = { 0 };
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName, sizeof(friendlyName), NULL)) {
                if ((strstr(friendlyName, "Wi-Fi") || strstr(friendlyName, "Wireless") || strstr(friendlyName, "WLAN") || strstr(friendlyName, "802.11")) &&
                    !strstr(friendlyName, "Virtual") && !strstr(friendlyName, "Direct") && !strstr(friendlyName, "Hosted")) {

                    SP_PROPCHANGE_PARAMS pcp;
                    pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
                    pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
                    pcp.StateChange = enable ? DPC_ENABLE : DPC_DISABLE;
                    pcp.Scope = DCPC_GLOBAL;
                    pcp.HwProfile = 0;

                    if (SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &pcp.ClassInstallHeader, sizeof(pcp))) {
                        SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);
                    }
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
}

bool RestartWin32Service(const char* serviceName) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceA(hSCM, serviceName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    DWORD timeout = 0;
    while (QueryServiceStatus(hService, &status) && status.dwCurrentState != SERVICE_STOPPED) {
        Sleep(500);
        timeout += 500;
        if (timeout > 10000) break;
    }

    BOOL success = StartServiceA(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return success == TRUE;
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

void ConfigureSslTlsIISCrypto(bool harden) {
    RunEmbeddedIISCrypto(harden);
}

void PerformAuditAndHighlight() {
    g_secureCount = 0;
    g_attentionCount = 0;
    g_insecureCount = 0;

    // 1. Bluetooth
    bool btActive = IsBluetoothEnabled();
    g_hardRows[0].liveInfo = btActive ? "Bluetooth is currently enabled." : "Bluetooth adapter is securely disabled.";
    g_hardRows[0].statusLabel = btActive ? "Warning: Enabled" : "Secured: Disabled";
    g_hardStates[0] = btActive ? 1 : 2;
    g_hardRows[0].actionLabel = btActive ? "Disable" : "Enable";
    SetWindowTextA(g_hardRows[0].hBtnAction, g_hardRows[0].actionLabel);
    ShowWindow(g_hardRows[0].hBtnAction, SW_SHOW);

    // 2. Wi-Fi
    bool wifiActive = IsWifiAdapterEnabled();
    g_hardRows[1].liveInfo = wifiActive ? "Wi-Fi is currently enabled." : "Wi-Fi adapter is securely disabled.";
    g_hardRows[1].statusLabel = wifiActive ? "Warning: Enabled" : "Secured: Disabled";
    g_hardStates[1] = wifiActive ? 1 : 2;
    g_hardRows[1].actionLabel = wifiActive ? "Disable" : "Enable";
    SetWindowTextA(g_hardRows[1].hBtnAction, g_hardRows[1].actionLabel);
    ShowWindow(g_hardRows[1].hBtnAction, SW_SHOW);

    // 3. SMB Server Protocols
    bool smbHardened = IsSMBv1Disabled();
    g_hardRows[2].liveInfo = smbHardened ? "SMBv1 protocol is securely disabled." : "SMBv1 protocol is currently enabled.";
    g_hardRows[2].statusLabel = smbHardened ? "Secured: Disabled" : "Warning: Enabled";
    g_hardStates[2] = smbHardened ? 2 : 1;
    g_hardRows[2].actionLabel = smbHardened ? "Enable" : "Secure";
    SetWindowTextA(g_hardRows[2].hBtnAction, g_hardRows[2].actionLabel);
    ShowWindow(g_hardRows[2].hBtnAction, SW_SHOW);

    // 4. Shared Network Printers
    g_printerList = GetSystemPrintersInfo();
    std::vector<std::string> sharedPrinters;
    for (const auto& printer : g_printerList) {
        if (printer.isShared) {
            std::string sName = printer.shareName.empty() ? printer.name : printer.shareName;
            sharedPrinters.push_back(sName);
        }
    }

    bool hasSharedPrinters = !sharedPrinters.empty();
    bool spoolerPolicySecure = IsSpoolerClientConnectionsDisabled();

    if (hasSharedPrinters || !spoolerPolicySecure) {
        if (hasSharedPrinters) {
            if (sharedPrinters.size() == 1) g_hardRows[3].liveInfo = "Printer shared: " + sharedPrinters[0];
            else {
                char buf[128];
                snprintf(buf, sizeof(buf), "Multiple (%d) shared printers detected.", (int)sharedPrinters.size());  g_hardRows[3].liveInfo = buf;
            }
        }
        else {
            g_hardRows[3].liveInfo = "Spooler remote RPC connections are allowed.";
        }
        g_hardRows[3].statusLabel = "Warning: Unsecured";
        g_hardStates[3] = 1;
        g_hardRows[3].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[3].hBtnAction, g_hardRows[3].actionLabel);
        ShowWindow(g_hardRows[3].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[3].liveInfo = "No shares & RPC client connections blocked.";
        g_hardRows[3].statusLabel = "Secured: Hardened";
        g_hardStates[3] = 2;
        g_hardRows[3].actionLabel = "Revert";
        SetWindowTextA(g_hardRows[3].hBtnAction, g_hardRows[3].actionLabel);
        ShowWindow(g_hardRows[3].hBtnAction, SW_SHOW);
    }

    // 5. Shared Folders
    std::string fullShareList = "";
    bool hasSharedFolders = GetSystemSharedFoldersInfo(fullShareList);
    if (hasSharedFolders && !fullShareList.empty()) {
        std::vector<std::string> sharedFolders;
        std::string token;
        std::stringstream ss(fullShareList);
        while (std::getline(ss, token, ',')) {
            size_t start = token.find_first_not_of(" ");
            if (start != std::string::npos) token = token.substr(start);
            if (!token.empty()) sharedFolders.push_back(token);
        }

        if (sharedFolders.size() == 1) g_hardRows[4].liveInfo = "Folder shared: " + sharedFolders[0];
        else {
            char buf[128];
            snprintf(buf, sizeof(buf), "Multiple (%d) shared network folders detected.", (int)sharedFolders.size());
            g_hardRows[4].liveInfo = buf;
        }
        g_hardRows[4].statusLabel = "Warning: Shared";
        g_hardStates[4] = 1;
        g_hardRows[4].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[4].hBtnAction, g_hardRows[4].actionLabel);
        ShowWindow(g_hardRows[4].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[4].liveInfo = "No shared network folders detected.";
        g_hardRows[4].statusLabel = "Secured: No Shares";
        g_hardStates[4] = 2;
        ShowWindow(g_hardRows[4].hBtnAction, SW_HIDE);
    }

    // 6. SSL / TLS
    bool sslTlsHardened = IsSslTlsHardened();
    g_hardRows[5].liveInfo = sslTlsHardened ? "Best practice IIS Crypto settings applied." : "Unsecured TLS/SSL ciphers are active.";
    g_hardRows[5].statusLabel = sslTlsHardened ? "Secured: Hardened" : "Warning: Unsecured";
    g_hardStates[5] = sslTlsHardened ? 2 : 1;
    g_hardRows[5].actionLabel = sslTlsHardened ? "Revert" : "Secure";
    SetWindowTextA(g_hardRows[5].hBtnAction, g_hardRows[5].actionLabel);
    ShowWindow(g_hardRows[5].hBtnAction, SW_SHOW);

    // 7. Browser Login
    bool browserLocked = IsBrowserAccountLocked();
    g_hardRows[6].liveInfo = browserLocked ? "Browser sign-in is securely disabled." : "Browser sign-in is currently allowed.";
    g_hardRows[6].statusLabel = browserLocked ? "Secured: Locked" : "Warning: Unlocked";
    g_hardStates[6] = browserLocked ? 2 : 1;
    g_hardRows[6].actionLabel = browserLocked ? "Unlock" : "Lock";
    SetWindowTextA(g_hardRows[6].hBtnAction, g_hardRows[6].actionLabel);
    ShowWindow(g_hardRows[6].hBtnAction, SW_SHOW);

    // 8. Browser Passwords
    bool passwordLocked = IsBrowserPasswordLocked();
    g_hardRows[7].liveInfo = passwordLocked ? "Password saving is securely disabled." : "Password saving is currently allowed.";
    g_hardRows[7].statusLabel = passwordLocked ? "Secured: Locked" : "Warning: Unlocked";
    g_hardStates[7] = passwordLocked ? 2 : 1;
    g_hardRows[7].actionLabel = passwordLocked ? "Unlock" : "Lock";
    SetWindowTextA(g_hardRows[7].hBtnAction, g_hardRows[7].actionLabel);
    ShowWindow(g_hardRows[7].hBtnAction, SW_SHOW);

    // 9. Local Users
    int userCount = 0;
    bool allUsersDisabled = true;
    bool allPasswordsExpire = true;

    g_hardRows[8].liveInfo = GetLocalUserAccountsInfo(userCount, allUsersDisabled, allPasswordsExpire);

    if ((userCount > 0 && !allUsersDisabled) || !allPasswordsExpire) {
        g_hardRows[8].statusLabel = "Warning: Action Needed";
        g_hardStates[8] = 1;
        g_hardRows[8].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[8].hBtnAction, g_hardRows[8].actionLabel);
        ShowWindow(g_hardRows[8].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[8].statusLabel = "Secured: Hardened";
        g_hardStates[8] = 2;
        g_hardRows[8].actionLabel = "Enable";
        SetWindowTextA(g_hardRows[8].hBtnAction, g_hardRows[8].actionLabel);
        ShowWindow(g_hardRows[8].hBtnAction, SW_SHOW);
    }

    // 10. Network Security Policies 
    bool netSecHardened = IsNetworkSecPoliciesHardened();
    g_hardRows[9].liveInfo = netSecHardened ? "NTLMv2 & SMB Signing strictly enforced." : "Legacy NTLM or unsigned SMB allowed.";
    g_hardRows[9].statusLabel = netSecHardened ? "Secured: Hardened" : "Warning: Unsecured";
    g_hardStates[9] = netSecHardened ? 2 : 1;
    g_hardRows[9].actionLabel = netSecHardened ? "Revert" : "Secure";
    SetWindowTextA(g_hardRows[9].hBtnAction, g_hardRows[9].actionLabel);
    ShowWindow(g_hardRows[9].hBtnAction, SW_SHOW);

    if (!btActive) g_secureCount++; else g_attentionCount++;
    if (!wifiActive) g_secureCount++; else g_attentionCount++;
    if (smbHardened) g_secureCount++; else g_insecureCount++;
    if (!hasSharedPrinters) g_secureCount++; else g_attentionCount++;
    if (!hasSharedFolders) g_secureCount++; else g_attentionCount++;
    if (sslTlsHardened) g_secureCount++; else g_insecureCount++;
    if (browserLocked) g_secureCount++; else g_insecureCount++;
    if (passwordLocked) g_secureCount++; else g_insecureCount++;
    if ((userCount == 0 || allUsersDisabled) && allPasswordsExpire) g_secureCount++; else g_insecureCount++;
    if (netSecHardened) g_secureCount++; else g_insecureCount++;
}

// --- WINDOW PROC ---
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND:
        return 1;


    case WM_CREATE:
    {
        g_hMainWnd = hwnd;
        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

        InitTheme();
        LoadVersionInfoFromResource();

        g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontSub = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontIcon = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe MDL2 Assets");

        CreateSidebarControls(hwnd);

        int startY = 55;
        int rowHeight = 38;

        for (int i = 0; i < 10; i++) {
            g_hardRows[i].hBtnAction = CreateWindowA("BUTTON", g_hardRows[i].actionLabel,
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                515, startY + 4, 70, 26, // Expanded position for more spacing
                hwnd, (HMENU)(UINT_PTR)(ID_HARD_BASE + i * 10 + 1), NULL, NULL);
            startY += rowHeight;
        }


        LogMessage("Security Tool Started");
        PerformAuditAndHighlight();
        break;
    }
    case WM_SEARCHPASS_CLOSED:
    {
        // Instantly re-enable the button the millisecond the window closes
        if (g_hBtnSearchPass) {
            EnableWindow(g_hBtnSearchPass, TRUE);
            InvalidateRect(g_hBtnSearchPass, NULL, FALSE);
        }
        break;
    }

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdcWindow = BeginPaint(hwnd, &ps);

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);
        int width = rcClient.right - rcClient.left;
        int height = rcClient.bottom - rcClient.top;

        HDC hdc = CreateCompatibleDC(hdcWindow);
        HBITMAP hMemBitmap = CreateCompatibleBitmap(hdcWindow, width, height);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdc, hMemBitmap);

        FillRect(hdc, &rcClient, g_hBrushBg);

        SetBkMode(hdc, TRANSPARENT);

        // Inside WM_PAINT of WindowProc, replace the entire Render Hardening Rows section:

         // Draw a distinct background container for the controls area
        RECT rcControlsBg = { 10, 10, 600, 55 + (10 * 38) + 10 };
        HBRUSH hControlBgBrush = CreateSolidBrush(RGB(15, 23, 42)); // Distinct container background
        FillRect(hdc, &rcControlsBg, hControlBgBrush);
        DeleteObject(hControlBgBrush);

        // Draw the Title
        SelectObject(hdc, g_hFontTitle);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        RECT rcTitle = { 15, 18, 290, 48 };
        DrawTextA(hdc, "System Hardening Controls", -1, &rcTitle, DT_LEFT | DT_VCENTER | DT_SINGLELINE);


        // Calculate metrics
        int percentMet = (g_totalControls > 0) ? (g_secureCount * 100 / g_totalControls) : 0;

        // Draw Progress Bar Background
        RECT rcProgBg = {290, 28,545, 38 }; // Positioned right of the title
        HBRUSH hProgBgBrush = CreateSolidBrush(RGB(30, 41, 59));
        FillRect(hdc, &rcProgBg, hProgBgBrush);
        DeleteObject(hProgBgBrush);

        // Draw Progress Bar Fill
        if (percentMet > 0) {
            RECT rcProgFill = rcProgBg;
            rcProgFill.right = rcProgBg.left + ((rcProgBg.right - rcProgBg.left) * percentMet / 100);

            // Color shifts based on security level (Red -> Teal)
            COLORREF barColor = (percentMet == 100) ? RGB(13, 148, 136) : RGB(96, 165, 250);
            if (percentMet < 50) barColor = RGB(248, 113, 113); // Red if poor

            HBRUSH hProgFillBrush = CreateSolidBrush(barColor);
            FillRect(hdc, &rcProgFill, hProgFillBrush);
            DeleteObject(hProgFillBrush);
        }

        // Draw Percentage Text
        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        char progText[32];
        snprintf(progText, sizeof(progText), "%d%%", percentMet);
        RECT rcProgText = { 555, 20,595, 45 };
        DrawTextA(hdc, progText, -1, &rcProgText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);


        // Render Hardening Rows
        int startY = 55; // Shifted down for the title
        int rowHeight = 38;

        for (int i = 0; i < 10; i++) {
            RECT rcRow = { 15, startY, 590, startY + rowHeight };

            if (i % 2 == 1) {
                // Alternating row colors inside the container
                HBRUSH hAltBrush = CreateSolidBrush(RGB(23, 32, 51));
                FillRect(hdc, &rcRow, hAltBrush);
                DeleteObject(hAltBrush);
            }

            // Icon
            SelectObject(hdc, g_hFontIcon);
            SetTextColor(hdc, RGB(148, 163, 184));
            RECT rcIcon = { 20, startY + 8, 50, startY + 30 };
            DrawTextW(hdc, &g_hardRows[i].iconGlyph, 1, &rcIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            // Name
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            RECT rcName = { 45, startY + 2, 310, startY + 20 };
            DrawTextA(hdc, g_hardRows[i].name, -1, &rcName, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            // Live Info
            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, RGB(148, 163, 184));
            RECT rcInfo = { 45, startY + 18, 300, startY + 36 };
            DrawTextA(hdc, g_hardRows[i].liveInfo.c_str(), -1, &rcInfo, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

            // Status Label
            COLORREF statusColor = (g_hardStates[i] == 2) ? RGB(96, 165, 250) : RGB(248, 113, 113);
            SetTextColor(hdc, statusColor);
            RECT rcStatus = { 275, startY + 10, 505, startY + 28 };
            DrawTextA(hdc, g_hardRows[i].statusLabel.c_str(), -1, &rcStatus, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

            startY += rowHeight;
        }

        BitBlt(hdcWindow, 0, 0, width, height, hdc, 0, 0, SRCCOPY);

        SelectObject(hdc, hOldBitmap);
        DeleteObject(hMemBitmap);
        DeleteDC(hdc);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);

        if (HandleSidebarCommand(hwnd, wmId)) {
            return 0; // The sidebar handled it, we can stop here
        }

        if (wmId == ID_BTN_SECURE_ALL) {
            if (!ShowDarkConfirmDialog(hwnd, "Are you sure you want to enforce all hardening policies?")) {
                return 0;
            }
            SetBluetoothDeviceState(false);
            SetWifiDeviceState(false);
            ConfigureSMB(true);
            OnLockdownPrintersButtonClicked();
            UnshareAllFolders();
            ConfigureSslTlsIISCrypto(true);
            ConfigureBrowserAccountLock(true);
            ConfigureBrowserPasswordLock(true);
            ConfigureLocalUsers(true);
            ConfigureNetworkSecPolicies(true);
            PerformAuditAndHighlight();
            UpdateStatus("All hardening policies enforced.");
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
        else if (wmId >= ID_HARD_BASE && wmId < ID_HARD_BASE + 100) {
            if (!ShowDarkConfirmDialog(hwnd, "Are you sure you want to change this security setting?")) {
                return 0;
            }
            int rowIdx = (wmId - ID_HARD_BASE) / 10;
            switch (rowIdx) {
            case 0: SetBluetoothDeviceState(g_hardStates[0] ==2); break;
            case 1: SetWifiDeviceState(g_hardStates[1] ==2); break;
            case 2: ConfigureSMB(g_hardStates[2] != 2); break;
            case 3:
                if (g_hardStates[3] != 2) OnLockdownPrintersButtonClicked();
                else OnRevertPrintersButtonClicked();
                break;
            case 4: UnshareAllFolders(); break;
            case 5: ConfigureSslTlsIISCrypto(g_hardStates[5] != 2); break;
            case 6: ConfigureBrowserAccountLock(g_hardStates[6] != 2); break;
            case 7: ConfigureBrowserPasswordLock(g_hardStates[7] != 2); break;
            case 8: ConfigureLocalUsers(g_hardStates[8] != 2); break;
            case 9: ConfigureNetworkSecPolicies(g_hardStates[9] != 2); break;
            }
            PerformAuditAndHighlight();
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
        break;
    }

    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;

        // 1. Draw the Sidebar Buttons
        if (IsSidebarButton(pdis->CtlID)) {
            DrawSidebarButton(pdis);
            return TRUE;
        }
        // 2. Draw the Row Action Buttons ("Secure", "Disable", "Enable")
        else if (pdis->CtlID >= ID_HARD_BASE && pdis->CtlID < ID_HARD_BASE + 100) {
            HDC hdc = pdis->hDC;
            bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;

            // Background color (slightly darker when clicked)
            COLORREF bgCol = isPressed ? RGB(15, 23, 42) : RGB(30, 41, 59);

            HBRUSH hBrush = CreateSolidBrush(bgCol);
            FillRect(hdc, &pdis->rcItem, hBrush);
            DeleteObject(hBrush);

            // Border color 
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(71, 85, 105));
            SelectObject(hdc, hPen);
            SelectObject(hdc, GetStockObject(NULL_BRUSH));

            // Draw with rounded corners
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
            DeleteObject(hPen);

            // Set up text drawing
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 255, 255)); // White text
            SelectObject(hdc, g_hFontBold);

            // Retrieve the text ("Secure", "Enable", etc.) and draw it
            char btnText[32] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));
            DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            return TRUE;
        }
        return TRUE;
    }

    

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "CSCsecureMainClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    // Optional: Load your app icon if you have it defined
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));

    if (!RegisterClassA(&wc)) {
        return 0;
    }

	LoadVersionInfoFromResource();

    std::string windowTitle = g_appProductName + " v" + g_appVersion;
	if (g_appProductName.empty()) {
        windowTitle += "CSCsecure";
	}

    HWND hwnd = CreateWindowExA(
        0,
        "CSCsecureMainClass",
        windowTitle.c_str(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) {
        return 0;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Standard Message Loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}