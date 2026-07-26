#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <setupapi.h>
#include <devguid.h>
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
#include <dwmapi.h> // Added for Dark Mode Title Bar

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "dwmapi.lib") // Added for Dark Mode Title Bar

// Dark Mode Title Bar Attributes
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
#define ID_STATUS_BAR        1004
#define ID_LOG_EDIT          1005
#define ID_BTN_MENU          1006
#define ID_HARD_BASE         2000

#define IDM_SETTINGS         3001
#define IDM_ABOUT            3002
#define IDM_SEARCHPASS       3003
#define IDM_WINUPDATE        3004
#define IDM_INVENTORY        3005

// Dark Theme Color Palette
#define COLOR_BG          RGB(11, 19, 43)
#define COLOR_PANEL       RGB(15, 23, 42)
#define COLOR_CARD_BG     RGB(15, 26, 48)
#define COLOR_BORDER      RGB(30, 41, 59)
#define COLOR_TEXT_WHITE  RGB(241, 245, 249)
#define COLOR_TEXT_MUTED  RGB(148, 163, 184)
#define COLOR_ACCENT_TEAL RGB(16, 185, 129)
#define COLOR_WARN_AMBER  RGB(245, 158, 11)
#define COLOR_DANGER_RED  RGB(239, 68, 68)

// Global Brushes, Fonts, & UI Handles
HBRUSH g_hBrushBg = NULL;
HBRUSH g_hBrushPanel = NULL;
HFONT  g_hFontTitle = NULL;
HFONT  g_hFontSub = NULL;
HFONT  g_hFontBold = NULL;
HWND   g_hMainWnd = NULL;
HWND   g_hLogWnd = NULL;
HWND   g_hLogEdit = NULL;

// Execution State & Live Feedback Message
std::string g_statusText = "Ready (Click to view logs)";
bool g_isExecuting = false;
std::vector<std::string> g_logMemory;

// System Hostname
char g_computerName[MAX_COMPUTERNAME_LENGTH + 1] = "UNKNOWN";

// Metric Counts (10 Hardening items total)
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
    HWND hBtnAction;
};

HardeningRow g_hardRows[10] = {
    {"Bluetooth Adapter", "Auditing...", "Auditing...", "Disable", NULL},
    {"Wi-Fi Network Adapter", "Auditing...", "Auditing...", "Disable", NULL},
    {"SMB Server Protocols", "Auditing...", "Auditing...", "Secure", NULL},
    {"Shared Network Printers", "Auditing...", "Auditing...", "Secure", NULL},
    {"Shared Network Folders / Files", "Auditing...", "Auditing...", "Secure", NULL},
    {"SSL / TLS & Ciphers", "Auditing...", "Auditing...", "Secure", NULL},
    {"Browser Account Login", "Auditing...", "Auditing...", "Lock", NULL},
    {"Browser Password Lock", "Auditing...", "Auditing...", "Lock", NULL},
    {"Local User Accounts", "Auditing...", "Auditing...", "Secure", NULL},
    {"Network Security Policies", "Auditing...", "Auditing...", "Secure", NULL}
};

struct PrinterStatus {
    std::string name;
    std::string shareName;
    bool isShared;
};

std::vector<PrinterStatus> g_printerList;

// Function Declarations
void LogMessage(const std::string& msg);
void UpdateStatus(const std::string& msg);

// --- NETWORK SECURITY POLICIES AUDIT & HARDENING ---
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
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) { // Optional check or check standard LDAP path below
        // Handled via NTDS / LDAP policies
    }

    // Standard path for LDAP client signing (LDAPClientIntegrity)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Just checking base registry for LDAP client path: SYSTEM\\CurrentControlSet\\Services\\LDAP
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
    DWORD restrictVal = harden ? 1 : 0; // 1 = Do not allow enumeration of SAM accounts/shares anonymously
    DWORD ldapVal = harden ? 2 : 0;     // 1 = Negotiate signing, 2 = Require signing

    // LSA Settings (Includes Anonymous Enumeration & NTLM)
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "LmCompatibilityLevel", 0, REG_DWORD, (const BYTE*)&lmCompat, sizeof(lmCompat));
        RegSetValueExA(hKey, "RestrictAnonymous", 0, REG_DWORD, (const BYTE*)&restrictVal, sizeof(restrictVal));
        RegSetValueExA(hKey, "RestrictAnonymousSAM", 0, REG_DWORD, (const BYTE*)&restrictVal, sizeof(restrictVal));
        RegCloseKey(hKey);
    }

    // SMB Server Settings
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigEnabled, sizeof(sigEnabled));
        RegSetValueExA(hKey, "RequireSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigRequired, sizeof(sigRequired));
        RegCloseKey(hKey);
    }

    // SMB Workstation Settings
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigEnabled, sizeof(sigEnabled));
        RegSetValueExA(hKey, "RequireSecuritySignature", 0, REG_DWORD, (const BYTE*)&sigRequired, sizeof(sigRequired));
        RegCloseKey(hKey);
    }

    // LDAP Client Signing Requirements
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LDAP", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "LDAPClientIntegrity", 0, REG_DWORD, (const BYTE*)&ldapVal, sizeof(ldapVal));
        RegCloseKey(hKey);
    }
}

// --- LOCAL USERS AUDIT & HARDENING ---
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

    // 1. Define paths for both files in the Temp directory
    std::wstring exePath = std::wstring(tempPath) + L"IISCryptoCli_Temp.exe";
    std::wstring tplPath = std::wstring(tempPath) + L"CustomHardening.ictpl";

    // 2. Extract the IISCrypto executable
    if (!ExtractResourceToFile(IDR_IISCRYPTOCLI, exePath)) return false;

    // 3. Build the command line and extract template if necessary
    std::wstring commandLine = L"\"" + exePath + L"\" ";

    if (useCustomTemplate) {
        // Extract the embedded template to the temp folder
        if (!ExtractResourceToFile(IDR_CUSTOMTEMPLATE, tplPath)) {
            DeleteFileW(exePath.c_str()); // Cleanup if template extraction fails
            return false;
        }
        // Target the absolute path of the newly extracted template
        commandLine += L"/template \"" + tplPath + L"\"";
    }
    else {
        commandLine += L"/template default";
    }

    // 4. Execute the process
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(NULL, &commandLine[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // 5. Cleanup both temp files
    DeleteFileW(exePath.c_str());
    if (useCustomTemplate) {
        DeleteFileW(tplPath.c_str());
    }

    return success;
}

// Log File & Status Dispatcher
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
    case WM_CREATE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        g_hLogEdit = CreateWindowExA(0, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, 0, rc.right, rc.bottom, hwnd, (HMENU)(UINT_PTR)ID_LOG_EDIT, NULL, NULL);

        SendMessageA(g_hLogEdit, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

        std::string fullLogText = "";
        for (const auto& line : g_logMemory) {
            fullLogText += line + "\r\n";
        }
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

    g_hLogWnd = CreateWindowExA(0, LOG_CLASS, "Execution Logs - Comtech Security Tool",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 450, hParent, NULL, GetModuleHandle(NULL), NULL);
}

// --- SYSTEM UTILITIES ---
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

// --- PRINTER ENUMERATION & UNShares ---
std::vector<PrinterStatus> GetSystemPrintersInfo() {
    std::vector<PrinterStatus> printerList;
    DWORD cbNeeded = 0, cReturned = 0;

    EnumPrintersA(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, NULL, 0, &cbNeeded, &cReturned);
    if (cbNeeded == 0) return printerList;

    std::vector<BYTE> buffer(cbNeeded);
    if (EnumPrintersA(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, buffer.data(), cbNeeded, &cbNeeded, &cReturned)) {
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
                PRINTER_DEFAULTSA pd = { NULL, NULL, PRINTER_ALL_ACCESS };

                if (OpenPrinterA(pPrinterInfo[i].pPrinterName, &hPrinter, &pd)) {
                    pPrinterInfo[i].Attributes &= ~PRINTER_ATTRIBUTE_SHARED;
                    SetPrinterA(hPrinter, 2, (LPBYTE)&pPrinterInfo[i], 0);
                    ClosePrinter(hPrinter);
                }
            }
        }
    }
}

// --- NETWORK SHARED FOLDERS AUDIT & UNShares ---
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
                        NetShareDel(NULL, (LMSTR)wShareName.c_str(), 0);
                    }
                }
                pTmpBuf++;
            }
            NetApiBufferFree(pBuf);
        }
    } while (res == ERROR_MORE_DATA);
}

// Hardware Bluetooth Detection
bool IsBluetoothEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_BLUETOOTH, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    bool anyEnabled = false;
    bool foundRadio = false;

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

// Physical Wi-Fi Adapter Detection
bool IsWifiAdapterEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    bool foundPhysicalWifi = false;
    bool wifiEnabled = false;

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

bool IsSMBv1Disabled() {
    HKEY hKey;
    DWORD smb1 = 1, dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SMB1", NULL, NULL, (LPBYTE)&smb1, &dwSize);
        RegCloseKey(hKey);
    }
    return (smb1 == 0);
}

bool IsSslTlsHardened() {
    HKEY hKey;
    DWORD tls10Enabled = 1, dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&tls10Enabled, &dwSize);
        RegCloseKey(hKey);
    }
    return (tls10Enabled == 0);
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
    // We now just pass a boolean to handle the internal extraction logic
    RunEmbeddedIISCrypto(harden);
}

// --- AUDIT ROUTINE ---
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
    ShowWindow(g_hardRows[2].hBtnAction, smbHardened ? SW_HIDE : SW_SHOW);

    // 4. Shared Printers
    g_printerList = GetSystemPrintersInfo();
    std::vector<std::string> sharedPrinters;
    for (const auto& printer : g_printerList) {
        if (printer.isShared) {
            std::string sName = printer.shareName.empty() ? printer.name : printer.shareName;
            sharedPrinters.push_back(sName);
        }
    }
    bool hasSharedPrinters = !sharedPrinters.empty();
    if (hasSharedPrinters) {
        if (sharedPrinters.size() == 1) g_hardRows[3].liveInfo = "Printer shared: " + sharedPrinters[0];
        else {
            char buf[128];
            snprintf(buf, sizeof(buf), "Shared printer: %s, and (%d) more.", sharedPrinters[0].c_str(), (int)(sharedPrinters.size() - 1));
            g_hardRows[3].liveInfo = buf;
        }
        g_hardRows[3].statusLabel = "Warning: Shared";
        g_hardStates[3] = 1;
        ShowWindow(g_hardRows[3].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[3].liveInfo = "No shared network printers detected.";
        g_hardRows[3].statusLabel = "Secured: No Shares";
        g_hardStates[3] = 2;
        ShowWindow(g_hardRows[3].hBtnAction, SW_HIDE);
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
            snprintf(buf, sizeof(buf), "Shared folder: %s, and (%d) more.", sharedFolders[0].c_str(), (int)(sharedFolders.size() - 1));
            g_hardRows[4].liveInfo = buf;
        }
        g_hardRows[4].statusLabel = "Warning: Shared";
        g_hardStates[4] = 1;
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
    ShowWindow(g_hardRows[5].hBtnAction, sslTlsHardened ? SW_HIDE : SW_SHOW);

    // 7. Browser Login
    bool browserLocked = IsBrowserAccountLocked();
    g_hardRows[6].liveInfo = browserLocked ? "Browser sign-in is securely disabled." : "Browser sign-in is currently allowed.";
    g_hardRows[6].statusLabel = browserLocked ? "Secured: Locked" : "Warning: Unlocked";
    g_hardStates[6] = browserLocked ? 2 : 1;
    ShowWindow(g_hardRows[6].hBtnAction, browserLocked ? SW_HIDE : SW_SHOW);

    // 8. Browser Passwords
    bool passwordLocked = IsBrowserPasswordLocked();
    g_hardRows[7].liveInfo = passwordLocked ? "Password saving is securely disabled." : "Password saving is currently allowed.";
    g_hardRows[7].statusLabel = passwordLocked ? "Secured: Locked" : "Warning: Unlocked";
    g_hardStates[7] = passwordLocked ? 2 : 1;
    ShowWindow(g_hardRows[7].hBtnAction, passwordLocked ? SW_HIDE : SW_SHOW);

    // 9. Local Users
    int userCount = 0;
    bool allUsersDisabled = true;
    bool allPasswordsExpire = true;

    g_hardRows[8].liveInfo = GetLocalUserAccountsInfo(userCount, allUsersDisabled, allPasswordsExpire);

    if ((userCount > 0 && !allUsersDisabled) || !allPasswordsExpire) {
        g_hardRows[8].statusLabel = "Warning: Action Needed";
        g_hardStates[8] = 1;
        ShowWindow(g_hardRows[8].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[8].statusLabel = "Secured: Hardened";
        g_hardStates[8] = 2;
        ShowWindow(g_hardRows[8].hBtnAction, SW_HIDE);
    }

    // 10. Network Security Policies (NTLMv2 & SMB Signing)
    bool netSecHardened = IsNetworkSecPoliciesHardened();
    g_hardRows[9].liveInfo = netSecHardened ? "NTLMv2 & SMB Signing strictly enforced." : "Legacy NTLM or unsigned SMB allowed.";
    g_hardRows[9].statusLabel = netSecHardened ? "Secured: Hardened" : "Warning: Unsecured";
    g_hardStates[9] = netSecHardened ? 2 : 1;
    ShowWindow(g_hardRows[9].hBtnAction, netSecHardened ? SW_HIDE : SW_SHOW);

    // Metric Evaluations
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
        g_hBrushBg = CreateSolidBrush(COLOR_BG);
        g_hBrushPanel = CreateSolidBrush(COLOR_PANEL);

        DWORD size = sizeof(g_computerName);
        GetComputerNameA(g_computerName, &size);

        g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontSub = CreateFontA(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

        // Burger Menu Button
        CreateWindowA("BUTTON", "", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 565, 15, 30, 30, hwnd, (HMENU)(UINT_PTR)ID_BTN_MENU, NULL, NULL);

        // "Secure All" button
        CreateWindowA("BUTTON", "Secure All", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 450, 78, 130, 30, hwnd, (HMENU)(UINT_PTR)ID_BTN_SECURE_ALL, NULL, NULL);

        // Status bar bottom (Shifted downward for 10th row)
        CreateWindowA("BUTTON", "", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, 639, 420, 20, hwnd, (HMENU)(UINT_PTR)ID_STATUS_BAR, NULL, NULL);

        // Adjusting rows upward to remove dead space
        int startY = 125;
        int rowHeight = 44;

        for (int i = 0; i < 10; i++) { // Increased loop max to 10
            g_hardRows[i].hBtnAction = CreateWindowA("BUTTON", g_hardRows[i].actionLabel,
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                490, startY + 6, 90, 28,
                hwnd, (HMENU)(UINT_PTR)(ID_HARD_BASE + i * 10 + 1), NULL, NULL);
            startY += rowHeight;
        }

        LogMessage("Security Tool Started");
        PerformAuditAndHighlight();
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
        SelectObject(hdc, g_hFontTitle);
        SetTextColor(hdc, COLOR_TEXT_WHITE);

        std::string dashTitle = "Dashboard - " + std::string(g_computerName);
        TextOutA(hdc, 25, 15, dashTitle.c_str(), (int)dashTitle.length());

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        TextOutA(hdc, 25, 40, "System Hardening Compliance Utility", 35);

        // Hardening Controls Container Panel
        HPEN hPenPanel = CreatePen(PS_SOLID, 1, COLOR_BORDER);
        SelectObject(hdc, g_hBrushPanel);
        SelectObject(hdc, hPenPanel);

        // Panel Bottom stretched to 574 to fit 10th row
        RECT rcPanel1 = { 25, 68, 595, 574 };
        RoundRect(hdc, rcPanel1.left, rcPanel1.top, rcPanel1.right, rcPanel1.bottom, 8, 8);

        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        TextOutA(hdc, 40, 82, "Hardening Controls", 18);

        // Progress Bar Metric
        int percent = (g_totalControls > 0) ? (g_secureCount * 100) / g_totalControls : 0;
        COLORREF barColor;
        if (percent >= 80) barColor = COLOR_ACCENT_TEAL;
        else if (percent >= 50) barColor = COLOR_WARN_AMBER;
        else barColor = COLOR_DANGER_RED;

        // Progress bar
        RECT rcProgBg = { 190, 87, 370, 91 };
        HBRUSH hTrackBrush = CreateSolidBrush(COLOR_BG);
        SelectObject(hdc, (HPEN)GetStockObject(NULL_PEN));
        SelectObject(hdc, hTrackBrush);
        RoundRect(hdc, rcProgBg.left, rcProgBg.top, rcProgBg.right, rcProgBg.bottom, 2, 2);

        if (percent > 0) {
            int fillWidth = (rcProgBg.right - rcProgBg.left) * percent / 100;
            if (fillWidth < 4) fillWidth = 4;
            RECT rcProgFg = { rcProgBg.left, rcProgBg.top, rcProgBg.left + fillWidth, rcProgBg.bottom };
            HBRUSH hFillBrush = CreateSolidBrush(barColor);
            SelectObject(hdc, hFillBrush);
            RoundRect(hdc, rcProgFg.left, rcProgFg.top, rcProgFg.right, rcProgFg.bottom, 2, 2);
            DeleteObject(hFillBrush);
        }
        DeleteObject(hTrackBrush);

        // Restore Percentage Indicator
        char pctStr[32];
        snprintf(pctStr, sizeof(pctStr), "%d%%", percent);
        SetTextColor(hdc, barColor);
        SelectObject(hdc, g_hFontBold);
        TextOutA(hdc, rcProgBg.right + 10, 82, pctStr, (int)strlen(pctStr));

        // Render List Elements
        int rowY = 125;
        int rowHeight = 44;

        for (int i = 0; i < 10; i++) { // Increased loop max to 10
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            TextOutA(hdc, 40, rowY, g_hardRows[i].name, (int)strlen(g_hardRows[i].name));

            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, COLOR_TEXT_MUTED);
            TextOutA(hdc, 40, rowY + 18, g_hardRows[i].liveInfo.c_str(), (int)g_hardRows[i].liveInfo.length());

            bool isSecure = (g_hardStates[i] == 2);
            SetTextColor(hdc, isSecure ? COLOR_ACCENT_TEAL : COLOR_DANGER_RED);

            // Shifted Status Text
            RECT rcStatus = { 330, rowY + 6, 480, rowY + 32 };
            std::string statusText = g_hardRows[i].statusLabel;
            DrawTextA(hdc, statusText.c_str(), -1, &rcStatus, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

            rowY += rowHeight;
        }

        // Bottom Footer details (Shifted downward to 641)
        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        TextOutA(hdc, 25, 641, "v4.2.0.0", 8);
        TextOutA(hdc, 380, 641, "© 2026 Comtech Security Tool", 33);

        DeleteObject(hPenPanel);

        BitBlt(hdcWindow, 0, 0, width, height, hdc, 0, 0, SRCCOPY);

        SelectObject(hdc, hOldBitmap);
        DeleteObject(hMemBitmap);
        DeleteDC(hdc);

        EndPaint(hwnd, &ps);
        break;
    }

    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;
        UINT id = pdis->CtlID;

        // Custom Hamburger menu drawing
        if (id == ID_BTN_MENU) {
            HBRUSH hBg = CreateSolidBrush(COLOR_BG);
            FillRect(hdc, &pdis->rcItem, hBg);
            DeleteObject(hBg);

            HBRUSH hIconBrush = CreateSolidBrush(COLOR_TEXT_WHITE);
            // Draw 3 distinct horizontal lines
            RECT r1 = { pdis->rcItem.left + 5, pdis->rcItem.top + 8, pdis->rcItem.right - 5, pdis->rcItem.top + 10 };
            RECT r2 = { pdis->rcItem.left + 5, pdis->rcItem.top + 14, pdis->rcItem.right - 5, pdis->rcItem.top + 16 };
            RECT r3 = { pdis->rcItem.left + 5, pdis->rcItem.top + 20, pdis->rcItem.right - 5, pdis->rcItem.top + 22 };

            FillRect(hdc, &r1, hIconBrush);
            FillRect(hdc, &r2, hIconBrush);
            FillRect(hdc, &r3, hIconBrush);

            DeleteObject(hIconBrush);
            return TRUE;
        }

        if (id == ID_STATUS_BAR) {
            COLORREF statusBg = g_isExecuting ? COLOR_WARN_AMBER : COLOR_BORDER;
            HBRUSH hStatusBrush = CreateSolidBrush(statusBg);
            FillRect(hdc, &pdis->rcItem, hStatusBrush);
            DeleteObject(hStatusBrush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, g_isExecuting ? RGB(0, 0, 0) : COLOR_TEXT_WHITE);
            SelectObject(hdc, g_hFontSub);
            DrawTextA(hdc, (" Status: " + g_statusText).c_str(), -1, &pdis->rcItem, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }

        if (id == ID_BTN_SECURE_ALL) {
            HBRUSH hBtnBrush = CreateSolidBrush(g_isExecuting ? COLOR_TEXT_MUTED : COLOR_ACCENT_TEAL);
            FillRect(hdc, &pdis->rcItem, hBtnBrush);
            DeleteObject(hBtnBrush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0, 0, 0));
            SelectObject(hdc, g_hFontBold);
            DrawTextA(hdc, g_isExecuting ? "Processing..." : "Secure All", -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }

        if (id >= ID_HARD_BASE) {
            int rowIndex = (id - ID_HARD_BASE) / 10;
            bool isSecure = (g_hardStates[rowIndex] == 2);

            HBRUSH hPanelBgBrush = CreateSolidBrush(COLOR_PANEL);
            FillRect(hdc, &pdis->rcItem, hPanelBgBrush);
            DeleteObject(hPanelBgBrush);

            HPEN hPen = CreatePen(PS_SOLID, 1, COLOR_BORDER);
            HBRUSH hBtnBrush = CreateSolidBrush(COLOR_BG);

            SelectObject(hdc, hPen);
            SelectObject(hdc, hBtnBrush);
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);

            char btnText[128] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, isSecure ? COLOR_ACCENT_TEAL : COLOR_TEXT_WHITE);

            SelectObject(hdc, g_hFontSub);
            DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            DeleteObject(hBtnBrush);
            DeleteObject(hPen);
            return TRUE;
        }
        break;
    }

    case WM_COMMAND:
    {
        WORD id = LOWORD(wParam);

        // Burger Menu Button Click Handling
        if (id == ID_BTN_MENU) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenuA(hMenu, MF_STRING, IDM_SETTINGS, "Settings");
            AppendMenuA(hMenu, MF_STRING, IDM_ABOUT, "About");
            AppendMenuA(hMenu, MF_STRING, IDM_SEARCHPASS, "Search Pass");
            AppendMenuA(hMenu, MF_STRING, IDM_WINUPDATE, "Open Windows Update");
            AppendMenuA(hMenu, MF_STRING, IDM_INVENTORY, "Get Inventory");

            HWND hBtn = GetDlgItem(hwnd, ID_BTN_MENU);
            RECT rcBtn;
            GetWindowRect(hBtn, &rcBtn);

            TrackPopupMenu(hMenu, TPM_RIGHTALIGN | TPM_TOPALIGN, rcBtn.right, rcBtn.bottom, 0, hwnd, NULL);
            DestroyMenu(hMenu);
            return 0;
        }

        // Burger Menu Dropdown Commands
        if (id == IDM_SETTINGS) { MessageBoxA(hwnd, "Settings module not yet implemented.", "Info", MB_OK); return 0; }
        if (id == IDM_ABOUT) { MessageBoxA(hwnd, "Comtech Security Tool v4.2.0\nSystem Hardening Utility", "About", MB_OK | MB_ICONINFORMATION); return 0; }
        if (id == IDM_SEARCHPASS) { MessageBoxA(hwnd, "Search Pass module loaded.", "Action", MB_OK); return 0; }
        if (id == IDM_WINUPDATE) { RunSilentCmd("start ms-settings:windowsupdate"); return 0; }
        if (id == IDM_INVENTORY) { MessageBoxA(hwnd, "Executing inventory collection...", "Action", MB_OK); return 0; }

        if (id == ID_STATUS_BAR) {
            ShowLogWindow(hwnd);
            return 0;
        }

        if (g_isExecuting) return 0;

        if (id >= ID_HARD_BASE) {
            int rowIndex = (id - ID_HARD_BASE) / 10;
            g_isExecuting = true;
            SetCursor(LoadCursor(NULL, IDC_WAIT));

            UpdateStatus("Applying Configuration...");
            switch (rowIndex) {
            case 0: SetBluetoothDeviceState(g_hardStates[0] == 2); break;
            case 1: SetWifiDeviceState(g_hardStates[1] == 2); break;
            case 2: ConfigureSMB(true); break;
            case 3: UnshareAllPrinters(); break;
            case 4: UnshareAllFolders(); break;
            case 5: ConfigureSslTlsIISCrypto(true); break;
            case 6: ConfigureBrowserAccountLock(true); break;
            case 7: ConfigureBrowserPasswordLock(true); break;
            case 8: ConfigureLocalUsers(true); break;
            case 9: ConfigureNetworkSecPolicies(true); break; // Apply 10th Control
            }

            PerformAuditAndHighlight();
            g_isExecuting = false;
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            UpdateStatus("Ready (Click to view logs)");
            return 0;
        }

        if (id == ID_BTN_SECURE_ALL) {
            g_isExecuting = true;
            SetCursor(LoadCursor(NULL, IDC_WAIT));
            UpdateStatus("Securing all unsecured components...");

            if (g_hardStates[0] == 1) SetBluetoothDeviceState(false);
            if (g_hardStates[1] == 1) SetWifiDeviceState(false);
            if (g_hardStates[2] == 1) ConfigureSMB(true);
            if (g_hardStates[3] == 1) UnshareAllPrinters();
            if (g_hardStates[4] == 1) UnshareAllFolders();
            if (g_hardStates[5] == 1) ConfigureSslTlsIISCrypto(true);
            if (g_hardStates[6] == 1) ConfigureBrowserAccountLock(true);
            if (g_hardStates[7] == 1) ConfigureBrowserPasswordLock(true);
            if (g_hardStates[8] == 1) ConfigureLocalUsers(true);
            if (g_hardStates[9] == 1) ConfigureNetworkSecPolicies(true); // Apply 10th Control on "Secure All"

            PerformAuditAndHighlight();

            g_isExecuting = false;
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            UpdateStatus("Ready (Click to view logs)");

            MessageBoxA(hwnd, "All required system resources have been successfully secured and locked down.", "Success", MB_OK | MB_ICONINFORMATION);
        }
        break;
    }

    case WM_SETCURSOR:
    {
        if (g_isExecuting) {
            SetCursor(LoadCursor(NULL, IDC_WAIT));
            return TRUE;
        }
        break;
    }

    case WM_DESTROY:
        DeleteObject(g_hBrushBg);
        DeleteObject(g_hBrushPanel);
        DeleteObject(g_hFontTitle);
        DeleteObject(g_hFontSub);
        DeleteObject(g_hFontBold);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "ModernSecPackageTool";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = NULL;
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    RegisterClass(&wc);

    // Adjusted window height up to 704 to fit the 10th row control
    HWND hwnd = CreateWindowExA(0, CLASS_NAME, "Comtech Security Tool",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 635, 704, NULL, NULL, hInstance, NULL);

    // Set Windows 10/11 Dark Title Bar theme constraint
    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));
    // Fallback for older Windows 10 builds
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, &useDarkMode, sizeof(useDarkMode));

    ShowWindow(hwnd, nCmdShow);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}