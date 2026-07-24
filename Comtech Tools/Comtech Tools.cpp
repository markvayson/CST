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

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "netapi32.lib")

#ifndef DPC_ENABLE
#define DPC_ENABLE 0x00000001
#endif
#ifndef DPC_DISABLE
#define DPC_DISABLE 0x00000002
#endif
#ifndef DCPC_GLOBAL
#define DCPC_GLOBAL 0x00000001
#endif

// Fallback Resource ID if not defined in Resource.h
#ifndef IDR_IISSCRYPTOCLI
#define IDR_IISSCRYPTOCLI 101
#endif

#ifndef IDI_ICON1
#define IDI_ICON1 102
#endif

// Control IDs
#define ID_BTN_BEST_PRACTICE 1001
#define ID_BTN_RESTORE       1002
#define ID_BTN_APPLY_CHANGES 1003
#define ID_STATUS_BAR        1004
#define ID_LOG_EDIT          1005
#define ID_HARD_BASE         2000
#define ID_SOFT_BASE         3000

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

// Metric Counts
int g_totalControls = 12;
int g_secureCount = 0;
int g_attentionCount = 0;
int g_insecureCount = 0;

// Target Hardening Action Choice (1 = Left Button / Bad or Unlocked, 2 = Right Button / Best or Locked)
int g_hardStates[9] = { 2, 2, 2, 1, 1, 2, 2, 2, 2 };

// Software Action States (0 = Ignore, 1 = Install/Update, 2 = Uninstall)
int g_softStates[3] = { 0, 0, 0 };

struct HardeningRow {
    const char* name;
    std::string liveInfo;
    const char* opt1Label;
    const char* opt2Label;
    HWND hBtnOpt1;
    HWND hBtnOpt2;
};

HardeningRow g_hardRows[9] = {
    {"Bluetooth Adapter", "Auditing...", "Enabled", "Disabled", NULL, NULL},
    {"Wi-Fi Network Adapter", "Auditing...", "Enabled", "Disabled", NULL, NULL},
    {"SMB Server Protocols", "Auditing...", "Default / Unhardened", "Harden (v1 Off / v2 On)", NULL, NULL},
    {"Shared Network Printers", "Auditing...", "Ignore", "Remove Shares", NULL, NULL},
    {"Shared Network Folders / Files", "Auditing...", "Ignore", "Remove Shares", NULL, NULL},
    {"SSL / TLS & Ciphers", "Auditing...", "Default / Unhardened", "Harden (IIS Crypto Best)", NULL, NULL},
    {"Browser Account Login", "Auditing...", "Unlocked", "Lock Accounts", NULL, NULL},
    {"Browser Password Lock", "Auditing...", "Unlocked", "Lock Passwords", NULL, NULL},
    {"Local User Accounts", "Auditing...", "Ignore", "Disable Inactive Users", NULL, NULL}
};

struct SoftwareRow {
    const char* name;
    std::string liveInfo;
    const char* packageId;
    HWND hBtnIgnore;
    HWND hBtnInstall;
    HWND hBtnUninstall;
};

SoftwareRow g_softRows[3] = {
    {"WinRAR Archiver", "Auditing...", "RARLab.WinRAR", NULL, NULL, NULL},
    {"Microsoft Office Suite", "Auditing...", "Microsoft.Office", NULL, NULL, NULL},
    {"Microsoft OneDrive", "Auditing...", "Microsoft.OneDrive", NULL, NULL, NULL}
};

struct PrinterStatus {
    std::string name;
    std::string shareName;
    bool isShared;
};

std::vector<PrinterStatus> g_printerList;

// Function Declaration
void LogMessage(const std::string& msg);

// --- LOCAL USERS AUDIT & HARDENING ---

// Returns local user summary string and populates user count (excluding Mark)
std::string GetLocalUserAccountsInfo(int& outUserCount, bool& outAllDisabled) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    outUserCount = 0;
    outAllDisabled = true;
    std::vector<std::string> activeUsers;

    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            // Dev Mode Exception: Exclude 'Mark'
            if (_stricmp(userName.c_str(), "Mark") == 0) {
                continue;
            }

            outUserCount++;

            // Check if account is active
            if ((pBuf[i].usri1_flags & UF_ACCOUNTDISABLE) == 0) {
                outAllDisabled = false;
                activeUsers.push_back(userName);
            }
        }
        NetApiBufferFree(pBuf);
    }

    if (outUserCount == 0) {
        return "No Local Users";
    }

    if (outAllDisabled) {
        return "Non-essential Accounts Disabled";
    }

    if (activeUsers.size() == 1) {
        return "Active Account: " + activeUsers[0];
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "Active: %s (%d total)", activeUsers[0].c_str(), (int)activeUsers.size());
    return std::string(buf);
}

// Disable or Enable local accounts across the machine
void ConfigureLocalUsers(bool disableAccounts) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            // Dev Mode Exception: Exclude 'Mark' from modification
            if (_stricmp(userName.c_str(), "Mark") == 0) {
                LogMessage("Local User: Skipping protected dev account 'Mark'");
                continue;
            }

            USER_INFO_1008 ui1008;
            DWORD dwParmErr = 0;

            if (disableAccounts) {
                ui1008.usri1008_flags = pBuf[i].usri1_flags | UF_ACCOUNTDISABLE;
            }
            else {
                ui1008.usri1008_flags = pBuf[i].usri1_flags & ~UF_ACCOUNTDISABLE;
            }

            NET_API_STATUS setStatus = NetUserSetInfo(NULL, wUserName.c_str(), 1008, (LPBYTE)&ui1008, &dwParmErr);
            if (setStatus == NERR_Success) {
                LogMessage("Local User '" + userName + "': " + (disableAccounts ? "DISABLED" : "ENABLED"));
            }
            else {
                LogMessage("Failed to update status for Local User: " + userName);
            }
        }
        NetApiBufferFree(pBuf);
    }
}

// --- EMBEDDED RESOURCE EXECUTION ---

bool RunEmbeddedIISCrypto(const std::wstring& arguments) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_IISSCRYPTOCLI), RT_RCDATA);
    if (!hRes) return false;

    HGLOBAL hMem = LoadResource(hModule, hRes);
    if (!hMem) return false;

    DWORD fileSize = SizeofResource(hModule, hRes);
    LPVOID pData = LockResource(hMem);
    if (!pData || fileSize == 0) return false;

    wchar_t tempPath[MAX_PATH];
    wchar_t exePath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"ISC", 0, exePath);

    std::wstring finalExePath = std::wstring(exePath) + L".exe";
    MoveFileW(exePath, finalExePath.c_str());

    HANDLE hFile = CreateFileW(finalExePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten = 0;
    WriteFile(hFile, pData, fileSize, &bytesWritten, NULL);
    CloseHandle(hFile);

    std::wstring commandLine = L"\"" + finalExePath + L"\" " + arguments;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(
        NULL,
        &commandLine[0],
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );

    if (success) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DeleteFileW(finalExePath.c_str());
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
                    if (SetPrinterA(hPrinter, 2, (LPBYTE)&pPrinterInfo[i], 0)) {
                        LogMessage("Unshared Printer: " + std::string(pPrinterInfo[i].pPrinterName));
                    }
                    else {
                        LogMessage("Failed to unshare printer: " + std::string(pPrinterInfo[i].pPrinterName));
                    }
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
                        if (NetShareDel(NULL, (LMSTR)wShareName.c_str(), 0) == NERR_Success) {
                            char nameA[256] = { 0 };
                            WideCharToMultiByte(CP_ACP, 0, wShareName.c_str(), -1, nameA, sizeof(nameA), NULL, NULL);
                            LogMessage("Unshared Folder: " + std::string(nameA));
                        }
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

// SSL / TLS Audit Detection
bool IsSslTlsHardened() {
    HKEY hKey;
    DWORD tls10Enabled = 1, dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&tls10Enabled, &dwSize);
        RegCloseKey(hKey);
    }
    return (tls10Enabled == 0);
}

// Multi-User Audit: Checks machine-wide HKLM policies for Edge, Chrome, Firefox, & Brave
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

// Audit: Checks machine-wide HKLM policies for Password Manager configurations
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

// Global Enforcement & System-Wide Session Termination
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
        LogMessage("Browser Account Sign-In & Sync: LOCKED for ALL Users");
        LogMessage("Force terminating browser instances across ALL active user sessions...");
        RunSilentCmd("taskkill /F /IM msedge.exe /IM chrome.exe /IM firefox.exe /IM brave.exe /IM opera.exe /IM vivaldi.exe /T >nul 2>&1");
    }
    else {
        LogMessage("Browser Account Sign-In & Sync: UNLOCKED for ALL Users");
    }
}

// Global Password Manager Lock for All Users (HKLM) with instant termination
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
        LogMessage("Browser Password Manager: LOCKED for ALL Users");
        LogMessage("Force terminating browser instances to apply Password Lock...");
        RunSilentCmd("taskkill /F /IM msedge.exe /IM chrome.exe /IM firefox.exe /IM brave.exe /IM opera.exe /IM vivaldi.exe /T >nul 2>&1");
    }
    else {
        LogMessage("Browser Password Manager: UNLOCKED for ALL Users");
    }
}

std::string CleanWinRARVersion(const std::string& nameVal, const std::string& verVal) {
    if (!verVal.empty()) {
        std::smatch match;
        std::regex verRegex("([0-9]+\\.[0-9]+)");
        if (std::regex_search(verVal, match, verRegex)) {
            return "v" + match.str(1);
        }
    }
    return "Installed";
}

std::string CleanOfficeVersion(const std::string& nameVal, const std::string& verVal) {
    if (nameVal.find("2024") != std::string::npos || verVal.find("16.0.17") != std::string::npos || verVal.find("16.0.18") != std::string::npos) return "Office 2024";
    if (nameVal.find("2021") != std::string::npos) return "Office 2021";
    if (nameVal.find("2019") != std::string::npos) return "Office 2019";
    if (nameVal.find("2016") != std::string::npos) return "Office 2016";
    if (nameVal.find("365") != std::string::npos || nameVal.find("Microsoft 365") != std::string::npos) return "Microsoft 365";
    return "Office Suite";
}

std::string DetectSoftwareVersion(const char* targetApp) {
    HKEY rootKeys[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const char* uninstallPaths[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    };

    for (int r = 0; r < 2; r++) {
        for (int p = 0; p < 2; p++) {
            HKEY hUninstallKey;
            if (RegOpenKeyExA(rootKeys[r], uninstallPaths[p], 0, KEY_READ, &hUninstallKey) == ERROR_SUCCESS) {
                DWORD dwSubKeys = 0;
                RegQueryInfoKeyA(hUninstallKey, NULL, NULL, NULL, &dwSubKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

                for (DWORD i = 0; i < dwSubKeys; i++) {
                    char subKeyName[256];
                    DWORD dwSize = sizeof(subKeyName);
                    if (RegEnumKeyExA(hUninstallKey, i, subKeyName, &dwSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                        HKEY hItemKey;
                        std::string fullPath = std::string(uninstallPaths[p]) + "\\" + subKeyName;
                        if (RegOpenKeyExA(rootKeys[r], fullPath.c_str(), 0, KEY_READ, &hItemKey) == ERROR_SUCCESS) {
                            char nameVal[256] = { 0 };
                            DWORD nSize = sizeof(nameVal);
                            RegQueryValueExA(hItemKey, "DisplayName", NULL, NULL, (LPBYTE)nameVal, &nSize);

                            if (strstr(nameVal, targetApp)) {
                                char verVal[64] = { 0 };
                                DWORD vSize = sizeof(verVal);
                                RegQueryValueExA(hItemKey, "DisplayVersion", NULL, NULL, (LPBYTE)verVal, &vSize);

                                RegCloseKey(hItemKey);
                                RegCloseKey(hUninstallKey);

                                if (strcmp(targetApp, "WinRAR") == 0) return CleanWinRARVersion(nameVal, verVal);
                                if (strcmp(targetApp, "Office") == 0) return CleanOfficeVersion(nameVal, verVal);
                                if (strcmp(targetApp, "OneDrive") == 0) return "Installed";
                            }
                            RegCloseKey(hItemKey);
                        }
                    }
                }
                RegCloseKey(hUninstallKey);
            }
        }
    }

    if (strcmp(targetApp, "WinRAR") == 0) {
        if (GetFileAttributesA("C:\\Program Files\\WinRAR\\WinRAR.exe") != INVALID_FILE_ATTRIBUTES ||
            GetFileAttributesA("C:\\Program Files (x86)\\WinRAR\\WinRAR.exe") != INVALID_FILE_ATTRIBUTES) {
            return "Installed";
        }
    }
    if (strcmp(targetApp, "Office") == 0) {
        HKEY hCtrKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration", 0, KEY_READ, &hCtrKey) == ERROR_SUCCESS) {
            char verVal[64] = { 0 };
            DWORD vSize = sizeof(verVal);
            RegQueryValueExA(hCtrKey, "ClientVersionToReport", NULL, NULL, (LPBYTE)verVal, &vSize);
            RegCloseKey(hCtrKey);
            return CleanOfficeVersion("Office", verVal);
        }
    }
    if (strcmp(targetApp, "OneDrive") == 0) {
        HKEY hOdKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\OneDrive", 0, KEY_READ, &hOdKey) == ERROR_SUCCESS) {
            RegCloseKey(hOdKey);
            return "Installed";
        }
    }

    return "Not Installed";
}

// --- HARDENING UTILITIES ---

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
    LogMessage(enable ? "Bluetooth Adapter: ENABLED" : "Bluetooth Adapter: DISABLED");
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
    LogMessage(enable ? "Wi-Fi Adapter: ENABLED" : "Wi-Fi Adapter: DISABLED");
}

// Native Win32 Service Restart (No PowerShell)
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

    LogMessage("Restarting LanmanServer service via Win32 SCM...");
    if (RestartWin32Service("LanmanServer")) {
        LogMessage("LanmanServer service successfully reloaded.");
    }
    else {
        LogMessage("Warning: Failed to restart LanmanServer service. A system reboot may be required.");
    }

    LogMessage(harden ? "SMB Configuration: HARDENED (SMBv1 Disabled)" : "SMB Configuration: DEFAULT (SMBv1 Enabled)");
}

void ConfigureSslTlsIISCrypto(bool harden) {
    if (harden) {
        LogMessage("Executing Embedded IIS Crypto CLI (Best Practice Template)...");
        if (RunEmbeddedIISCrypto(L"/template \"CustomHardening.ictpl\" ")) {
            LogMessage("SSL / TLS & Cipher Configuration Applied via IIS Crypto");
        }
        else {
            LogMessage("Error: Failed to execute embedded IIS Crypto CLI resource.");
        }
    }
    else {
        LogMessage("Executing Embedded IIS Crypto CLI (Reset Default Template)...");
        if (RunEmbeddedIISCrypto(L"/template default")) {
            LogMessage("SSL / TLS & Cipher Configuration Reset to Default");
        }
        else {
            LogMessage("Error: Failed to execute embedded IIS Crypto CLI resource.");
        }
    }
}

void PerformAuditAndHighlight() {
    // Reset counters at the START of audit
    g_secureCount = 0;
    g_attentionCount = 0;
    g_insecureCount = 0;

    bool btActive = IsBluetoothEnabled();
    g_hardRows[0].liveInfo = btActive ? "Currently Enabled" : "Currently Disabled";
    g_hardStates[0] = btActive ? 1 : 2;

    bool wifiActive = IsWifiAdapterEnabled();
    g_hardRows[1].liveInfo = wifiActive ? "Currently Enabled" : "Currently Disabled";
    g_hardStates[1] = wifiActive ? 1 : 2;

    bool smbHardened = IsSMBv1Disabled();
    g_hardRows[2].liveInfo = smbHardened ? "SMBv1 Disabled / Hardened" : "SMBv1 Enabled";
    g_hardStates[2] = smbHardened ? 2 : 1;

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
        if (sharedPrinters.size() == 1) {
            g_hardRows[3].liveInfo = "Shared: " + sharedPrinters[0];
        }
        else {
            char buf[128];
            snprintf(buf, sizeof(buf), "Shared: %s, (%d) more", sharedPrinters[0].c_str(), (int)(sharedPrinters.size() - 1));
            g_hardRows[3].liveInfo = buf;
        }
        g_hardStates[3] = 1;
        ShowWindow(g_hardRows[3].hBtnOpt1, SW_SHOW);
        ShowWindow(g_hardRows[3].hBtnOpt2, SW_SHOW);
    }
    else {
        g_hardRows[3].liveInfo = "No Shared Printer";
        g_hardStates[3] = 2;
        ShowWindow(g_hardRows[3].hBtnOpt1, SW_HIDE);
        ShowWindow(g_hardRows[3].hBtnOpt2, SW_HIDE);
    }

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

        if (sharedFolders.size() == 1) {
            g_hardRows[4].liveInfo = "Shared: " + sharedFolders[0];
        }
        else {
            char buf[128];
            snprintf(buf, sizeof(buf), "Shared: %s, (%d) more", sharedFolders[0].c_str(), (int)(sharedFolders.size() - 1));
            g_hardRows[4].liveInfo = buf;
        }
        g_hardStates[4] = 1;
        ShowWindow(g_hardRows[4].hBtnOpt1, SW_SHOW);
        ShowWindow(g_hardRows[4].hBtnOpt2, SW_SHOW);
    }
    else {
        g_hardRows[4].liveInfo = "No Shared Folders";
        g_hardStates[4] = 2;
        ShowWindow(g_hardRows[4].hBtnOpt1, SW_HIDE);
        ShowWindow(g_hardRows[4].hBtnOpt2, SW_HIDE);
    }

    bool sslTlsHardened = IsSslTlsHardened();
    g_hardRows[5].liveInfo = sslTlsHardened ? "TLS 1.2/1.3 Hardened" : "Weak Protocols / Ciphers Active";
    g_hardStates[5] = sslTlsHardened ? 2 : 1;

    bool browserLocked = IsBrowserAccountLocked();
    g_hardRows[6].liveInfo = browserLocked ? "Sign-In Disabled (Locked)" : "Sign-In Allowed (Unlocked)";
    g_hardStates[6] = browserLocked ? 2 : 1;

    bool passwordLocked = IsBrowserPasswordLocked();
    g_hardRows[7].liveInfo = passwordLocked ? "Password Saving Disabled" : "Password Saving Allowed";
    g_hardStates[7] = passwordLocked ? 2 : 1;

    // Audit Local Users Control
    int userCount = 0;
    bool allUsersDisabled = true;
    g_hardRows[8].liveInfo = GetLocalUserAccountsInfo(userCount, allUsersDisabled);

    if (userCount > 0 && !allUsersDisabled) {
        g_hardStates[8] = 1;
        ShowWindow(g_hardRows[8].hBtnOpt1, SW_SHOW);
        ShowWindow(g_hardRows[8].hBtnOpt2, SW_SHOW);
    }
    else {
        g_hardStates[8] = 2;
        ShowWindow(g_hardRows[8].hBtnOpt1, SW_HIDE);
        ShowWindow(g_hardRows[8].hBtnOpt2, SW_HIDE);
    }

    // Software Management Audits
    std::string rarVer = DetectSoftwareVersion("WinRAR");
    g_softRows[0].liveInfo = (rarVer == "Not Installed") ? "Not Installed" : rarVer;

    std::string offVer = DetectSoftwareVersion("Office");
    g_softRows[1].liveInfo = (offVer == "Not Installed") ? "Not Installed" : offVer;

    std::string odVer = DetectSoftwareVersion("OneDrive");
    g_softRows[2].liveInfo = (odVer == "Not Installed") ? "Not Installed" : odVer;

    // --- Metric Evaluations ---
    if (!btActive) g_secureCount++; else g_attentionCount++;
    if (!wifiActive) g_secureCount++; else g_attentionCount++;
    if (smbHardened) g_secureCount++; else g_insecureCount++;
    if (!hasSharedPrinters) g_secureCount++; else g_attentionCount++;
    if (!hasSharedFolders) g_secureCount++; else g_attentionCount++;
    if (sslTlsHardened) g_secureCount++; else g_insecureCount++;
    if (browserLocked) g_secureCount++; else g_insecureCount++;
    if (passwordLocked) g_secureCount++; else g_insecureCount++;
    if (userCount == 0 || allUsersDisabled) g_secureCount++; else g_insecureCount++;

    if (g_softRows[0].liveInfo != "Not Installed") g_secureCount++; else g_attentionCount++;
    if (g_softRows[1].liveInfo != "Not Installed") g_secureCount++; else g_attentionCount++;
    if (g_softRows[2].liveInfo == "Not Installed") g_secureCount++; else g_attentionCount++;
}

// --- DRAWING HELPERS ---

void DrawCard(HDC hdc, RECT rc, COLORREF borderColor, const char* title, const char* countStr, const char* subtext) {
    HBRUSH hCardBrush = CreateSolidBrush(COLOR_CARD_BG);
    HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
    HGDIOBJ hOldBrush = SelectObject(hdc, hCardBrush);
    HGDIOBJ hOldPen = SelectObject(hdc, hPen);

    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 10, 10);
    SetBkMode(hdc, TRANSPARENT);

    SetTextColor(hdc, COLOR_TEXT_MUTED);
    SelectObject(hdc, g_hFontSub);
    RECT rcTitle = { rc.left + 15, rc.top + 12, rc.right - 15, rc.top + 30 };
    DrawTextA(hdc, title, -1, &rcTitle, DT_LEFT | DT_SINGLELINE);

    SetTextColor(hdc, COLOR_TEXT_WHITE);
    SelectObject(hdc, g_hFontTitle);
    RECT rcCount = { rc.left + 15, rc.top + 32, rc.right - 15, rc.top + 65 };
    DrawTextA(hdc, countStr, -1, &rcCount, DT_LEFT | DT_SINGLELINE);

    SetTextColor(hdc, COLOR_TEXT_MUTED);
    SelectObject(hdc, g_hFontSub);
    RECT rcSub = { rc.left + 15, rc.top + 68, rc.right - 15, rc.bottom - 10 };
    DrawTextA(hdc, subtext, -1, &rcSub, DT_LEFT | DT_SINGLELINE);

    SelectObject(hdc, hOldBrush);
    SelectObject(hdc, hOldPen);
    DeleteObject(hCardBrush);
    DeleteObject(hPen);
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
        g_hFontSub = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

        CreateWindowA("BUTTON", "Best Practices", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 350, 20, 120, 36, hwnd, (HMENU)(UINT_PTR)ID_BTN_BEST_PRACTICE, NULL, NULL);
        CreateWindowA("BUTTON", "Restore Mode", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 480, 20, 120, 36, hwnd, (HMENU)(UINT_PTR)ID_BTN_RESTORE, NULL, NULL);
        CreateWindowA("BUTTON", "Apply Changes", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 610, 20, 140, 36, hwnd, (HMENU)(UINT_PTR)ID_BTN_APPLY_CHANGES, NULL, NULL);

        CreateWindowA("BUTTON", "", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 100, 786, 420, 22, hwnd, (HMENU)(UINT_PTR)ID_STATUS_BAR, NULL, NULL);

        int startY = 222;
        for (int i = 0; i < 9; i++) {
            g_hardRows[i].hBtnOpt1 = CreateWindowA("BUTTON", g_hardRows[i].opt1Label, WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 410, startY, 160, 26, hwnd, (HMENU)(UINT_PTR)(ID_HARD_BASE + i * 10 + 1), NULL, NULL);
            g_hardRows[i].hBtnOpt2 = CreateWindowA("BUTTON", g_hardRows[i].opt2Label, WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 580, startY, 160, 26, hwnd, (HMENU)(UINT_PTR)(ID_HARD_BASE + i * 10 + 2), NULL, NULL);
            startY += 36;
        }

        int softY = 620;
        for (int i = 0; i < 3; i++) {
            g_softRows[i].hBtnIgnore = CreateWindowA("BUTTON", "Ignore", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 410, softY, 100, 26, hwnd, (HMENU)(UINT_PTR)(ID_SOFT_BASE + i * 10 + 0), NULL, NULL);
            g_softRows[i].hBtnInstall = CreateWindowA("BUTTON", "Install / Update", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 515, softY, 115, 26, hwnd, (HMENU)(UINT_PTR)(ID_SOFT_BASE + i * 10 + 1), NULL, NULL);
            g_softRows[i].hBtnUninstall = CreateWindowA("BUTTON", "Uninstall", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 635, softY, 105, 26, hwnd, (HMENU)(UINT_PTR)(ID_SOFT_BASE + i * 10 + 2), NULL, NULL);
            softY += 36;
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
        TextOutA(hdc, 25, 18, dashTitle.c_str(), (int)dashTitle.length());

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        TextOutA(hdc, 25, 45, "System Hardening & Software Package Manager", 43);

        char totalBuf[16], secureBuf[16], attnBuf[16], insecBuf[16];
        snprintf(totalBuf, sizeof(totalBuf), "%d", g_totalControls);
        snprintf(secureBuf, sizeof(secureBuf), "%d", g_secureCount);
        snprintf(attnBuf, sizeof(attnBuf), "%d", g_attentionCount);
        snprintf(insecBuf, sizeof(insecBuf), "%d", g_insecureCount);

        DrawCard(hdc, { 25, 75, 195, 160 }, RGB(30, 58, 138), "Total Controls", totalBuf, "Configured");
        DrawCard(hdc, { 210, 75, 380, 160 }, RGB(16, 185, 129), "Secure", secureBuf, "Up to date");
        DrawCard(hdc, { 395, 75, 565, 160 }, RGB(245, 158, 11), "Attention", attnBuf, "Review needed");
        DrawCard(hdc, { 580, 75, 750, 160 }, RGB(239, 68, 68), "Insecure", insecBuf, "Action required");

        HPEN hPenPanel = CreatePen(PS_SOLID, 1, COLOR_BORDER);
        SelectObject(hdc, g_hBrushPanel);
        SelectObject(hdc, hPenPanel);

        RECT rcPanel1 = { 25, 175, 750, 560 };
        RoundRect(hdc, rcPanel1.left, rcPanel1.top, rcPanel1.right, rcPanel1.bottom, 10, 10);

        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        TextOutA(hdc, 40, 183, "Hardening Controls", 18);

        RECT rcHardHeaderLeft = { 410, 183, 570, 215 };
        RECT rcHardHeaderRight = { 580, 183, 740, 215 };
        DrawTextA(hdc, "Insecured Action", -1, &rcHardHeaderLeft, DT_CENTER | DT_WORDBREAK);
        DrawTextA(hdc, "Secured Action", -1, &rcHardHeaderRight, DT_CENTER | DT_WORDBREAK);

        int rowY = 222;
        for (int i = 0; i < 9; i++) {
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            TextOutA(hdc, 40, rowY, g_hardRows[i].name, (int)strlen(g_hardRows[i].name));

            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, COLOR_TEXT_MUTED);
            TextOutA(hdc, 40, rowY + 15, g_hardRows[i].liveInfo.c_str(), (int)g_hardRows[i].liveInfo.length());

            if ((i == 3 || i == 4 || i == 8) && !IsWindowVisible(g_hardRows[i].hBtnOpt1)) {
                RECT rcNoItems = { 410, rowY, 740, rowY + 26 };
                SetTextColor(hdc, COLOR_TEXT_MUTED);
                SelectObject(hdc, g_hFontSub);
                const char* placeholder = (i == 8) ? "No Local Users" : ((i == 3) ? "No Shared Printer" : "No Shared Folders");
                DrawTextA(hdc, placeholder, -1, &rcNoItems, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }

            rowY += 36;
        }

        RECT rcPanel2 = { 25, 575, 750, 770 };
        RoundRect(hdc, rcPanel2.left, rcPanel2.top, rcPanel2.right, rcPanel2.bottom, 10, 10);

        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        TextOutA(hdc, 40, 585, "Software Management (WinRAR, Office, OneDrive)", 47);

        int softY = 620;
        for (int i = 0; i < 3; i++) {
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            TextOutA(hdc, 40, softY, g_softRows[i].name, (int)strlen(g_softRows[i].name));

            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, COLOR_TEXT_MUTED);
            TextOutA(hdc, 40, softY + 15, g_softRows[i].liveInfo.c_str(), (int)g_softRows[i].liveInfo.length());

            softY += 36;
        }

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        TextOutA(hdc, 25, 788, "v4.2.0.0", 8);
        TextOutA(hdc, 530, 788, "© 2026 Comtech Security Tool", 33);

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

        if (id == ID_BTN_APPLY_CHANGES) {
            HBRUSH hBtnBrush = CreateSolidBrush(g_isExecuting ? COLOR_TEXT_MUTED : COLOR_ACCENT_TEAL);
            FillRect(hdc, &pdis->rcItem, hBtnBrush);
            DeleteObject(hBtnBrush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0, 0, 0));
            SelectObject(hdc, g_hFontBold);
            DrawTextA(hdc, g_isExecuting ? "Processing..." : "Apply Changes", -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }

        if (id == ID_BTN_BEST_PRACTICE || id == ID_BTN_RESTORE) {
            HBRUSH hParentBrush = CreateSolidBrush(COLOR_BG);
            FillRect(hdc, &pdis->rcItem, hParentBrush);
            DeleteObject(hParentBrush);

            HPEN hNullPen = (HPEN)GetStockObject(NULL_PEN);
            HBRUSH hBtnBrush = CreateSolidBrush(COLOR_CARD_BG);

            SelectObject(hdc, hNullPen);
            SelectObject(hdc, hBtnBrush);
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);

            char btnText[64] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            SelectObject(hdc, g_hFontSub);
            DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            DeleteObject(hBtnBrush);
            return TRUE;
        }

        if (id >= ID_HARD_BASE && id < ID_SOFT_BASE) {
            int rowIndex = (id - ID_HARD_BASE) / 10;
            int btnType = (id - ID_HARD_BASE) % 10;

            bool isSelected = (g_hardStates[rowIndex] == btnType);

            COLORREF bgCol = COLOR_CARD_BG;
            COLORREF txtCol = COLOR_TEXT_WHITE;

            if (isSelected) {
                if (btnType == 1) {
                    bgCol = COLOR_DANGER_RED;
                    txtCol = COLOR_TEXT_WHITE;
                }
                else if (btnType == 2) {
                    bgCol = COLOR_ACCENT_TEAL;
                    txtCol = RGB(0, 0, 0);
                }
            }

            HBRUSH hPanelBgBrush = CreateSolidBrush(COLOR_PANEL);
            FillRect(hdc, &pdis->rcItem, hPanelBgBrush);
            DeleteObject(hPanelBgBrush);

            HPEN hNullPen = (HPEN)GetStockObject(NULL_PEN);
            HBRUSH hBtnBrush = CreateSolidBrush(bgCol);

            SelectObject(hdc, hNullPen);
            SelectObject(hdc, hBtnBrush);
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);

            char btnText[128] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, txtCol);
            SelectObject(hdc, g_hFontSub);
            DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            DeleteObject(hBtnBrush);
            return TRUE;
        }

        if (id >= ID_SOFT_BASE) {
            int rowIndex = (id - ID_SOFT_BASE) / 10;
            int btnType = (id - ID_SOFT_BASE) % 10;

            bool isSelected = (g_softStates[rowIndex] == btnType);

            COLORREF bgCol = COLOR_CARD_BG;
            COLORREF txtCol = COLOR_TEXT_WHITE;

            if (isSelected) {
                if (rowIndex == 2 && btnType == 0) {
                    bgCol = COLOR_DANGER_RED;
                    txtCol = COLOR_TEXT_WHITE;
                }
                else {
                    bgCol = COLOR_ACCENT_TEAL;
                    txtCol = RGB(0, 0, 0);
                }
            }

            HBRUSH hPanelBgBrush = CreateSolidBrush(COLOR_PANEL);
            FillRect(hdc, &pdis->rcItem, hPanelBgBrush);
            DeleteObject(hPanelBgBrush);

            HPEN hNullPen = (HPEN)GetStockObject(NULL_PEN);
            HBRUSH hBtnBrush = CreateSolidBrush(bgCol);

            SelectObject(hdc, hNullPen);
            SelectObject(hdc, hBtnBrush);
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);

            char btnText[128] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, txtCol);
            SelectObject(hdc, g_hFontSub);
            DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            DeleteObject(hBtnBrush);
            return TRUE;
        }
        break;
    }

    case WM_COMMAND:
    {
        WORD id = LOWORD(wParam);

        if (id == ID_STATUS_BAR) {
            ShowLogWindow(hwnd);
            return 0;
        }

        if (g_isExecuting) return 0;

        if (id >= ID_HARD_BASE && id < ID_SOFT_BASE) {
            int rowIndex = (id - ID_HARD_BASE) / 10;
            int btnType = (id - ID_HARD_BASE) % 10;

            g_hardStates[rowIndex] = btnType;
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }

        if (id >= ID_SOFT_BASE) {
            int rowIndex = (id - ID_SOFT_BASE) / 10;
            int btnType = (id - ID_SOFT_BASE) % 10;

            g_softStates[rowIndex] = btnType;
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }

        if (id == ID_BTN_BEST_PRACTICE) {
            g_hardStates[0] = 2;
            g_hardStates[1] = 2;
            g_hardStates[2] = 2;
            g_hardStates[3] = 2;
            g_hardStates[4] = 2;
            g_hardStates[5] = 2;
            g_hardStates[6] = 2;
            g_hardStates[7] = 2;
            g_hardStates[8] = 2;

            g_softStates[0] = 1;
            g_softStates[1] = 1;
            g_softStates[2] = 2;

            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            LogMessage("Loaded 'Best Practice' preset selections.");
            MessageBoxA(hwnd, "Best Practice configuration loaded!\nClick 'Apply Changes' to execute.", "Best Practice", MB_OK | MB_ICONINFORMATION);
        }

        if (id == ID_BTN_RESTORE) {
            g_hardStates[0] = 1;
            g_hardStates[1] = 1;
            g_hardStates[2] = 1;
            g_hardStates[3] = 1;
            g_hardStates[4] = 1;
            g_hardStates[5] = 1;
            g_hardStates[6] = 1;
            g_hardStates[7] = 1;
            g_hardStates[8] = 1;

            g_softStates[0] = 0;
            g_softStates[1] = 0;
            g_softStates[2] = 0;

            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            LogMessage("Loaded 'Restore Mode' preset selections.");
            MessageBoxA(hwnd, "Switched UI to Restore Mode.\nSelect the desired restore actions and click 'Apply Changes'.", "Restore Mode", MB_OK | MB_ICONINFORMATION);
        }

        if (id == ID_BTN_APPLY_CHANGES) {
            g_isExecuting = true;
            SetCursor(LoadCursor(NULL, IDC_WAIT));
            bool changesMade = false;

            // 1. Bluetooth
            bool currentBt = IsBluetoothEnabled();
            bool wantBt = (g_hardStates[0] == 1);
            if (currentBt != wantBt) {
                UpdateStatus("Applying Bluetooth Settings...");
                SetBluetoothDeviceState(wantBt);
                changesMade = true;
            }

            // 2. Wi-Fi
            bool currentWifi = IsWifiAdapterEnabled();
            bool wantWifi = (g_hardStates[1] == 1);
            if (currentWifi != wantWifi) {
                UpdateStatus("Applying Wi-Fi Adapter Settings...");
                SetWifiDeviceState(wantWifi);
                changesMade = true;
            }

            // 3. SMB Protocols
            bool currentSmbLocked = IsSMBv1Disabled();
            bool wantSmbLocked = (g_hardStates[2] == 2);
            if (currentSmbLocked != wantSmbLocked) {
                UpdateStatus("Configuring SMB Security Protocols...");
                ConfigureSMB(wantSmbLocked);
                changesMade = true;
            }

            // 4. Printers
            if (g_hardStates[3] == 2) {
                std::vector<PrinterStatus> plist = GetSystemPrintersInfo();
                bool hasShares = false;
                for (const auto& p : plist) {
                    if (p.isShared) { hasShares = true; break; }
                }
                if (hasShares) {
                    UpdateStatus("Removing Network Printer Shares...");
                    UnshareAllPrinters();
                    changesMade = true;
                }
            }

            // 5. Folders
            if (g_hardStates[4] == 2) {
                std::string dummy;
                if (GetSystemSharedFoldersInfo(dummy)) {
                    UpdateStatus("Removing Network Shared Folders...");
                    UnshareAllFolders();
                    changesMade = true;
                }
            }

            // 6. SSL / TLS
            bool currentSslLocked = IsSslTlsHardened();
            bool wantSslLocked = (g_hardStates[5] == 2);
            if (currentSslLocked != wantSslLocked) {
                UpdateStatus("Configuring SSL / TLS Ciphers via IIS Crypto...");
                ConfigureSslTlsIISCrypto(wantSslLocked);
                changesMade = true;
            }

            // 7. Browser Account Lock
            bool currentAcctLocked = IsBrowserAccountLocked();
            bool wantAcctLocked = (g_hardStates[6] == 2);
            if (currentAcctLocked != wantAcctLocked) {
                UpdateStatus("Configuring Browser Account Lock Policies...");
                ConfigureBrowserAccountLock(wantAcctLocked);
                changesMade = true;
            }

            // 8. Browser Password Lock
            bool currentPassLocked = IsBrowserPasswordLocked();
            bool wantPassLocked = (g_hardStates[7] == 2);
            if (currentPassLocked != wantPassLocked) {
                UpdateStatus("Configuring Browser Password Lock Policies...");
                ConfigureBrowserPasswordLock(wantPassLocked);
                changesMade = true;
            }

            // 9. Local Users Account Enforcement
            if (g_hardStates[8] == 2) {
                int dummyCount = 0;
                bool dummyAllDisabled = false;
                GetLocalUserAccountsInfo(dummyCount, dummyAllDisabled);
                if (dummyCount > 0 && !dummyAllDisabled) {
                    UpdateStatus("Disabling inactive local user accounts...");
                    ConfigureLocalUsers(true);
                    changesMade = true;
                }
            }

            // 10. Software Management
            const char* swNames[3] = { "WinRAR", "Office", "OneDrive" };
            for (int i = 0; i < 3; i++) {
                if (g_softStates[i] == 0) continue;

                bool isInstalled = (DetectSoftwareVersion(swNames[i]) != "Not Installed");
                char cmd[512] = { 0 };

                if (g_softStates[i] == 1) {
                    UpdateStatus("Winget: Installing / Updating " + std::string(g_softRows[i].name) + "...");
                    snprintf(cmd, sizeof(cmd), "winget install --id %s --silent --accept-source-agreements --accept-package-agreements", g_softRows[i].packageId);
                    RunSilentCmd(cmd);
                    changesMade = true;
                }
                else if (g_softStates[i] == 2 && isInstalled) {
                    UpdateStatus("Winget: Uninstalling " + std::string(g_softRows[i].name) + "...");
                    snprintf(cmd, sizeof(cmd), "winget uninstall --id %s --silent --accept-source-agreements", g_softRows[i].packageId);
                    RunSilentCmd(cmd);
                    changesMade = true;
                }
            }

            UpdateStatus("Running Audit & Refreshing Metrics...");
            PerformAuditAndHighlight();

            g_isExecuting = false;
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            UpdateStatus("Ready (Click to view logs)");

            if (changesMade) {
                MessageBoxA(hwnd, "Configuration and package management tasks completed!", "Success", MB_OK | MB_ICONINFORMATION);
            }
            else {
                MessageBoxA(hwnd, "No changes were necessary. The system already matches the requested configuration.", "No Changes", MB_OK | MB_ICONINFORMATION);
            }
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

    HWND hwnd = CreateWindowExA(0, CLASS_NAME, "Comtech Security Tool",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 790, 860, NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}