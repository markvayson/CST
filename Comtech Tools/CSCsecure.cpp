#define WIN32_LEAN_AND_MEAN
#include "CSCsecure.h"
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
#include <dwmapi.h> 
#include "Inventory.h"

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "dwmapi.lib") 
#pragma comment(lib, "version.lib")

// Retrieves a StringFileInfo entry from VS_VERSION_INFO in resources
std::string GetFileVersionValue(const char* valueName) {
    char szPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, szPath, MAX_PATH)) return "";

    DWORD dwDummy = 0;
    DWORD dwSize = GetFileVersionInfoSizeA(szPath, &dwDummy);
    if (dwSize == 0) return "";

    std::vector<BYTE> data(dwSize);
    if (!GetFileVersionInfoA(szPath, 0, dwSize, data.data())) return "";

    // Query translation table block dynamically
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
        // Fallback to English/Unicode (040904b0) as defined in cscsecure.rc
        snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\040904b0\\%s", valueName);
    }

    LPVOID lpBuffer = NULL;
    UINT len = 0;
    if (VerQueryValueA(data.data(), subBlock, &lpBuffer, &len) && lpBuffer && len > 0) {
        return std::string(static_cast<char*>(lpBuffer));
    }

    return "";
}

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

// System Hostname & OS 
char g_computerName[MAX_COMPUTERNAME_LENGTH + 1] = "UNKNOWN";
std::string g_osVersion = "Windows 11 25H2";

// Metric Counts 
int g_totalControls = 10;
int g_secureCount = 0;
int g_attentionCount = 0;
int g_insecureCount = 0;

int g_hardStates[10] = { 2, 2, 2, 1, 1, 1, 2, 2, 2, 2 };

// Dynamic Version Globals
std::string g_appProductName = "CSCsecure";
std::string g_appVersion = "3.1.0";
std::string g_appDescription = "System Hardening Utility";
std::string g_footerVersionStr = "CSCsecure v3.1.0 \xA9 2026";

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

// --- DYNAMIC VERSION LOADER ---
void LoadVersionInfoFromResource() {
    std::string name = GetFileVersionValue("ProductName");
    std::string ver = GetFileVersionValue("ProductVersion");
    std::string desc = GetFileVersionValue("FileDescription");

    if (!name.empty()) g_appProductName = name;
    if (!ver.empty()) g_appVersion = ver;
    if (!desc.empty()) g_appDescription = desc;

    if (!g_appProductName.empty() && !g_appVersion.empty()) {
        g_footerVersionStr = g_appProductName + " v" + g_appVersion + " \xA9 2026";
    }
}

// --- CUSTOM NATIVE CONFIRMATION DIALOG ---
bool g_confirmResult = false;
std::string g_confirmMsg = "";

LRESULT CALLBACK ConfirmWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CreateWindowA("BUTTON", "Confirm", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 35, 90, 90, 30, hwnd, (HMENU)1, NULL, NULL);
        CreateWindowA("BUTTON", "Cancel", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 145, 90, 90, 30, hwnd, (HMENU)2, NULL, NULL);
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        FillRect(hdc, &rc, g_hBrushBg);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontSub);

        RECT textRc = { 15, 25, rc.right - 15, 75 };
        DrawTextA(hdc, g_confirmMsg.c_str(), -1, &textRc, DT_CENTER | DT_WORDBREAK);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;
        bool isConfirm = (pdis->CtlID == 1);

        HBRUSH hBtnBrush = CreateSolidBrush(isConfirm ? COLOR_DANGER_RED : COLOR_PANEL);
        FillRect(hdc, &pdis->rcItem, hBtnBrush);
        DeleteObject(hBtnBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, isConfirm ? COLOR_DANGER_RED : COLOR_BORDER);
        SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontBold);
        DrawTextA(hdc, isConfirm ? "Confirm" : "Cancel", -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) { g_confirmResult = true; PostMessage(hwnd, WM_CLOSE, 0, 0); }
        if (LOWORD(wParam) == 2) { g_confirmResult = false; PostMessage(hwnd, WM_CLOSE, 0, 0); }
        break;
    }
    case WM_CLOSE: {
        EnableWindow(GetParent(hwnd), TRUE);
        SetForegroundWindow(GetParent(hwnd));
        DestroyWindow(hwnd);
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

bool ShowDarkConfirmDialog(HWND hParent, const char* msg) {
    g_confirmMsg = msg;
    g_confirmResult = false;

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = ConfirmWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "DarkConfirmDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClass(&wc);

    HWND hConfirm = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        "DarkConfirmDialog", "Action Required",
        WS_POPUP | WS_BORDER | WS_CAPTION,
        0, 0, 285, 170, hParent, NULL, GetModuleHandle(NULL), NULL);

    RECT rcParent; GetWindowRect(hParent, &rcParent);
    SetWindowPos(hConfirm, NULL,
        rcParent.left + (rcParent.right - rcParent.left) / 2 - 142,
        rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 85,
        285, 170, SWP_NOZORDER);

    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hConfirm, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    EnableWindow(hParent, FALSE);
    ShowWindow(hConfirm, SW_SHOW);

    MSG wmsg;
    while (IsWindow(hConfirm) && GetMessage(&wmsg, NULL, 0, 0)) {
        TranslateMessage(&wmsg);
        DispatchMessage(&wmsg);
    }
    return g_confirmResult;
}

// --- CUSTOM NATIVE BURGER MENU POPUP DIALOG ---
LRESULT CALLBACK MenuPopupWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        int y = 50;
        int btnWidth = 240;
        int btnHeight = 34;
        int spacing = 10;

        CreateWindowA("BUTTON", "About", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, y, btnWidth, btnHeight, hwnd, (HMENU)IDM_ABOUT, NULL, NULL);
        y += btnHeight + spacing;
        CreateWindowA("BUTTON", "Search Pass", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, y, btnWidth, btnHeight, hwnd, (HMENU)IDM_SEARCHPASS, NULL, NULL);
        y += btnHeight + spacing;
        CreateWindowA("BUTTON", "Open Windows Update", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, y, btnWidth, btnHeight, hwnd, (HMENU)IDM_WINUPDATE, NULL, NULL);
        y += btnHeight + spacing;
        CreateWindowA("BUTTON", "Get Inventory", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, y, btnWidth, btnHeight, hwnd, (HMENU)IDM_INVENTORY, NULL, NULL);
        y += btnHeight + spacing + 5;
        CreateWindowA("BUTTON", "Close", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, y, btnWidth, btnHeight, hwnd, (HMENU)IDCANCEL, NULL, NULL);
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        FillRect(hdc, &rc, g_hBrushBg);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontTitle);

        RECT titleRc = { 0, 12, rc.right, 42 };
        DrawTextA(hdc, "Menu Options", -1, &titleRc, DT_CENTER | DT_SINGLELINE);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;
        UINT id = pdis->CtlID;

        bool isClose = (id == IDCANCEL);
        HBRUSH hBtnBrush = CreateSolidBrush(isClose ? COLOR_PANEL : COLOR_CARD_BG);
        FillRect(hdc, &pdis->rcItem, hBtnBrush);
        DeleteObject(hBtnBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, isClose ? COLOR_BORDER : COLOR_ACCENT_TEAL);
        SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, isClose ? COLOR_TEXT_MUTED : COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontBold);

        char btnText[64] = { 0 };
        GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));
        DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        HWND hParent = GetParent(hwnd);
        PostMessage(hwnd, WM_CLOSE, 0, 0);
        if (id != IDCANCEL && hParent) {
            PostMessage(hParent, WM_COMMAND, wParam, lParam);
        }
        break;
    }
    case WM_CLOSE: {
        EnableWindow(GetParent(hwnd), TRUE);
        SetForegroundWindow(GetParent(hwnd));
        DestroyWindow(hwnd);
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ShowDarkMenuDialog(HWND hParent) {
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MenuPopupWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "DarkMenuPopupDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClass(&wc);

    HWND hPopup = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        "DarkMenuPopupDialog", "CSCsecure Menu",
        WS_POPUP | WS_BORDER | WS_CAPTION,
        0, 0, 305, 360, hParent, NULL, GetModuleHandle(NULL), NULL);

    RECT rcParent; GetWindowRect(hParent, &rcParent);
    SetWindowPos(hPopup, NULL,
        rcParent.left + (rcParent.right - rcParent.left) / 2 - 152,
        rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 180,
        305, 360, SWP_NOZORDER);

    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hPopup, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    EnableWindow(hParent, FALSE);
    ShowWindow(hPopup, SW_SHOW);

    MSG wmsg;
    while (IsWindow(hPopup) && GetMessage(&wmsg, NULL, 0, 0)) {
        TranslateMessage(&wmsg);
        DispatchMessage(&wmsg);
    }
}

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

bool IsSMBv1Disabled() {
    HKEY hKey;
    DWORD smb1 = 1, dwSize = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SMB1", NULL, NULL, (LPBYTE)&smb1, &dwSize);
        RegCloseKey(hKey);
    }
    return (smb1 == 0);
}

// Helper function to check if a specific SCHANNEL key is explicitly disabled
bool CheckSchannelKeyDisabled(const char* subKey) {
    HKEY hKey;
    DWORD enabled = 1; // Default to enabled/OS default if the key doesn't exist
    DWORD dwSize = sizeof(DWORD);
    char fullPath[512];

    snprintf(fullPath, sizeof(fullPath), "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\%s", subKey);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, fullPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // IIS Crypto sets 'Enabled' to 0 when disabling a component
        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&enabled, &dwSize) != ERROR_SUCCESS) {
            enabled = 1; // If the value is missing, it's not explicitly disabled
        }
        RegCloseKey(hKey);
    }
    return (enabled == 0);
}

// Upgraded TLS Hardening Check
bool IsSslTlsHardened() {
    // 1. Check if legacy protocols are explicitly disabled
    bool noTls10 = CheckSchannelKeyDisabled("Protocols\\TLS 1.0\\Server");
    bool noTls11 = CheckSchannelKeyDisabled("Protocols\\TLS 1.1\\Server");
    bool noSsl30 = CheckSchannelKeyDisabled("Protocols\\SSL 3.0\\Server");

    // 2. Check if weak ciphers are explicitly disabled (Key indicators of a template)
    bool noRc4 = CheckSchannelKeyDisabled("Ciphers\\RC4 128/128");
    bool noNull = CheckSchannelKeyDisabled("Ciphers\\NULL");
    bool noDes = CheckSchannelKeyDisabled("Ciphers\\DES 56/56");

    // 3. Check if weak hashes are explicitly disabled
    bool noMd5 = CheckSchannelKeyDisabled("Hashes\\MD5");

    // The system is only considered hardened if ALL these weak components are explicitly turned off.
    // If someone only manually tweaked the protocols, the ciphers/hashes will fail this check.
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
        g_hardRows[3].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[3].hBtnAction, g_hardRows[3].actionLabel);
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
        g_hBrushBg = CreateSolidBrush(COLOR_BG);
        g_hBrushPanel = CreateSolidBrush(COLOR_PANEL);

        // --- NEW: Load the dynamically queried version numbers here ---
        LoadVersionInfoFromResource();

        DWORD size = sizeof(g_computerName);
        GetComputerNameA(g_computerName, &size);

        // Fetch Dynamic Windows Version
        HKEY hKey;
        char productName[128] = { 0 };
        char displayVersion[64] = { 0 };
        char currentBuild[64] = { 0 };
        DWORD bufLen = sizeof(productName);

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName, &bufLen) == ERROR_SUCCESS) {

                bufLen = sizeof(currentBuild);
                RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (LPBYTE)currentBuild, &bufLen);

                std::string prodStr(productName);
                if (atoi(currentBuild) >= 22000) {
                    size_t pos = prodStr.find("Windows 10");
                    if (pos != std::string::npos) {
                        prodStr.replace(pos, 10, "Windows 11");
                    }
                }

                bufLen = sizeof(displayVersion);
                if (RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &bufLen) == ERROR_SUCCESS) {
                    g_osVersion = prodStr + " " + std::string(displayVersion);
                }
                else {
                    g_osVersion = prodStr;
                }
            }
            RegCloseKey(hKey);
        }

        g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontSub = CreateFontA(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

        CreateWindowA("BUTTON", "", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 565, 15, 30, 30, hwnd, (HMENU)(UINT_PTR)ID_BTN_MENU, NULL, NULL);
        CreateWindowA("BUTTON", "Secure All", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 450, 78, 130, 30, hwnd, (HMENU)(UINT_PTR)ID_BTN_SECURE_ALL, NULL, NULL);

        // Adjusted Status Bar
        CreateWindowA("BUTTON", "", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, 650, 420, 24, hwnd, (HMENU)(UINT_PTR)ID_STATUS_BAR, NULL, NULL);

        int startY = 125;
        int rowHeight = 44;

        for (int i = 0; i < 10; i++) {
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

        std::string dashTitle = std::string(g_computerName) + " - " + g_osVersion;
        TextOutA(hdc, 25, 15, dashTitle.c_str(), (int)dashTitle.length());

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        TextOutA(hdc, 25, 40, "System Hardening Compliance Utility", 35);

        HPEN hPenPanel = CreatePen(PS_SOLID, 1, COLOR_BORDER);
        SelectObject(hdc, g_hBrushPanel);
        SelectObject(hdc, hPenPanel);

        RECT rcPanel1 = { 25, 68, 595, 574 };
        RoundRect(hdc, rcPanel1.left, rcPanel1.top, rcPanel1.right, rcPanel1.bottom, 8, 8);

        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        TextOutA(hdc, 40, 82, "Hardening Controls", 18);

        int percent = (g_totalControls > 0) ? (g_secureCount * 100) / g_totalControls : 0;
        COLORREF barColor;
        if (percent >= 80) barColor = COLOR_ACCENT_TEAL;
        else if (percent >= 50) barColor = COLOR_WARN_AMBER;
        else barColor = COLOR_DANGER_RED;

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

        char pctStr[32];
        snprintf(pctStr, sizeof(pctStr), "%d%%", percent);
        SetTextColor(hdc, barColor);
        SelectObject(hdc, g_hFontBold);
        TextOutA(hdc, rcProgBg.right + 10, 82, pctStr, (int)strlen(pctStr));

        int rowY = 125;
        int rowHeight = 44;

        for (int i = 0; i < 10; i++) {
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            TextOutA(hdc, 40, rowY, g_hardRows[i].name, (int)strlen(g_hardRows[i].name));

            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, COLOR_TEXT_MUTED);
            TextOutA(hdc, 40, rowY + 18, g_hardRows[i].liveInfo.c_str(), (int)g_hardRows[i].liveInfo.length());

            bool isSecure = (g_hardStates[i] == 2);
            SetTextColor(hdc, isSecure ? COLOR_ACCENT_TEAL : COLOR_DANGER_RED);

            RECT rcStatus = { 330, rowY + 6, 480, rowY + 32 };
            std::string statusText = g_hardRows[i].statusLabel;
            DrawTextA(hdc, statusText.c_str(), -1, &rcStatus, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

            rowY += rowHeight;
        }

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);

        // --- NEW: Using the dynamic global string for the footer version text ---
        TextOutA(hdc, 455, 654, g_footerVersionStr.c_str(), (int)g_footerVersionStr.length());

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

        if (id == ID_BTN_MENU) {
            HBRUSH hBg = CreateSolidBrush(COLOR_BG);
            FillRect(hdc, &pdis->rcItem, hBg);
            DeleteObject(hBg);

            HBRUSH hIconBrush = CreateSolidBrush(COLOR_TEXT_WHITE);
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

        // Hardening Controls Button Styles
        if (id >= ID_HARD_BASE) {
            int rowIndex = (id - ID_HARD_BASE) / 10;
            bool isSecure = (g_hardStates[rowIndex] == 2);

            HBRUSH hPanelBgBrush = CreateSolidBrush(COLOR_PANEL);
            FillRect(hdc, &pdis->rcItem, hPanelBgBrush);
            DeleteObject(hPanelBgBrush);

            HPEN hPen;
            HBRUSH hBtnBrush;
            COLORREF textColor;

            // Highlight button when warning; subtle outline when secured/enabled
            if (isSecure) {
                hBtnBrush = CreateSolidBrush(COLOR_BG);
                hPen = CreatePen(PS_SOLID, 1, COLOR_BORDER);
                textColor = COLOR_TEXT_MUTED;
            }
            else {
                hBtnBrush = CreateSolidBrush(COLOR_ACCENT_TEAL);
                hPen = CreatePen(PS_SOLID, 1, COLOR_ACCENT_TEAL);
                textColor = RGB(0, 0, 0);
            }

            SelectObject(hdc, hPen);
            SelectObject(hdc, hBtnBrush);
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);

            char btnText[128] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, textColor);

            SelectObject(hdc, g_hFontBold);
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

        // Burger Button now opens Popup Window instead of Dropdown Menu
        if (id == ID_BTN_MENU) {
            ShowDarkMenuDialog(hwnd);
            return 0;
        }

        // --- NEW: Using the dynamic global string for the MessageBox body ---
        if (id == IDM_ABOUT) {
            std::string aboutMsg = g_appProductName + " v" + g_appVersion + "\n" + g_appDescription;
            MessageBoxA(hwnd, aboutMsg.c_str(), "About", MB_OK | MB_ICONINFORMATION);
            return 0;
        }

        if (id == IDM_SEARCHPASS) { MessageBoxA(hwnd, "Search Pass module loaded.", "Action", MB_OK); return 0; }
        if (id == IDM_WINUPDATE) { RunSilentCmd("start ms-settings:windowsupdate"); return 0; }
        if (id == IDM_INVENTORY) {
            RunInventoryCollection(hwnd);
            return 0;
        }

        if (id == ID_STATUS_BAR) {
            ShowLogWindow(hwnd);
            return 0;
        }

        if (g_isExecuting) return 0;

        // Individual Control Row Button Handler (Supports both Secured & Unsecured states)
        if (id >= ID_HARD_BASE) {
            int rowIndex = (id - ID_HARD_BASE) / 10;
            bool isSecured = (g_hardStates[rowIndex] == 2);

            const char* confirmPrompt = isSecured ?
                "Are you sure you want to change / restore this setting?" :
                "Are you sure you want to secure this component?";

            if (!ShowDarkConfirmDialog(hwnd, confirmPrompt)) {
                return 0;
            }

            g_isExecuting = true;
            SetCursor(LoadCursor(NULL, IDC_WAIT));
            UpdateStatus("Processing security component...");

            bool enableOrHarden = !isSecured;

            switch (rowIndex) {
            case 0: SetBluetoothDeviceState(isSecured ? true : false); break;
            case 1: SetWifiDeviceState(isSecured ? true : false); break;
            case 2: ConfigureSMB(enableOrHarden); break;
            case 3: UnshareAllPrinters(); break;
            case 4: UnshareAllFolders(); break;
            case 5: ConfigureSslTlsIISCrypto(enableOrHarden); break;
            case 6: ConfigureBrowserAccountLock(enableOrHarden); break;
            case 7: ConfigureBrowserPasswordLock(enableOrHarden); break;
            case 8: ConfigureLocalUsers(enableOrHarden); break;
            case 9: ConfigureNetworkSecPolicies(enableOrHarden); break;
            }

            PerformAuditAndHighlight();

            g_isExecuting = false;
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            UpdateStatus("Ready (Click to view logs)");

            return 0;
        }

        if (id == ID_BTN_SECURE_ALL) {

            if (!ShowDarkConfirmDialog(hwnd, "Are you sure you want to secure ALL unresolved components automatically?")) {
                return 0;
            }

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
            if (g_hardStates[9] == 1) ConfigureNetworkSecPolicies(true);

            PerformAuditAndHighlight();

            g_isExecuting = false;
            SetCursor(LoadCursor(NULL, IDC_ARROW));
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            UpdateStatus("Ready (Click to view logs)");
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
    std::string ver = GetFileVersionValue("ProductVersion");
    std::string windowTitle = "CSCsecure v" + ver;
    HWND hwnd = CreateWindowExA(0, CLASS_NAME, windowTitle.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 635, 715, NULL, NULL, hInstance, NULL);

    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, &useDarkMode, sizeof(useDarkMode));

    ShowWindow(hwnd, nCmdShow);

    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}