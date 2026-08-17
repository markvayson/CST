#define WIN32_LEAN_AND_MEAN
#include "CSCsecure.h"
#include "ConfirmDialog.h"
#include <windows.h>
#include <commctrl.h>
#include <userenv.h>
#include <winspool.h>
#include <lm.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <shellapi.h>


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
#include <functional>
#include "Sidebar.h"
#include "WindowsFeatures.h"
#include "WifiAdapter.h"
#include "Bluetooth.h"
#include "SmbProtocol.h"
#include "NetworkPrinters.h"
#include "SharedFolders.h"
#include "IISCrypto.h"
#include "BrowserAccount.h"
#include "BrowserPassword.h"
#include "LocalAccounts.h"
#include "NetworkSecPolicies.h"
#include "WinRARUtils.h"


#pragma comment(lib, "d2d1.lib")
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

#ifndef DPC_DISABLE
#define DPC_DISABLE 0x00000002
#endif
#ifndef DCPC_GLOBAL
#define DCPC_GLOBAL 0x00000001
#endif

// DEBUG / TEMPORARY: Unsecure All Control ID
#define ID_BTN_UNSECURE_ALL  1004

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
#define ID_CHK_BASE          4000
#ifndef IDM_ABOUT
#define IDM_ABOUT            3002
#endif
#define IDM_SEARCHPASS       3003
#define IDM_WINUPDATE        3004
#define IDM_INVENTORY        3005
#define ID_CHK_SELECT_ALL 4099

HWND  g_hChkSelectAll = NULL;
HWND g_hMainWnd = NULL;
HWND g_hLogWnd = NULL;
HWND g_hLogEdit = NULL;
HWND g_hBtnSecureAll = NULL;
bool g_isSelectAllChecked = true;

// Execution State & Live Feedback Message
std::string g_statusText = "";
bool g_isExecuting = false;
std::vector<std::string> g_logMemory;


// Metric Counts 
int g_totalControls = 12;
int g_secureCount = 0;
int g_attentionCount = 0;
int g_insecureCount = 0;

int g_hardStates[12] = { 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2 };


struct HardeningRow {
    const char* name;
    std::string liveInfo;
    std::string statusLabel;
    const char* actionLabel;
    wchar_t iconGlyph;
    HWND hBtnAction;
    HWND hChkBox;
    bool isChecked;

};

HardeningRow g_hardRows[12] = {
    {"Bluetooth Adapter", "Auditing...", "Auditing...", "Disable", L'\xE702', NULL, NULL, true},
    {"Wi-Fi Network Adapter", "Auditing...", "Auditing...", "Disable", L'\xE701', NULL, NULL, true},
    {"SMB Server Protocols", "Auditing...", "Auditing...", "Secure", L'\xE839', NULL, NULL, true},
    {"Shared Network Printers", "Auditing...", "Auditing...", "Secure", L'\xE749', NULL, NULL, true},
    {"Shared Network Folders / Files", "Auditing...", "Auditing...", "Secure", L'\xE8B7', NULL, NULL, true},
    {"SSL / TLS & Ciphers", "Auditing...", "Auditing...", "Secure", L'\xE72E', NULL, NULL, true},
    {"Browser Account Login", "Auditing...", "Auditing...", "Lock", L'\xE77B', NULL, NULL, true},
    {"Browser Password Lock & Removal", "Auditing...", "Auditing...", "Lock", L'\xE890', NULL, NULL, true},
    {"Local User Accounts", "Auditing...", "Auditing...", "Secure", L'\xE716', NULL, NULL, true},
    {"Network Security Policies", "Auditing...", "Auditing...", "Secure", L'\xE912', NULL, NULL, true},
    {"Legacy & Unused Windows Features", "Auditing...", "Auditing...", "Disable", L'\xE74C', NULL, NULL, true},
    {"WinRAR Archiver", "Auditing...", "Auditing...", "Install", L'\xE8B5', NULL, NULL, true}
};

// Add custom checkbox drawing helper at the top or above WM_PAINT
void DrawCustomCheckbox(HDC hdc, int x, int y, bool isChecked, bool isDisabled, bool isSecured) {
    RECT rcBox = { x, y, x + 16, y + 16 };

    if (isSecured) {
        // Option A: Render a clean custom "Secured" check badge for already secured items
        HBRUSH hBadgeBrush = CreateSolidBrush(RGB(13, 148, 136)); // Teal/Green accent
        FillRect(hdc, &rcBox, hBadgeBrush);
        DeleteObject(hBadgeBrush);

        // Draw Checkmark Glyph inside the badge
        HFONT hFontCheck = CreateFontA(12, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, "Segoe MDL2 Assets");
        HFONT hOldFont = (HFONT)SelectObject(hdc, hFontCheck);
        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkMode(hdc, TRANSPARENT);

        // Segoe MDL2 Assets 0xE73E = Checkmark
        wchar_t checkGlyph = 0xE73E;
        DrawTextW(hdc, &checkGlyph, 1, &rcBox, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, hOldFont);
        DeleteObject(hFontCheck);
    }
    else {
        // Standard Dark Checkbox Box
        HBRUSH hBgBrush = CreateSolidBrush(isChecked ? RGB(37, 99, 235) : RGB(15, 23, 42)); // Blue when checked, Dark Blue/Gray when unchecked
        HPEN hBorderPen = CreatePen(PS_SOLID, 1, isChecked ? RGB(59, 130, 246) : RGB(71, 85, 105));

        HPEN hOldPen = (HPEN)SelectObject(hdc, hBorderPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hBgBrush);

        RoundRect(hdc, rcBox.left, rcBox.top, rcBox.right, rcBox.bottom, 4, 4);

        if (isChecked) {
            HFONT hFontCheck = CreateFontA(11, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE, "Segoe MDL2 Assets");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFontCheck);
            SetTextColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);

            wchar_t checkGlyph = 0xE73E; // Checkmark
            DrawTextW(hdc, &checkGlyph, 1, &rcBox, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(hdc, hOldFont);
            DeleteObject(hFontCheck);

        }

        SelectObject(hdc, hOldPen);
        SelectObject(hdc, hOldBrush);
        DeleteObject(hBorderPen);
        DeleteObject(hBgBrush);
    }
}

void UpdateSecureAllButtonText() {
    int unsecureCount = 0;
    int checkedUnsecureCount = 0;

    for (int i = 0; i < 12; i++) {
        // Only consider items that are NOT secured
        if (g_hardStates[i] != 2) {
            unsecureCount++;
            if (g_hardRows[i].isChecked) {
                checkedUnsecureCount++;
            }
        }
    }

    // Determine if header checkbox should be checked
    g_isSelectAllChecked = (unsecureCount > 0 && checkedUnsecureCount == unsecureCount);

    if (g_hChkSelectAll) {
        SendMessage(g_hChkSelectAll, BM_SETCHECK, g_isSelectAllChecked ? BST_CHECKED : BST_UNCHECKED, 0);
        InvalidateRect(g_hChkSelectAll, NULL, FALSE);
    }

    std::string btnText;

    // Display "Secure All" if all remaining unsecured controls are checked
    if (unsecureCount > 0 && checkedUnsecureCount == unsecureCount) {
        btnText = "Secure All";
    }
    else {
        btnText = "Secure (" + std::to_string(checkedUnsecureCount) + ")";
    }

    if (g_hBtnSecureAll) {
        SetWindowTextA(g_hBtnSecureAll, btnText.c_str());
    }
}

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








void PerformAuditAndHighlight() {
    g_secureCount = 0;
    g_attentionCount = 0;
    g_insecureCount = 0;

    // 1. Bluetooth
    bool btActive = IsBluetoothEnabled();
    g_hardRows[0].liveInfo = btActive ? "Bluetooth is currently enabled." : "Bluetooth adapter is securely disabled.";
    g_hardRows[0].statusLabel = btActive ? "Warning" : "Secured";
    g_hardStates[0] = btActive ? 1 : 2;
    g_hardRows[0].actionLabel = btActive ? "Disable" : "Enable";
    SetWindowTextA(g_hardRows[0].hBtnAction, g_hardRows[0].actionLabel);
    ShowWindow(g_hardRows[0].hBtnAction, SW_SHOW);

    // 2. Wi-Fi
    bool wifiActive = IsWifiAdapterEnabled();
    g_hardRows[1].liveInfo = wifiActive ? "Wi-Fi is currently enabled." : "Wi-Fi adapter is securely disabled.";
    g_hardRows[1].statusLabel = wifiActive ? "Warning" : "Secured";
    g_hardStates[1] = wifiActive ? 1 : 2;
    g_hardRows[1].actionLabel = wifiActive ? "Disable" : "Enable";
    SetWindowTextA(g_hardRows[1].hBtnAction, g_hardRows[1].actionLabel);
    ShowWindow(g_hardRows[1].hBtnAction, SW_SHOW);

    // 3. SMB Server Protocols
    bool smbHardened = IsSMBv1Disabled();
    g_hardRows[2].liveInfo = smbHardened ? "SMBv1 protocol is securely disabled." : "SMBv1 protocol is currently enabled.";
    g_hardRows[2].statusLabel = smbHardened ? "Secured" : "Warning";
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
        g_hardRows[3].statusLabel = "Warning";
        g_hardStates[3] = 1;
        g_hardRows[3].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[3].hBtnAction, g_hardRows[3].actionLabel);
        ShowWindow(g_hardRows[3].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[3].liveInfo = "No shares & RPC client connections blocked.";
        g_hardRows[3].statusLabel = "Secured";
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
        g_hardRows[4].statusLabel = "Warning";
        g_hardStates[4] = 1;
        g_hardRows[4].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[4].hBtnAction, g_hardRows[4].actionLabel);
        ShowWindow(g_hardRows[4].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[4].liveInfo = "No shared network folders detected.";
        g_hardRows[4].statusLabel = "Secured";
        g_hardStates[4] = 2;
        ShowWindow(g_hardRows[4].hBtnAction, SW_HIDE);
    }

    // 6. SSL / TLS
    bool sslTlsHardened = IsSslTlsHardened();
    g_hardRows[5].liveInfo = sslTlsHardened ? "Best practice IIS Crypto settings applied." : "Unsecured TLS/SSL ciphers are active.";
    g_hardRows[5].statusLabel = sslTlsHardened ? "Secured" : "Warning";
    g_hardStates[5] = sslTlsHardened ? 2 : 1;
    g_hardRows[5].actionLabel = sslTlsHardened ? "Revert" : "Secure";
    SetWindowTextA(g_hardRows[5].hBtnAction, g_hardRows[5].actionLabel);
    ShowWindow(g_hardRows[5].hBtnAction, SW_SHOW);

    // 7. Browser Login
    bool browserLocked = IsBrowserAccountLocked();
    g_hardRows[6].liveInfo = browserLocked ? "Browser sign-in is securely disabled." : "Browser sign-in is currently allowed.";
    g_hardRows[6].statusLabel = browserLocked ? "Secured" : "Warning";
    g_hardStates[6] = browserLocked ? 2 : 1;
    g_hardRows[6].actionLabel = browserLocked ? "Unlock" : "Lock";
    SetWindowTextA(g_hardRows[6].hBtnAction, g_hardRows[6].actionLabel);
    ShowWindow(g_hardRows[6].hBtnAction, SW_SHOW);

    // 8. Browser Passwords
    bool passwordLocked = IsBrowserPasswordLocked();
    bool passwordsExistOnDisk = AreBrowserCredentialsPresent();

    if (passwordLocked && !passwordsExistOnDisk) {
        g_hardRows[7].liveInfo = "Policy locked and local password vaults are empty.";
        g_hardRows[7].statusLabel = "Secured";
        g_hardStates[7] = 2;
        g_hardRows[7].actionLabel = "Unlock";
    }
    else if (passwordLocked && passwordsExistOnDisk) {
        // The registry is locked, but the passwords were never purged!
        g_hardRows[7].liveInfo = "Policy locked, but passwords STILL exist on disk!";
        g_hardRows[7].statusLabel = "Warning";
        g_hardStates[7] = 1;
        g_hardRows[7].actionLabel = "Purge";
    }
    else {
        g_hardRows[7].liveInfo = "Password saving allowed and data may exist.";
        g_hardRows[7].statusLabel = "Warning";
        g_hardStates[7] = 1;
        g_hardRows[7].actionLabel = "Lock";
    }

    SetWindowTextA(g_hardRows[7].hBtnAction, g_hardRows[7].actionLabel);
    ShowWindow(g_hardRows[7].hBtnAction, SW_SHOW);

    // 9. Local Users
    int userCount = 0;
    bool allUsersDisabled = true;
    bool allPasswordsExpire = true;

    g_hardRows[8].liveInfo = GetLocalUserAccountsInfo(userCount, allUsersDisabled, allPasswordsExpire);

    if ((userCount > 0 && !allUsersDisabled) || !allPasswordsExpire) {
        g_hardRows[8].statusLabel = "Warning";
        g_hardStates[8] = 1;
        g_hardRows[8].actionLabel = "Secure";
        SetWindowTextA(g_hardRows[8].hBtnAction, g_hardRows[8].actionLabel);
        ShowWindow(g_hardRows[8].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[8].statusLabel = "Secured";
        g_hardStates[8] = 2;
        g_hardRows[8].actionLabel = "Open";
        SetWindowTextA(g_hardRows[8].hBtnAction, g_hardRows[8].actionLabel);
        ShowWindow(g_hardRows[8].hBtnAction, SW_SHOW);
    }

    // 10. Network Security Policies 
    bool netSecHardened = IsNetworkSecPoliciesHardened();
    g_hardRows[9].liveInfo = netSecHardened ? "NTLMv2 & SMB Signing strictly enforced." : "Legacy NTLM or unsigned SMB allowed.";
    g_hardRows[9].statusLabel = netSecHardened ? "Secured" : "Warning";
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


    // 11. Unneeded Windows Features (Index 10)
    bool unneededFeaturesActive = AreUnneededWindowsFeaturesEnabled();
    if (unneededFeaturesActive) {
        g_hardRows[10].liveInfo = "IIS, Telnet, or legacy SMB features are installed.";
        g_hardRows[10].statusLabel = "Warning";
        g_hardStates[10] = 1;
        g_hardRows[10].actionLabel = "Disable";
        SetWindowTextA(g_hardRows[10].hBtnAction, g_hardRows[10].actionLabel);
        ShowWindow(g_hardRows[10].hBtnAction, SW_SHOW);
    }
    else {
        g_hardRows[10].liveInfo = "Unused Windows features are securely disabled.";
        g_hardRows[10].statusLabel = "Secured";
        g_hardStates[10] = 2;
        g_hardRows[10].actionLabel = "Open";
        SetWindowTextA(g_hardRows[10].hBtnAction, g_hardRows[10].actionLabel);
        ShowWindow(g_hardRows[10].hBtnAction, SW_SHOW);
        
    }

    // --- Update your existing metric counters block ---
    // [Keep your existing if statements, and add this new one at the end:]
    if (!unneededFeaturesActive) g_secureCount++; else g_insecureCount++;

    // 12. WinRAR Archiver (Index 11)
    std::wstring winrarVer;
    bool winrarInstalled = GetWinRARVersion(winrarVer);
    std::wstring latestVersion = GetLatestWinRARVersionOnline();

    if (winrarInstalled) {
        std::string verStr(winrarVer.begin(), winrarVer.end());

        if (!latestVersion.empty() && IsVersionOlder(winrarVer, latestVersion)) {
            // Outdated
            std::string latestStr(latestVersion.begin(), latestVersion.end());
            g_hardRows[11].liveInfo = "WinRAR v" + verStr + " (Latest: v" + latestStr + ")";
            g_hardRows[11].statusLabel = "Warning";
            g_hardStates[11] = 1;
            g_hardRows[11].actionLabel = "Update";
            g_insecureCount++;
        }
        else {
            // Installed & Up-to-date
            g_hardRows[11].liveInfo = "WinRAR Installed (v" + verStr + ")";
            g_hardRows[11].statusLabel = "Secured";
            g_hardStates[11] = 2;
            g_hardRows[11].actionLabel = "Open";
            g_secureCount++;
        }
    }
    else {
        // Not installed -> Baseline state is SECURED
        g_hardRows[11].liveInfo = "WinRAR is not installed on this device.";
        g_hardRows[11].statusLabel = "Secured";
        g_hardStates[11] = 2;
        g_hardRows[11].actionLabel = "Install";
        g_secureCount++;
    }

    for (int i = 0; i < 12; i++) {
        if (g_hardStates[i] == 2) {
            // Control is already secured -> Hide checkbox completely
            ShowWindow(g_hardRows[i].hChkBox, SW_HIDE);
            g_hardRows[i].isChecked = false;
        }
        else {
            // Control needs hardening -> Show checkbox
            ShowWindow(g_hardRows[i].hChkBox, SW_SHOW);
            EnableWindow(g_hardRows[i].hChkBox, TRUE);
        }
    }

    // Recalculate button label based on updated audit states
    UpdateSecureAllButtonText();

    SetWindowTextA(g_hardRows[11].hBtnAction, g_hardRows[11].actionLabel);
    ShowWindow(g_hardRows[11].hBtnAction, SW_SHOW);
}








LRESULT CALLBACK HoverButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (uMsg) {
    case WM_MOUSEMOVE: {
        // If it isn't already hovered, set the property and start tracking
        if (!GetPropA(hWnd, "Hovered")) {
            SetPropA(hWnd, "Hovered", (HANDLE)1);

            TRACKMOUSEEVENT tme = { sizeof(TRACKMOUSEEVENT), TME_LEAVE, hWnd, 0 };
            TrackMouseEvent(&tme);

            InvalidateRect(hWnd, NULL, FALSE);
        }
        break;
    }
    case WM_MOUSELEAVE: {
        // Mouse left the button, remove property and redraw
        RemovePropA(hWnd, "Hovered");
        InvalidateRect(hWnd, NULL, FALSE);
        break;
    }
    case WM_DESTROY: {
        RemovePropA(hWnd, "Hovered");
        RemoveWindowSubclass(hWnd, HoverButtonProc, uIdSubclass);
        break;
    }
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}


// --- WINDOW PROC ---
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_ERASEBKGND:
        return 1;
    case (WM_APP + 100):
    {
        int rowIdx = (int)wParam;
        std::string title = "Operation Failed";
        std::string msg = "Failed to update security policy:\n\"" +
            std::string(g_hardRows[rowIdx].name) +
            "\"\n\nCheck application logs or system permissions.";

        // Displays your dark theme error dialog
        ShowDarkMessageDialog(hwnd, title.c_str(), msg.c_str());
        return 0;
    }

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

        g_hChkSelectAll = CreateWindowA("BUTTON", "",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            18, 25, 18, 18,
            hwnd, (HMENU)(UINT_PTR)ID_CHK_SELECT_ALL, NULL, NULL);
        SendMessage(g_hChkSelectAll, BM_SETCHECK, BST_CHECKED, 0);

        int startY = 55;
        int rowHeight = 38;

        for (int i = 0; i < 12; i++) {
            // Create the Checkbox control
            g_hardRows[i].hChkBox = CreateWindowA("BUTTON", "",
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                18, startY + 10, 18, 18,
                hwnd, (HMENU)(UINT_PTR)(ID_CHK_BASE + i), NULL, NULL);

            // Default state: Checked
            SendMessage(g_hardRows[i].hChkBox, BM_SETCHECK, BST_CHECKED, 0);

            // Create Action Button (shift x position slightly right if needed to accommodate checkbox)
            g_hardRows[i].hBtnAction = CreateWindowA("BUTTON", g_hardRows[i].actionLabel,
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                505, startY + 4, 80, 26,
                hwnd, (HMENU)(UINT_PTR)(ID_HARD_BASE + i * 10 + 1), NULL, NULL);

            SetWindowSubclass(g_hardRows[i].hBtnAction, HoverButtonProc, 0, 0);
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

        // Draw a distinct background container for the controls area
        RECT rcControlsBg = { 10, 10, 600, 55 + (12 * 38) + 10 };
        HBRUSH hControlBgBrush = CreateSolidBrush(RGB(15, 23, 42));
        FillRect(hdc, &rcControlsBg, hControlBgBrush);
        DeleteObject(hControlBgBrush);

        // Draw the Title
        SelectObject(hdc, g_hFontTitle);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        RECT rcTitle = { 45, 20, 290, 48 };
        DrawTextA(hdc, "System Hardening Controls", -1, &rcTitle, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Calculate metrics
        int percentMet = (g_totalControls > 0) ? (g_secureCount * 100 / g_totalControls) : 0;

        // Draw Progress Bar Background
        RECT rcProgBg = { 290, 28, 545, 38 };
        HBRUSH hProgBgBrush = CreateSolidBrush(RGB(30, 41, 59));
        FillRect(hdc, &rcProgBg, hProgBgBrush);
        DeleteObject(hProgBgBrush);

        // Draw Progress Bar Fill
        if (percentMet > 0) {
            RECT rcProgFill = rcProgBg;
            rcProgFill.right = rcProgBg.left + ((rcProgBg.right - rcProgBg.left) * percentMet / 100);

            COLORREF barColor = (percentMet == 100) ? RGB(13, 148, 136) : RGB(96, 165, 250);
            if (percentMet < 50) barColor = RGB(248, 113, 113);

            HBRUSH hProgFillBrush = CreateSolidBrush(barColor);
            FillRect(hdc, &rcProgFill, hProgFillBrush);
            DeleteObject(hProgFillBrush);
        }

        // Draw Percentage Text
        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        char progText[32];
        snprintf(progText, sizeof(progText), "%d%%", percentMet);
        RECT rcProgText = { 555, 20, 595, 45 };
        DrawTextA(hdc, progText, -1, &rcProgText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Render Hardening Rows
        int startY = 55;
        int rowHeight = 38;

        for (int i = 0; i < 12; i++) {
            RECT rcRow = { 15, startY, 590, startY + rowHeight };

            if (i % 2 == 1) {
                HBRUSH hAltBrush = CreateSolidBrush(RGB(23, 32, 51));
                FillRect(hdc, &rcRow, hAltBrush);
                DeleteObject(hAltBrush);
            }

            // 1. Draw Icon (Explicitly select icon font and handle drawing first)
            HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);
            SetTextColor(hdc, RGB(148, 163, 184));
            RECT rcIcon = { 42, startY + 8, 68, startY + 30 };
            DrawTextW(hdc, &g_hardRows[i].iconGlyph, 1, &rcIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            // 2. Name
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, COLOR_TEXT_WHITE);
            RECT rcName = { 68, startY + 2, 310, startY + 20 };
            DrawTextA(hdc, g_hardRows[i].name, -1, &rcName, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

            // 3. Live Info
            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, RGB(148, 163, 184));
            RECT rcInfo = { 68, startY + 18, 300, startY + 36 };
            DrawTextA(hdc, g_hardRows[i].liveInfo.c_str(), -1, &rcInfo, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

            // 4. Dynamic Status Label Color
           // 4. Dynamic Status Label Color & Icons
            COLORREF statusColor;
            wchar_t statusIcon;

            if (g_hardRows[i].statusLabel == "Checking...") {
                statusColor = RGB(251, 191, 36);  // Amber
                statusIcon = L'\xE895';            // Sync / Loading icon
            }
            else if (g_hardStates[i] == 2) {
                statusColor = RGB(96, 165, 250);  // Blue for Secured
                statusIcon = L'\xEA18';            // Shield with Checkmark glyph
            }
            else {
                statusColor = RGB(248, 113, 113);  // Red/Orange for Warning
                statusIcon = L'\xE7BA';            // Warning Triangle icon
            }

            // A. Draw Status Icon (Shifted right closer to button at X=415)
            SelectObject(hdc, g_hFontIcon);
            SetTextColor(hdc, statusColor);
            SetBkMode(hdc, TRANSPARENT);
            RECT rcStatusIcon = { 415, startY + 10, 435, startY + 28 };
            DrawTextW(hdc, &statusIcon, 1, &rcStatusIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            // B. Draw Status Text Label (Shifted right to X=437)
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, statusColor);
            RECT rcStatusText = { 437, startY + 10, 505, startY + 28 };
            DrawTextA(hdc, g_hardRows[i].statusLabel.c_str(), -1, &rcStatusText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            // Restore font handle
            SelectObject(hdc, hOldFont);

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

        if (wmId == ID_CHK_SELECT_ALL) {
            // Toggle the state
            g_isSelectAllChecked = !g_isSelectAllChecked;

            // Update the header checkbox visual state
            SendMessage(g_hChkSelectAll, BM_SETCHECK, g_isSelectAllChecked ? BST_CHECKED : BST_UNCHECKED, 0);
            InvalidateRect(g_hChkSelectAll, NULL, FALSE);

            // Apply state to all unsecured controls
            for (int i = 0; i < 12; i++) {
                if (g_hardStates[i] != 2) {
                    g_hardRows[i].isChecked = g_isSelectAllChecked;
                    if (g_hardRows[i].hChkBox) {
                        SendMessage(g_hardRows[i].hChkBox, BM_SETCHECK, g_isSelectAllChecked ? BST_CHECKED : BST_UNCHECKED, 0);
                        InvalidateRect(g_hardRows[i].hChkBox, NULL, FALSE);
                    }
                }
            }

            UpdateSecureAllButtonText();
            return 0;
        }

        if (wmId >= ID_CHK_BASE && wmId < ID_CHK_BASE + 12) {
            int index = wmId - ID_CHK_BASE;

            // Only allow toggling if it is not already secured
            if (g_hardStates[index] != 2) {
                g_hardRows[index].isChecked = !g_hardRows[index].isChecked; // Toggle state
                SendMessage(g_hardRows[index].hChkBox, BM_SETCHECK, g_hardRows[index].isChecked ? BST_CHECKED : BST_UNCHECKED, 0);
                InvalidateRect(g_hardRows[index].hChkBox, NULL, FALSE); // Force redraw
                UpdateSecureAllButtonText();
            }
            return 0;
        }

        // 2. Explicitly handle the Secure All button FIRST
        if (wmId == ID_BTN_SECURE_ALL) {
            if (g_isExecuting) return 0;

            if (!ShowDarkConfirmDialog(hwnd, "Enforce Selected Hardening Policies", "Are you sure you want to enforce selected hardening policies?")) {
                return 0;
            }

            g_isExecuting = true;
            UpdateStatus("Enforcing selected hardening policies... Please wait.");

            // Disable all row buttons and checkboxes during batch execution
            for (int i = 0; i < 12; i++) {
                if (g_hardRows[i].hBtnAction) EnableWindow(g_hardRows[i].hBtnAction, FALSE);
                if (g_hardRows[i].hChkBox) EnableWindow(g_hardRows[i].hChkBox, FALSE);
            }

            std::thread([hwnd]() {
                auto RunTaskWithChecking = [hwnd](int rowIdx, const char* taskName, std::function<void()> actionFunc) {
                    // Only execute if not already secured and user kept checkbox checked
                    if (g_hardStates[rowIdx] != 2 && g_hardRows[rowIdx].isChecked) {
                        g_hardStates[rowIdx] = 1;
                        g_hardRows[rowIdx].statusLabel = "Checking...";
                        g_hardRows[rowIdx].liveInfo = "Applying policy...";

                        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);

                        actionFunc();

                        PerformAuditAndHighlight();
                        UpdateStatus(std::string(taskName) + " completed.");
                        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
                    }
                    };

                // Execute sequentially for checked rows
                RunTaskWithChecking(0, "Bluetooth Adapter", []() { SetBluetoothDeviceState(false); });
                RunTaskWithChecking(1, "Wi-Fi Adapter", []() { SetWifiDeviceState(false); });
                RunTaskWithChecking(2, "SMB Protocols", []() { ConfigureSMB(true); });
                RunTaskWithChecking(3, "Shared Printers", []() { OnLockdownPrintersButtonClicked(); });
                RunTaskWithChecking(4, "Shared Folders", []() { UnshareAllFolders(); });
                RunTaskWithChecking(5, "SSL/TLS Ciphers", []() { ConfigureSslTlsIISCrypto(true); });
                RunTaskWithChecking(6, "Browser Accounts", []() { ConfigureBrowserAccountLock(true); });
                RunTaskWithChecking(7, "Browser Passwords", []() { ConfigureBrowserPasswordLock(true); });
                RunTaskWithChecking(8, "Local Users", []() { ConfigureLocalUsers(true); });
                RunTaskWithChecking(9, "Network Security Policies", []() { ConfigureNetworkSecPolicies(true); });
                RunTaskWithChecking(10, "Unneeded Windows Features", []() { DisableUnneededWindowsFeaturesNative(); });
                RunTaskWithChecking(11, "WinRAR Installation", []() { InstallLatestWinRAR(); });

                g_isExecuting = false;
                PerformAuditAndHighlight();
                UpdateStatus("Selected hardening policies enforced successfully.");
                }).detach();

            return 0;
        }

        // 3. Delegate other sidebar commands (Inventory, SearchPass, Windows Update, etc.)
        if (HandleSidebarCommand(hwnd, wmId)) {
            return 0;
        }

        // 4. Handle Individual Row Buttons
        if (wmId >= ID_HARD_BASE && wmId < ID_HARD_BASE + 120) {
            int rowIdx = (wmId - ID_HARD_BASE) / 10;
            bool isSecured = (g_hardStates[rowIdx] == 2);
            
            if (rowIdx == 8 && isSecured) {
                // Option 2: Open standalone lusrmgr MMC directly focused on Users
                ShellExecuteA(hwnd, "open", "mmc.exe", "lusrmgr.msc /s", NULL, SW_SHOWNORMAL);
                return 0;
            }
            if (rowIdx == 10) {
                ShellExecuteA(hwnd, "open", "optionalfeatures.exe", NULL, NULL, SW_SHOWNORMAL);
                return 0;
            }

            if (rowIdx == 11 && isSecured) {
                std::wstring testVer;
                if (GetWinRARVersion(testVer)) {
                    ShellExecuteA(hwnd, "open", "control.exe", "appwiz.cpl", NULL, SW_SHOWNORMAL);
                    return 0;
                }
            }
            else if (isSecured) {
                if (!ShowDarkPasswordDialog(hwnd, "Enter administrator password to revert this setting:")) {
                    return 0;
                }
            }

            g_hardRows[rowIdx].statusLabel = "Checking...";
            g_hardRows[rowIdx].liveInfo = "Applying changes and auditing status...";

            EnableWindow(g_hardRows[rowIdx].hBtnAction, FALSE);
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);

            std::thread([hwnd, rowIdx]() {
                switch (rowIdx) {
                case 0: HandleBluetoothToggle(hwnd);  break;
                case 1: SetWifiDeviceState(g_hardStates[1] == 2); break;
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
                case 10: DisableUnneededWindowsFeaturesNative(); break;
                case 11: InstallLatestWinRAR(); break;
                }

                PerformAuditAndHighlight();
                EnableWindow(g_hardRows[rowIdx].hBtnAction, TRUE);
                RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);

                if (g_hardStates[rowIdx] != 2) {
                    PostMessage(hwnd, WM_APP + 100, (WPARAM)rowIdx, 0);
                }
                }).detach();
        }
        break;
    }

    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;

        if ((pdis->CtlID >= ID_CHK_BASE && pdis->CtlID < ID_CHK_BASE + 12) || pdis->CtlID == ID_CHK_SELECT_ALL) {
            int rowIdx = pdis->CtlID - ID_CHK_BASE;
            bool isChecked = false;
            bool isSecured = false;

            COLORREF bgCol = RGB(15, 23, 42);
            if (pdis->CtlID >= ID_CHK_BASE && pdis->CtlID < ID_CHK_BASE + 12) {
                if (rowIdx % 2 == 1) {
                    bgCol = RGB(23, 32, 51);
                }
            }
            HBRUSH hBgFill = CreateSolidBrush(bgCol);
            FillRect(pdis->hDC, &pdis->rcItem, hBgFill);
            DeleteObject(hBgFill);

            if (pdis->CtlID == ID_CHK_SELECT_ALL) {
                isChecked = g_isSelectAllChecked;
            }
            else {
                isChecked = g_hardRows[rowIdx].isChecked;
                isSecured = (g_hardStates[rowIdx] == 2);
            }

            bool isDisabled = (pdis->itemState & ODS_DISABLED) != 0;
            DrawCustomCheckbox(pdis->hDC, pdis->rcItem.left, pdis->rcItem.top, isChecked, isDisabled, isSecured);
            return TRUE;
        }

        if (IsSidebarButton(pdis->CtlID)) {
            DrawSidebarButton(pdis);
            return TRUE;
        }

        // Draw the Styled Action Buttons
        // Draw the Styled Action Buttons
        else if (pdis->CtlID >= ID_HARD_BASE && pdis->CtlID < ID_HARD_BASE + 120) {
            HDC hdc = pdis->hDC;
            bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;
            bool isHovered = GetPropA(pdis->hwndItem, "Hovered") != NULL;

            char btnText[32] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));
            std::string textStr(btnText);

            // Determine Icon based on Action Type
            wchar_t buttonIcon = L'\xE8AC';

            if (textStr == "Disable") {
                buttonIcon = L'\xF140';           // Prohibit / Block
            }
            else if (textStr == "Enable") {
                buttonIcon = L'\xE8A5';           // Document / File
            }
            else if (textStr == "Revert") {
                buttonIcon = L'\xE8AC';           // Swap / Revert
            }
            else if (textStr == "Lock" || textStr == "Purge") {
                buttonIcon = L'\xF140';           // Prohibit / Lock
            }
            else if (textStr == "Open" || textStr == "Secure" || textStr == "Install" || textStr == "Update") {
                buttonIcon = L'\xE8A5';           // Open / Document
            }

            // Colors: Clean neutral dark scheme
            COLORREF bgCol = isPressed ? RGB(30, 41, 59) : (isHovered ? RGB(51, 65, 85) : RGB(23, 32, 51));
            COLORREF borderCol = isHovered ? RGB(71, 85, 105) : RGB(51, 65, 85);
            COLORREF textCol = RGB(226, 232, 240); // Soft bright white

            // 1. Fill Background
            HBRUSH hBrush = CreateSolidBrush(bgCol);
            FillRect(hdc, &pdis->rcItem, hBrush);
            DeleteObject(hBrush);

            // 2. Draw Subtle Border
            HPEN hPen = CreatePen(PS_SOLID, 1, borderCol);
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));

            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);

            SelectObject(hdc, hOldPen);
            SelectObject(hdc, hOldBrush);
            DeleteObject(hPen);

            // 3. Draw Icon (Shifted to left with proper padding)
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, textCol);

            HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);
            RECT rcBtnIcon = { pdis->rcItem.left + 6, pdis->rcItem.top, pdis->rcItem.left + 22, pdis->rcItem.bottom };
            DrawTextW(hdc, &buttonIcon, 1, &rcBtnIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            // 4. Draw Text Label (Starts at left + 28 to leave a clean 6px gap after the icon)
            SelectObject(hdc, g_hFontBold);
            RECT rcBtnText = { pdis->rcItem.left + 28, pdis->rcItem.top, pdis->rcItem.right - 4, pdis->rcItem.bottom };
            DrawTextA(hdc, btnText, -1, &rcBtnText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            SelectObject(hdc, hOldFont);
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
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
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