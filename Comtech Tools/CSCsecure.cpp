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
#include <chrono>
#include <functional>
#include "Sidebar.h"
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
#include "ProgressBar.h"
#include "Refresh.h"

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "dwmapi.lib") 
#pragma comment(lib, "version.lib")
#pragma comment(lib, "userenv.lib")



void UpdateStatus(const std::string& msg);
void PerformAuditAndHighlight();
void UpdateSecureAllButtonText();


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

float g_animatedSecureCount = 0.0f;
static float g_targetSecureCount = 0.0f;

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

// Control & Menu IDs
#define ID_BTN_SECURE_ALL    1003
#define ID_LOG_EDIT          1005
#define ID_BTN_MENU          1006
#define ID_HARD_BASE         2000
#define ID_CHK_BASE          4000
#define ID_CHK_SELECT_ALL    4099
#define WM_SHOW_RESTART_PROMPT (WM_USER + 100)
#define TIMER_PROGRESS_ANIM 101

HWND g_hChkSelectAll = NULL;
HWND g_hMainWnd = NULL;
HWND g_hLogWnd = NULL;
HWND g_hLogEdit = NULL;
HWND g_hBtnSecureAll = NULL;
bool g_isSelectAllChecked = true;



void RunPowerShellInspector(const std::string& title, const std::string& psCode) {
    // Encapsulate the script so it displays the code first, executes it, and holds the window open
    std::string wrapper =
        "$Host.UI.RawUI.WindowTitle = '" + title + "'; " +
        "Write-Host '==================================================' -ForegroundColor Cyan; " +
        "Write-Host ' Executing Audit Script for: " + title + "' -ForegroundColor Cyan; " +
        "Write-Host '==================================================' -ForegroundColor Cyan; " +
        "Write-Host '' ; " +
        "Write-Host '--- [ POWERSHELL CODE ] ---' -ForegroundColor Yellow; " +
        "Write-Host @'\n" + psCode + "\n'@ -ForegroundColor Gray; " +
        "Write-Host '----------------------------' -ForegroundColor Yellow; " +
        "Write-Host '' ; " +
        "Write-Host '--- [ EXECUTION RESULT ] ---' -ForegroundColor Green; " +
        psCode + "; " +
        "Write-Host '' ; " +
        "Write-Host 'Press any key to exit...' -ForegroundColor DarkGray; " +
        "$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');";

    // Launch PowerShell in a single interactive window
    std::string cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + wrapper + "\"";
    WinExec(cmd.c_str(), SW_SHOWNORMAL);
}

void ExecuteButtonActionWithSpinner(HWND hBtn, std::function<void()> action, std::string completedLabel) {
    if (!hBtn || !IsWindow(hBtn)) return;
    EnableWindow(hBtn, FALSE);

    std::thread([hBtn, action, completedLabel]() {
        int frameIdx = 0;
        bool isDone = false;

        // Set spinning state flag on the button control
        SetPropA(hBtn, "IsSpinning", (HANDLE)1);

        // Run the system modification task on a separate thread
        std::thread task([action, &isDone]() {
            action();
            isDone = true;
            });

        // Animate the spinner frame index while processing
        while (!isDone) {
            SetPropA(hBtn, "SpinnerFrameIndex", (HANDLE)(INT_PTR)frameIdx);
            InvalidateRect(hBtn, NULL, FALSE); // Force redraw of button badge area

            frameIdx = (frameIdx + 1) % 8; // Cycle through the 8 MDL2 ring spinner frames
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }

        // Clean up task thread
        if (task.joinable()) {
            task.join();
        }

        RemovePropA(hBtn, "IsSpinning");
        RemovePropA(hBtn, "SpinnerFrameIndex");

        // Restore button state and label
        SetWindowTextA(hBtn, completedLabel.c_str());
        EnableWindow(hBtn, TRUE);

        // Refresh UI & audit state
        PerformAuditAndHighlight();
        }).detach();
}
bool RestartWin32Service(const char* serviceName) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return false;

    SC_HANDLE hService = OpenServiceA(hSCManager, serviceName, SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;

    // Stop the service if running
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    // Simple wait loop until stopped
    int timeout = 10; // 10 seconds max
    while (QueryServiceStatus(hService, &status) && timeout-- > 0) {
        if (status.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(1000);
    }

    // Start the service
    bool success = StartServiceA(hService, 0, NULL) != 0;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return success;
}

// Execution State & Live Feedback
std::string g_statusText = "";
bool g_isExecuting = false;
std::vector<std::string> g_logMemory;

// Metric Counts 
int g_totalControls = 0;
int g_secureCount = 0;
int g_attentionCount = 0;
int g_insecureCount = 0;
int g_currentPercent = 0;
int g_targetPercent = 10;


std::vector<PrinterStatus> g_printerList;


// --- DATA-DRIVEN ARCHITECTURE ---
struct SecurityControl {
    std::string name;
    std::string liveInfo;
    std::string statusLabel;
    std::string actionLabel;
    wchar_t iconGlyph;
    HWND hBtnAction;
    HWND hChkBox;
    bool isChecked;
    int state; // 1 = Warning, 2 = Secured
    bool isHovered = false;

    std::function<void(SecurityControl&)> auditFunc;
    std::function<void(bool)> enforceFunc;
};




std::vector<SecurityControl> g_controls;


void InitializeControls() {
    g_controls = {
        // 1. Bluetooth
        {
            "Bluetooth Adapter", "Auditing...", "Auditing...", "Disable", L'\xE702', NULL, NULL, true, 2, false,
            [](SecurityControl& ctrl) {
                bool active = IsBluetoothEnabled();
                ctrl.liveInfo = active ? "Bluetooth is currently enabled." : "Bluetooth adapter is securely disabled.";
                ctrl.statusLabel = active ? "Warning" : "Secured";
                ctrl.state = active ? 1 : 2;
                ctrl.actionLabel = active ? "Disable" : "Enable";
            },
            [](bool enable) { HandleBluetoothToggle(g_hMainWnd); }
        },
        // 2. Wi-Fi
        {
            "Wi-Fi Network Adapter", "Auditing...", "Auditing...", "Disable", L'\xE701', NULL, NULL, true, 2, false,
            [](SecurityControl& ctrl) {
                bool active = IsWifiAdapterEnabled();
                ctrl.liveInfo = active ? "Wi-Fi is currently enabled." : "Wi-Fi adapter is securely disabled.";
                ctrl.statusLabel = active ? "Warning" : "Secured";
                ctrl.state = active ? 1 : 2;
                ctrl.actionLabel = active ? "Disable" : "Enable";
            },
            [](bool enable) { SetWifiDeviceState(!enable); }
        },

        // 3. SMB Protocols
{
    "SMB Server Protocols", "Auditing...", "Auditing...", "Secure", L'\xE839', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        bool smbHardened = IsSMBv1Disabled();
        ctrl.liveInfo = smbHardened ? "SMBv1 protocol is securely disabled." : "SMBv1 protocol is currently enabled.";
        ctrl.statusLabel = smbHardened ? "Secured" : "Warning";
        ctrl.state = smbHardened ? 2 : 1;
        ctrl.actionLabel = smbHardened ? "Inspect" : "Secure";
    },
    [](bool secure) {
        if (secure) {
            // Apply hardening changes directly
            ConfigureSMB(true);
        }
 else {
std::string script =
        "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol; "
        "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol";

    RunPowerShellInspector("SMB Server Protocol Inspector", script);
        }
    }
},

        // 4. Shared Printers
        {
            "Shared Network Printers", "Auditing...", "Auditing...", "Secure", L'\xE749', NULL, NULL, true, 2, false,
            [](SecurityControl& ctrl) {
                g_printerList = GetSystemPrintersInfo();
                std::vector<std::string> sharedPrinters;
                for (const auto& printer : g_printerList) {
                    if (printer.isShared) {
                        sharedPrinters.push_back(printer.shareName.empty() ? printer.name : printer.shareName);
                    }
                }
                bool hasShared = !sharedPrinters.empty();
                bool spoolerSecure = IsSpoolerClientConnectionsDisabled();

                if (hasShared || !spoolerSecure) {
                    if (hasShared) {
                        if (sharedPrinters.size() == 1) ctrl.liveInfo = "Printer shared: " + sharedPrinters[0];
                        else ctrl.liveInfo = "Multiple (" + std::to_string(sharedPrinters.size()) + ") shared printers detected.";
                    }
 else {
  ctrl.liveInfo = "Spooler remote RPC connections are allowed.";
}
ctrl.statusLabel = "Warning";
ctrl.state = 1;
ctrl.actionLabel = "Secure";
}
else {
 ctrl.liveInfo = "No shares & RPC client connections blocked.";
 ctrl.statusLabel = "Secured";
 ctrl.state = 2;
 ctrl.actionLabel = "Inspect";
}
},
[](bool secure) {
            // If unsecured (state 1), enforce lockdown; if secured (state 2), open PowerShell
            if (secure) {
                OnLockdownPrintersButtonClicked();
            }
     else {
                std::string script =
        "Get-Printer | Select-Object Name, Shared, Published; "
        "Get-SmbShare | Where-Object { $_.Special -eq $false }";

    RunPowerShellInspector("Shared Network Printers Inspector", script);
  }
}
},
// 5. Shared Folders
{
    "Shared Network Folders / Files", "Auditing...", "Auditing...", "Secure", L'\xE8B7', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
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
            if (sharedFolders.size() == 1) ctrl.liveInfo = "Folder shared: " + sharedFolders[0];
            else ctrl.liveInfo = "Multiple (" + std::to_string(sharedFolders.size()) + ") shared network folders detected.";
            ctrl.statusLabel = "Warning";
            ctrl.state = 1;
            ctrl.actionLabel = "Secure";
        }
else {
 ctrl.liveInfo = "No shared network folders detected.";
 ctrl.statusLabel = "Secured";
 ctrl.state = 2;
 ctrl.actionLabel = "";
 if (ctrl.hBtnAction) EnableWindow(ctrl.hBtnAction, FALSE);
}
},
[](bool secure) { UnshareAllFolders(); }
},
// 6. SSL / TLS
{
    "SSL / TLS & Ciphers", "Auditing...", "Auditing...", "Secure", L'\xE72E', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        bool sslTlsHardened = IsSslTlsHardened();
        ctrl.liveInfo = sslTlsHardened ? "Best practice IIS Crypto settings applied." : "Unsecured TLS/SSL ciphers are active.";
        ctrl.statusLabel = sslTlsHardened ? "Secured" : "Warning";
        ctrl.state = sslTlsHardened ? 2 : 1;
        ctrl.actionLabel = sslTlsHardened ? "Inspect" : "Secure";
    },
    [](bool secure) { ConfigureSslTlsIISCrypto(secure); }
},
// 7. Browser Login
{
    "Browser Account Login", "Auditing...", "Auditing...", "Lock", L'\xE77B', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        bool locked = IsBrowserAccountLocked();
        ctrl.liveInfo = locked ? "Browser sign-in is securely disabled." : "Browser sign-in is currently allowed.";
        ctrl.statusLabel = locked ? "Secured" : "Warning";
        ctrl.state = locked ? 2 : 1;
        ctrl.actionLabel = locked ? "Unlock" : "Lock";
    },
    [](bool secure) { ConfigureBrowserAccountLock(secure); }
},
// 8. Browser Passwords
{
    "Browser Password Lock & Removal", "Auditing...", "Auditing...", "Lock", L'\xE890', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        bool locked = IsBrowserPasswordLocked();
        bool exist = AreBrowserCredentialsPresent();
        if (locked && !exist) {
            ctrl.liveInfo = "Policy locked and local password vaults are empty.";
            ctrl.statusLabel = "Secured";
            ctrl.state = 2;
            ctrl.actionLabel = "Unlock";
        }
else if (locked && exist) {
 ctrl.liveInfo = "Policy locked, but passwords STILL exist on disk!";
 ctrl.statusLabel = "Warning";
 ctrl.state = 1;
 ctrl.actionLabel = "Purge";
}
else {
 ctrl.liveInfo = "Password saving allowed and data may exist.";
 ctrl.statusLabel = "Warning";
 ctrl.state = 1;
 ctrl.actionLabel = "Lock";
}
},
[](bool secure) { ConfigureBrowserPasswordLock(secure); }
},
// 9. Local User Accounts
{
    "Local User Accounts", "Auditing...", "Auditing...", "Secure", L'\xE716', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        int userCount = 0;
        bool allDisabled = true, allExpire = true;
        ctrl.liveInfo = GetLocalUserAccountsInfo(userCount, allDisabled, allExpire);
        if ((userCount > 0 && !allDisabled) || !allExpire) {
            ctrl.statusLabel = "Warning";
            ctrl.state = 1;
            ctrl.actionLabel = "Secure";
        }
else {
 ctrl.statusLabel = "Secured";
 ctrl.state = 2;
 ctrl.actionLabel = "Inspect";
}
},
[](bool secure) {
    if (!secure) {
        ShellExecuteA(g_hMainWnd, "open", "mmc.exe", "lusrmgr.msc /s", NULL, SW_SHOWNORMAL);
    }
else {
 ConfigureLocalUsers(true);
}
}
},
// 10. Network Security Policies
{
    "Network Security Policies", "Auditing...", "Auditing...", "Secure", L'\xE912', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        bool hardened = IsNetworkSecPoliciesHardened();
        ctrl.liveInfo = hardened ? "NTLMv2 & SMB Signing strictly enforced." : "Legacy NTLM or unsigned SMB allowed.";
        ctrl.statusLabel = hardened ? "Secured" : "Warning";
        ctrl.state = hardened ? 2 : 1;
        ctrl.actionLabel = hardened ? "Revert" : "Secure";
    },
    [](bool secure) { ConfigureNetworkSecPolicies(secure); }
},
// 11. WinRAR Archiver (Corrected Index 10)
{
    "WinRAR Archiver", "Auditing...", "Auditing...", "Install", L'\xE7B8', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        std::wstring winrarVer;
        bool winrarInstalled = GetWinRARVersion(winrarVer);
        std::wstring latestVersion = GetLatestWinRARVersionOnline();

        if (winrarInstalled) {
            std::string verStr(winrarVer.begin(), winrarVer.end());
            if (!latestVersion.empty() && IsVersionOlder(winrarVer, latestVersion)) {
                std::string latestStr(latestVersion.begin(), latestVersion.end());
                ctrl.liveInfo = "WinRAR v" + verStr + " (Latest: v" + latestStr + ")";
                ctrl.statusLabel = "Warning";
                ctrl.state = 1;
                ctrl.actionLabel = "Update";
            }
else {
 ctrl.liveInfo = "WinRAR Installed (v" + verStr + ")";
 ctrl.statusLabel = "Secured";
 ctrl.state = 2;
 ctrl.actionLabel = "Inspect";
}
}
else {
 ctrl.liveInfo = "WinRAR is not installed on this device.";
 ctrl.statusLabel = "Secured";
 ctrl.state = 2;
 ctrl.actionLabel = "Install";
}
},
[](bool secure) {
    // Check current button label to determine action instead of relying on 'secure'
    char btnText[32] = { 0 };
    if (g_controls[10].hBtnAction) {
        GetWindowTextA(g_controls[10].hBtnAction, btnText, sizeof(btnText));
    }

    if (std::string(btnText) == "Inspect") {
        ShellExecuteA(g_hMainWnd, "open", "control.exe", "appwiz.cpl", NULL, SW_SHOWNORMAL);
    }
    else {
        // Triggers for "Install" or "Update"
        InstallLatestWinRAR();
    }
}
}
    };

    g_totalControls = static_cast<int>(g_controls.size());
}

void UpdateSecureAllButtonText() {
    int unsecureCount = 0;
    int checkedUnsecureCount = 0;

    for (const auto& ctrl : g_controls) {
        if (ctrl.state != 2) {
            unsecureCount++;
            if (ctrl.isChecked) checkedUnsecureCount++;
        }
    }

    g_isSelectAllChecked = (unsecureCount > 0 && checkedUnsecureCount == unsecureCount);

    if (g_hChkSelectAll) {
        SendMessage(g_hChkSelectAll, BM_SETCHECK, g_isSelectAllChecked ? BST_CHECKED : BST_UNCHECKED, 0);
        InvalidateRect(g_hChkSelectAll, NULL, FALSE);
    }

    std::string btnText = (unsecureCount > 0 && checkedUnsecureCount == unsecureCount)
        ? "Secure All"
        : "Secure (" + std::to_string(checkedUnsecureCount) + ")";

    if (g_hBtnSecureAll) {
        SetWindowTextA(g_hBtnSecureAll, btnText.c_str());
    }
}

void PerformAuditAndHighlight() {
    g_secureCount = 0;
    g_attentionCount = 0;
    g_insecureCount = 0;

    for (auto& ctrl : g_controls) {
        if (ctrl.auditFunc) {
            ctrl.auditFunc(ctrl);
        }

        // If the control is unsecured (state != 2), automatically check it for "Secure All"
        if (ctrl.state != 2) {
            ctrl.isChecked = true;
            g_insecureCount++;
        }
        else {
            ctrl.isChecked = false;
            g_secureCount++;
        }

        if (ctrl.hBtnAction && IsWindow(ctrl.hBtnAction)) {
            SetWindowTextA(ctrl.hBtnAction, ctrl.actionLabel.c_str());
            ShowWindow(ctrl.hBtnAction, SW_SHOW);
        }
    }

    UpdateSecureAllButtonText();
    g_targetSecureCount = static_cast<float>(g_secureCount);
    SetTimer(g_hMainWnd, TIMER_PROGRESS_ANIM, 16, NULL);
}

void UpdateStatus(const std::string& msg) {
    g_statusText = msg;
    if (g_hMainWnd) {
        RedrawWindow(g_hMainWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    }
}

void LoadVersionInfoFromResource() {
    std::string name = GetFileVersionValue("ProductName");
    std::string ver = GetFileVersionValue("ProductVersion");
    if (!name.empty()) g_appProductName = name;
    if (!ver.empty()) g_appVersion = ver;
}

LRESULT CALLBACK HoverButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (uMsg) {
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE:
        if (!GetPropA(hWnd, "Hovered")) {
            SetPropA(hWnd, "Hovered", (HANDLE)1);
            TRACKMOUSEEVENT tme = { sizeof(TRACKMOUSEEVENT), TME_LEAVE, hWnd, 0 };
            TrackMouseEvent(&tme);

            LONG_PTR ctlId = GetWindowLongPtr(hWnd, GWLP_ID);
            if (ctlId >= ID_HARD_BASE && ctlId < ID_HARD_BASE + (int)(g_controls.size() * 10)) {
                size_t rowIdx = (ctlId - ID_HARD_BASE) / 10;
                if (rowIdx < g_controls.size()) {
                    g_controls[rowIdx].isHovered = true;

                    // Calculate exact rect of the icon for this row only
                    int startY = 55 + (static_cast<int>(rowIdx) * 38);
                    RECT rcIconArea = { 15, startY, 48, startY + 38 };
                    InvalidateRect(g_hMainWnd, &rcIconArea, FALSE); // Repaint ONLY the icon region
                }
            }
            InvalidateRect(hWnd, NULL, FALSE);
        }
        break;
    case WM_MOUSELEAVE: {

        RemovePropA(hWnd, "Hovered");
        LONG_PTR ctlId = GetWindowLongPtr(hWnd, GWLP_ID);
        if (ctlId >= ID_HARD_BASE && ctlId < ID_HARD_BASE + (int)(g_controls.size() * 10)) {
            size_t rowIdx = (ctlId - ID_HARD_BASE) / 10;
            if (rowIdx < g_controls.size()) {
                g_controls[rowIdx].isHovered = false;

                // Calculate exact rect of the icon for this row only
                int startY = 55 + (static_cast<int>(rowIdx) * 38);
                RECT rcIconArea = { 15, startY, 48, startY + 38 };
                InvalidateRect(g_hMainWnd, &rcIconArea, FALSE); // Repaint ONLY the icon region
            }
        }
        InvalidateRect(hWnd, NULL, FALSE);
        break;
    }
    case WM_DESTROY:
        RemovePropA(hWnd, "Hovered");
        RemoveWindowSubclass(hWnd, HoverButtonProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

// --- MAIN WINDOW PROC ---
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_TIMER:
        if (wParam == TIMER_PROGRESS_ANIM) {
            float diff = g_targetSecureCount - g_animatedSecureCount;

            // Easing interpolation step
            if (fabsf(diff) > 0.01f) {
                g_animatedSecureCount += diff * 0.15f; // Adjust speed (0.15f = smooth ease-out)
            }
            else {
                g_animatedSecureCount = g_targetSecureCount;
                KillTimer(hwnd, TIMER_PROGRESS_ANIM); // Stop timer when reached
            }

            RECT rcProgressRegion = { 150, 12, 470, 48 };
            InvalidateRect(hwnd, &rcProgressRegion, FALSE);
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_SHOW_RESTART_PROMPT: {
        if (ShowDarkRestartDialog(hwnd)) {
            // Execute Windows Restart Command
            ShellExecuteA(NULL, "open", "shutdown.exe", "/r /t 0", NULL, SW_HIDE);
        }
        return 0;
    }
    case WM_CREATE: {
        
        g_hMainWnd = hwnd;
        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

        InitTheme();
        LoadVersionInfoFromResource();
        InitializeControls(); // Initialize central registry
        CreateRefreshButton(hwnd);

        g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontSub = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontIcon = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe MDL2 Assets");

        CreateSidebarControls(hwnd);

        int startY = 55;
        int rowHeight = 38;
        
        for (size_t i = 0; i < g_controls.size(); i++) {
            // Optional: Add HWND checkbox creation if using physical controls
            g_controls[i].hChkBox = CreateWindowA("BUTTON", "",
                WS_CHILD | BS_CHECKBOX,
                5, startY + 8, 15, 15,
                hwnd, (HMENU)(UINT_PTR)(ID_CHK_BASE + i), NULL, NULL);

            g_controls[i].hBtnAction = CreateWindowA("BUTTON", g_controls[i].actionLabel.c_str(),
                WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
                370, startY + 5, 90, 28,
                hwnd, (HMENU)(UINT_PTR)(ID_HARD_BASE + i * 10 + 1), NULL, NULL);

            SetWindowSubclass(g_controls[i].hBtnAction, HoverButtonProc, 0, 0);
            startY += rowHeight;
        }
        PerformAuditAndHighlight();
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdcWindow = BeginPaint(hwnd, &ps);

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);
        int width = rcClient.right - rcClient.left;
        int height = rcClient.bottom - rcClient.top;

        HDC hdc = CreateCompatibleDC(hdcWindow);
        HBITMAP hMemBitmap = CreateCompatibleBitmap(hdcWindow, width, height);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdc, hMemBitmap);

        // 1. Base window background (Lighter tone)
        HBRUSH hBaseBgBrush = CreateSolidBrush(RGB(23, 32, 51));
        FillRect(hdc, &rcClient, hBaseBgBrush);
        DeleteObject(hBaseBgBrush);
        SetBkMode(hdc, TRANSPARENT);

        // 2. Render rounded card containers (Darker panel tone)
        HBRUSH hPanelSurfaceBrush = CreateSolidBrush(RGB(15, 23, 42));
        HPEN hNullPen = (HPEN)GetStockObject(NULL_PEN);

        HPEN hOldPen = (HPEN)SelectObject(hdc, hNullPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hPanelSurfaceBrush);

        // Corner radius for rounded panels (ellipse width/height)
        int cornerRadius = 16;

        // Left Control Panel Card
        RoundRect(hdc, 10, 10, 475, height - 10, cornerRadius, cornerRadius);

        // Right Side Panel Card (Aligned with 10px outer margin on right)
        RoundRect(hdc, 485, 10, width - 10, height - 10, cornerRadius, cornerRadius);

        // Cleanup drawing objects
        SelectObject(hdc, hOldBrush);
        SelectObject(hdc, hOldPen);
        DeleteObject(hPanelSurfaceBrush);

        SelectObject(hdc, g_hFontTitle);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        RECT rcTitle = { 20, 20, 150, 40 };
        DrawTextA(hdc, "System Controls", -1, &rcTitle, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

       
        int percentMet = (g_totalControls > 0)
            ? static_cast<int>(std::round((g_animatedSecureCount * 100.0f) / static_cast<float>(g_totalControls)))
            : 0;

        RenderProgressBar(hdc, g_totalControls, g_animatedSecureCount, percentMet);


        // Dynamic Color based on completion state
        COLORREF percentColor;
        if (percentMet >= 100)      percentColor = RGB(45, 212, 191); // Teal / Green
        else if (percentMet >= 50) percentColor = RGB(96, 165, 250); // Accent Blue
        else                       percentColor = RGB(248, 113, 113); // Soft Red

        SetTextColor(hdc, percentColor);

        char progText[16];
        snprintf(progText, sizeof(progText), "%d%%", percentMet);
        RECT rcProgText = { 405, 20, 440, 42 };
        DrawTextA(hdc, progText, -1, &rcProgText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // 4. Render Individual Controls
        int startY = 55;
        int rowHeight = 38;

        for (size_t i = 0; i < g_controls.size(); i++) {
            int savedDC = SaveDC(hdc);
            // Check hover status for dynamic accent styling

            bool isRowActive = g_controls[i].isHovered;

            // Optional Glow/Round Highlight Circle behind the Left Icon when Hovered
            if (isRowActive) {
                HBRUSH hGlowBrush = CreateSolidBrush(RGB(30, 58, 138)); // Dark accent blue background
                HPEN hGlowPen = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));  // Vibrant blue ring
                HPEN hOldPen = (HPEN)SelectObject(hdc, hGlowPen);
                HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hGlowBrush);

                RoundRect(hdc, 18, startY + 5, 44, startY + 31, 6, 6);

                SelectObject(hdc, hOldPen);
                SelectObject(hdc, hOldBrush);
                DeleteObject(hGlowPen);
                DeleteObject(hGlowBrush);
            }

            // Set Icon Color (Glow Bright Blue on Hover, Gray otherwise)
            COLORREF iconColor = isRowActive ? RGB(96, 165, 250) : RGB(148, 163, 184);

            HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);
            SetTextColor(hdc, iconColor);
            RECT rcIcon = { 18, startY + 5, 44, startY + 31 };
            DrawTextW(hdc, &g_controls[i].iconGlyph, 1, &rcIcon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // Control Title
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, isRowActive ? RGB(255, 255, 255) : COLOR_TEXT_WHITE);
            RECT rcName = { 48, startY + 2, 330, startY + 20 };
            DrawTextA(hdc, g_controls[i].name.c_str(), -1, &rcName, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

            // Subtitle / Live Info
            SelectObject(hdc, g_hFontSub);
            SetTextColor(hdc, RGB(148, 163, 184));
            RECT rcInfo = { 48, startY + 18, 330, startY + 36 };
            DrawTextA(hdc, g_controls[i].liveInfo.c_str(), -1, &rcInfo, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            RestoreDC(hdc, savedDC);
            startY += rowHeight;
        }
            
            
        BitBlt(hdcWindow, 0, 0, width, height, hdc, 0, 0, SRCCOPY);
        SelectObject(hdc, hOldBitmap);
        DeleteObject(hMemBitmap);
        DeleteDC(hdc);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_COMMAND: {

        int wmId = LOWORD(wParam);
        if (wmId == ID_BTN_REFRESH) {
            ExecuteAppRefresh(hwnd);
            return 0;
        }


        if (wmId >= ID_HARD_BASE && wmId < ID_HARD_BASE + (int)(g_controls.size() * 10)) {
            size_t rowIdx = (wmId - ID_HARD_BASE) / 10;
            if (rowIdx < g_controls.size()) {
                auto& ctrl = g_controls[rowIdx];
                bool isSecured = (ctrl.state == 2);
                std::string action = ctrl.actionLabel;

                // ASK FOR CREDENTIALS FIRST
                if (isSecured && action != "Inspect" && action != "Open") {
                    if (!ShowDarkPasswordDialog(hwnd, "Enter administrator password to continue:")) {
                        return 0; // User canceled or password failed — stop execution!
                    }
                }

                // DETERMINE TARGET STATE BASED ON CURRENT STATE
                bool targetState = !isSecured;

                auto actionTask = [&ctrl, targetState]() {
                    if (ctrl.enforceFunc) {
                        ctrl.enforceFunc(targetState);
                    }
                };

                std::string completedLabel = (ctrl.state == 2) ? "Disable" : "Secured";
                ExecuteButtonActionWithSpinner(ctrl.hBtnAction, actionTask, completedLabel);
            }
            return 0;
        }

        for (auto& ctrl : g_controls) {
            if (ctrl.hBtnAction && (HWND)lParam == ctrl.hBtnAction) {

                auto actionTask = [&ctrl]() {
                    if (ctrl.enforceFunc) {
                        ctrl.enforceFunc(true);
                    }
                    };

                ExecuteButtonActionWithSpinner(ctrl.hBtnAction, actionTask, "Secured");
                break;
            }
        }

        if (wmId == ID_CHK_SELECT_ALL) {
            g_isSelectAllChecked = !g_isSelectAllChecked;
            SendMessage(g_hChkSelectAll, BM_SETCHECK, g_isSelectAllChecked ? BST_CHECKED : BST_UNCHECKED, 0);
            InvalidateRect(g_hChkSelectAll, NULL, FALSE);

            for (auto& ctrl : g_controls) {
                if (ctrl.state != 2) {
                    ctrl.isChecked = g_isSelectAllChecked;
                    if (ctrl.hChkBox) {
                        SendMessage(ctrl.hChkBox, BM_SETCHECK, g_isSelectAllChecked ? BST_CHECKED : BST_UNCHECKED, 0);
                        InvalidateRect(ctrl.hChkBox, NULL, FALSE);
                    }
                }
            }
            UpdateSecureAllButtonText();
            return 0;
        }

        if (wmId == ID_BTN_SECURE_ALL) {
            if (g_isExecuting) return 0;

            std::string selectedList = "";
            int selectedCount = 0;

            for (const auto& ctrl : g_controls) {
                if (ctrl.state != 2 && ctrl.isChecked) {
                    selectedList += "  - " + ctrl.name + "\n";
                    selectedCount++;
                }
            }

            if (selectedCount == 0) {
                ShowDarkMessageDialog(hwnd, "No Controls Selected", "Please select at least one control to enforce.");
                return 0;
            }

            std::string confirmMsg = "Are you sure you want to enforce the following hardening policies?\n\n" + selectedList;
            if (!ShowDarkConfirmDialog(hwnd, "Enforce Selected Hardening Policies", confirmMsg.c_str())) {
                return 0;
            }

            g_isExecuting = true;
            UpdateStatus("Enforcing selected hardening policies... Please wait.");

            // Disable main global buttons
            if (g_hBtnSecureAll) EnableWindow(g_hBtnSecureAll, FALSE);
            if (g_hChkSelectAll) EnableWindow(g_hChkSelectAll, FALSE);

            // Disable all row action buttons and checkboxes to prevent clicking during execution
            for (auto& ctrl : g_controls) {
                if (ctrl.hBtnAction) EnableWindow(ctrl.hBtnAction, FALSE);
                if (ctrl.hChkBox) EnableWindow(ctrl.hChkBox, FALSE);
            }

            std::thread([hwnd]() {
                for (size_t i = 0; i < g_controls.size(); i++) {
                    if (g_controls[i].state != 2 && g_controls[i].isChecked) {
                        HWND hBtn = g_controls[i].hBtnAction;

                        // Mark current processing state & attach spinner property
                        g_controls[i].statusLabel = "Applying...";
                        g_controls[i].liveInfo = "Applying policy...";

                        if (hBtn && IsWindow(hBtn)) {
                            SetPropA(hBtn, "IsSpinning", (HANDLE)1);
                        }

                        bool isDone = false;
                        int frameIdx = 0;

                        // Run enforcement task on a worker thread
                        std::thread task([i, &isDone]() {
                            if (g_controls[i].enforceFunc) {
                                g_controls[i].enforceFunc(true);
                            }
                            isDone = true;
                            });

                        // Animate loading spinner frame index on the button control while processing
                        while (!isDone) {
                            if (hBtn && IsWindow(hBtn)) {
                                SetPropA(hBtn, "SpinnerFrameIndex", (HANDLE)(INT_PTR)frameIdx);
                                InvalidateRect(hBtn, NULL, FALSE);
                            }
                            frameIdx = (frameIdx + 1) % 8;
                            std::this_thread::sleep_for(std::chrono::milliseconds(80));
                        }

                        if (task.joinable()) {
                            task.join();
                        }

                        // Remove spinner properties upon completion
                        if (hBtn && IsWindow(hBtn)) {
                            RemovePropA(hBtn, "IsSpinning");
                            RemovePropA(hBtn, "SpinnerFrameIndex");
                            InvalidateRect(hBtn, NULL, FALSE);
                        }

                        // Allow brief delay for OS/service changes to take effect
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));

                        // Audit individually right away to update warning/check icon and status
                        if (g_controls[i].auditFunc) {
                            g_controls[i].auditFunc(g_controls[i]);
                        }

                        // Refresh UI immediately
                        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
                    }
                }

                // Final overall re-audit to update counters and header metrics
                PerformAuditAndHighlight();

                // Re-enable main global buttons
                if (g_hBtnSecureAll) EnableWindow(g_hBtnSecureAll, TRUE);
                if (g_hChkSelectAll) EnableWindow(g_hChkSelectAll, TRUE);

                // Re-enable individual controls
                for (auto& ctrl : g_controls) {
                    if (ctrl.hBtnAction) EnableWindow(ctrl.hBtnAction, TRUE);
                    if (ctrl.hChkBox) EnableWindow(ctrl.hChkBox, TRUE);
                }

                g_isExecuting = false;
                UpdateStatus("Selected hardening policies enforced successfully.");
                RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);

                PostMessage(hwnd, WM_SHOW_RESTART_PROMPT, 0, 0);
                }).detach();

            return 0;
        }

        if (HandleSidebarCommand(hwnd, wmId)) return 0;

        break;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        if (DrawRefreshButton(pdis)) {
            return TRUE;
        }

        if (IsSidebarButton(pdis->CtlID)) {
            DrawSidebarButton(pdis);
            return TRUE;
        }

        if (pdis->CtlID >= ID_HARD_BASE && pdis->CtlID < ID_HARD_BASE + (int)(g_controls.size() * 10)) {
            HDC hdc = pdis->hDC;
            size_t rowIdx = (pdis->CtlID - ID_HARD_BASE) / 10;
            if (rowIdx >= g_controls.size()) return TRUE;

            // 1. Status Icon & Processing State
            bool isSpinning = GetPropA(pdis->hwndItem, "IsSpinning") != NULL;
            wchar_t statusIcon = (g_controls[rowIdx].state == 2) ? L'\xE73E' : L'\xEdb1'; // Check vs Warning
            COLORREF statusIconColor = (g_controls[rowIdx].state == 2) ? RGB(59, 130, 246) : RGB(239, 68, 68);

            // 2. Spinner Frames Setup
            if (isSpinning) {
                static const wchar_t spinnerFrames[] = { L'\xE712', L'\xE713', L'\xE714', L'\xE715', L'\xE716', L'\xE717', L'\xE718', L'\xE719' };
                INT_PTR frameIdx = (INT_PTR)GetPropA(pdis->hwndItem, "SpinnerFrameIndex");
                statusIcon = spinnerFrames[frameIdx % 8];
                statusIconColor = RGB(96, 165, 250); // Active blue highlight
            }

            char btnText[32] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));
            bool hasButtonText = (btnText[0] != '\0' && strcmp(btnText, " ") != 0);

            bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;
            bool isHovered = GetPropA(pdis->hwndItem, "Hovered") != NULL;

            COLORREF bgCol = isPressed ? RGB(16, 22, 34) : (isHovered ? RGB(32, 44, 66) : RGB(23, 31, 48));
            COLORREF borderCol = isHovered ? RGB(71, 85, 105) : RGB(45, 55, 75);
            COLORREF textCol = RGB(241, 245, 249);

            // --- 3. RENDER CONTAINER (BACKGROUND & BORDER) ---
            HBRUSH hBrush = CreateSolidBrush(bgCol);
            FillRect(hdc, &pdis->rcItem, hBrush);
            DeleteObject(hBrush);

            HPEN hPen = CreatePen(PS_SOLID, 1, borderCol);
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 8, 8);

            // --- MODE A: ACTIVE LOADING SPINNER (3 VERTICAL EQUALIZER BARS / DONEWENFU STYLE) ---
            if (isSpinning) {
                SelectObject(hdc, hOldPen);
                SelectObject(hdc, hOldBrush);
                DeleteObject(hPen);

                SetBkMode(hdc, TRANSPARENT);

                INT_PTR frameIdx = (INT_PTR)GetPropA(pdis->hwndItem, "SpinnerFrameIndex");

                // Exact center coordinates across the button
                int cx = (pdis->rcItem.left + pdis->rcItem.right) / 2;
                int cy = (pdis->rcItem.top + pdis->rcItem.bottom) / 2;

                int barWidth = 4;
                int barSpacing = 3;
                int maxBarHeight = 14;
                int totalWidth = (3 * barWidth) + (2 * barSpacing);
                int startX = cx - (totalWidth / 2);

                // Height ratios for each bar across an 8-frame wave sequence
                static const float heightRatios[8][3] = {
                    { 0.4f, 0.7f, 1.0f }, // Frame 0: Ascending scale
                    { 0.2f, 0.5f, 0.8f }, // Frame 1
                    { 0.5f, 0.3f, 0.5f }, // Frame 2
                    { 0.8f, 0.4f, 0.3f }, // Frame 3
                    { 1.0f, 0.7f, 0.4f }, // Frame 4: Descending scale
                    { 0.8f, 0.9f, 0.6f }, // Frame 5
                    { 0.5f, 1.0f, 0.8f }, // Frame 6: Center peak
                    { 0.3f, 0.8f, 0.9f }  // Frame 7
                };

                int currentFrame = (int)(frameIdx % 8);

                for (int i = 0; i < 3; i++) {
                    float ratio = heightRatios[currentFrame][i];
                    int currentHeight = static_cast<int>(maxBarHeight * ratio);

                    int bx = startX + i * (barWidth + barSpacing);
                    int by = cy - (currentHeight / 2);

                    RECT rcBar = { bx, by, bx + barWidth, by + currentHeight };

                    // Vibrant blue bar fill matching the theme palette
                    HBRUSH hBarBrush = CreateSolidBrush(RGB(56, 189, 248));
                    FillRect(hdc, &rcBar, hBarBrush);
                    DeleteObject(hBarBrush);
                }

                return TRUE;
            }

            // --- MODE B: CHECK-ONLY BADGE (NO TEXT ASSIGNED) ---
            if (!hasButtonText) {
                SelectObject(hdc, hOldPen);
                SelectObject(hdc, hOldBrush);
                DeleteObject(hPen);

                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, statusIconColor);
                HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);

                DrawTextW(hdc, &statusIcon, 1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                SelectObject(hdc, hOldFont);
                return TRUE;
            }

            // --- MODE C: DUAL-PANE BUTTON (DIVIDER + ICON + ACTION TEXT) ---
            int dividerX = pdis->rcItem.left + 24;
            MoveToEx(hdc, dividerX, pdis->rcItem.top + 2, NULL);
            LineTo(hdc, dividerX, pdis->rcItem.bottom - 2);

            SelectObject(hdc, hOldPen);
            SelectObject(hdc, hOldBrush);
            DeleteObject(hPen);

            SetBkMode(hdc, TRANSPARENT);

            // Status Icon Badge
            SetTextColor(hdc, statusIconColor);
            HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);
            RECT rcBadgeIcon = { pdis->rcItem.left + 2, pdis->rcItem.top, dividerX, pdis->rcItem.bottom };
            DrawTextW(hdc, &statusIcon, 1, &rcBadgeIcon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // Action Label
            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, textCol);
            RECT rcActionText = { dividerX + 8, pdis->rcItem.top, pdis->rcItem.right - 2, pdis->rcItem.bottom };
            DrawTextA(hdc, btnText, -1, &rcActionText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

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
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));

    if (!RegisterClassA(&wc)) return 0;

    LoadVersionInfoFromResource();

    std::string windowTitle = g_appProductName + " v" + g_appVersion;
    if (g_appProductName.empty()) windowTitle += "CSCsecure";

    HWND hwnd = CreateWindowExA(
        0,
        "CSCsecureMainClass", windowTitle.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 600,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}