#define WIN32_LEAN_AND_MEAN
#include "ui.h"
#include "ConfirmDialog.h"
#include "Resource.h"
#include "Inventory.h"
#include "version.h"
#include "Credentials.h"
#include "Theme.h"
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
#include "SecureAllHandler.h"

#include "Sidebar.h"

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <d2d1.h>
#include <dwmapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <sstream>
#include <cmath>
#include <sys/stat.h>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "userenv.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

#ifndef WM_REFRESH_WINRAR_UI
#define WM_REFRESH_WINRAR_UI (WM_USER + 101)
#endif

// Control & Menu IDs
#define ID_BTN_SECURE_ALL    1003
#define ID_LOG_EDIT          1005
#define ID_BTN_MENU          1006
#define ID_HARD_BASE         2000
#define ID_CHK_BASE          4000
#define ID_CHK_SELECT_ALL    4099
#define WM_SHOW_RESTART_PROMPT (WM_USER + 100)
#define TIMER_PROGRESS_ANIM  101

static const int kLeftInfoBarTop = 20;
static const int kLeftInfoBarHeight = 76;
static const int kLeftHeaderOffset = 86;

static int g_hoveredInfoCell = -1;
static bool g_trackingInfoHover = false;

HWND g_hChkSelectAll = NULL;
HWND g_hMainWnd = NULL;
HWND g_hLogWnd = NULL;
HWND g_hLogEdit = NULL;
HWND g_hBtnSecureAll = NULL;
bool g_isSelectAllChecked = true;

std::string g_appProductName = "";
std::string g_appVersion = "";
float g_animatedSecureCount = 0.0f;
static float g_targetSecureCount = 0.0f;

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
std::vector<SecurityControl> g_controls;

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

static void GetSystemIdentityInfo(std::string& host, std::string& osName, std::string& osVer) {
    char hostName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD size = sizeof(hostName);
    if (GetComputerNameA(hostName, &size)) host = hostName;
    else host = "Unknown";

    char osBuf[128] = "Unknown OS";
    char verBuf[64] = "";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD bufSize = sizeof(osBuf);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)osBuf, &bufSize);

        bufSize = sizeof(verBuf);
        RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)verBuf, &bufSize);

        char buildBuf[64] = { 0 };
        bufSize = sizeof(buildBuf);
        if (RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (LPBYTE)buildBuf, &bufSize) == ERROR_SUCCESS) {
            if (atoi(buildBuf) >= 22000) {
                std::string sName = osBuf;
                size_t pos = sName.find("Windows 10");
                if (pos != std::string::npos) {
                    sName.replace(pos, 10, "Windows 11");
                    strcpy_s(osBuf, sizeof(osBuf), sName.c_str());
                }
            }
        }
        RegCloseKey(hKey);
    }
    osName = osBuf;
    osVer = verBuf;
}

static RECT GetSystemInfoCardRect() {
    return RECT{ 20, kLeftInfoBarTop, 465, kLeftInfoBarTop + kLeftInfoBarHeight };
}

static void GetSystemInfoCellRects(RECT outRects[4]) {
    RECT rcBar = GetSystemInfoCardRect();
    const int cardPadX = 12;
    const int cardPadY = 10;
    const int gridHeight = (rcBar.bottom - rcBar.top) - (cardPadY * 2);
    int innerTop = rcBar.top + ((rcBar.bottom - rcBar.top) - gridHeight) / 2;
    RECT rcInner = { rcBar.left + cardPadX, innerTop, rcBar.right - cardPadX, innerTop + gridHeight };
    int midX = rcInner.left + (rcInner.right - rcInner.left) / 2;
    int midY = rcInner.top + (rcInner.bottom - rcInner.top) / 2;
    const int gap = 8;

    // Interactive/hit-test cell areas (separated so hover boxes do not cross dividers)
    outRects[0] = { rcInner.left,  rcInner.top,  midX - gap / 2, midY - gap / 2 }; // Host
    outRects[1] = { midX + gap / 2, rcInner.top,  rcInner.right, midY - gap / 2 }; // IP
    outRects[2] = { rcInner.left,  midY + gap / 2, midX - gap / 2, rcInner.bottom }; // OS
    outRects[3] = { midX + gap / 2, midY + gap / 2, rcInner.right, rcInner.bottom }; // Version
}

static int HitTestSystemInfoCard(POINT pt) {
    RECT cells[4];
    GetSystemInfoCellRects(cells);
    for (int i = 0; i < 4; ++i) {
        if (PtInRect(&cells[i], pt)) return i;
    }
    return -1;
}

static void DrawSystemInfoTopBar(HDC hdc, int left, int right) {
    (void)left; (void)right;
    std::string host, osName, osVer;
    GetSystemIdentityInfo(host, osName, osVer);
    std::string ip = GetLocalIPAddress();

    RECT rcBar = GetSystemInfoCardRect();

    HBRUSH hBarBg = CreateSolidBrush(COLOR_PANEL);
    HPEN hBarPen = CreatePen(PS_SOLID, 1, COLOR_BORDER);
    HGDIOBJ oldBrush = SelectObject(hdc, hBarBg);
    HGDIOBJ oldPen = SelectObject(hdc, hBarPen);
    RoundRect(hdc, rcBar.left, rcBar.top, rcBar.right, rcBar.bottom, 6, 6);
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(hBarBg);
    DeleteObject(hBarPen);

    RECT cellRects[4];
    GetSystemInfoCellRects(cellRects);

    // Subtle interior grid dividers
    HPEN hDivPen = CreatePen(PS_SOLID, 1, COLOR_BORDER);
    HGDIOBJ oldDivPen = SelectObject(hdc, hDivPen);
    int vX = (cellRects[0].right + cellRects[1].left) / 2;
    int hY = (cellRects[0].bottom + cellRects[2].top) / 2;
    MoveToEx(hdc, vX, cellRects[0].top, NULL);
    LineTo(hdc, vX, cellRects[2].bottom);
    MoveToEx(hdc, cellRects[0].left, hY, NULL);
    LineTo(hdc, cellRects[1].right, hY);
    SelectObject(hdc, oldDivPen);
    DeleteObject(hDivPen);

    // Hover highlight per interactive cell (contained within cell bounds)
    if (g_hoveredInfoCell >= 0 && g_hoveredInfoCell < 4) {
        RECT rcHover = cellRects[g_hoveredInfoCell];
        HBRUSH hHoverBg = CreateSolidBrush(RGB(30, 41, 59));
        HPEN hHoverPen = CreatePen(PS_SOLID, 1, RGB(71, 85, 105));
        HGDIOBJ oldHB = SelectObject(hdc, hHoverBg);
        HGDIOBJ oldHP = SelectObject(hdc, hHoverPen);
        RoundRect(hdc, rcHover.left, rcHover.top, rcHover.right, rcHover.bottom, 6, 6);
        SelectObject(hdc, oldHB);
        SelectObject(hdc, oldHP);
        DeleteObject(hHoverBg);
        DeleteObject(hHoverPen);
    }

    struct Cell { RECT rc; wchar_t icon; const char* label; std::string value; };
    Cell cells[4] = {
        { cellRects[0], L'\xE7F4', "Host:",    host.empty() ? "N/A" : host },
        { cellRects[1], L'\xE839', "IP:",      ip.empty() ? "N/A" : ip },
        { cellRects[2], L'\xE770', "OS:",      osName.empty() ? "N/A" : osName },
        { cellRects[3], L'\xE946', "Version:", osVer.empty() ? "N/A" : osVer }
    };

    HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontSub);
    for (int i = 0; i < 4; ++i) {
        const Cell& c = cells[i];

        // Internal padding inside each interactive cell
        RECT rcContent = c.rc;
        InflateRect(&rcContent, -10, -6);

        SelectObject(hdc, g_hFontIcon);
        SetTextColor(hdc, COLOR_ACCENT_TEAL);
        RECT rcIcon = { rcContent.left, rcContent.top, rcContent.left + 18, rcContent.bottom };
        DrawTextW(hdc, &c.icon, 1, &rcIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        RECT rcLabel = { rcContent.left + 20, rcContent.top, rcContent.right, rcContent.bottom };
        DrawTextA(hdc, c.label, -1, &rcLabel, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        SIZE szLabel = { 0, 0 };
        GetTextExtentPoint32A(hdc, c.label, lstrlenA(c.label), &szLabel);

        SetTextColor(hdc, COLOR_TEXT_WHITE);
        RECT rcValue = { rcLabel.left + szLabel.cx + 6, rcContent.top, rcContent.right, rcContent.bottom };
        DrawTextA(hdc, c.value.c_str(), -1, &rcValue, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }
    SelectObject(hdc, hOldFont);
}



// Helper function to update control text and force parent window repaint
void UpdateControlLiveInfo(SecurityControl* pCtrl, const std::string& infoText, const std::string& status) {
    if (!pCtrl) return;

    pCtrl->liveInfo = infoText;
    pCtrl->statusLabel = status;

    if (pCtrl->hBtnAction && IsWindow(pCtrl->hBtnAction)) {
        InvalidateRect(pCtrl->hBtnAction, NULL, FALSE);
    }

    // Calculate row index and invalidate the main window's row rectangle
    size_t ctrlIndex = 0;
    for (size_t i = 0; i < g_controls.size(); i++) {
        if (&g_controls[i] == pCtrl) {
            ctrlIndex = i;
            break;
        }
    }

    if (g_hMainWnd && IsWindow(g_hMainWnd)) {
        int startY = 55 + kLeftHeaderOffset + (static_cast<int>(ctrlIndex) * 38);
        RECT rcRow = { 48, startY + 18, 330, startY + 36 };
        InvalidateRect(g_hMainWnd, &rcRow, FALSE);
    }
}



void LoadVersionInfoFromResource() {
    std::string name = GetFileVersionValue("ProductName");
    std::string ver = GetFileVersionValue("ProductVersion");
    if (!name.empty()) g_appProductName = name;
    if (!ver.empty()) g_appVersion = ver;
}

void RunPowerShellInspector(const std::string& title, const std::string& psCode) {
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

    std::string cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + wrapper + "\"";
    WinExec(cmd.c_str(), SW_SHOWNORMAL);
}

void SetAllControlsEnabled(bool enable) {
    if (g_hBtnSecureAll) EnableWindow(g_hBtnSecureAll, enable);
    if (g_hChkSelectAll) EnableWindow(g_hChkSelectAll, enable);

    for (auto& ctrl : g_controls) {
        if (ctrl.hBtnAction && IsWindow(ctrl.hBtnAction)) {
            EnableWindow(ctrl.hBtnAction, enable);
        }
        if (ctrl.hChkBox && IsWindow(ctrl.hChkBox)) {
            EnableWindow(ctrl.hChkBox, enable);
        }
    }

    // Set cursor state immediately
    if (!enable) {
        SetCursor(LoadCursor(NULL, IDC_WAIT));
    }
    else {
        SetCursor(LoadCursor(NULL, IDC_ARROW));
    }

    // Force full window repaint so disabled button styles render immediately
    if (g_hMainWnd && IsWindow(g_hMainWnd)) {
        RedrawWindow(g_hMainWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    }
}

void ExecuteButtonActionWithSpinner(HWND hBtn, SecurityControl* pCtrl, std::function<void()> action) {
    if (!hBtn || !IsWindow(hBtn)) return;

    // Lock global execution state and disable all UI controls
    g_isExecuting = true;
    SetAllControlsEnabled(false);

    std::thread([hBtn, pCtrl, action]() {
        int frameIdx = 0;
        bool isDone = false;

        SetPropA(hBtn, "IsSpinning", (HANDLE)1);

        std::thread task([action, &isDone]() {
            action();
            isDone = true;
            });

        while (!isDone) {
            SetPropA(hBtn, "SpinnerFrameIndex", (HANDLE)(INT_PTR)frameIdx);

            // Redraw strictly this single button window
            InvalidateRect(hBtn, NULL, TRUE);

            frameIdx = (frameIdx + 1) % 8;
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }

        if (task.joinable()) {
            task.join();
        }

        RemovePropA(hBtn, "IsSpinning");
        RemovePropA(hBtn, "SpinnerFrameIndex");

        // Set the text from pCtrl if provided, or read current control action text
        if (pCtrl) {
            SetWindowTextA(hBtn, pCtrl->actionLabel.c_str());
        }

        // Unlock global execution state and re-enable all UI controls on the main thread
        g_isExecuting = false;
        SetAllControlsEnabled(true);

        InvalidateRect(hBtn, NULL, FALSE);
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
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    int timeout = 10;
    while (QueryServiceStatus(hService, &status) && timeout-- > 0) {
        if (status.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(1000);
    }

    bool success = StartServiceA(hService, 0, NULL) != 0;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return success;
}

void InitializeControls() {
    g_controls = {
        // 1. Bluetooth
 {
     "Bluetooth Adapter", "Auditing...", "Auditing...", "Disable", L'\xE702', NULL, NULL, true, 2, false,
     [](SecurityControl& ctrl) {
         if (ctrl.statusLabel == "Applying...") return;

         bool active = IsBluetoothEnabled();
         ctrl.liveInfo = active ? "Bluetooth is currently enabled." : "Bluetooth adapter is securely disabled.";
         ctrl.statusLabel = active ? "Warning" : "Secured";
         ctrl.state = active ? 1 : 2;
         ctrl.actionLabel = active ? "Disable" : "Enable";
     },
     [](bool enable) {
         SecurityControl* pCtrl = nullptr;
         for (auto& c : g_controls) {
             if (c.name == "Bluetooth Adapter") {
                 pCtrl = &c;
                 break;
             }
         }
         HandleBluetoothToggle(g_hMainWnd, pCtrl);
     }
 },
        // 2. Wi-Fi
        {
            "Wi-Fi Network Adapter", "Auditing...", "Auditing...", "Disable", L'\xE701', NULL, NULL, true, 2, false,
            [](SecurityControl& ctrl) {
                if (ctrl.statusLabel == "Applying...") return;

                bool active = IsWifiAdapterEnabled();
                ctrl.liveInfo = active ? "Wi-Fi is currently enabled." : "Wi-Fi adapter is securely disabled.";
                ctrl.statusLabel = active ? "Warning" : "Secured";
                ctrl.state = active ? 1 : 2;
                ctrl.actionLabel = active ? "Disable" : "Enable";
            },
            [](bool enable) {
                SecurityControl* pCtrl = nullptr;
                for (auto& c : g_controls) { if (c.name == "Wi-Fi Network Adapter") { pCtrl = &c; break; } }
                if (!pCtrl) return;

                UpdateControlLiveInfo(pCtrl, enable ? "Disabling Wi-Fi..." : "Enabling Wi-Fi...");
                ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl, enable]() {
                    SetWifiDeviceState(!enable);

                    pCtrl->statusLabel = "";
                    PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
                    });
            }
        },
        // 3. SMB Protocols
        {
            "SMB Server Protocols", "Auditing...", "Auditing...", "Secure", L'\xE839', NULL, NULL, true, 2, false,
            [](SecurityControl& ctrl) {
                if (ctrl.statusLabel == "Applying...") return;

                bool smbHardened = IsSMBv1Disabled();
                ctrl.liveInfo = smbHardened ? "SMBv1 protocol is securely disabled." : "SMBv1 protocol is currently enabled.";
                ctrl.statusLabel = smbHardened ? "Secured" : "Warning";
                ctrl.state = smbHardened ? 2 : 1;
                ctrl.actionLabel = smbHardened ? "Inspect" : "Secure";
            },
            [](bool secure) {
                SecurityControl* pCtrl = nullptr;
                for (auto& c : g_controls) { if (c.name == "SMB Server Protocols") { pCtrl = &c; break; } }
                if (!pCtrl) return;

                if (!secure) {
                    std::string script =
                        "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol; "
                        "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol";
                    RunPowerShellInspector("SMB Server Protocol Inspector", script);
                }
 else {
                    UpdateControlLiveInfo(pCtrl, "Configuring SMB protocols...");

                    ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
                        ConfigureSMB(true);

                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        pCtrl->statusLabel = "";
                        PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
                        });
}
}
},
// 4. Shared Printers
{
    "Shared Network Printers", "Auditing...", "Auditing...", "Secure", L'\xE749', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

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
        SecurityControl* pCtrl = nullptr;
        for (auto& c : g_controls) { if (c.name == "Shared Network Printers") { pCtrl = &c; break; } }
        if (!pCtrl) return;

        if (!secure) {
            std::string script =
                "Get-Printer | Select-Object Name, Shared, Published; "
                "Get-SmbShare | Where-Object { $_.Special -eq $false }";
            RunPowerShellInspector("Shared Network Printers Inspector", script);
        }
else {
            UpdateControlLiveInfo(pCtrl, "Securing printer shares & RPC...");

            ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
                OnLockdownPrintersButtonClicked();

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                pCtrl->statusLabel = "";
                PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
                });
}
}
},
// 5. Shared Folders
{
    "Shared Network Folders / Files", "Auditing...", "Auditing...", "Secure", L'\xE8B7', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

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
    [](bool secure) {
        SecurityControl* pCtrl = nullptr;
    for (auto& c : g_controls) { if (c.name == "Shared Network Folders / Files") { pCtrl = &c; break; } }
    if (!pCtrl) return;

    UpdateControlLiveInfo(pCtrl, "Unsharing all network folders...");

    ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
        UnshareAllFolders();

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        pCtrl->statusLabel = "";
        PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
    });
    }
},
// 6. SSL / TLS
{
    "SSL / TLS & Ciphers", "Auditing...", "Auditing...", "Secure", L'\xE72E', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

        bool sslTlsHardened = IsSslTlsHardened();
        ctrl.liveInfo = sslTlsHardened ? "Best practice IIS Crypto settings applied." : "Unsecured TLS/SSL ciphers are active.";
        ctrl.statusLabel = sslTlsHardened ? "Secured" : "Warning";
        ctrl.state = sslTlsHardened ? 2 : 1;
        ctrl.actionLabel = sslTlsHardened ? "Inspect" : "Secure";
    },
    [](bool secure) {
       SecurityControl* pCtrl = nullptr;
    for (auto& c : g_controls) { if (c.name == "SSL / TLS & Ciphers") { pCtrl = &c; break; } }
    if (!pCtrl) return;

    if (pCtrl->state == 2 || !secure) {
        ShellExecuteA(g_hMainWnd, "open", "iiscrypto.exe", NULL, NULL, SW_SHOWNORMAL);
        return;
    }

    UpdateControlLiveInfo(pCtrl, "Hardening TLS/SSL ciphers...");

    ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
        ConfigureSslTlsIISCrypto(true);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        pCtrl->statusLabel = "";
        PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
    });
    }
},
// 7. Browser Login
{
    "Browser Account Login", "Auditing...", "Auditing...", "Lock", L'\xE77B', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

        bool locked = IsBrowserAccountLocked();
        ctrl.liveInfo = locked ? "Browser sign-in is securely disabled." : "Browser sign-in is currently allowed.";
        ctrl.statusLabel = locked ? "Secured" : "Warning";
        ctrl.state = locked ? 2 : 1;
        ctrl.actionLabel = locked ? "Unlock" : "Lock";
    },
    [](bool secure) {
       SecurityControl* pCtrl = nullptr;
    for (auto& c : g_controls) { if (c.name == "Browser Account Login") { pCtrl = &c; break; } }
    if (!pCtrl) return;

    UpdateControlLiveInfo(pCtrl, secure ? "Locking browser sign-in..." : "Unlocking browser sign-in...");

    ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl, secure]() {
        ConfigureBrowserAccountLock(secure);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        pCtrl->statusLabel = "";
        PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
    });
    }
},
// 8. Browser Passwords
{
    "Browser Password Lock & Removal", "Auditing...", "Auditing...", "Lock", L'\xE890', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

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
    [](bool secure) {
        SecurityControl* pCtrl = nullptr;
    for (auto& c : g_controls) { if (c.name == "Browser Password Lock & Removal") { pCtrl = &c; break; } }
    if (!pCtrl) return;

    UpdateControlLiveInfo(pCtrl, "Updating password security policies...");

    ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl, secure]() {
        ConfigureBrowserPasswordLock(secure);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        pCtrl->statusLabel = "";
        PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
    });
    }
},
// 9. Local User Accounts
{
    "Local User Accounts", "Auditing...", "Auditing...", "Secure", L'\xE716', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

        int userCount = 0;
        bool allDisabled = true, allExpire = true;
        bool anyMustChange = false, anyCannotChange = false, anyLockedOut = false;
        ctrl.liveInfo = GetLocalUserAccountsInfo(userCount, allDisabled, allExpire, anyMustChange, anyCannotChange, anyLockedOut);
        if ((userCount > 0 && !allDisabled) || !allExpire || anyMustChange || anyCannotChange || anyLockedOut) {
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
      SecurityControl* pCtrl = nullptr;
    for (auto& c : g_controls) { if (c.name == "Local User Accounts") { pCtrl = &c; break; } }
    if (!pCtrl) return;

    if (!secure) {
        ShellExecuteA(g_hMainWnd, "open", "mmc.exe", "lusrmgr.msc /s", NULL, SW_SHOWNORMAL);
    }
    else {
        UpdateControlLiveInfo(pCtrl, "Securing local user accounts...");

        ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
            ConfigureLocalUsers(true);

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            pCtrl->statusLabel = "";
            PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
        });
        }
    }
},
// 10. Network Security Policies
{
    "Network Security Policies", "Auditing...", "Auditing...", "Secure", L'\xE912', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

        bool hardened = IsNetworkSecPoliciesHardened();
        ctrl.liveInfo = hardened ? "NTLMv2 & SMB Signing strictly enforced." : "Legacy NTLM or unsigned SMB allowed.";
        ctrl.statusLabel = hardened ? "Secured" : "Warning";
        ctrl.state = hardened ? 2 : 1;
        ctrl.actionLabel = hardened ? "Inspect" : "Secure";
    },
    [](bool secure) {
        SecurityControl* pCtrl = nullptr;
        for (auto& c : g_controls) { if (c.name == "Network Security Policies") { pCtrl = &c; break; } }
        if (!pCtrl) return;

        // If it's already secured and user clicks "Inspect", open Group Policy Editor
        if (pCtrl->state == 2 || !secure) {
            ShellExecuteA(g_hMainWnd, "open", "mmc.exe", "gpedit.msc", NULL, SW_SHOWNORMAL);
            return;
        }

        UpdateControlLiveInfo(pCtrl, "Enforcing NTLMv2 & SMB signing...");

        ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
            ConfigureNetworkSecPolicies(true);

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            pCtrl->statusLabel = "";
            PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
        });
    }
},
// 11. WinRAR Archiver
{
    "WinRAR Archiver", "Auditing...", "Auditing...", "Install", L'\xE7B8', NULL, NULL, true, 2, false,
    [](SecurityControl& ctrl) {
        if (ctrl.statusLabel == "Applying...") return;

        std::wstring winrarVer;
        bool winrarInstalled = GetWinRARVersion(winrarVer);
        std::wstring latestVersion = GetLatestWinRARVersionOnline();

        if (winrarInstalled) {
            std::string verStr(winrarVer.begin(), winrarVer.end());
            if (!latestVersion.empty() && verStr != "Installed" && IsVersionOlder(winrarVer, latestVersion)) {
                std::string latestStr(latestVersion.begin(), latestVersion.end());
                ctrl.liveInfo = "WinRAR v" + verStr + " (Latest: v" + latestStr + ")";
                ctrl.statusLabel = "Warning";
                ctrl.state = 1;
                ctrl.actionLabel = "Update";
            }
            else {
                ctrl.liveInfo = (verStr == "Installed") ? "WinRAR is installed." : "WinRAR v" + verStr + " is installed.";
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
        SecurityControl* pCtrl = nullptr;
        for (auto& c : g_controls) { if (c.name == "WinRAR Archiver") { pCtrl = &c; break; } }
        if (!pCtrl) return;

        std::wstring ver;
        if (GetWinRARVersion(ver) && pCtrl->actionLabel == "Inspect") {
            ShellExecuteA(g_hMainWnd, "open", "control.exe", "appwiz.cpl", NULL, SW_SHOWNORMAL);
        }
        else {
            UpdateControlLiveInfo(pCtrl, "Installing WinRAR...");

            ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl]() {
                InstallLatestWinRAR();

                UpdateControlLiveInfo(pCtrl, "Verifying installation...");

                std::wstring installedVer;
                int retries = 20;
                while (retries-- > 0) {
                    if (GetWinRARVersion(installedVer) && !installedVer.empty()) break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                pCtrl->statusLabel = "";
                if (pCtrl->auditFunc) {
                    pCtrl->auditFunc(*pCtrl);
                }
                PostMessage(g_hMainWnd, WM_REFRESH_WINRAR_UI, 0, (LPARAM)pCtrl);
                });
        }
    }
}

    };

    g_totalControls = static_cast<int>(g_controls.size());
}

void PerformAuditAndHighlight() {
    g_secureCount = 0;
    g_attentionCount = 0;
    g_insecureCount = 0;

    for (auto& ctrl : g_controls) {
        if (ctrl.auditFunc) {
            ctrl.auditFunc(ctrl);
        }

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

    g_targetSecureCount = static_cast<float>(g_secureCount);
    SetTimer(g_hMainWnd, TIMER_PROGRESS_ANIM, 16, NULL);

    SaveOrUpdateControlCSV();
}

void UpdateStatus(const std::string& msg) {
    g_statusText = msg;
    if (g_hMainWnd) {
        InvalidateRect(g_hMainWnd, NULL, FALSE);
    }
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

                    int startY = 55 + kLeftHeaderOffset + (static_cast<int>(rowIdx) * 38);
                    RECT rcIconArea = { 15, startY, 48, startY + 38 };
                    InvalidateRect(hWnd, NULL, TRUE);
                }
            }
        }
        break;
    case WM_MOUSELEAVE: {
        RemovePropA(hWnd, "Hovered");
        LONG_PTR ctlId = GetWindowLongPtr(hWnd, GWLP_ID);
        if (ctlId >= ID_HARD_BASE && ctlId < ID_HARD_BASE + (int)(g_controls.size() * 10)) {
            size_t rowIdx = (ctlId - ID_HARD_BASE) / 10;
            if (rowIdx < g_controls.size()) {
                g_controls[rowIdx].isHovered = false;

                int startY = 55 + kLeftHeaderOffset + (static_cast<int>(rowIdx) * 38);
                RECT rcIconArea = { 15, startY, 48, startY + 38 };
                InvalidateRect(hWnd, NULL, TRUE);
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

void LayoutMainControls(HWND hwnd) {
    int startY = 55 + kLeftHeaderOffset;
    int rowHeight = 38;

    for (size_t i = 0; i < g_controls.size(); i++) {
        if (g_controls[i].hChkBox && IsWindow(g_controls[i].hChkBox)) {
            MoveWindow(g_controls[i].hChkBox, 5, startY + 8, 15, 15, TRUE);
        }
        if (g_controls[i].hBtnAction && IsWindow(g_controls[i].hBtnAction)) {
            MoveWindow(g_controls[i].hBtnAction, 370, startY + 5, 90, 28, TRUE);
        }
        startY += rowHeight;
    }

    if (g_hBtnRefresh && IsWindow(g_hBtnRefresh)) {
        MoveWindow(g_hBtnRefresh, 440, 20 + kLeftHeaderOffset, 24, 24, TRUE);
    }

    LayoutSidebarControls(hwnd);
}

void ResizeToFitControls(HWND hwnd) {
    int startY = 55 + kLeftHeaderOffset;
    int rowHeight = 38;
    int bottomPadding = 40;

    // 1. Calculate height needed based on security control rows
    int controlsHeight = startY + (static_cast<int>(g_controls.size()) * rowHeight) + bottomPadding;

    // 2. Calculate height needed based on sidebar elements
    int sidebarStartY = 20;
    int btnHeight = 42;
    int spacing = 12;
    int numSidebarButtons = 7;

    int sidebarContentHeight = sidebarStartY
        + (numSidebarButtons * (btnHeight + spacing))
        + spacing
        + btnHeight /* Restart Button height */ + 20 /* bottom margin */ + bottomPadding;

    // Use the maximum required height between the main list and sidebar
    int clientHeight = (controlsHeight > sidebarContentHeight) ? controlsHeight : sidebarContentHeight;

    // Set window size (Main control panel width + Sidebar width + margins)
    RECT rc = { 0, 0, 690, clientHeight };
    AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);

    SetWindowPos(hwnd, NULL, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE | SWP_NOZORDER);
    LayoutMainControls(hwnd);
    InvalidateRect(hwnd, NULL, TRUE);
}
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_SETCURSOR: {
        if (g_isExecuting) {
            SetCursor(LoadCursor(NULL, IDC_WAIT));
            return TRUE;
        }
        if (LOWORD(lParam) == HTCLIENT) {
            POINT pt;
            GetCursorPos(&pt);
            ScreenToClient(hwnd, &pt);
            if (HitTestSystemInfoCard(pt) >= 0) {
                SetCursor(LoadCursor(NULL, IDC_HAND));
                return TRUE;
            }
        }
        break;
    }
    case WM_MOUSEMOVE: {
        if (!g_trackingInfoHover) {
            TRACKMOUSEEVENT tme = { sizeof(TRACKMOUSEEVENT), TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&tme);
            g_trackingInfoHover = true;
        }

        POINT pt = { (short)LOWORD(lParam), (short)HIWORD(lParam) };
        int hit = HitTestSystemInfoCard(pt);
        if (hit >= 0) {
            SetCursor(LoadCursor(NULL, IDC_HAND));
        }
        if (hit != g_hoveredInfoCell) {
            g_hoveredInfoCell = hit;
            RECT rc = GetSystemInfoCardRect();
            InvalidateRect(hwnd, &rc, FALSE);
        }
        break;
    }
    case WM_MOUSELEAVE: {
        g_trackingInfoHover = false;
        if (g_hoveredInfoCell != -1) {
            g_hoveredInfoCell = -1;
            RECT rc = GetSystemInfoCardRect();
            InvalidateRect(hwnd, &rc, FALSE);
        }
        break;
    }
    case WM_LBUTTONUP: {
        POINT pt = { (short)LOWORD(lParam), (short)HIWORD(lParam) };
        int hit = HitTestSystemInfoCard(pt);
        if (hit >= 0) {
            if (hit == 1) {
                ShellExecuteA(hwnd, "open", "control.exe", "ncpa.cpl", NULL, SW_SHOW);
            } else {
                ShellExecuteA(hwnd, "open", "ms-settings:about", NULL, NULL, SW_SHOW);
            }
            return 0;
        }
        break;
    }
    case WM_REFRESH_CONTROL_UI:
    case WM_REFRESH_WINRAR_UI: {
        SecurityControl* pCtrl = (SecurityControl*)lParam;

        if (pCtrl) {
            // Ensure statusLabel is empty so auditFunc isn't blocked by guard clause
            pCtrl->statusLabel = "";

            // Re-run audit logic for the updated control
            if (pCtrl->auditFunc) {
                pCtrl->auditFunc(*pCtrl);
            }

            // Update button text and state
            if (pCtrl->hBtnAction && IsWindow(pCtrl->hBtnAction)) {
                SetWindowTextA(pCtrl->hBtnAction, pCtrl->actionLabel.c_str());
                EnableWindow(pCtrl->hBtnAction, TRUE);
                InvalidateRect(pCtrl->hBtnAction, NULL, FALSE);
            }

            // Recalculate secure count for progress bar animation
            int newSecureCount = 0;
            for (const auto& ctrl : g_controls) {
                if (ctrl.state == 2) {
                    newSecureCount++;
                }
            }
            g_secureCount = newSecureCount;
            g_targetSecureCount = static_cast<float>(g_secureCount);

            // Trigger progress bar smooth animation & repaint top header
            SetTimer(hwnd, TIMER_PROGRESS_ANIM, 16, NULL);
            RECT rcProgressRegion = { 150, 12 + kLeftHeaderOffset, 470, 48 + kLeftHeaderOffset };
            InvalidateRect(hwnd, &rcProgressRegion, FALSE);

            // Calculate and invalidate the full row rectangle on the main window
            size_t ctrlIndex = 0;
            for (size_t i = 0; i < g_controls.size(); i++) {
                if (&g_controls[i] == pCtrl) {
                    ctrlIndex = i;
                    break;
                }
            }

            int startY = 55 + kLeftHeaderOffset + (static_cast<int>(ctrlIndex) * 38);
            RECT rcRow = { 10, startY, 475, startY + 38 };
            InvalidateRect(hwnd, &rcRow, FALSE);
            SaveOrUpdateControlCSV();
        }
        return 0;
    }
    case WM_TIMER:
        if (wParam == TIMER_PROGRESS_ANIM) {
            float diff = g_targetSecureCount - g_animatedSecureCount;

            if (fabsf(diff) > 0.01f) {
                g_animatedSecureCount += diff * 0.15f;
            }
            else {
                g_animatedSecureCount = g_targetSecureCount;
                KillTimer(hwnd, TIMER_PROGRESS_ANIM);
            }

            RECT rcProgressRegion = { 150, 12 + kLeftHeaderOffset, 470, 48 + kLeftHeaderOffset };
            InvalidateRect(hwnd, &rcProgressRegion, FALSE);
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_SHOW_RESTART_PROMPT: {
        ShowDarkNoticeDialog(hwnd, "Restart Reminder", "Please don't forget to restart the device");
        return 0;
    }
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) {
            LayoutMainControls(hwnd);
        }
        return 0;
    case WM_CREATE: {
        g_hMainWnd = hwnd;
        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

        InitTheme();
        LoadVersionInfoFromResource();
        InitializeControls();
        ResizeToFitControls(hwnd);
        CreateRefreshButton(hwnd);
        LayoutMainControls(hwnd);

        g_hFontTitle = CreateFontA(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontSub = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontBold = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
        g_hFontIcon = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe MDL2 Assets");

        CreateSidebarControls(hwnd);

        int startY = 55 + kLeftHeaderOffset;
        int rowHeight = 38;

        for (size_t i = 0; i < g_controls.size(); i++) {
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

        HBRUSH hBaseBgBrush = CreateSolidBrush(RGB(23, 32, 51));
        FillRect(hdc, &rcClient, hBaseBgBrush);
        DeleteObject(hBaseBgBrush);
        SetBkMode(hdc, TRANSPARENT);

        HBRUSH hPanelSurfaceBrush = CreateSolidBrush(RGB(15, 23, 42));
        HPEN hNullPen = (HPEN)GetStockObject(NULL_PEN);

        HPEN hOldPen = (HPEN)SelectObject(hdc, hNullPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hPanelSurfaceBrush);

        int cornerRadius = 16;
        int cardBottom = height - 10;

        RoundRect(hdc, 10, 10, 475, cardBottom, cornerRadius, cornerRadius);
        RoundRect(hdc, 480, 10, width - 10, cardBottom, cornerRadius, cornerRadius);

        SelectObject(hdc, hOldBrush);
        SelectObject(hdc, hOldPen);
        DeleteObject(hPanelSurfaceBrush);

        DrawSystemInfoTopBar(hdc, 20, 465);

        SelectObject(hdc, g_hFontTitle);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        RECT rcTitle = { 20, 20 + kLeftHeaderOffset, 200, 40 + kLeftHeaderOffset };
        DrawTextA(hdc, "System Controls", -1, &rcTitle, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        int percentMet = (g_totalControls > 0)
            ? static_cast<int>(std::round((g_animatedSecureCount * 100.0f) / static_cast<float>(g_totalControls)))
            : 0;

        RenderProgressBar(hdc, g_totalControls, g_animatedSecureCount, percentMet, 23 + kLeftHeaderOffset);

        COLORREF percentColor;
        if (percentMet >= 100)      percentColor = RGB(45, 212, 191);
        else if (percentMet >= 50) percentColor = RGB(96, 165, 250);
        else                       percentColor = RGB(248, 113, 113);

        SetTextColor(hdc, percentColor);

        char progText[16];
        snprintf(progText, sizeof(progText), "%d%%", percentMet);
        RECT rcProgText = { 405, 20 + kLeftHeaderOffset, 440, 42 + kLeftHeaderOffset };
        DrawTextA(hdc, progText, -1, &rcProgText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        int startY = 55 + kLeftHeaderOffset;
        int rowHeight = 38;

        for (size_t i = 0; i < g_controls.size(); i++) {
            int savedDC = SaveDC(hdc);

            bool isRowActive = g_controls[i].isHovered;

            if (isRowActive) {
                HBRUSH hGlowBrush = CreateSolidBrush(RGB(30, 58, 138));
                HPEN hGlowPen = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
                HPEN hOldPen = (HPEN)SelectObject(hdc, hGlowPen);
                HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hGlowBrush);

                RoundRect(hdc, 18, startY + 5, 44, startY + 31, 6, 6);

                SelectObject(hdc, hOldPen);
                SelectObject(hdc, hOldBrush);
                DeleteObject(hGlowPen);
                DeleteObject(hGlowBrush);
            }

            COLORREF iconColor = isRowActive ? RGB(96, 165, 250) : RGB(148, 163, 184);

            HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);
            SetTextColor(hdc, iconColor);
            RECT rcIcon = { 18, startY + 5, 44, startY + 31 };
            DrawTextW(hdc, &g_controls[i].iconGlyph, 1, &rcIcon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(hdc, g_hFontBold);
            SetTextColor(hdc, isRowActive ? RGB(255, 255, 255) : COLOR_TEXT_WHITE);
            RECT rcName = { 48, startY + 2, 330, startY + 20 };
            DrawTextA(hdc, g_controls[i].name.c_str(), -1, &rcName, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

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
        if (HandleSidebarCommand(hwnd, wmId)) {
            return 0;
        }
        if (wmId == ID_BTN_REFRESH) {
            ExecuteAppRefresh(hwnd);
            return 0;
        }

        if (wmId >= ID_HARD_BASE && wmId < ID_HARD_BASE + (int)(g_controls.size() * 10)) {
            if (g_isExecuting) return 0;
            size_t rowIdx = (wmId - ID_HARD_BASE) / 10;
            if (rowIdx < g_controls.size()) {
                auto& ctrl = g_controls[rowIdx];
                bool isSecured = (ctrl.state == 2);
                std::string action = ctrl.actionLabel;

                if (isSecured && action != "Inspect" && action != "Open" && action != "Install") {
                    if (!ShowDarkPasswordDialog(hwnd, "Enter administrator password to continue:")) {
                        return 0;
                    }
                }

                bool targetState = !isSecured;

                if (ctrl.enforceFunc) {
                    ctrl.enforceFunc(targetState);
                }
            }
            return 0;
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
            return 0;
        }

        if (wmId == ID_BTN_SECURE_ALL) {
            HandleSecureAllAction(hwnd, g_controls, g_isExecuting);
            return 0;
        }
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        if (!pdis) return TRUE;

        // Direct routing based on Control ID
        if (pdis->CtlID == ID_BTN_REFRESH) {
            DrawRefreshButton(pdis);
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

            bool isSpinning = GetPropA(pdis->hwndItem, "IsSpinning") != NULL;
            bool isDisabled = (pdis->itemState & ODS_DISABLED) != 0; // Check if disabled state flag is active

            wchar_t statusIcon = (g_controls[rowIdx].state == 2) ? L'\xE73E' : L'\xEdb1';
            COLORREF statusIconColor = (g_controls[rowIdx].state == 2) ? RGB(59, 130, 246) : RGB(239, 68, 68);

            if (isDisabled) {
                statusIconColor = RGB(100, 116, 139); // Muted grey icon
            }

            if (isSpinning) {
                static const wchar_t spinnerFrames[] = { L'\xE712', L'\xE713', L'\xE714', L'\xE715', L'\xE716', L'\xE717', L'\xE718', L'\xE719' };
                INT_PTR frameIdx = (INT_PTR)GetPropA(pdis->hwndItem, "SpinnerFrameIndex");
                statusIcon = spinnerFrames[frameIdx % 8];
                statusIconColor = RGB(96, 165, 250);
            }

            char btnText[32] = { 0 };
            GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));
            bool hasButtonText = (btnText[0] != '\0' && strcmp(btnText, " ") != 0);

            bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;
            bool isHovered = GetPropA(pdis->hwndItem, "Hovered") != NULL;

            // Apply greyed out dark styling if disabled
            COLORREF bgCol;
            COLORREF borderCol;
            COLORREF textCol;

            if (isDisabled) {
                bgCol = RGB(15, 23, 36);        // Dark greyed background
                borderCol = RGB(30, 41, 59);    // Muted border
                textCol = RGB(100, 116, 139);   // Dimmed grey text
            }
            else {
                bgCol = isPressed ? RGB(16, 22, 34) : (isHovered ? RGB(32, 44, 66) : RGB(23, 31, 48));
                borderCol = isHovered ? RGB(71, 85, 105) : RGB(45, 55, 75);
                textCol = RGB(241, 245, 249);
            }

            HBRUSH hBrush = CreateSolidBrush(bgCol);
            FillRect(hdc, &pdis->rcItem, hBrush);
            DeleteObject(hBrush);

            HPEN hPen = CreatePen(PS_SOLID, 1, borderCol);
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 8, 8);

            if (isSpinning) {
                SelectObject(hdc, hOldPen);
                SelectObject(hdc, hOldBrush);
                DeleteObject(hPen);

                SetBkMode(hdc, TRANSPARENT);

                INT_PTR frameIdx = (INT_PTR)GetPropA(pdis->hwndItem, "SpinnerFrameIndex");

                int cx = (pdis->rcItem.left + pdis->rcItem.right) / 2;
                int cy = (pdis->rcItem.top + pdis->rcItem.bottom) / 2;

                int barWidth = 4;
                int barSpacing = 3;
                int maxBarHeight = 14;
                int totalWidth = (3 * barWidth) + (2 * barSpacing);
                int startX = cx - (totalWidth / 2);

                static const float heightRatios[8][3] = {
                    { 0.4f, 0.7f, 1.0f },
                    { 0.2f, 0.5f, 0.8f },
                    { 0.5f, 0.3f, 0.5f },
                    { 0.8f, 0.4f, 0.3f },
                    { 1.0f, 0.7f, 0.4f },
                    { 0.8f, 0.9f, 0.6f },
                    { 0.5f, 1.0f, 0.8f },
                    { 0.3f, 0.8f, 0.9f }
                };

                int currentFrame = (int)(frameIdx % 8);

                for (int i = 0; i < 3; i++) {
                    float ratio = heightRatios[currentFrame][i];
                    int currentHeight = static_cast<int>(maxBarHeight * ratio);

                    int bx = startX + i * (barWidth + barSpacing);
                    int by = cy - (currentHeight / 2);

                    RECT rcBar = { bx, by, bx + barWidth, by + currentHeight };

                    HBRUSH hBarBrush = CreateSolidBrush(RGB(56, 189, 248));
                    FillRect(hdc, &rcBar, hBarBrush);
                    DeleteObject(hBarBrush);
                }

                return TRUE;
            }

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

            int dividerX = pdis->rcItem.left + 24;
            MoveToEx(hdc, dividerX, pdis->rcItem.top + 2, NULL);
            LineTo(hdc, dividerX, pdis->rcItem.bottom - 2);

            SelectObject(hdc, hOldPen);
            SelectObject(hdc, hOldBrush);
            DeleteObject(hPen);

            SetBkMode(hdc, TRANSPARENT);

            SetTextColor(hdc, statusIconColor);
            HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontIcon);
            RECT rcBadgeIcon = { pdis->rcItem.left + 2, pdis->rcItem.top, dividerX, pdis->rcItem.bottom };
            DrawTextW(hdc, &statusIcon, 1, &rcBadgeIcon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

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