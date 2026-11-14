#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

#include "Sidebar.h"
#include "Credentials.h"
#include <thread>
#include "Resource.h"
#include "Theme.h"
#include "Inventory.h"
#include <commctrl.h>
#include <shellapi.h>
#include "ConfirmDialog.h"
#include <string>

// Control & Menu IDs
#define ID_BTN_SECURE_ALL  1003
#define IDM_INVENTORY      3005
#define IDM_WINUPDATE      3004
#define ID_BTN_RESTART     3006
#define ID_SIDEBAR_SYSINFO 3010
#define ID_SIDEBAR_IPINFO  3011
#define IDM_WIN_FEATURES   3012

// (Credentials button opens available drives in Explorer tabs)

static HWND g_hBtnInventory = NULL;
static HWND g_hBtnCredentials = NULL;
static HWND g_hBtnUpdate = NULL;
static HWND g_hBtnWinFeatures = NULL;
static HWND g_hBtnRestart = NULL;

// Helper function to get local IP address
std::string GetLocalIPAddress() {
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

    if (pAddresses == NULL) return "N/A";

    DWORD dwRetVal = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        dwRetVal = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    }

    std::string ipStr = "N/A";

    if (dwRetVal == NO_ERROR && pAddresses != NULL) {
        for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next) {
            // Skip loopback and down interfaces
            if (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK || pCurrAddresses->OperStatus != IfOperStatusUp)
                continue;

            // FIXED: Using PIP_ADAPTER_UNICAST_ADDRESS instead of PIP_ADAPTER_UNICODE_ADDRESS
            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr != NULL && pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    char ipBuffer[INET_ADDRSTRLEN] = { 0 };
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipBuffer, sizeof(ipBuffer));
                    ipStr = ipBuffer;
                    break;
                }
            }
            if (ipStr != "N/A") break;
        }
    }

    if (pAddresses) free(pAddresses);
    return ipStr;
}


bool HandleSidebarCommand(HWND hwnd, int wmId) {
    switch (wmId) {
    case IDM_INVENTORY:
        // Triggers the dual-input dialog and launches InventoryThreadProc
        RunInventoryCollection(hwnd);
        return true;

    case ID_SIDEBAR_IPINFO:
        ShellExecuteA(hwnd, "open", "control.exe", "ncpa.cpl", NULL, SW_SHOW);
        return true;

    case IDM_SEARCHPASS:
        ExecuteCredentialsSearch();
        return true;

    case ID_BTN_SECURE_ALL:
        return false;

    case IDM_WIN_FEATURES:
        ShellExecuteA(hwnd, "open", "optionalfeatures.exe", NULL, NULL, SW_SHOW);
        return true;

    case ID_BTN_RESTART:
        if (ShowDarkRestartDialog(hwnd)) {
            ShellExecuteA(NULL, "open", "shutdown.exe", "/r /t 0", NULL, SW_HIDE);
        }
        return true;

    case ID_SIDEBAR_SYSINFO:
        ShellExecuteA(hwnd, "open", "ms-settings:about", NULL, NULL, SW_SHOW);
        return true;

    case IDM_WINUPDATE:
        // FIXED: Launch Windows Update settings natively
        ShellExecuteA(hwnd, "open", "ms-settings:windowsupdate", NULL, NULL, SW_SHOW);
        return true;
    }

    return false;
}

LRESULT CALLBACK SidebarBtnSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    static bool bTracking = (dwRefData != 0);
    switch (uMsg) {
    case WM_MOUSEMOVE:
        if (!IsWindowEnabled(hWnd)) break;
        if (!bTracking) {
            TRACKMOUSEEVENT tme = { sizeof(TRACKMOUSEEVENT), TME_LEAVE, hWnd, 0 };
            TrackMouseEvent(&tme);
            bTracking = true;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        bTracking = false;
        InvalidateRect(hWnd, NULL, FALSE);
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, SidebarBtnSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void CreateSidebarControls(HWND hwndParent) {
    int sidebarX = 500;
    int btnWidth = 160;
    int btnHeight = 42;
    int sidebarStartY = 20;
    int spacing = 12;

    g_hBtnSecureAll = CreateWindowA("BUTTON", "Secure Controls", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)ID_BTN_SECURE_ALL, NULL, NULL);
    SetWindowSubclass(g_hBtnSecureAll, SidebarBtnSubclassProc, 1, 0);

    g_hBtnInventory = CreateWindowA("BUTTON", "Collect Inventories", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing), btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_INVENTORY, NULL, NULL);
    SetWindowSubclass(g_hBtnInventory, SidebarBtnSubclassProc, 1, 0);

    g_hBtnCredentials = CreateWindowA("BUTTON", "Credentials", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing) * 2, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_SEARCHPASS, NULL, NULL);
    SetWindowSubclass(g_hBtnCredentials, SidebarBtnSubclassProc, 3, 0); // Use unique subclass ID for credentials button

    g_hBtnUpdate = CreateWindowA("BUTTON", "Windows Update", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing) * 3, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_WINUPDATE, NULL, NULL);
    SetWindowSubclass(g_hBtnUpdate, SidebarBtnSubclassProc, 1, 0);

    g_hBtnWinFeatures = CreateWindowA("BUTTON", "Windows Features", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing) * 4, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_WIN_FEATURES, NULL, NULL);
    SetWindowSubclass(g_hBtnWinFeatures, SidebarBtnSubclassProc, 1, 0);

    g_hBtnRestart = CreateWindowA("BUTTON", "Restart Device", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, 0, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)ID_BTN_RESTART, NULL, NULL);
    SetWindowSubclass(g_hBtnRestart, SidebarBtnSubclassProc, 1, 0);

    LayoutSidebarControls(hwndParent);
}

void LayoutSidebarControls(HWND hwndParent) {
    int sidebarX = 500;
    int btnWidth = 160;
    int btnHeight = 42;
    int sidebarStartY = 20;
    int spacing = 12;

    RECT rcClient;
    GetClientRect(hwndParent, &rcClient);

    if (g_hBtnSecureAll) MoveWindow(g_hBtnSecureAll, sidebarX, sidebarStartY, btnWidth, btnHeight, TRUE);
    if (g_hBtnInventory) MoveWindow(g_hBtnInventory, sidebarX, sidebarStartY + (btnHeight + spacing), btnWidth, btnHeight, TRUE);
    if (g_hBtnCredentials) MoveWindow(g_hBtnCredentials, sidebarX, sidebarStartY + (btnHeight + spacing) * 2, btnWidth, btnHeight, TRUE);
    if (g_hBtnUpdate) MoveWindow(g_hBtnUpdate, sidebarX, sidebarStartY + (btnHeight + spacing) * 3, btnWidth, btnHeight, TRUE);
    if (g_hBtnWinFeatures) MoveWindow(g_hBtnWinFeatures, sidebarX, sidebarStartY + (btnHeight + spacing) * 4, btnWidth, btnHeight, TRUE);

    int bottomMargin = 20;
    int restartY = rcClient.bottom - btnHeight - bottomMargin;
    if (g_hBtnRestart) MoveWindow(g_hBtnRestart, sidebarX, restartY, btnWidth, btnHeight, TRUE);
}

bool IsSidebarButton(UINT ctlId) {
    return (ctlId == ID_BTN_SECURE_ALL ||
        ctlId == IDM_INVENTORY ||
        ctlId == IDM_SEARCHPASS ||
        ctlId == IDM_WINUPDATE ||
        ctlId == IDM_WIN_FEATURES ||
        ctlId == ID_BTN_RESTART);
}


void DrawSidebarButton(LPDRAWITEMSTRUCT pdis) {
    HDC hdc = pdis->hDC;
    UINT ctlId = pdis->CtlID;

    SetBkMode(hdc, TRANSPARENT);
    bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;
    bool isDisabled = (pdis->itemState & ODS_DISABLED) != 0;

    POINT pt;
    GetCursorPos(&pt);
    ScreenToClient(pdis->hwndItem, &pt);
    RECT rcClient;
    GetClientRect(pdis->hwndItem, &rcClient);
    bool isHovered = !isDisabled && PtInRect(&rcClient, pt);

    // (System Information and IP boxes removed from sidebar; info now shown in left panel header)

    // --- Standard Buttons ---
    COLORREF bgCol = COLOR_PANEL;
    COLORREF borderColor = COLOR_BORDER;
    COLORREF textColor = COLOR_TEXT_WHITE;

    if (ctlId == ID_BTN_SECURE_ALL) {
        if (isDisabled) {
            bgCol = RGB(23, 32, 51);
            borderColor = RGB(30, 41, 59);
            textColor = RGB(100, 116, 139);
        }
        else if (isPressed) {
            bgCol = RGB(13, 45, 52);
            borderColor = RGB(20, 184, 166);
            textColor = RGB(45, 212, 191);
        }
        else if (isHovered) {
            bgCol = RGB(17, 58, 66);
            borderColor = RGB(45, 212, 191);
            textColor = RGB(45, 212, 191);
        }
        else {
            bgCol = COLOR_PANEL;
            borderColor = RGB(20, 184, 166);
            textColor = RGB(45, 212, 191);
        }
    }
    else {
        if (isDisabled) {
            bgCol = RGB(23, 32, 51);
            borderColor = RGB(30, 41, 59);
            textColor = RGB(148, 163, 184);
        }
        else if (isPressed) {
            bgCol = RGB(15, 23, 42);
            borderColor = RGB(71, 85, 105);
        }
        else if (isHovered) {
            bgCol = RGB(30, 41, 59);
            borderColor = RGB(71, 85, 105);
        }
    }

    // Fill Background
    HBRUSH hBrush = CreateSolidBrush(bgCol);
    FillRect(hdc, &pdis->rcItem, hBrush);
    DeleteObject(hBrush);

    // Draw Border
    HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
    SelectObject(hdc, hPen);
    SelectObject(hdc, GetStockObject(NULL_BRUSH));
    RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6);
    DeleteObject(hPen);

    // Icon Glyph
    wchar_t icon = L'\0';
    if (ctlId == ID_BTN_SECURE_ALL) icon = L'\xE8DA';
    else if (ctlId == IDM_INVENTORY) icon = L'\xE9F9';
    else if (ctlId == IDM_SEARCHPASS) icon = L'\xE192';
    else if (ctlId == IDM_WINUPDATE) icon = L'\xE895';
    else if (ctlId == IDM_WIN_FEATURES) icon = L'\xE71D';
    else if (ctlId == ID_SIDEBAR_IPINFO) icon = L'\xE839';
    else if (ctlId == ID_BTN_RESTART) icon = L'\xE7E8';

    SetTextColor(hdc, textColor);

    SelectObject(hdc, g_hFontIcon);
    RECT rcIcon = pdis->rcItem;
    rcIcon.left += 15;
    DrawTextW(hdc, &icon, 1, &rcIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // Button Text
    SelectObject(hdc, g_hFontBold);
    RECT rcText = pdis->rcItem;
    rcText.left += 40;
    char btnText[64] = { 0 };
    GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));
    DrawTextA(hdc, btnText, -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}