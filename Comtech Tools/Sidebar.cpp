#define WIN32_LEAN_AND_MEAN
#include "Sidebar.h"
#include "SearchPass.h"
#include <thread>
#include "Resource.h"
#include "Theme.h"
#include "Inventory.h"
#include <commctrl.h>
#include <shellapi.h>


// Control & Menu IDs
#define ID_BTN_SECURE_ALL 1003
#define IDM_INVENTORY     3005
#define IDM_SEARCHPASS    3003
#define IDM_WINUPDATE     3004
#define ID_BTN_RESTART    3006


HWND g_hBtnSearchPass = NULL;

bool HandleSidebarCommand(HWND hwnd, int wmId) {
    switch (wmId) {
    case IDM_INVENTORY:
        // Triggers the dual-input dialog and launches InventoryThreadProc
        RunInventoryCollection(hwnd);
        return true;


    case IDM_SEARCHPASS:
        if (IsWindow(g_hSearchResultsWnd)) {
            SetForegroundWindow(g_hSearchResultsWnd);
            return true;
        }
        if (g_hBtnSearchPass) {
            EnableWindow(g_hBtnSearchPass, FALSE);
            InvalidateRect(g_hBtnSearchPass, NULL, FALSE);
        }
        std::thread(ExecuteFastSearch).detach();
        return true;

    case ID_BTN_SECURE_ALL:

        return false;

    case ID_BTN_RESTART:
        // You will need to insert your specific Win32 restart routine here
        MessageBoxW(hwnd, L"Initiating System Restart...", L"CSCsecure", MB_OK | MB_ICONWARNING);
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
    int sidebarX = 610;
    int btnWidth = 165;
    int btnHeight = 48;
    int sidebarStartY = 20;
    int spacing = 12;

    HWND hBtnSecureAll = CreateWindowA("BUTTON", "Secure All", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)ID_BTN_SECURE_ALL, NULL, NULL);
    SetWindowSubclass(hBtnSecureAll, SidebarBtnSubclassProc, 1, 0);

    HWND hBtnInv = CreateWindowA("BUTTON", "Collect Inventories", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing), btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_INVENTORY, NULL, NULL);
    SetWindowSubclass(hBtnInv, SidebarBtnSubclassProc, 1, 0);

    g_hBtnSearchPass = CreateWindowA("BUTTON", "Search Pass", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing) * 2, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_SEARCHPASS, NULL, NULL);
    SetWindowSubclass(g_hBtnSearchPass, SidebarBtnSubclassProc, 1, 0);

    HWND hBtnUpdate = CreateWindowA("BUTTON", "Windows Update", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY + (btnHeight + spacing) * 3, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)IDM_WINUPDATE, NULL, NULL);
    SetWindowSubclass(hBtnUpdate, SidebarBtnSubclassProc, 1, 0);


    RECT rcClient;
    GetClientRect(hwndParent, &rcClient);

    int bottomMargin = 20;
    int restartY = rcClient.bottom - btnHeight - bottomMargin;
    int aboutY = restartY - btnHeight - spacing;

  
    HWND hBtnRestart = CreateWindowA("BUTTON", "Restart", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, restartY, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)ID_BTN_RESTART, NULL, NULL);
    SetWindowSubclass(hBtnRestart, SidebarBtnSubclassProc, 1, 0);


}

bool IsSidebarButton(UINT ctlId) {
    return (ctlId == ID_BTN_SECURE_ALL ||
        ctlId == IDM_INVENTORY ||
        ctlId == IDM_SEARCHPASS ||
        ctlId == IDM_WINUPDATE ||
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

    COLORREF bgCol = COLOR_PANEL;
    COLORREF borderColor = COLOR_BORDER;
    COLORREF textColor = COLOR_TEXT_WHITE;

    if (ctlId == ID_BTN_SECURE_ALL) {
        // --- Outlined Teal Accent CTA ---
        borderColor = RGB(20, 184, 166); // Teal border
        textColor = RGB(45, 212, 191);   // Bright teal text & icon

        if (isPressed) {
            bgCol = RGB(13, 45, 52);      // Dark teal pressed fill
        }
        else if (isHovered) {
            bgCol = RGB(17, 58, 66);      // Subtle dark teal hover tint
            borderColor = RGB(45, 212, 191);
        }
        else {
            bgCol = COLOR_PANEL;          // Clean dark background
        }
    }
    else {
        // --- Standard Sidebar Buttons ---
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
    else if (ctlId == ID_BTN_RESTART) icon = L'\xE14C';

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