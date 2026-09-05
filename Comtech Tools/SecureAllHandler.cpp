#include "SecureAllHandler.h"
#include "CSCsecure.h"
#include <windows.h>
#include <vector>
#include <string>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

#define ID_BTN_CONFIRM   1001
#define ID_BTN_CANCEL    1002
#define ID_CHK_ITEM_BASE 2000

static ConfirmDialogData* g_pDialogData = nullptr;

static LRESULT CALLBACK ConfirmDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {

    case WM_CREATE: {
        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

        CREATESTRUCT* pCS = (CREATESTRUCT*)lParam;
        g_pDialogData = (ConfirmDialogData*)pCS->lpCreateParams;

        int startY = 40;
        int rowHeight = 24;

        // Create Checkboxes
        for (size_t i = 0; i < g_pDialogData->items.size(); i++) {
            HWND hChk = CreateWindowA("BUTTON", "",
                WS_CHILD | WS_VISIBLE | BS_CHECKBOX,
                24, startY + (static_cast<int>(i) * rowHeight) + 2, 16, 16,
                hwnd, (HMENU)(UINT_PTR)(ID_CHK_ITEM_BASE + i), NULL, NULL);

            bool isChecked = g_pDialogData->selectedItems[i];
            SendMessage(hChk, BM_SETCHECK, isChecked ? BST_CHECKED : BST_UNCHECKED, 0);
        }

        // Fixed layout placement based on parent width (360px window = ~344px client area)
        int clientWidth = 344;
        int contentBottomY = startY + (static_cast<int>(g_pDialogData->items.size()) * rowHeight);

        int btnWidth = 80;
        int btnHeight = 28;
        int buttonY = contentBottomY + 16;

        int cancelX = clientWidth - 16 - btnWidth;
        int confirmX = cancelX - 8 - btnWidth;

        CreateWindowA("BUTTON", "Confirm",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            confirmX, buttonY, btnWidth, btnHeight, hwnd, (HMENU)ID_BTN_CONFIRM, NULL, NULL);

        CreateWindowA("BUTTON", "Cancel",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            cancelX, buttonY, btnWidth, btnHeight, hwnd, (HMENU)ID_BTN_CANCEL, NULL, NULL);

        break;
    }

    case WM_COMMAND: {
        int wmId = LOWORD(wParam);

        if (wmId >= ID_CHK_ITEM_BASE && wmId < ID_CHK_ITEM_BASE + (int)g_pDialogData->items.size()) {
            size_t idx = wmId - ID_CHK_ITEM_BASE;
            HWND hChk = (HWND)lParam;
            bool currentlyChecked = (SendMessage(hChk, BM_GETCHECK, 0, 0) == BST_CHECKED);

            SendMessage(hChk, BM_SETCHECK, currentlyChecked ? BST_UNCHECKED : BST_CHECKED, 0);
            g_pDialogData->selectedItems[idx] = !currentlyChecked;

            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        if (wmId == ID_BTN_CONFIRM) {
            if (g_pDialogData) g_pDialogData->confirmed = true;
            DestroyWindow(hwnd);
            return 0;
        }

        if (wmId == ID_BTN_CANCEL) {
            if (g_pDialogData) g_pDialogData->confirmed = false;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rcClient;
        GetClientRect(hwnd, &rcClient);

        // Dark background
        HBRUSH hBg = CreateSolidBrush(RGB(15, 23, 42));
        FillRect(hdc, &rcClient, hBg);
        DeleteObject(hBg);

        SetBkMode(hdc, TRANSPARENT);

        // Crisp Segoe UI font using negative height matching system pixel density
        HFONT hFontBody = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
        HFONT hOldFont = (HFONT)SelectObject(hdc, hFontBody);

        // Header Text
        SetTextColor(hdc, RGB(203, 213, 225));
        RECT rcMsg = { 20, 14, rcClient.right - 20, 34 };
        DrawTextA(hdc, g_pDialogData->message.c_str(), -1, &rcMsg, DT_LEFT | DT_SINGLELINE);

        // Control item names
        int startY = 40;
        int rowHeight = 24;
        for (size_t i = 0; i < g_pDialogData->items.size(); i++) {
            RECT rcItem = { 48, startY + (static_cast<int>(i) * rowHeight), rcClient.right - 20, startY + (static_cast<int>(i) * rowHeight) + 20 };

            if (g_pDialogData->selectedItems[i]) {
                SetTextColor(hdc, RGB(241, 245, 249));
            }
            else {
                SetTextColor(hdc, RGB(100, 116, 139));
            }

            DrawTextA(hdc, g_pDialogData->items[i].c_str(), -1, &rcItem, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        }

        SelectObject(hdc, hOldFont);
        DeleteObject(hFontBody);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;

        bool isConfirm = (pdis->CtlID == ID_BTN_CONFIRM);

        COLORREF bgCol = isConfirm ? RGB(56, 157, 237) : RGB(30, 41, 59);
        COLORREF borderCol = isConfirm ? RGB(56, 157, 237) : RGB(51, 65, 85);

        HBRUSH hBrush = CreateSolidBrush(bgCol);
        FillRect(hdc, &pdis->rcItem, hBrush);
        DeleteObject(hBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, borderCol);
        HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
        SelectObject(hdc, hOldPen);
        SelectObject(hdc, hOldBrush);
        DeleteObject(hPen);

        char btnText[32] = { 0 };
        GetWindowTextA(pdis->hwndItem, btnText, sizeof(btnText));

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(241, 245, 249));

        HFONT hFontBtn = CreateFontA(-12, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
        HFONT hOldFont = (HFONT)SelectObject(hdc, hFontBtn);

        DrawTextA(hdc, btnText, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SelectObject(hdc, hOldFont);
        DeleteObject(hFontBtn);
        return TRUE;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        SetTextColor(hdcStatic, RGB(241, 245, 249));
        SetBkMode(hdcStatic, TRANSPARENT);

        static HBRUSH hBgBrush = CreateSolidBrush(RGB(15, 23, 42));
        return (LRESULT)hBgBrush;
    }
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

bool ShowCustomConfirmDialog(HWND hParent, ConfirmDialogData* pData) {
    WNDCLASSEXA wc = { sizeof(WNDCLASSEXA) };
    wc.lpfnWndProc = ConfirmDialogProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "CustomConfirmDialogClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassExA(&wc);

    int dialogWidth = 360;
    int itemRows = pData ? static_cast<int>(pData->items.size()) : 0;
    // Increased base height so bottom buttons fit completely inside client area
    int dialogHeight = 135 + (itemRows * 24);
    int posX = CW_USEDEFAULT;
    int posY = CW_USEDEFAULT;

    if (hParent && IsWindow(hParent)) {
        RECT rcParent;
        GetWindowRect(hParent, &rcParent);
        int parentWidth = rcParent.right - rcParent.left;
        int parentHeight = rcParent.bottom - rcParent.top;

        posX = rcParent.left + (parentWidth - dialogWidth) / 2;
        posY = rcParent.top + (parentHeight - dialogHeight) / 2;
    }

    HWND hDlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME,
        "CustomConfirmDialogClass",
        "Secure Controls",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        posX, posY, dialogWidth, dialogHeight,
        hParent, NULL, GetModuleHandle(NULL), pData
    );

    if (!hDlg) return false;

    EnableWindow(hParent, FALSE);
    MSG msg;
    while (IsWindow(hDlg) && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);

    return pData->confirmed;
}

void HandleSecureAllAction(HWND hwnd, std::vector<SecurityControl>& controls, bool& isExecuting) {
    if (isExecuting) return;

    ConfirmDialogData dlgData;
    dlgData.message = "Select controls to enforce:";

    std::vector<SecurityControl*> candidateControls;

    for (auto& ctrl : controls) {
        if (ctrl.state != 2) {
            dlgData.items.push_back(ctrl.name);
            dlgData.selectedItems.push_back(ctrl.isChecked);
            candidateControls.push_back(&ctrl);
        }
    }

    if (candidateControls.empty()) {
        MessageBoxA(hwnd, "All system controls are already secured.", "Notice", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (!ShowCustomConfirmDialog(hwnd, &dlgData) || !dlgData.confirmed) {
        return;
    }

    for (size_t i = 0; i < candidateControls.size(); i++) {
        if (i < dlgData.selectedItems.size() && dlgData.selectedItems[i]) {
            if (candidateControls[i]->enforceFunc) {
                candidateControls[i]->enforceFunc(true);
            }
        }
    }
}