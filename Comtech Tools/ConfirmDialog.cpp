#include "ConfirmDialog.h"
#include "Theme.h" // Ensure this has g_hBrushBg, COLOR_TEXT_WHITE, etc.
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

// Local variables only needed by this dialog
static bool g_confirmResult = false;
static std::string g_confirmMsg = "";

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

        HBRUSH hBtnBrush = CreateSolidBrush(isConfirm ? COLOR_ACCENT_TEAL : COLOR_PANEL);
        FillRect(hdc, &pdis->rcItem, hBtnBrush);
        DeleteObject(hBtnBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, isConfirm ? COLOR_ACCENT_TEAL : COLOR_BORDER);
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

// --- Dark Message Box (OK Only) ---
static std::string g_messageMsg = "";

LRESULT CALLBACK MessageWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // Centered OK button
        CreateWindowA("BUTTON", "OK", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 97, 90, 90, 30, hwnd, (HMENU)1, NULL, NULL);
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
        DrawTextA(hdc, g_messageMsg.c_str(), -1, &textRc, DT_CENTER | DT_WORDBREAK);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;

        HBRUSH hBtnBrush = CreateSolidBrush(COLOR_ACCENT_TEAL);
        FillRect(hdc, &pdis->rcItem, hBtnBrush);
        DeleteObject(hBtnBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, COLOR_ACCENT_TEAL);
        SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontBold);
        DrawTextA(hdc, "OK", -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) { PostMessage(hwnd, WM_CLOSE, 0, 0); }
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

void ShowDarkMessageDialog(HWND hParent, const char* msg) {
    g_messageMsg = msg;

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = MessageWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "DarkMessageDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClass(&wc);

    HWND hMsgWnd = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        "DarkMessageDialog", "Information",
        WS_POPUP | WS_BORDER | WS_CAPTION,
        0, 0, 285, 170, hParent, NULL, GetModuleHandle(NULL), NULL);

    RECT rcParent; GetWindowRect(hParent, &rcParent);
    SetWindowPos(hMsgWnd, NULL,
        rcParent.left + (rcParent.right - rcParent.left) / 2 - 142,
        rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 85,
        285, 170, SWP_NOZORDER);

    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hMsgWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    EnableWindow(hParent, FALSE);
    ShowWindow(hMsgWnd, SW_SHOW);

    MSG wmsg;
    while (IsWindow(hMsgWnd) && GetMessage(&wmsg, NULL, 0, 0)) {
        TranslateMessage(&wmsg);
        DispatchMessage(&wmsg);
    }
}