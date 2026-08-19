#include "ConfirmDialog.h"
#include "Theme.h" // Ensure this has g_hBrushBg, COLOR_TEXT_WHITE, etc.
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

// --- Dark Confirm Dialog ---
static bool g_confirmResult = false;
static std::string g_confirmMsg = "";
static int g_computedDialogHeight = 220;
// --- Dark Restart Dialog ---
static bool g_restartNowResult = false;

LRESULT CALLBACK RestartWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CreateWindowA("BUTTON", "Restart Now", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 25, 90, 110, 32, hwnd, (HMENU)1, NULL, NULL);
        CreateWindowA("BUTTON", "Restart Later", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 145, 90, 110, 32, hwnd, (HMENU)2, NULL, NULL);
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

        RECT textRc = { 15, 20, rc.right - 15, 75 };
        DrawTextA(hdc, "System hardening changes have been applied.\nWould you like to restart your device now?", -1, &textRc, DT_CENTER | DT_WORDBREAK);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;
        bool isNow = (pdis->CtlID == 1);

        HBRUSH hBtnBrush = CreateSolidBrush(isNow ? COLOR_ACCENT_TEAL : COLOR_PANEL);
        FillRect(hdc, &pdis->rcItem, hBtnBrush);
        DeleteObject(hBtnBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, isNow ? COLOR_ACCENT_TEAL : COLOR_BORDER);
        SelectObject(hdc, hPen);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontBold);
        DrawTextA(hdc, isNow ? "Restart Now" : "Restart Later", -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return TRUE;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) { g_restartNowResult = true; PostMessage(hwnd, WM_CLOSE, 0, 0); }
        if (LOWORD(wParam) == 2) { g_restartNowResult = false; PostMessage(hwnd, WM_CLOSE, 0, 0); }
        break;
    }
    case WM_CLOSE: {
        HWND hParent = GetParent(hwnd);
        if (hParent) {
            SendMessage(hParent, WM_SETREDRAW, FALSE, 0);
            EnableWindow(hParent, TRUE);
            SetForegroundWindow(hParent);
            SendMessage(hParent, WM_SETREDRAW, TRUE, 0);
            RedrawWindow(hParent, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
        DestroyWindow(hwnd);
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

bool ShowDarkRestartDialog(HWND hParent) {
    g_restartNowResult = false;

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = RestartWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "DarkRestartDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClass(&wc);

    HWND hRestart = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        "DarkRestartDialog", "Restart Required",
        WS_POPUP | WS_BORDER | WS_CAPTION,
        0, 0, 280, 170, hParent, NULL, GetModuleHandle(NULL), NULL);

    RECT rcParent; GetWindowRect(hParent, &rcParent);
    SetWindowPos(hRestart, NULL,
        rcParent.left + (rcParent.right - rcParent.left) / 2 - 140,
        rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 85,
        280, 170, SWP_NOZORDER);

    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hRestart, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    EnableWindow(hParent, FALSE);
    ShowWindow(hRestart, SW_SHOW);

    MSG wmsg;
    while (IsWindow(hRestart) && GetMessage(&wmsg, NULL, 0, 0)) {
        TranslateMessage(&wmsg);
        DispatchMessage(&wmsg);
    }
    return g_restartNowResult;
}



LRESULT CALLBACK ConfirmWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // Assign explicit Control IDs (101 & 102) so we can query them later
        CreateWindowA("BUTTON", "Confirm", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 100, 32, hwnd, (HMENU)101, NULL, NULL);
        CreateWindowA("BUTTON", "Cancel", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, 100, 32, hwnd, (HMENU)102, NULL, NULL);
        break;
    }
    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);
        int buttonWidth = 100;
        int buttonHeight = 32;
        int buttonY = height - buttonHeight - 15; // 15px bottom margin

        // Center the two buttons side-by-side inside the dialog
        int totalWidth = (buttonWidth * 2) + 15; // 15px gap between buttons
        int startX = (width - totalWidth) / 2;

        HWND hConfirmBtn = GetDlgItem(hwnd, 101);
        HWND hCancelBtn = GetDlgItem(hwnd, 102);

        if (hConfirmBtn) {
            MoveWindow(hConfirmBtn, startX, buttonY, buttonWidth, buttonHeight, TRUE);
        }
        if (hCancelBtn) {
            MoveWindow(hCancelBtn, startX + buttonWidth + 15, buttonY, buttonWidth, buttonHeight, TRUE);
        }
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

        // Restrict text rendering area so text never overlaps the buttons
        RECT textRc = { 20, 20, rc.right - 20, rc.bottom - 60 };
        DrawTextA(hdc, g_confirmMsg.c_str(), -1, &textRc, DT_LEFT | DT_WORDBREAK);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        HDC hdc = pdis->hDC;
        bool isConfirm = (pdis->CtlID == 101);

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
        if (LOWORD(wParam) == 101) { g_confirmResult = true; PostMessage(hwnd, WM_CLOSE, 0, 0); }
        if (LOWORD(wParam) == 102) { g_confirmResult = false; PostMessage(hwnd, WM_CLOSE, 0, 0); }
        break;
    }
    case WM_CLOSE: {
        HWND hParent = GetParent(hwnd);
        if (hParent) {
            SendMessage(hParent, WM_SETREDRAW, FALSE, 0);
            EnableWindow(hParent, TRUE);
            SetForegroundWindow(hParent);
            SendMessage(hParent, WM_SETREDRAW, TRUE, 0);
            RedrawWindow(hParent, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
        DestroyWindow(hwnd);
        break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}


bool ShowDarkConfirmDialog(HWND hParent, const char* title, const char* msg) {
    g_confirmMsg = msg;
    g_confirmResult = false;

    // Calculate required text height
    HDC hdcScreen = GetDC(NULL);
    HFONT hOldFont = (HFONT)SelectObject(hdcScreen, g_hFontSub);

    RECT calcRc = { 0, 0, 300, 0 }; // 340 dialog width - 40 total padding
    DrawTextA(hdcScreen, msg, -1, &calcRc, DT_CALCRECT | DT_WORDBREAK);

    SelectObject(hdcScreen, hOldFont);
    ReleaseDC(NULL, hdcScreen);

    int textHeight = calcRc.bottom - calcRc.top;

    // 20px top padding + text + 20px middle gap + 32px button + 15px bottom padding
    int clientHeight = 20 + textHeight + 20 + 32 + 15;

    RECT windowRc = { 0, 0, 340, clientHeight };
    DWORD dwStyle = WS_POPUP | WS_BORDER | WS_CAPTION;
    AdjustWindowRectEx(&windowRc, dwStyle, FALSE, WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME);

    int totalWindowWidth = windowRc.right - windowRc.left;
    int totalWindowHeight = windowRc.bottom - windowRc.top;

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = ConfirmWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "DarkConfirmDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClass(&wc);

    HWND hConfirm = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        "DarkConfirmDialog", title,
        dwStyle,
        0, 0, totalWindowWidth, totalWindowHeight, hParent, NULL, GetModuleHandle(NULL), NULL);

    RECT rcParent; GetWindowRect(hParent, &rcParent);
    SetWindowPos(hConfirm, NULL,
        rcParent.left + (rcParent.right - rcParent.left) / 2 - (totalWindowWidth / 2),
        rcParent.top + (rcParent.bottom - rcParent.top) / 2 - (totalWindowHeight / 2),
        totalWindowWidth, totalWindowHeight, SWP_NOZORDER);

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
        // Position OK button at bottom center
        CreateWindowA("BUTTON", "OK", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 125, 120, 90, 30, hwnd, (HMENU)1, NULL, NULL); 
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

            // Increased height rect to fit 3-4 lines of text
            RECT textRc = { 15, 15, rc.right - 15, 110 }; 
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
        HWND hParent = GetParent(hwnd); 
            if (hParent) {
                SendMessage(hParent, WM_SETREDRAW, FALSE, 0); 
                    EnableWindow(hParent, TRUE); 
                    SetForegroundWindow(hParent); 
                    SendMessage(hParent, WM_SETREDRAW, TRUE, 0); 
                    RedrawWindow(hParent, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN); 
            }
        DestroyWindow(hwnd); 
            break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam); 
}

void ShowDarkMessageDialog(HWND hParent, const char* title, const char* msg) {
    g_messageMsg = msg; 

        WNDCLASS wc = { 0 }; 
        wc.lpfnWndProc = MessageWndProc; 
        wc.hInstance = GetModuleHandle(NULL); 
        wc.lpszClassName = "DarkMessageDialog"; 
        wc.hbrBackground = g_hBrushBg; 
        RegisterClass(&wc); 

        // Expanded window dimensions: 340x200
        HWND hMsgWnd = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME, 
            "DarkMessageDialog", title, 
            WS_POPUP | WS_BORDER | WS_CAPTION, 
            0, 0, 340, 200, hParent, NULL, GetModuleHandle(NULL), NULL); 

        RECT rcParent; GetWindowRect(hParent, &rcParent); 
        SetWindowPos(hMsgWnd, NULL, 
            rcParent.left + (rcParent.right - rcParent.left) / 2 - 170, 
            rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 100, 
            340, 200, SWP_NOZORDER); 

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

void ShowDarkMessageDialog(HWND hParent, const char* msg) {
    ShowDarkMessageDialog(hParent, "CSCsecure", msg); 
}


// --- Dark Password Dialog ---
static bool g_passResult = false; 
static std::string g_passMsg = ""; 
static HWND g_hPassEdit = NULL; 

// Subclass procedure for the Password Edit Box to handle the Enter key
LRESULT CALLBACK EditSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    if (uMsg == WM_KEYDOWN && wParam == VK_RETURN) {
        // Trigger the Confirm button action (ID = 1) on parent window
        HWND hParent = GetParent(hWnd);
        if (hParent) {
            SendMessage(hParent, WM_COMMAND, MAKEWPARAM(1, BN_CLICKED), (LPARAM)GetDlgItem(hParent, 1));
        }
        return 0; // Prevent default chime sound
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK PasswordWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // Create the password input field
        g_hPassEdit = CreateWindowExA(0, "EDIT", "", 
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 
            42, 60, 200, 22, hwnd, (HMENU)3, NULL, NULL); 

            // Apply font
            SendMessageA(g_hPassEdit, WM_SETFONT, (WPARAM)g_hFontSub, TRUE); 

            // Subclass edit control to intercept the 'Enter' key
            SetWindowSubclass(g_hPassEdit, EditSubclassProc, 0, 0);

        CreateWindowA("BUTTON", "Confirm", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 35, 100, 90, 30, hwnd, (HMENU)1, NULL, NULL); 
            CreateWindowA("BUTTON", "Cancel", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 145, 100, 90, 30, hwnd, (HMENU)2, NULL, NULL); 
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

            RECT textRc = { 15, 20, rc.right - 15, 55 }; 
            DrawTextA(hdc, g_passMsg.c_str(), -1, &textRc, DT_CENTER | DT_WORDBREAK); 

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
        if (LOWORD(wParam) == 1) {
            
            // Read password from edit control
            char passBuffer[256] = { 0 }; 
                GetWindowTextA(g_hPassEdit, passBuffer, sizeof(passBuffer)); 

                if (strcmp(passBuffer, "Kdc5ea4k$") == 0) {
                    
                    g_passResult = true; 
                        PostMessage(hwnd, WM_CLOSE, 0, 0); 
                }
                else {
                    MessageBoxA(hwnd, "Incorrect Password", "Error", MB_ICONERROR | MB_OK); 
                        // Focus back to edit box and select text for quick retry
                        SetFocus(g_hPassEdit);
                    SendMessage(g_hPassEdit, EM_SETSEL, 0, -1);
                }
        }
        if (LOWORD(wParam) == 2) {
            
            g_passResult = false; 
                PostMessage(hwnd, WM_CLOSE, 0, 0); 
        }
        break;
    }
    case WM_CLOSE: {
        // Remove subclass before destruction
        RemoveWindowSubclass(g_hPassEdit, EditSubclassProc, 0);

        HWND hParent = GetParent(hwnd); 
            if (hParent) {
                SendMessage(hParent, WM_SETREDRAW, FALSE, 0); 
                    EnableWindow(hParent, TRUE); 
                    SetForegroundWindow(hParent); 
                    SendMessage(hParent, WM_SETREDRAW, TRUE, 0); 
                    RedrawWindow(hParent, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN); 
            }
        DestroyWindow(hwnd); 
            break;
    }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam); 
}

bool ShowDarkPasswordDialog(HWND hParent, const char* msg) {
    g_passMsg = msg; 
        g_passResult = false; 

        WNDCLASS wc = { 0 }; 
        wc.lpfnWndProc = PasswordWndProc; 
        wc.hInstance = GetModuleHandle(NULL); 
        wc.lpszClassName = "DarkPasswordDialog"; 
        wc.hbrBackground = g_hBrushBg; 
        RegisterClass(&wc); 

        // Made the dialog slightly taller (190px) to accommodate the text box
        HWND hPassWnd = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME, 
            "DarkPasswordDialog", "Authentication Required", 
            WS_POPUP | WS_BORDER | WS_CAPTION, 
            0, 0, 285, 190, hParent, NULL, GetModuleHandle(NULL), NULL); 

        RECT rcParent; GetWindowRect(hParent, &rcParent); 
        SetWindowPos(hPassWnd, NULL, 
            rcParent.left + (rcParent.right - rcParent.left) / 2 - 142, 
            rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 95, 
            285, 190, SWP_NOZORDER); 

        BOOL useDarkMode = TRUE; 
        ::DwmSetWindowAttribute(hPassWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode)); 

        EnableWindow(hParent, FALSE); 
        ShowWindow(hPassWnd, SW_SHOW); 

        // Focus immediately on the input field when window appears
        SetFocus(g_hPassEdit);

    MSG wmsg;
    while (IsWindow(hPassWnd) && GetMessage(&wmsg, NULL, 0, 0)) {
        
        TranslateMessage(&wmsg); 
            DispatchMessage(&wmsg); 
    }
    return g_passResult; 
}