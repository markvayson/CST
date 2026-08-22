#include "Refresh.h"
#include "Theme.h"
#include <commctrl.h>
#include <thread>
#include <chrono>

HWND g_hBtnRefresh = NULL;

extern LRESULT CALLBACK HoverButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
extern HFONT g_hFontIcon;
extern float g_animatedSecureCount;

// Declared in CSCsecure.cpp
extern void PerformAuditAndHighlight();

void CreateRefreshButton(HWND hParentWnd) {
    g_hBtnRefresh = CreateWindowA("BUTTON", "",
        WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        440, 20, 24, 24,
        hParentWnd, (HMENU)ID_BTN_REFRESH, NULL, NULL);

    if (g_hBtnRefresh) {
        SetWindowSubclass(g_hBtnRefresh, HoverButtonProc, 0, 0);
    }
}

bool DrawRefreshButton(LPDRAWITEMSTRUCT pdis) {
    if (!pdis || pdis->CtlID != ID_BTN_REFRESH) return false;

    HDC hdcMem = CreateCompatibleDC(pdis->hDC);
    int width = pdis->rcItem.right - pdis->rcItem.left;
    int height = pdis->rcItem.bottom - pdis->rcItem.top;
    HBITMAP hBitmap = CreateCompatibleBitmap(pdis->hDC, width, height);
    HBITMAP hOldBmp = (HBITMAP)SelectObject(hdcMem, hBitmap);

    bool isHovered = GetPropA(pdis->hwndItem, "Hovered") != NULL;
    bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;
    bool isSpinning = GetPropA(pdis->hwndItem, "IsRefreshing") != NULL;

    COLORREF bgCol = isPressed ? RGB(30, 58, 138) : (isHovered ? RGB(30, 41, 59) : RGB(15, 23, 42));
    RECT rcLocal = { 0, 0, width, height };

    // 1. Render Flat Background (No Border)
    HBRUSH hBg = CreateSolidBrush(bgCol);
    FillRect(hdcMem, &rcLocal, hBg);
    DeleteObject(hBg);

    // 2. Render Icon / Spinning Animation
    SetBkMode(hdcMem, TRANSPARENT);
    HFONT hOldFont = (HFONT)SelectObject(hdcMem, g_hFontIcon);

    if (isSpinning) {
        static const wchar_t spinnerFrames[] = { L'\xE712', L'\xE713', L'\xE714', L'\xE715', L'\xE716', L'\xE717', L'\xE718', L'\xE719' };
        INT_PTR frameIdx = (INT_PTR)GetPropA(pdis->hwndItem, "RefreshFrame");

        SetTextColor(hdcMem, RGB(96, 165, 250));
        DrawTextW(hdcMem, &spinnerFrames[frameIdx % 8], 1, &rcLocal, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
    else {
        SetTextColor(hdcMem, isHovered ? RGB(96, 165, 250) : RGB(148, 163, 184));
        wchar_t refreshGlyph = L'\xE72C';
        DrawTextW(hdcMem, &refreshGlyph, 1, &rcLocal, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }

    SelectObject(hdcMem, hOldFont);

    // Blit double-buffered content to window
    BitBlt(pdis->hDC, 0, 0, width, height, hdcMem, 0, 0, SRCCOPY);

    SelectObject(hdcMem, hOldBmp);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);

    return true;
}

void ExecuteAppRefresh(HWND hCurrentWnd) {
    // Prevent double execution if already refreshing
    if (!g_hBtnRefresh || GetPropA(g_hBtnRefresh, "IsRefreshing")) return;

    EnableWindow(g_hBtnRefresh, FALSE);
    SetPropA(g_hBtnRefresh, "IsRefreshing", (HANDLE)1);

    std::thread([hCurrentWnd]() {
        bool isDone = false;
        int frameIdx = 0;

        g_animatedSecureCount = 0.0f;

        // Immediately invalidate header/progress region to show 0%
        RECT rcProgressRegion = { 150, 12, 470, 48 };
        InvalidateRect(hCurrentWnd, &rcProgressRegion, FALSE);

        // Background Audit Worker Thread
        std::thread auditThread([&isDone]() {
            PerformAuditAndHighlight(); // Perform work[cite: 1]
            isDone = true;
            });

        // Animate button spinner on UI thread safely
        while (!isDone) {
            SetPropA(g_hBtnRefresh, "RefreshFrame", (HANDLE)(INT_PTR)frameIdx); //[cite: 1]

            // Redraw ONLY the refresh button area without erasing parent background[cite: 1]
            RedrawWindow(g_hBtnRefresh, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);

            frameIdx = (frameIdx + 1) % 8; //[cite: 1]
            std::this_thread::sleep_for(std::chrono::milliseconds(60)); //[cite: 1]
        }

        if (auditThread.joinable()) {
            auditThread.join(); //[cite: 1]
        }

        // Cleanup button properties
        RemovePropA(g_hBtnRefresh, "IsRefreshing"); //[cite: 1]
        RemovePropA(g_hBtnRefresh, "RefreshFrame"); //[cite: 1]

        EnableWindow(g_hBtnRefresh, TRUE); //[cite: 1]

        // Smooth single-frame parent repaint once complete[cite: 1]
        RedrawWindow(hCurrentWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }).detach(); //[cite: 1]
}