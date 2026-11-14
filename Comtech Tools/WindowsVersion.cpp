#include "WindowsVersion.h"
#include "Theme.h"

#include <dwmapi.h>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

namespace {

struct Date {
    int year = 0;
    int month = 0;
    int day = 0;
};

struct EolRow {
    const char* os;
    const char* version;
    const char* homePro;
    Date homeProEol;
};

struct Layout {
    int margin = 20;
    int topInfoH = 22;
    int noteH = 18;
    int headerH = 28;
    int rowH = 28;
    int tableTop = 0;
    int tableBottom = 0;
    int buttonW = 90;
    int buttonH = 32;
    int buttonGap = 12;
    int dlgW = 560;
    int dlgH = 0;
    RECT rcButton = {};
    RECT rcNote = {};
    RECT rcCurrent = {};
};

std::string g_currentVersion;
std::vector<EolRow> g_rows;
Layout g_layout;

std::string ReadRegStringLocal(HKEY root, const char* subKey, const char* valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
        return "";
    }

    char buffer[256] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExA(hKey, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            result = buffer;
        }
    }
    RegCloseKey(hKey);
    return result;
}

std::string GetCurrentWindowsVersionText() {
    const char* key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::string product = ReadRegStringLocal(HKEY_LOCAL_MACHINE, key, "ProductName");
    std::string display = ReadRegStringLocal(HKEY_LOCAL_MACHINE, key, "DisplayVersion");
    std::string build = ReadRegStringLocal(HKEY_LOCAL_MACHINE, key, "CurrentBuild");
    std::string ubrStr;

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD ubr = 0;
        DWORD size = sizeof(ubr);
        if (RegQueryValueExA(hKey, "UBR", nullptr, nullptr, reinterpret_cast<LPBYTE>(&ubr), &size) == ERROR_SUCCESS) {
            ubrStr = "." + std::to_string(ubr);
        }
        RegCloseKey(hKey);
    }

    if (product.empty()) product = "Windows";
    if (!build.empty() && atoi(build.c_str()) >= 22000) {
        size_t pos = product.find("Windows 10");
        if (pos != std::string::npos) {
            product.replace(pos, 10, "Windows 11");
        }
    }

    std::string text = "Current version: " + product;
    if (!display.empty()) text += " " + display;
    if (!build.empty()) text += " (Build " + build + ubrStr + ")";
    return text;
}

int DateToInt(const Date& d) {
    return d.year * 10000 + d.month * 100 + d.day;
}

bool IsSupported(const EolRow& row) {
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    Date today{ static_cast<int>(st.wYear), static_cast<int>(st.wMonth), static_cast<int>(st.wDay) };
    return DateToInt(today) <= DateToInt(row.homeProEol);
}

void BuildRows() {
    g_rows = {
        { "Windows 10", "21H2", "Jun 13, 2023", {2023, 6, 13} },
        { "Windows 10", "22H2", "Oct 14, 2025", {2025, 10, 14} },
        { "Windows 11", "21H2", "Oct 10, 2023", {2023, 10, 10} },
        { "Windows 11", "22H2", "Oct 8, 2024",  {2024, 10, 8} },
        { "Windows 11", "23H2", "Nov 11, 2025", {2025, 11, 11} },
        { "Windows 11", "24H2", "Oct 13, 2026", {2026, 10, 13} },
        { "Windows 11", "25H2", "Oct 12, 2027", {2027, 10, 12} },
    };
}

void ComputeLayout() {
    BuildRows();
    g_currentVersion = GetCurrentWindowsVersionText();

    g_layout.tableTop = g_layout.margin + g_layout.topInfoH + 8;
    g_layout.tableBottom = g_layout.tableTop + g_layout.headerH + static_cast<int>(g_rows.size()) * g_layout.rowH;

    int noteTop = g_layout.tableBottom + 8;
    g_layout.rcNote = { g_layout.margin, noteTop, g_layout.dlgW - g_layout.margin, noteTop + g_layout.noteH * 2 };

    int buttonTop = g_layout.rcNote.bottom + g_layout.buttonGap;
    int buttonLeft = (g_layout.dlgW - g_layout.buttonW) / 2;
    g_layout.rcButton = { buttonLeft, buttonTop, buttonLeft + g_layout.buttonW, buttonTop + g_layout.buttonH };

    g_layout.dlgH = g_layout.rcButton.bottom + g_layout.margin;
    g_layout.rcCurrent = { g_layout.margin, g_layout.margin, g_layout.dlgW - g_layout.margin, g_layout.margin + g_layout.topInfoH };
}

void DrawTable(HDC hdc) {
    const int left = g_layout.margin;
    const int right = g_layout.dlgW - g_layout.margin;
    const int top = g_layout.tableTop;
    const int bottom = g_layout.tableBottom;

    const int col1 = left + 120; // OS
    const int col2 = col1 + 80;  // Version
    const int col3 = col2 + 150; // Status

    HBRUSH hHeaderBg = CreateSolidBrush(RGB(30, 41, 59));
    RECT rcHeader = { left, top, right, top + g_layout.headerH };
    FillRect(hdc, &rcHeader, hHeaderBg);
    DeleteObject(hHeaderBg);

    HPEN hPen = CreatePen(PS_SOLID, 1, COLOR_BORDER);
    HGDIOBJ oldPen = SelectObject(hdc, hPen);

    MoveToEx(hdc, left, top, nullptr); LineTo(hdc, right, top);
    MoveToEx(hdc, left, bottom, nullptr); LineTo(hdc, right, bottom);
    MoveToEx(hdc, left, top, nullptr); LineTo(hdc, left, bottom);
    MoveToEx(hdc, right, top, nullptr); LineTo(hdc, right, bottom);

    MoveToEx(hdc, left, top + g_layout.headerH, nullptr); LineTo(hdc, right, top + g_layout.headerH);
    for (size_t i = 1; i <= g_rows.size(); ++i) {
        int y = top + g_layout.headerH + static_cast<int>(i) * g_layout.rowH;
        MoveToEx(hdc, left, y, nullptr); LineTo(hdc, right, y);
    }

    MoveToEx(hdc, col1, top, nullptr); LineTo(hdc, col1, bottom);
    MoveToEx(hdc, col2, top, nullptr); LineTo(hdc, col2, bottom);
    MoveToEx(hdc, col3, top, nullptr); LineTo(hdc, col3, bottom);

    SetBkMode(hdc, TRANSPARENT);

    auto drawCellText = [&](const RECT& rc, const char* text, HFONT font, COLORREF color, UINT fmt) {
        HFONT oldFont = (HFONT)SelectObject(hdc, font);
        SetTextColor(hdc, color);
        RECT r = rc;
        r.left += 10; r.right -= 10;
        DrawTextA(hdc, text, -1, &r, fmt | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        SelectObject(hdc, oldFont);
    };

    drawCellText({ left, top, col1, top + g_layout.headerH }, "Windows", g_hFontBold, COLOR_TEXT_WHITE, DT_LEFT);
    drawCellText({ col1, top, col2, top + g_layout.headerH }, "Version", g_hFontBold, COLOR_TEXT_WHITE, DT_LEFT);
    drawCellText({ col2, top, col3, top + g_layout.headerH }, "Status", g_hFontBold, COLOR_TEXT_WHITE, DT_LEFT);
    drawCellText({ col3, top, right, top + g_layout.headerH }, "Home / Pro End of Life", g_hFontBold, COLOR_TEXT_WHITE, DT_LEFT);

    for (size_t i = 0; i < g_rows.size(); ++i) {
        int y = top + g_layout.headerH + static_cast<int>(i) * g_layout.rowH;
        RECT r1 = { left, y, col1, y + g_layout.rowH };
        RECT r2 = { col1, y, col2, y + g_layout.rowH };
        RECT r3 = { col2, y, col3, y + g_layout.rowH };
        RECT r4 = { col3, y, right, y + g_layout.rowH };

        if (i % 2 == 1) {
            HBRUSH hAlt = CreateSolidBrush(RGB(23, 32, 51));
            RECT rowRc = { left + 1, y + 1, right - 1, y + g_layout.rowH - 1 };
            FillRect(hdc, &rowRc, hAlt);
            DeleteObject(hAlt);
        }

        drawCellText(r1, g_rows[i].os, g_hFontSub, COLOR_TEXT_WHITE, DT_LEFT);
        drawCellText(r2, g_rows[i].version, g_hFontSub, COLOR_TEXT_WHITE, DT_LEFT);

        if (IsSupported(g_rows[i])) {
            drawCellText(r3, "Supported", g_hFontSub, RGB(96, 165, 250), DT_LEFT);
        } else {
            drawCellText(r3, "Not supported", g_hFontSub, COLOR_DANGER_RED, DT_LEFT);
        }

        drawCellText(r4, g_rows[i].homePro, g_hFontSub, RGB(203, 213, 225), DT_LEFT);
    }

    SelectObject(hdc, oldPen);
    DeleteObject(hPen);
}

void PositionOkButton(HWND hwnd) {
    HWND hBtn = GetDlgItem(hwnd, 1);
    if (hBtn) {
        MoveWindow(hBtn, g_layout.rcButton.left, g_layout.rcButton.top,
            g_layout.buttonW, g_layout.buttonH, TRUE);
    }
}

LRESULT CALLBACK WindowsEolWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CreateWindowA("BUTTON", "OK", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            0, 0, g_layout.buttonW, g_layout.buttonH, hwnd, reinterpret_cast<HMENU>(1), nullptr, nullptr);
        PositionOkButton(hwnd);
        break;
    }
    case WM_SIZE:
        PositionOkButton(hwnd);
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        FillRect(hdc, &rc, g_hBrushBg);
        SetBkMode(hdc, TRANSPARENT);

        HFONT oldFont = (HFONT)SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        DrawTextA(hdc, g_currentVersion.c_str(), -1, &g_layout.rcCurrent, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        SelectObject(hdc, oldFont);

        DrawTable(hdc);

        SelectObject(hdc, g_hFontSub);
        SetTextColor(hdc, COLOR_TEXT_MUTED);
        DrawTextA(hdc, "Status and dates shown are for Windows Home/Pro editions based on Microsoft lifecycle end-of-servicing dates.",
            -1, &g_layout.rcNote, DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_DRAWITEM: {
        auto* pdis = reinterpret_cast<LPDRAWITEMSTRUCT>(lParam);
        HDC hdc = pdis->hDC;

        HBRUSH hBtnBrush = CreateSolidBrush(COLOR_ACCENT_TEAL);
        FillRect(hdc, &pdis->rcItem, hBtnBrush);
        DeleteObject(hBtnBrush);

        HPEN hPen = CreatePen(PS_SOLID, 1, COLOR_ACCENT_TEAL);
        HGDIOBJ oldPen = SelectObject(hdc, hPen);
        HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(hPen);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);
        SelectObject(hdc, g_hFontBold);
        DrawTextA(hdc, "OK", -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        break;
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

} // namespace

void ShowWindowsVersionEolDialog(HWND hParent) {
    ComputeLayout();

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowsEolWndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "WindowsVersionEolDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClassA(&wc);

    RECT wr = { 0, 0, g_layout.dlgW, g_layout.dlgH };
    DWORD style = WS_POPUP | WS_BORDER | WS_CAPTION;
    DWORD exStyle = WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME;
    AdjustWindowRectEx(&wr, style, FALSE, exStyle);

    int winW = wr.right - wr.left;
    int winH = wr.bottom - wr.top;

    HWND hWnd = CreateWindowExA(
        exStyle,
        "WindowsVersionEolDialog",
        "Windows Version End of Life",
        style,
        0, 0, winW, winH,
        hParent, nullptr, GetModuleHandle(nullptr), nullptr);

    if (!hWnd) return;

    RECT rcParent = {};
    if (hParent && GetWindowRect(hParent, &rcParent)) {
        SetWindowPos(hWnd, nullptr,
            rcParent.left + (rcParent.right - rcParent.left - winW) / 2,
            rcParent.top + (rcParent.bottom - rcParent.top - winH) / 2,
            winW, winH, SWP_NOZORDER);
    }

    BOOL useDarkMode = TRUE;
    DwmSetWindowAttribute(hWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    if (hParent) EnableWindow(hParent, FALSE);
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    MSG msg;
    while (IsWindow(hWnd) && GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
