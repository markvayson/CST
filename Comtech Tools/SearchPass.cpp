#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <string>


#define WIN32_LEAN_AND_MEAN
#include "Resource.h"
#include "version.h"
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// Enforce modern Visual Styles & Common Controls v6 for Header Checkboxes
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <windows.h>
#include <windowsx.h>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cwctype>
#include <shellapi.h>
#include <objbase.h>
#include <mutex>
#include <cstdio>
#include <fstream>
#include <commctrl.h>
#include "Theme.h"
#include "SearchPass.h"
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#include <uxtheme.h>
#pragma comment(lib, "uxtheme.lib")
#include <vsstyle.h>

#pragma comment(lib, "comctl32.lib")

// Globals
std::vector<std::wstring> g_foundFiles;
std::mutex g_resultsMutex;
std::wstring g_scanCompleteTime = L"";

// Sorting & Sync Globals
int g_sortColumn = -1;
bool g_sortAscending = true;
bool g_bUpdatingCheckboxes = false;

#define IDC_LISTVIEW       101
#define IDC_BTN_QUARANTINE 102
#define IDC_BTN_EXPORT     103
#define IDC_BTN_CLEAR      104
#define IDC_STATIC_COUNT   105
#define IDC_BTN_REFRESH     107
#define IDC_BTN_ANYDESK 108

#define IDM_SEARCHPASS 106


extern bool ShowDarkConfirmDialog(HWND hParent, const char* title, const char* msg);
extern void ShowDarkMessageDialog(HWND hParent, const char* msg);

void UpdateDeleteButtonState(HWND hListView, HWND hBtn) {
    int count = ListView_GetItemCount(hListView);
    int checkedCount = 0;
    for (int i = 0; i < count; ++i) {
        if (ListView_GetCheckState(hListView, i)) checkedCount++;
    }
    EnableWindow(hBtn, checkedCount > 0);
}


bool ContainsIgnoreCase(const std::wstring& str, const std::wstring& sub) {
    return StrStrIW(str.c_str(), sub.c_str()) != NULL;
}

void SearchDirectoryRecursive(const std::wstring& currentDir, const std::wstring& targetStr, std::vector<std::wstring>& localFoundFiles) {
    if (ContainsIgnoreCase(currentDir, L"Windows")) return;

    std::wstring searchPath = currentDir + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileExW(searchPath.c_str(), FindExInfoBasic, &findData, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
            std::wstring fullPath = currentDir + L"\\" + findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                SearchDirectoryRecursive(fullPath, targetStr, localFoundFiles);
            }
            else {
                if (ContainsIgnoreCase(findData.cFileName, targetStr)) {
                    localFoundFiles.push_back(fullPath);
                }
            }
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
}


void ExecutePermanentDelete(HWND hListView) {
    if (!ShowDarkConfirmDialog(GetParent(hListView), "Permanently Delete Files", "Are you sure you want to permanently delete the flagged files to meet ADHICS standards?")) {
        return;
    }

    int count = ListView_GetItemCount(hListView);
    for (int i = count - 1; i >= 0; --i) {
        if (ListView_GetCheckState(hListView, i)) {
            wchar_t filePath[MAX_PATH];
            ListView_GetItemText(hListView, i, 1, filePath, MAX_PATH);

            // Delete the file directly
            if (DeleteFileW(filePath)) {
                ListView_DeleteItem(hListView, i);
            }
        }
    }
}

struct SortContext {
    HWND hListView;
    int iColumn;
    bool bAscending;
};

void GetListViewItemTextW(HWND hListView, int item, int subItem, wchar_t* outBuf, int maxLen) {
    LVITEMW lvi = { 0 };
    lvi.iSubItem = subItem;
    lvi.cchTextMax = maxLen;
    lvi.pszText = outBuf;
    SendMessageW(hListView, LVM_GETITEMTEXTW, (WPARAM)item, (LPARAM)&lvi);
}

int CALLBACK CompareListViewItems(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    SortContext* ctx = (SortContext*)lParamSort;
    wchar_t buf1[MAX_PATH] = { 0 };
    wchar_t buf2[MAX_PATH] = { 0 };

    GetListViewItemTextW(ctx->hListView, (int)lParam1, ctx->iColumn, buf1, MAX_PATH);
    GetListViewItemTextW(ctx->hListView, (int)lParam2, ctx->iColumn, buf2, MAX_PATH);

    int result = _wcsicmp(buf1, buf2);
    return ctx->bAscending ? result : -result;
}

void UpdateHeaderCheckboxState(HWND hListView, HWND hHeader) {
    int count = ListView_GetItemCount(hListView);
    if (count == 0) return;

    bool allChecked = true;
    for (int i = 0; i < count; ++i) {
        if (!ListView_GetCheckState(hListView, i)) {
            allChecked = false;
            break;
        }
    }

    HDITEMW hdi = { 0 };
    hdi.mask = HDI_FORMAT;
    Header_GetItem(hHeader, 0, &hdi);
    bool isHeaderChecked = (hdi.fmt & HDF_CHECKED) != 0;

    if (allChecked != isHeaderChecked) {
        if (allChecked) hdi.fmt |= HDF_CHECKED;
        else hdi.fmt &= ~HDF_CHECKED;
        Header_SetItem(hHeader, 0, &hdi);
    }
}

LRESULT CALLBACK ListViewSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    if (uMsg == WM_NOTIFY) {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        HWND hHeader = ListView_GetHeader(hWnd);
       

        if (pnmh->hwndFrom == hHeader && pnmh->code == NM_CUSTOMDRAW) {
            LPNMCUSTOMDRAW pcd = (LPNMCUSTOMDRAW)lParam;
            switch (pcd->dwDrawStage) {
            case CDDS_PREPAINT:
                RECT rc;
                GetClientRect(hHeader, &rc);
                FillRect(pcd->hdc, &rc, (HBRUSH)dwRefData);
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT: {
                FillRect(pcd->hdc, &pcd->rc, (HBRUSH)dwRefData);

                wchar_t buf[256] = { 0 };
                HDITEMW hdi = { 0 };
                hdi.mask = HDI_TEXT | HDI_FORMAT;
                hdi.pszText = buf;
                hdi.cchTextMax = 256;
                Header_GetItem(hHeader, (int)pcd->dwItemSpec, &hdi);

                RECT rcText = pcd->rc;

                if (pcd->dwItemSpec == 0) {
                    HTHEME hTheme = OpenThemeData(hWnd, L"Button");
                    if (hTheme) {
                        RECT rcCheck = pcd->rc;
                        rcCheck.left = pcd->rc.left + 8;
                        rcCheck.right = rcCheck.left + 13;
                        rcCheck.top = rcCheck.top + ((rcCheck.bottom - rcCheck.top) - 13) / 2;
                        rcCheck.bottom = rcCheck.top + 13;

                        int state = (hdi.fmt & HDF_CHECKED) ? CBS_CHECKEDNORMAL : CBS_UNCHECKEDNORMAL;
                        DrawThemeBackground(hTheme, pcd->hdc, BP_CHECKBOX, state, &rcCheck, NULL);
                        CloseThemeData(hTheme);
                    }
                    rcText.left = pcd->rc.left + 28;
                }
                else {
                    rcText.left += 6;
                }

                SetBkMode(pcd->hdc, TRANSPARENT);
                SetTextColor(pcd->hdc, RGB(241, 245, 249));
                DrawTextW(pcd->hdc, buf, -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

                HBRUSH hBorderBrush = CreateSolidBrush(RGB(30, 41, 59));
                RECT rcDivider = { pcd->rc.right - 1, pcd->rc.top, pcd->rc.right, pcd->rc.bottom };
                FillRect(pcd->hdc, &rcDivider, hBorderBrush);
                DeleteObject(hBorderBrush);

                return CDRF_SKIPDEFAULT;
            }
            }
            return CDRF_DODEFAULT;
        }
    }
    else if (uMsg == WM_NCDESTROY) {
        RemoveWindowSubclass(hWnd, ListViewSubclassProc, uIdSubclass);
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK HeaderSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (uMsg) {

    case WM_LBUTTONDBLCLK:
        // Consumes the double-click message entirely so the column cannot auto-resize
        return 0;

    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, HeaderSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}


void ExecuteAnydeskRemoval(HWND hParent) {
    // Show wait window so user knows it's scanning
    HINSTANCE hInstance = GetModuleHandle(NULL);
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    HWND hWaitWnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"ModernWaitClass", L"",
        WS_POPUP | WS_VISIBLE, (screenW / 2) - 175, (screenH / 2) - 60, 350, 120, NULL, NULL, hInstance, NULL);

    int deletedCount = 0;
    DWORD driveMask = GetLogicalDrives();

    // Scan drives iterativly
    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (driveMask & (1 << (letter - 'A'))) {
            std::wstring driveRoot = std::wstring(1, (wchar_t)letter) + L":\\";
            if (GetDriveTypeW(driveRoot.c_str()) == DRIVE_FIXED) {

                std::vector<std::wstring> dirsToScan;
                dirsToScan.push_back(driveRoot);

                while (!dirsToScan.empty()) {
                    std::wstring currentDir = dirsToScan.back();
                    dirsToScan.pop_back();

                    if (ContainsIgnoreCase(currentDir, L"Windows")) continue;

                    WIN32_FIND_DATAW findData;
                    std::wstring searchPath = currentDir + L"\\*";
                    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

                    if (hFind != INVALID_HANDLE_VALUE) {
                        do {
                            if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
                                std::wstring fullPath = currentDir + L"\\" + findData.cFileName;
                                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                                    dirsToScan.push_back(fullPath);
                                }
                                else {
                                    if (_wcsicmp(findData.cFileName, L"anydesk.exe") == 0) {
                                        if (DeleteFileW(fullPath.c_str())) {
                                            deletedCount++;
                                        }
                                    }
                                }
                            }
                        } while (FindNextFileW(hFind, &findData));
                        FindClose(hFind);
                    }
                }
            }
        }
    }

    DestroyWindow(hWaitWnd);

    char msgBuffer[256];
    snprintf(msgBuffer, sizeof(msgBuffer), "AnyDesk scan complete. Successfully removed %d instance(s).", deletedCount);
    ShowDarkMessageDialog(hParent, msgBuffer);
}



HWND g_hSearchResultsWnd = NULL;

LRESULT CALLBACK SearchResultsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hListView, hHeader, hBtnQuarantine, hBtnExport, hBtnClear, hStaticCount;
    static HIMAGELIST hSysImageList;
    static HWND hBtnRefresh, hBtnAnydesk;

    switch (msg) {
    case WM_CREATE: {
        g_hSearchResultsWnd = hwnd;
        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icex);

        BOOL useDarkMode = TRUE;
        DwmSetWindowAttribute(hwnd, 20, &useDarkMode, sizeof(useDarkMode));

        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        std::vector<std::wstring>* pFiles = (std::vector<std::wstring>*)cs->lpCreateParams;

        hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_ALIGNLEFT,
            0, 0, 0, 0, hwnd, (HMENU)IDC_LISTVIEW, cs->hInstance, NULL);

        SetWindowTheme(hListView, L"DarkMode_Explorer", NULL);
        SetWindowSubclass(hListView, ListViewSubclassProc, 1, (DWORD_PTR)g_hBrushPanel);

        ListView_SetExtendedListViewStyle(hListView, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_TRACKSELECT);
        ListView_SetBkColor(hListView, COLOR_PANEL);
        ListView_SetTextBkColor(hListView, COLOR_PANEL);
        ListView_SetTextColor(hListView, COLOR_TEXT_WHITE);

        SendMessageW(hListView, WM_SETFONT, (WPARAM)g_hFontSub, FALSE);
        hHeader = ListView_GetHeader(hListView);
        if (hHeader) {
            DWORD dwHeaderStyle = GetWindowLongW(hHeader, GWL_STYLE);
            SetWindowLongW(hHeader, GWL_STYLE, dwHeaderStyle | HDS_CHECKBOXES);

            // Subclass the header to prevent resizing and cursor changes
            SetWindowSubclass(hHeader, HeaderSubclassProc, 2, 0);
        }
        hBtnQuarantine = CreateWindowA("BUTTON", "Delete Checked", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_QUARANTINE, NULL, NULL);
        hBtnAnydesk = CreateWindowA("BUTTON", "Remove AnyDesk", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_ANYDESK, NULL, NULL);
        hBtnRefresh = CreateWindowA("BUTTON", "Refresh", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 0, 0, 0, 0, hwnd, (HMENU)IDC_BTN_REFRESH, NULL, NULL);

        SendMessageW(hBtnQuarantine, WM_SETFONT, (WPARAM)g_hFontSub, MAKELPARAM(TRUE, 0));
        SendMessageW(hBtnAnydesk, WM_SETFONT, (WPARAM)g_hFontSub, MAKELPARAM(TRUE, 0));
        SendMessageW(hBtnRefresh, WM_SETFONT, (WPARAM)g_hFontSub, MAKELPARAM(TRUE, 0));
        // Bottom Left Scanned Count Label
        hStaticCount = CreateWindowW(
            L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            15, 568, 300, 23,
            hwnd, (HMENU)IDC_STATIC_COUNT, cs->hInstance, NULL
        );
        SendMessageW(hStaticCount, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

        SHFILEINFOW sfi = { 0 };
        hSysImageList = (HIMAGELIST)SHGetFileInfoW(L"C:\\", 0, &sfi, sizeof(sfi), SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
        ListView_SetImageList(hListView, hSysImageList, LVSIL_SMALL);

        // ADD THIS LINE to strip out the solid white background caching:
        ImageList_SetBkColor(hSysImageList, CLR_NONE);

        LVCOLUMNW lvc = { 0 };
        lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

        lvc.iSubItem = 0; lvc.pszText = (LPWSTR)L"File Name"; lvc.cx = 300; lvc.fmt = LVCFMT_LEFT;
        SendMessageW(hListView, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

        HDITEMW hdi = { 0 };
        hdi.mask = HDI_FORMAT;
        Header_GetItem(hHeader, 0, &hdi);
        hdi.fmt |= HDF_CHECKBOX;
        Header_SetItem(hHeader, 0, &hdi);

        lvc.iSubItem = 1; lvc.pszText = (LPWSTR)L"File Path"; lvc.cx = 400; SendMessageW(hListView, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);
        lvc.iSubItem = 2; lvc.pszText = (LPWSTR)L"Type"; lvc.cx = 70; SendMessageW(hListView, LVM_INSERTCOLUMNW, 2, (LPARAM)&lvc);
        
        SendMessageW(hListView, WM_SETREDRAW, FALSE, 0);

        for (size_t i = 0; i < pFiles->size(); ++i) {
            const std::wstring& path = (*pFiles)[i];
            size_t slashPos = path.find_last_of(L"\\/");
            std::wstring fileName = (slashPos != std::wstring::npos) ? path.substr(slashPos + 1) : path;
            size_t dotPos = fileName.find_last_of(L".");
            std::wstring ext = (dotPos != std::wstring::npos) ? fileName.substr(dotPos) : L".file";

            SHGetFileInfoW(ext.c_str(), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);

            LVITEMW lvi = { 0 };
            lvi.mask = LVIF_TEXT | LVIF_IMAGE;
            lvi.iItem = (int)i;
            lvi.iSubItem = 0;
            lvi.iImage = sfi.iIcon;
            lvi.pszText = (LPWSTR)fileName.c_str();
            SendMessageW(hListView, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

            LVITEMW lviSet = { 0 };
            lviSet.iSubItem = 1; lviSet.pszText = (LPWSTR)path.c_str(); SendMessageW(hListView, LVM_SETITEMTEXTW, (WPARAM)i, (LPARAM)&lviSet);
            lviSet.iSubItem = 2; lviSet.pszText = (LPWSTR)ext.c_str(); SendMessageW(hListView, LVM_SETITEMTEXTW, (WPARAM)i, (LPARAM)&lviSet);
        }

        SendMessageW(hListView, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hListView, NULL, TRUE);

        // Update Scan Count Text
        wchar_t countText[128];
        swprintf(countText, 128, L"Files scanned: %d", (int)pFiles->size());
        SetWindowTextW(hStaticCount, countText);
        UpdateDeleteButtonState(hListView, hBtnQuarantine);
        break;
    }

    case WM_SIZE: {
        RECT rc; GetClientRect(hwnd, &rc);
        int topMargin = 10;
        int bottomMargin = 50;
        int listHeight = rc.bottom - topMargin - bottomMargin;

        SetWindowPos(hListView, NULL, 10, topMargin, rc.right - 20, listHeight, SWP_NOZORDER);
        SetWindowPos(hStaticCount, NULL, 15, rc.bottom - 35, 300, 23, SWP_NOZORDER);
        

        int btnWidth = 140;
        int btnHeight = 32;
        int margin = 10;

        SetWindowPos(hBtnQuarantine, NULL, rc.right - btnWidth - margin, rc.bottom - 40, btnWidth, btnHeight, SWP_NOZORDER);
        SetWindowPos(hBtnAnydesk, NULL, rc.right - (btnWidth * 2) - (margin * 2), rc.bottom - 40, btnWidth, btnHeight, SWP_NOZORDER);
        SetWindowPos(hBtnRefresh, NULL, rc.right - (btnWidth * 3) - (margin * 3), rc.bottom - 40, btnWidth, btnHeight, SWP_NOZORDER);


        int totalWidth = rc.right - 20;
        int col0 = ListView_GetColumnWidth(hListView, 0);
        int col2 = ListView_GetColumnWidth(hListView, 2);

        RECT rcList;
        GetClientRect(hListView, &rcList);
        int availableWidth = rcList.right;


        int newCol1Width = availableWidth - col0 - col2;


        if (newCol1Width > 100) {
            ListView_SetColumnWidth(hListView, 1, newCol1Width);
        }
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BTN_QUARANTINE) {
            int itemCount = ListView_GetItemCount(hListView);
            int targetCount = 0;
            for (int i = 0; i < itemCount; ++i) {
                if (ListView_GetCheckState(hListView, i)) targetCount++;
            }
            if (targetCount > 0) {
                char msgBuffer[256];
                snprintf(msgBuffer, 256, "Are you sure you want to permanently delete %d selected item(s)?", targetCount);
                if (ShowDarkConfirmDialog(hwnd, "Delete Files", msgBuffer)) {
                    int deleted = 0;
                    for (int i = itemCount - 1; i >= 0; --i) {
                        if (ListView_GetCheckState(hListView, i)) {
                            wchar_t buffer[MAX_PATH];
                            GetListViewItemTextW(hListView, i, 1, buffer, MAX_PATH);
                            if (DeleteFileW(buffer)) {
                                ListView_DeleteItem(hListView, i);
                                deleted++;
                            }
                        }
                    }


                    ShowDarkMessageDialog(hwnd, "Selected file(s) deleted successfuly.");
                    UpdateHeaderCheckboxState(hListView, hHeader);

                    // Update count display

                    wchar_t countText[128];
                    swprintf(countText, 128, L"Files scanned: %d", ListView_GetItemCount(hListView));
                    SetWindowTextW(hStaticCount, countText);


					UpdateDeleteButtonState(hListView, hBtnQuarantine);
                }
            }
        }
        else if (LOWORD(wParam) == IDC_BTN_ANYDESK) {
            if (ShowDarkConfirmDialog(hwnd, "Delete AnyDesk.exe", "Are you sure you want to delete all AnyDesk.exe?")) {
                std::thread(ExecuteAnydeskRemoval, hwnd).detach();
            }
        }
        else if (LOWORD(wParam) == IDC_BTN_REFRESH) {
            // Close the current window and launch a fresh search
            PostMessage(hwnd, WM_CLOSE, 0, 0);
            std::thread(ExecuteFastSearch).detach();
        }
        break;

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        if (pdis->CtlID == IDC_BTN_QUARANTINE || pdis->CtlID == IDC_BTN_ANYDESK || pdis->CtlID == IDC_BTN_REFRESH) {
            SetBkMode(pdis->hDC, TRANSPARENT);

            bool isDisabled = (pdis->itemState & ODS_DISABLED);
            bool isSelected = (pdis->itemState & ODS_SELECTED);

            COLORREF bgColor = isDisabled ? RGB(30, 41, 59) : (isSelected ? RGB(15, 23, 42) : COLOR_ACCENT_TEAL);
            HBRUSH hBg = CreateSolidBrush(bgColor);
            FillRect(pdis->hDC, &pdis->rcItem, hBg);
            DeleteObject(hBg);

            COLORREF borderColor = isDisabled ? RGB(40, 50, 70) : RGB(13, 148, 136);
            HBRUSH hBorder = CreateSolidBrush(borderColor);
            FrameRect(pdis->hDC, &pdis->rcItem, hBorder);
            DeleteObject(hBorder);

            SetTextColor(pdis->hDC, isDisabled ? RGB(148, 163, 184) : RGB(255, 255, 255));
            wchar_t text[64];
            GetWindowTextW(pdis->hwndItem, text, 64);
            DrawTextW(pdis->hDC, text, -1, &pdis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            return TRUE;
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        HWND hwndStatic = (HWND)lParam;
        if (hwndStatic == hStaticCount) {
            SetTextColor(hdcStatic, COLOR_TEXT_WHITE);
            SetBkColor(hdcStatic, COLOR_BG);
            return (INT_PTR)g_hBrushBg;
        }
        break;
    }
    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;

        if (pnmh->hwndFrom == hHeader &&
            (pnmh->code == HDN_BEGINTRACKW || pnmh->code == HDN_BEGINTRACKA)) {
            return TRUE; // Returning TRUE blocks the drag action
        }


        if (pnmh->code == LVN_KEYDOWN && pnmh->idFrom == IDC_LISTVIEW) {
            LPNMLVKEYDOWN pnkd = (LPNMLVKEYDOWN)lParam;

            if (pnkd->wVKey == VK_SPACE) {
                // Toggle check state for ALL highlighted items
                int focusItem = ListView_GetNextItem(hListView, -1, LVNI_FOCUSED);
                if (focusItem != -1) {
                    BOOL newState = !ListView_GetCheckState(hListView, focusItem);
                    int item = -1;
                    g_bUpdatingCheckboxes = true; // Prevent rapid state-change events

                    while ((item = ListView_GetNextItem(hListView, item, LVNI_SELECTED)) != -1) {
                        ListView_SetCheckState(hListView, item, newState);
                    }
                    g_bUpdatingCheckboxes = false;

                    UpdateHeaderCheckboxState(hListView, hHeader);

                    // Re-evaluate button enable/disable state
                    UpdateDeleteButtonState(hListView, hBtnQuarantine);

                }
                return 1;
            }
            else if (pnkd->wVKey == VK_DELETE) {
                SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(IDC_BTN_QUARANTINE, 0), 0);
                return 1;
            }
        }

        if (pnmh->code == NM_DBLCLK && pnmh->idFrom == IDC_LISTVIEW) {
            LPNMITEMACTIVATE pnmia = (LPNMITEMACTIVATE)lParam;
            if (pnmia->iItem != -1) {
                wchar_t filePath[MAX_PATH];
                GetListViewItemTextW(hListView, pnmia->iItem, 1, filePath, MAX_PATH);

                if (pnmia->iSubItem == 0) {
                    ShellExecuteW(hwnd, L"open", filePath, NULL, NULL, SW_SHOWNORMAL);
                }
                else if (pnmia->iSubItem == 1) {
                    std::wstring pathStr(filePath);
                    size_t lastSlash = pathStr.find_last_of(L"\\/");
                    if (lastSlash != std::wstring::npos) {
                        std::wstring folderPath = pathStr.substr(0, lastSlash);
                        ShellExecuteW(hwnd, L"open", folderPath.c_str(), NULL, NULL, SW_SHOWNORMAL);
                    }
                }
            }
        }



        if (pnmh->code == NM_CUSTOMDRAW && pnmh->idFrom == IDC_LISTVIEW) {
            LPNMLVCUSTOMDRAW pCustomDraw = (LPNMLVCUSTOMDRAW)lParam;
            switch (pCustomDraw->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT:
                return CDRF_NOTIFYSUBITEMDRAW | CDRF_NEWFONT;
            case (CDDS_ITEMPREPAINT | CDDS_SUBITEM): {
                HDC hdc = pCustomDraw->nmcd.hdc;
                RECT rc = pCustomDraw->nmcd.rc;
                int item = (int)pCustomDraw->nmcd.dwItemSpec;
                int subitem = pCustomDraw->iSubItem;

                RECT rcBg = rc;
                if (subitem == 0) {
                    RECT rcBounds;
                    ListView_GetItemRect(hListView, item, &rcBounds, LVIR_BOUNDS);
                    rcBg.left = rcBounds.left;
                }

                bool bSelected = ListView_GetItemState(hListView, item, LVIS_SELECTED) & LVIS_SELECTED;
                bool bHot = (pCustomDraw->nmcd.uItemState & CDIS_HOT) != 0;

                COLORREF bgColor = bSelected ? RGB(30, 41, 59) : (bHot ? RGB(23, 32, 51) : RGB(15, 23, 42));
                HBRUSH hBg = CreateSolidBrush(bgColor);
                FillRect(hdc, &rcBg, hBg);
                DeleteObject(hBg);

                wchar_t text[MAX_PATH] = { 0 };
                ListView_GetItemText(hListView, item, subitem, text, MAX_PATH);
                RECT rcText = rc;
                rcText.right -= 4;
                SelectObject(hdc, g_hFontSub);

                if (subitem == 0) {
                    HTHEME hTheme = OpenThemeData(pCustomDraw->nmcd.hdr.hwndFrom, L"Button");
                    if (hTheme) {
                        RECT rcCheck = rcBg;
                        rcCheck.left = rcBg.left + 8;
                        rcCheck.right = rcCheck.left + 13;
                        rcCheck.top = rcCheck.top + ((rcCheck.bottom - rcCheck.top) - 13) / 2;
                        rcCheck.bottom = rcCheck.top + 13;

                        BOOL bChecked = ListView_GetCheckState(hListView, item);
                        int state = bChecked ? CBS_CHECKEDNORMAL : CBS_UNCHECKEDNORMAL;
                        DrawThemeBackground(hTheme, hdc, BP_CHECKBOX, state, &rcCheck, NULL);
                        CloseThemeData(hTheme);
                    }

                    LVITEMW lvi = { 0 };
                    lvi.mask = LVIF_IMAGE;
                    lvi.iItem = item;
                    lvi.iSubItem = 0;
                    ListView_GetItem(hListView, &lvi);

                    int iconLeft = rcBg.left + 28;

                    HIMAGELIST hImageList = ListView_GetImageList(hListView, LVSIL_SMALL);
                    if (hImageList && lvi.iImage >= 0) {
                        int iconTop = rcBg.top + ((rcBg.bottom - rcBg.top) - 16) / 2;
                        ImageList_Draw(hImageList, lvi.iImage, hdc, iconLeft, iconTop, ILD_TRANSPARENT);
                    }
                    rcText.left = rcBg.left + 50;
                }
                else if (subitem == 1) {
                    SelectObject(hdc, g_hFontIcon);
                    SetBkMode(hdc, TRANSPARENT);

                    SetTextColor(hdc, bHot ? RGB(147, 197, 253) : RGB(96, 165, 250));

                    RECT rcIcon = rcText;
                    rcIcon.left += 6;
                    DrawTextW(hdc, L"\xE838", -1, &rcIcon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

                    rcText.left += 30;
                }
                else {
                    rcText.left += 6;
                }

                SelectObject(hdc, g_hFontSub);
                SetBkMode(hdc, TRANSPARENT);

                if (subitem == 0) {
                    SetTextColor(hdc, RGB(255, 255, 255)); // Bright White[cite: 8]
                }
                else {
                    SetTextColor(hdc, RGB(148, 163, 184)); // Slate Gray[cite: 8]
                }

                DrawTextW(hdc, text, -1, &rcText, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

                HBRUSH hBorderBrush = CreateSolidBrush(RGB(30, 41, 59));
                RECT rcRightBorder = { rc.right - 1, rc.top, rc.right, rc.bottom };
                FillRect(hdc, &rcRightBorder, hBorderBrush);

                RECT rcBottomBorder = { rcBg.left, rc.bottom - 1, rc.right, rc.bottom };
                FillRect(hdc, &rcBottomBorder, hBorderBrush);
                DeleteObject(hBorderBrush);

                return CDRF_SKIPDEFAULT;
            }
            }
            return CDRF_DODEFAULT;
        }


        if (pnmh->code == HDN_ITEMSTATEICONCLICK) {
            LPNMHEADER pnmHeader = (LPNMHEADER)lParam;
            if (pnmHeader->iItem == 0) {
                UpdateDeleteButtonState(hListView, hBtnQuarantine);
                g_bUpdatingCheckboxes = true;

                HDITEMW hdi = { 0 };
                hdi.mask = HDI_FORMAT;
                Header_GetItem(hHeader, 0, &hdi);

                bool bChecking = !(hdi.fmt & HDF_CHECKED);
                if (bChecking) hdi.fmt |= HDF_CHECKED;
                else hdi.fmt &= ~HDF_CHECKED;
                Header_SetItem(hHeader, 0, &hdi);

                int count = ListView_GetItemCount(hListView);
                for (int i = 0; i < count; i++) {
                    ListView_SetCheckState(hListView, i, bChecking);
                }

                g_bUpdatingCheckboxes = false;
                return 0;
            }
        }


        if (pnmh->code == LVN_COLUMNCLICK) {
            LPNMLISTVIEW pNMLV = (LPNMLISTVIEW)lParam;

            if (g_sortColumn == pNMLV->iSubItem) {
                g_sortAscending = !g_sortAscending;
            }
            else {
                g_sortColumn = pNMLV->iSubItem;
                g_sortAscending = true;
            }

            SortContext ctx = { hListView, g_sortColumn, g_sortAscending };
            ListView_SortItemsEx(hListView, CompareListViewItems, (LPARAM)&ctx);
        }

        if (pnmh->code == LVN_ITEMCHANGED && pnmh->idFrom == IDC_LISTVIEW) {
            LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
            if (!g_bUpdatingCheckboxes && (pnmv->uChanged & LVIF_STATE)) {
                UINT oldState = pnmv->uOldState & LVIS_STATEIMAGEMASK;
                UINT newState = pnmv->uNewState & LVIS_STATEIMAGEMASK;
                if (oldState != newState) {
                    UpdateHeaderCheckboxState(hListView, hHeader);
                    UpdateDeleteButtonState(hListView, hBtnQuarantine);

                }
            }
        }

        break;
    }

    case WM_DESTROY:
    {
        g_hSearchResultsWnd = NULL;
        if (g_hMainWnd) {
            HWND hBtn = GetDlgItem(g_hMainWnd, IDM_SEARCHPASS);
            if (hBtn) {
                EnableWindow(hBtn, TRUE);
                InvalidateRect(hBtn, NULL, FALSE);
            }
            PostMessage(g_hMainWnd, WM_SEARCHPASS_CLOSED, 0, 0);
        }
        PostQuitMessage(0);
        return 0;
    }
    }
    // ADD THIS LINE: Pass unhandled messages back to Windows
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WaitWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HFONT hFontTitle, hFontSub;
    switch (msg) {
    case WM_CREATE:
        hFontTitle = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        hFontSub = (HFONT)GetStockObject(DEFAULT_GUI_FONT);


        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        FillRect(hdc, &rc, g_hBrushBg);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLOR_TEXT_WHITE);


        SelectObject(hdc, g_hFontTitle);
        RECT rcTitle = rc; rcTitle.top += 25;
        DrawTextW(hdc, L"Scanning Drives", -1, &rcTitle, DT_CENTER | DT_TOP | DT_SINGLELINE);

        SelectObject(hdc, g_hFontSub);
        RECT rcSub = rc; rcSub.top += 55;
        DrawTextW(hdc, L"Searching for insecure password files...", -1, &rcSub, DT_CENTER | DT_TOP | DT_SINGLELINE);

        HBRUSH hBorder = CreateSolidBrush(RGB(60, 60, 60));
        FrameRect(hdc, &rc, hBorder);
        DeleteObject(hBorder);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void ShowInteractiveResults(std::vector<std::wstring>& files) {
    HINSTANCE hInstance = GetModuleHandle(NULL);

    WNDCLASSEXW wcCheck = { 0 };
    if (!GetClassInfoExW(hInstance, L"SearchResultsClass", &wcCheck)) {
        WNDCLASSEXW wc = { 0 };
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.lpfnWndProc = SearchResultsWndProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = L"SearchResultsClass";
        wc.hbrBackground = g_hBrushBg;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);

        HICON hAppIcon = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_SHARED);
        HICON hAppIconSm = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED);

        wc.hIcon = hAppIcon;
        wc.hIconSm = hAppIconSm;

        RegisterClassExW(&wc);
    }

    std::wstring title = std::wstring(g_appProductName.begin(), g_appProductName.end()) +
        L" v" + std::wstring(g_appVersion.begin(), g_appVersion.end()) +
        L" - Search Results";

    HWND hwnd = CreateWindowExW(0, L"SearchResultsClass", title.c_str(),
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 650,
        NULL, NULL, hInstance, (LPVOID)&files);

    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);
}
void ExecuteFastSearch() {
    HRESULT hrComInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    {
        std::lock_guard<std::mutex> lock(g_resultsMutex);
        g_foundFiles.clear();
    }

    HINSTANCE hInstance = GetModuleHandle(NULL);
    WNDCLASSW wcWait = { 0 };
    wcWait.lpfnWndProc = WaitWndProc;
    wcWait.hInstance = hInstance;
    wcWait.lpszClassName = L"ModernWaitClass";
    wcWait.hCursor = LoadCursor(NULL, IDC_WAIT);
    RegisterClassW(&wcWait);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    HWND hWaitWnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"ModernWaitClass", L"",
        WS_POPUP | WS_VISIBLE,
        (screenW / 2) - 175, (screenH / 2) - 60, 350, 120,
        NULL, NULL, hInstance, NULL
    );

    HCURSOR hOldCursor = SetCursor(LoadCursor(NULL, IDC_WAIT));
    DWORD driveMask = GetLogicalDrives();
    std::vector<std::thread> searchThreads;
    std::wstring target = L"passw";

    std::atomic<int> activeThreads{ 0 };

    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (driveMask & (1 << (letter - 'A'))) {
            std::wstring driveRoot = std::wstring(1, (wchar_t)letter) + L":\\";
            if (GetDriveTypeW(driveRoot.c_str()) == DRIVE_FIXED) {
                activeThreads++;
                searchThreads.emplace_back([driveRoot, target, &activeThreads]() {
                    std::vector<std::wstring> localFiles;

                    // Call with 3 arguments now
                    SearchDirectoryRecursive(driveRoot, target, localFiles);

                    // Lock the global mutex just once per thread to merge the results
                    if (!localFiles.empty()) {
                        std::lock_guard<std::mutex> lock(g_resultsMutex);
                        g_foundFiles.insert(g_foundFiles.end(), localFiles.begin(), localFiles.end());
                    }

                    activeThreads--;
                    });
            }
        }
    }

    while (activeThreads > 0) {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }

    for (auto& th : searchThreads) {
        if (th.joinable()) th.detach();
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timeBuf[32];
    swprintf(timeBuf, 32, L"%d:%02d %s", (st.wHour % 12 == 0) ? 12 : st.wHour % 12, st.wMinute, (st.wHour >= 12) ? L"PM" : L"AM");
    g_scanCompleteTime = timeBuf;

    SetCursor(hOldCursor);
    DestroyWindow(hWaitWnd);
    UnregisterClassW(L"ModernWaitClass", hInstance);

    if (!g_foundFiles.empty()) {
        ShowInteractiveResults(g_foundFiles);
    
        MSG msg;
		while (GetMessage(&msg, NULL, 0, 0)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);

			if (g_hSearchResultsWnd == NULL) {
				break; // Exit the loop if the search results window is closed
			}
		}
    
    }
    else {
        MessageBoxW(NULL, L"No file containing 'passw' was found.", L"Search Complete", MB_OK | MB_ICONINFORMATION);
    }

    if (SUCCEEDED(hrComInit)) {
        CoUninitialize();
    }
}