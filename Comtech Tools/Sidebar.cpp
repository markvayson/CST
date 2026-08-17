#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

#include "Sidebar.h"
#include "SearchPass.h"
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
#define IDM_SEARCHPASS     3003
#define IDM_WINUPDATE      3004
#define ID_BTN_RESTART     3006
#define ID_SIDEBAR_SYSINFO 3010
#define ID_SIDEBAR_IPINFO  3011

HWND g_hBtnSearchPass = NULL;

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
        // Trigger the custom dark mode confirmation dialog
        if (ShowDarkConfirmDialog(hwnd, "System Restart", "Are you sure you want to restart the computer?")) {

            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;

            // 1. Get a token for this process to adjust privileges
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {

                // 2. Get the LUID for the shutdown privilege
                LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                // 3. Elevate the process token with the shutdown privilege
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

                // 4. If privilege escalation is successful, invoke the restart
                if (GetLastError() == ERROR_SUCCESS) {
                    // EWX_REBOOT shuts down and restarts the system.
                    // EWX_FORCE forces processes to terminate without prompting the user.
                    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
                }
            }
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
    int sidebarX = 610;
    int btnWidth = 165;
    int btnHeight = 48;
    int sidebarStartY = 20;
    int spacing = 12;

    g_hBtnSecureAll = CreateWindowA("BUTTON", "Secure All", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sidebarStartY, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)ID_BTN_SECURE_ALL, NULL, NULL);
    SetWindowSubclass(g_hBtnSecureAll, SidebarBtnSubclassProc, 1, 0);

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

    // Retrieve Host and OS Info
    char hostName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD size = sizeof(hostName);
    GetComputerNameA(hostName, &size);

    char osName[128] = "Unknown OS";
    char osVer[64] = "";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD bufSize = sizeof(osName);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)osName, &bufSize);

        bufSize = sizeof(osVer);
        RegQueryValueExA(hKey, "DisplayVersion", NULL, NULL, (LPBYTE)osVer, &bufSize);

        char buildBuf[64] = { 0 };
        bufSize = sizeof(buildBuf);
        if (RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (LPBYTE)buildBuf, &bufSize) == ERROR_SUCCESS) {
            if (atoi(buildBuf) >= 22000) {
                std::string sName = osName;
                size_t pos = sName.find("Windows 10");
                if (pos != std::string::npos) {
                    sName.replace(pos, 10, "Windows 11");
                    strcpy_s(osName, sizeof(osName), sName.c_str());
                }
            }
        }
        RegCloseKey(hKey);
    }

    char sysInfoFull[256];
    snprintf(sysInfoFull, sizeof(sysInfoFull), "Host|%s\nOS|%s\nVersion|%s", hostName, osName, osVer);

    // IP Address button height and Y calculation
    int ipBtnHeight = 40;
    int ipY = restartY - ipBtnHeight - spacing;

    // SysInfo Panel Y calculation
    int sysInfoHeight = 115;
    int sysInfoY = ipY - sysInfoHeight - spacing;

    // 1. System Info Panel
    HWND hSysInfoPanel = CreateWindowA("BUTTON", sysInfoFull, WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, sysInfoY, btnWidth, sysInfoHeight, hwndParent, (HMENU)(UINT_PTR)ID_SIDEBAR_SYSINFO, NULL, NULL);
    SetWindowSubclass(hSysInfoPanel, SidebarBtnSubclassProc, 1, 0);

    // 2. IP Address Control (between SysInfo and Restart)
    std::string ipAddr = GetLocalIPAddress();
    std::string ipLabel = "IP: " + ipAddr;
    HWND hIpBtn = CreateWindowA("BUTTON", ipLabel.c_str(), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, ipY, btnWidth, ipBtnHeight, hwndParent, (HMENU)(UINT_PTR)ID_SIDEBAR_IPINFO, NULL, NULL);
    SetWindowSubclass(hIpBtn, SidebarBtnSubclassProc, 1, 0);

    // 3. Restart Button
    HWND hBtnRestart = CreateWindowA("BUTTON", "Restart Device", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        sidebarX, restartY, btnWidth, btnHeight, hwndParent, (HMENU)(UINT_PTR)ID_BTN_RESTART, NULL, NULL);
    SetWindowSubclass(hBtnRestart, SidebarBtnSubclassProc, 1, 0);

}

bool IsSidebarButton(UINT ctlId) {
    return (ctlId == ID_BTN_SECURE_ALL ||
        ctlId == IDM_INVENTORY ||
        ctlId == IDM_SEARCHPASS ||
        ctlId == IDM_WINUPDATE ||
        ctlId == ID_BTN_RESTART ||
        ctlId == ID_SIDEBAR_SYSINFO ||
        ctlId == ID_SIDEBAR_IPINFO);
}


void DrawSidebarButton(LPDRAWITEMSTRUCT pdis) {
    HDC hdc = pdis->hDC;
    UINT ctlId = pdis->CtlID;

    SetBkMode(hdc, TRANSPARENT);


    // --- Custom drawing for System Info Panel ---
    if (ctlId == ID_SIDEBAR_SYSINFO) {
        

        bool isPressed = (pdis->itemState & ODS_SELECTED) != 0; 
            POINT pt; GetCursorPos(&pt); ScreenToClient(pdis->hwndItem, &pt); 
            RECT rcClient; GetClientRect(pdis->hwndItem, &rcClient); 
            bool isHovered = PtInRect(&rcClient, pt); 

            COLORREF bgCol = isPressed ? RGB(15, 23, 42) : (isHovered ? RGB(23, 32, 51) : COLOR_PANEL); 
            COLORREF borderColor = isHovered ? RGB(71, 85, 105) : COLOR_BORDER; 

            // 1. Panel Background & Border (FIXED: Using bgCol and borderColor)
            HBRUSH hBrush = CreateSolidBrush(bgCol);
        FillRect(hdc, &pdis->rcItem, hBrush); 
            DeleteObject(hBrush); 

            HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
        SelectObject(hdc, hPen); 
            SelectObject(hdc, GetStockObject(NULL_BRUSH)); 
            RoundRect(hdc, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 6, 6); 
            DeleteObject(hPen); 

            int currentY = pdis->rcItem.top + 10; 

            // 2. Header Icon & Title
            SetTextColor(hdc, COLOR_ACCENT_TEAL); 
            SelectObject(hdc, g_hFontIcon); 
            RECT rcHeaderIcon = { pdis->rcItem.left + 12, currentY, pdis->rcItem.right, currentY + 20 }; 
            wchar_t infoIcon = L'\xE946'; 
            DrawTextW(hdc, &infoIcon, 1, &rcHeaderIcon, DT_LEFT | DT_TOP | DT_SINGLELINE); 

            SelectObject(hdc, g_hFontBold); 
            RECT rcHeaderText = { pdis->rcItem.left + 34, currentY, pdis->rcItem.right, currentY + 20 }; 
            DrawTextA(hdc, "System Information", -1, &rcHeaderText, DT_LEFT | DT_TOP | DT_SINGLELINE); 

            currentY += 26; 

            // 3. Parse and Draw Info Rows
            char sysInfoText[256] = { 0 }; 
            GetWindowTextA(pdis->hwndItem, sysInfoText, sizeof(sysInfoText)); 

            char* context = NULL; 
            char* line = strtok_s(sysInfoText, "\n", &context); 

            while (line != NULL) {
                
                std::string s(line); 
                    size_t delimPos = s.find("|"); 

                    if (delimPos != std::string::npos) {
                        
                        std::string label = s.substr(0, delimPos); 
                            std::string value = s.substr(delimPos + 1); 

                            wchar_t rowIcon = L'\xE7F8'; 
                            if (label == "Host") rowIcon = L'\xE7F4'; 
                            else if (label == "OS") rowIcon = L'\xE8A9'; 
                            else if (label == "Version") rowIcon = L'\xE835'; 

                                // Draw Row Icon
                                SetTextColor(hdc, COLOR_TEXT_MUTED); 
                                SelectObject(hdc, g_hFontIcon); 
                                RECT rcRowIcon = { pdis->rcItem.left + 12, currentY, pdis->rcItem.right, currentY + 20 }; 
                                DrawTextW(hdc, &rowIcon, 1, &rcRowIcon, DT_LEFT | DT_TOP | DT_SINGLELINE); 

                                // Draw Label
                                SetTextColor(hdc, COLOR_TEXT_WHITE); 
                                SelectObject(hdc, g_hFontSub); 
                                RECT rcLabel = { pdis->rcItem.left + 32, currentY, pdis->rcItem.right, currentY + 20 }; 
                                DrawTextA(hdc, label.c_str(), -1, &rcLabel, DT_LEFT | DT_TOP | DT_SINGLELINE); 

                                // Calculate Label Width to dynamically offset Value rect
                                SIZE szLabel; 
                                GetTextExtentPoint32A(hdc, label.c_str(), (int)label.length(), &szLabel); 

                                // Draw Value
                                SetTextColor(hdc, COLOR_ACCENT_TEAL); 
                                int valueLeft = rcLabel.left + szLabel.cx + 6; 
                                RECT rcValue = { valueLeft, currentY, pdis->rcItem.right - 12, currentY + 20 }; 
                                DrawTextA(hdc, value.c_str(), -1, &rcValue, DT_RIGHT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS); 
                    }

                currentY += 22; 
                    line = strtok_s(NULL, "\n", &context); 
            }
        return; 
    }
    // ------------------------------------------------

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