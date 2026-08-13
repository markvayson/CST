#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <dwmapi.h>
#include <time.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "ConfirmDialog.h"
#include "Theme.h"
#include "Inventory.h"

#include <comdef.h>
#include <wbemidl.h>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dwmapi.lib")

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

// --- CUSTOM INPUT BOX STATE ---
static std::string g_inputDept;
static bool g_inputDone = false;
static bool g_inputCancelled = false;
static HWND hEditDept = NULL;
static HWND hLblError = NULL; // Error label handle

static LRESULT CALLBACK DeptEditSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    if (uMsg == WM_KEYDOWN && wParam == VK_RETURN) {
        // Trigger the OK button action (ID = 1) on parent window
        HWND hParent = GetParent(hWnd);
        if (hParent) {
            SendMessage(hParent, WM_COMMAND, MAKEWPARAM(1, BN_CLICKED), (LPARAM)GetDlgItem(hParent, 1));
        }
        return 0; // Prevent default system chime sound
    }
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}


static LRESULT CALLBACK InputBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HBRUSH hEditBrush = NULL;

    switch (msg) {
    case WM_CREATE: {
        hEditBrush = CreateSolidBrush(COLOR_PANEL);
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        HWND hCtl = (HWND)lParam;

        if (hCtl == hLblError) {
            SetTextColor(hdcStatic, RGB(248, 113, 113));
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)g_hBrushBg;
        }

        SetTextColor(hdcStatic, COLOR_TEXT_WHITE);
        SetBkMode(hdcStatic, TRANSPARENT);
        return (LRESULT)g_hBrushBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, COLOR_TEXT_WHITE);
        SetBkColor(hdcEdit, COLOR_PANEL);
        return (LRESULT)hEditBrush;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pdis = (LPDRAWITEMSTRUCT)lParam;
        if (pdis->CtlID == 1) { // OK Button
            HDC hdc = pdis->hDC;
            bool isPressed = (pdis->itemState & ODS_SELECTED) != 0;

            COLORREF bgCol = isPressed ? RGB(13, 45, 52) : COLOR_ACCENT_TEAL;
            HBRUSH hBtnBrush = CreateSolidBrush(bgCol);
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
        break;
    }
    case WM_COMMAND:
        if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == hEditDept) {
            if (hLblError && IsWindowVisible(hLblError)) {
                ShowWindow(hLblError, SW_HIDE);
            }
        }

        if (LOWORD(wParam) == 1) { // OK Button
            char buf1[256] = { 0 };
            GetWindowTextA(hEditDept, buf1, sizeof(buf1));

            if (strlen(buf1) == 0) {
                if (hLblError) ShowWindow(hLblError, SW_SHOW);
                return 0;
            }

            g_inputDept = buf1;
            g_inputDone = true;
            g_inputCancelled = false;
            if (hEditBrush) { DeleteObject(hEditBrush); hEditBrush = NULL; }

            // Freeze parent redraw BEFORE destroying to suppress OS flashing
            HWND hParent = GetParent(hwnd);
            if (hParent) {
                SendMessage(hParent, WM_SETREDRAW, FALSE, 0);
            }

            DestroyWindow(hwnd);
        }
        break;
    case WM_CLOSE:
        g_inputDone = true;
        g_inputCancelled = true;
        if (hEditBrush) { DeleteObject(hEditBrush); hEditBrush = NULL; }

        // Freeze parent redraw BEFORE destroying
        {
            HWND hParent = GetParent(hwnd);
            if (hParent) {
                SendMessage(hParent, WM_SETREDRAW, FALSE, 0);
            }
        }

        DestroyWindow(hwnd);
        break;
    default:
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

static bool AskUserDepartment(HWND hParent, std::string& outDept) {
    g_inputDept = "";
    g_inputDone = false;
    g_inputCancelled = false;

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = InputBoxProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "CustomInputDialog";
    wc.hbrBackground = g_hBrushBg;
    RegisterClass(&wc);

    HWND hInputWnd = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "CustomInputDialog", "Enter Inventory Details",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        0, 0, 320, 175, hParent, NULL, GetModuleHandle(NULL), NULL);

    BOOL useDarkMode = TRUE;
    ::DwmSetWindowAttribute(hInputWnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &useDarkMode, sizeof(useDarkMode));

    if (hParent) {
        RECT rcParent; GetWindowRect(hParent, &rcParent);
        SetWindowPos(hInputWnd, NULL,
            rcParent.left + (rcParent.right - rcParent.left) / 2 - 160,
            rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 87,
            320, 175, SWP_NOZORDER);
    }

    HWND hLblDept = CreateWindowA("STATIC", "Department:", WS_VISIBLE | WS_CHILD, 20, 25, 100, 20, hInputWnd, NULL, NULL, NULL);
    SendMessageA(hLblDept, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

    // Assign explicit control ID (3) matching Password Dialog pattern
    hEditDept = CreateWindowExA(0, "EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 120, 23, 160, 24, hInputWnd, (HMENU)3, NULL, NULL);
    SendMessageA(hEditDept, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

    // Subclass edit control to handle 'Enter' key
    SetWindowSubclass(hEditDept, DeptEditSubclassProc, 0, 0);

    hLblError = CreateWindowA("STATIC", "Please enter Department", WS_CHILD | SS_CENTER, 20, 60, 260, 18, hInputWnd, NULL, NULL, NULL);
    SendMessageA(hLblError, WM_SETFONT, (WPARAM)g_hFontSub, TRUE);

    CreateWindowA("BUTTON", "OK", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 115, 88, 90, 32, hInputWnd, (HMENU)1, NULL, NULL);

    if (hParent) EnableWindow(hParent, FALSE);

    ShowWindow(hInputWnd, SW_SHOW);

    // Focus immediately on input field when window opens
    SetFocus(hEditDept);

    MSG msg;
    while (!g_inputDone && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Unfreeze and cleanly redraw parent after dialog is fully gone
    if (hParent) {
        EnableWindow(hParent, TRUE);
        SetForegroundWindow(hParent);
        SendMessage(hParent, WM_SETREDRAW, TRUE, 0);
        RedrawWindow(hParent, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
    }

    if (g_inputCancelled) {
        return false;
    }

    outDept = g_inputDept;
    return true;
}


// --- HELPER FUNCTIONS ---
std::string GetRegString(HKEY hKey, const std::string& subKey, const std::string& value) {
    DWORD dataSize = 0;
    if (RegGetValueA(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_SZ, nullptr, nullptr, &dataSize) != ERROR_SUCCESS) return "N/A";
    std::string data(dataSize, '\0');
    if (RegGetValueA(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_SZ, nullptr, &data[0], &dataSize) == ERROR_SUCCESS) {
        data.resize(dataSize > 0 ? dataSize - 1 : 0);
        return data;
    }
    return "N/A";
}

DWORD GetRegDword(HKEY hKey, const std::string& subKey, const std::string& value) {
    DWORD data = 0;
    DWORD dataSize = sizeof(data);
    if (RegGetValueA(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_DWORD, nullptr, &data, &dataSize) == ERROR_SUCCESS) {
        return data;
    }
    return 0;
}

std::string GetSerialNumber() {
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool needUninit = (hres == S_OK);

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );

    if (FAILED(hres)) {
        if (needUninit) CoUninitialize();
        return "N/A";
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        if (needUninit) CoUninitialize();
        return "N/A";
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT SerialNumber FROM Win32_BIOS"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        if (needUninit) CoUninitialize();
        return "N/A";
    }

    std::string serialNumber = "N/A";
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
            _bstr_t bstrVal(vtProp.bstrVal);
            std::wstring wserial((wchar_t*)bstrVal);
            serialNumber = std::string(wserial.begin(), wserial.end());
        }
        VariantClear(&vtProp);
        pclsObj->Release();
        break;
    }

    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    if (needUninit) CoUninitialize();

    // Trim whitespace
    serialNumber.erase(serialNumber.find_last_not_of(" \n\r\t") + 1);
    serialNumber.erase(0, serialNumber.find_first_not_of(" \n\r\t"));
    return serialNumber.empty() ? "N/A" : serialNumber;
}

struct SoftwareItem {
    std::string displayName;
    std::string displayVersion;
    std::string publisher;
    std::string installDate;
};

static std::string EscapeCsv(const std::string& input) {
    bool needsQuotes = false;
    std::string escaped = "";
    for (char c : input) {
        if (c == '"') {
            escaped += "\"\"";
            needsQuotes = true;
        }
        else {
            escaped += c;
            if (c == ',' || c == '\n' || c == '\r') needsQuotes = true;
        }
    }
    if (needsQuotes) {
        return "\"" + escaped + "\"";
    }
    return escaped;
}

static void CreateDir(const std::string& path) {
    CreateDirectoryA(path.c_str(), NULL);
}

static std::string GetCurrentTimestamp() {
    time_t rawtime;
    struct tm timeinfo;
    char buffer[64];
    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

static std::string GetTodayDate() {
    time_t rawtime;
    struct tm timeinfo;
    char buffer[64];
    time(&rawtime);
    localtime_s(&timeinfo, &rawtime);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d", &timeinfo);
    return std::string(buffer);
}

static std::string ReadRegString(HKEY hKeyRoot, const char* subKey, const char* valueName) {
    HKEY hKey;
    char buffer[512] = { 0 };
    DWORD dwSize = sizeof(buffer);
    if (RegOpenKeyExA(hKeyRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)buffer, &dwSize);
        RegCloseKey(hKey);
    }
    return std::string(buffer);
}

static void ScanUninstallKey(HKEY hRootKey, const char* subKeyPath, std::vector<SoftwareItem>& outSoftware) {
    HKEY hUninstallKey;
    if (RegOpenKeyExA(hRootKey, subKeyPath, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hUninstallKey) != ERROR_SUCCESS) {
        return;
    }

    DWORD dwSubKeys = 0;
    RegQueryInfoKeyA(hUninstallKey, NULL, NULL, NULL, &dwSubKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    for (DWORD i = 0; i < dwSubKeys; i++) {
        char subKeyName[256] = { 0 };
        DWORD dwNameSize = sizeof(subKeyName);
        if (RegEnumKeyExA(hUninstallKey, i, subKeyName, &dwNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hAppKey;
            std::string fullAppPath = std::string(subKeyPath) + "\\" + subKeyName;
            if (RegOpenKeyExA(hRootKey, fullAppPath.c_str(), 0, KEY_READ, &hAppKey) == ERROR_SUCCESS) {

                DWORD sysComponent = 0;
                DWORD dwSize = sizeof(DWORD);
                if (RegQueryValueExA(hAppKey, "SystemComponent", NULL, NULL, (LPBYTE)&sysComponent, &dwSize) == ERROR_SUCCESS && sysComponent == 1) {
                    RegCloseKey(hAppKey);
                    continue;
                }

                char parentKey[256] = { 0 };
                dwSize = sizeof(parentKey);
                if (RegQueryValueExA(hAppKey, "ParentKeyName", NULL, NULL, (LPBYTE)parentKey, &dwSize) == ERROR_SUCCESS && strlen(parentKey) > 0) {
                    RegCloseKey(hAppKey);
                    continue;
                }

                char displayName[512] = { 0 };
                dwSize = sizeof(displayName);
                if (RegQueryValueExA(hAppKey, "DisplayName", NULL, NULL, (LPBYTE)displayName, &dwSize) == ERROR_SUCCESS && strlen(displayName) > 0) {
                    SoftwareItem item;
                    item.displayName = displayName;

                    char version[256] = { 0 };
                    dwSize = sizeof(version);
                    RegQueryValueExA(hAppKey, "DisplayVersion", NULL, NULL, (LPBYTE)version, &dwSize);
                    item.displayVersion = version;

                    char publisher[256] = { 0 };
                    dwSize = sizeof(publisher);
                    RegQueryValueExA(hAppKey, "Publisher", NULL, NULL, (LPBYTE)publisher, &dwSize);
                    item.publisher = publisher;

                    char installDate[256] = { 0 };
                    dwSize = sizeof(installDate);
                    RegQueryValueExA(hAppKey, "InstallDate", NULL, NULL, (LPBYTE)installDate, &dwSize);
                    item.installDate = installDate;

                    outSoftware.push_back(item);
                }
                RegCloseKey(hAppKey);
            }
        }
    }
    RegCloseKey(hUninstallKey);
}

static int CollectSoftwareInventory(const std::string& hostname, const std::string& scanDate, const std::string& inventoryFolder) {
    std::vector<SoftwareItem> softwareList;

    ScanUninstallKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", softwareList);
    ScanUninstallKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", softwareList);

    if (softwareList.empty()) return 0;

    std::string softwareFolder = inventoryFolder + "\\Software Inventory";
    CreateDir(softwareFolder);

    std::string targetCsv = softwareFolder + "\\" + hostname + ".csv";
    std::string masterCsv = inventoryFolder + "\\Master_Software_Inventory.csv";
    std::string masterBkpCsv = softwareFolder + "\\Master_Software_Inventory_bkp.csv";

    std::ofstream fileTarget(targetCsv);
    if (fileTarget.is_open()) {
        fileTarget << "\"PC_Name\",\"DisplayName\",\"DisplayVersion\",\"Publisher\",\"InstallDate\",\"ScanDate\"\n";
        for (const auto& item : softwareList) {
            fileTarget << EscapeCsv(hostname) << ","
                << EscapeCsv(item.displayName) << ","
                << EscapeCsv(item.displayVersion) << ","
                << EscapeCsv(item.publisher) << ","
                << EscapeCsv(item.installDate) << ","
                << EscapeCsv(scanDate) << "\n";
        }
        fileTarget.close();
    }

    auto appendMaster = [&](const std::string& path) {
        bool exists = GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
        std::ofstream file(path, std::ios::app);
        if (file.is_open()) {
            if (!exists) {
                file << "\"PC_Name\",\"DisplayName\",\"DisplayVersion\",\"Publisher\",\"InstallDate\",\"ScanDate\"\n";
            }
            for (const auto& item : softwareList) {
                file << EscapeCsv(hostname) << ","
                    << EscapeCsv(item.displayName) << ","
                    << EscapeCsv(item.displayVersion) << ","
                    << EscapeCsv(item.publisher) << ","
                    << EscapeCsv(item.installDate) << ","
                    << EscapeCsv(scanDate) << "\n";
            }
            file.close();
        }
        };

    appendMaster(masterCsv);
    appendMaster(masterBkpCsv);

    return (int)softwareList.size();
}

static bool CollectAssetInventory(const std::string& hostname, const std::string& scanDate, const std::string& inventoryFolder, const std::string& department, const std::string& assetOwner) {
    std::string assetFolder = inventoryFolder + "\\Asset Inventory";
    CreateDir(assetFolder);

    std::string mfr = ReadRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer");
    std::string model = ReadRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName");
    std::string serial = GetSerialNumber();
    std::string cpu = ReadRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");

    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    double ramGb = 0.0;
    if (GlobalMemoryStatusEx(&statex)) {
        ramGb = (double)statex.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
    }

    std::string osName = ReadRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
    std::string buildNum = ReadRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber");
    std::string displayVer = ReadRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion");

    if (atoi(buildNum.c_str()) >= 22000) {
        size_t pos = osName.find("Windows 10");
        if (pos != std::string::npos) osName.replace(pos, 10, "Windows 11");
    }

    std::string softwareVersionStr = osName + " " + displayVer;

    char systemDetailsBuf[1024];
    snprintf(systemDetailsBuf, sizeof(systemDetailsBuf),
        "Device name: %s, Processor: %s, Installed RAM: %.2f GB, Windows Edition: %s, Windows Version: %s, OS Build: %s",
        hostname.c_str(), cpu.c_str(), ramGb, osName.c_str(), displayVer.c_str(), buildNum.c_str());

    std::string macAddresses = "";
    std::string ipAddresses = "";

    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses != NULL) {
        DWORD dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
            dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        }

        if (dwRetVal == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
            while (pCurrAddresses) {
                if (pCurrAddresses->OperStatus == IfOperStatusUp && pCurrAddresses->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
                    if (pCurrAddresses->PhysicalAddressLength > 0) {
                        char macBuf[64] = { 0 };
                        snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                            pCurrAddresses->PhysicalAddress[0], pCurrAddresses->PhysicalAddress[1],
                            pCurrAddresses->PhysicalAddress[2], pCurrAddresses->PhysicalAddress[3],
                            pCurrAddresses->PhysicalAddress[4], pCurrAddresses->PhysicalAddress[5]);
                        if (!macAddresses.empty()) macAddresses += ", ";
                        macAddresses += macBuf;
                    }

                    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                    while (pUnicast) {
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                            sockaddr_in* sa_in = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                            char ipBuf[INET_ADDRSTRLEN] = { 0 };
                            inet_ntop(AF_INET, &(sa_in->sin_addr), ipBuf, INET_ADDRSTRLEN);
                            if (strlen(ipBuf) > 0) {
                                if (!ipAddresses.empty()) ipAddresses += ", ";
                                ipAddresses += ipBuf;
                            }
                        }
                        pUnicast = pUnicast->Next;
                    }
                }
                pCurrAddresses = pCurrAddresses->Next;
            }
        }
        free(pAddresses);
    }

    std::string assetCsv = assetFolder + "\\" + hostname + "_Asset.csv";
    std::string masterAssetCsv = inventoryFolder + "\\Master_Asset_Inventory.csv";
    std::string masterAssetBkpCsv = assetFolder + "\\Master_Asset_Inventory_bkp.csv";

    std::string assetUpdatedDate = GetTodayDate();

    auto writeAssetRow = [&](std::ofstream& file) {
        file << EscapeCsv("Desktop") << ","
            << EscapeCsv(mfr) << ","
            << EscapeCsv(model) << ","
            << EscapeCsv(department) << ","
            << EscapeCsv(serial) << ","
            << EscapeCsv(macAddresses) << ","
            << EscapeCsv(systemDetailsBuf) << ","
            << EscapeCsv(ipAddresses) << ","
            << EscapeCsv(hostname) << ","
            << EscapeCsv("CONFIDENTIAL") << ","
            << "\"4\",\"4\",\"3\","
            << EscapeCsv("CRITICAL") << ","
            << EscapeCsv("ACTIVE-WORKING") << ","
            << EscapeCsv(assetOwner) << ","
            << EscapeCsv(assetUpdatedDate) << ","
            << EscapeCsv(softwareVersionStr) << ","
            << EscapeCsv(scanDate) << "\n";
        };

    std::string header = "\"Description\",\"Manufacturer\",\"Model\",\"Department\",\"SerialNumber\",\"MacAddress\",\"SystemDetails\",\"IpAddress\",\"HostName\",\"AssetClassification\",\"C\",\"I\",\"A\",\"StatusOfTheAsset\",\"StatusErrorNotes\",\"AssetOwner\",\"AssetUpdatedDate\",\"SoftwareVersion\",\"EndOfSupportLife\",\"ScanDate\"\n";

    std::ofstream f1(assetCsv);
    if (f1.is_open()) {
        f1 << header;
        writeAssetRow(f1);
        f1.close();
    }

    auto appendMasterAsset = [&](const std::string& path) {
        bool exists = GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
        std::ofstream f(path, std::ios::app);
        if (f.is_open()) {
            if (!exists) f << header;
            writeAssetRow(f);
            f.close();
        }
        };

    appendMasterAsset(masterAssetCsv);
    appendMasterAsset(masterAssetBkpCsv);

    return true;
}


// Declare external logging functions from CSCsecure.cpp
extern void LogMessage(const std::string& msg);
extern void UpdateStatus(const std::string& msg);

// --- THREAD PROCEDURE ---
static DWORD WINAPI InventoryThreadProc(LPVOID lpParam) {
    HWND hParent = (HWND)lpParam;

    std::string departmentInput;

    if (!AskUserDepartment(hParent, departmentInput)) {
        return 0;
    }

    char exePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string scriptDir(exePath);
    size_t pos = scriptDir.find_last_of("\\/");
    if (pos != std::string::npos) scriptDir = scriptDir.substr(0, pos);

    std::string inventoryFolder = scriptDir + "\\Inventory Folder";
    CreateDir(inventoryFolder);

    char hostBuf[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD hostLen = sizeof(hostBuf);
    GetComputerNameA(hostBuf, &hostLen);
    std::string hostname = hostBuf;

    std::string scanDate = GetCurrentTimestamp();

    int swCount = CollectSoftwareInventory(hostname, scanDate, inventoryFolder);
    bool assetSuccess = CollectAssetInventory(hostname, scanDate, inventoryFolder, departmentInput, "");

    char msgBuf[512];
    if (swCount > 0 || assetSuccess) {
        snprintf(msgBuf, sizeof(msgBuf), "Inventory collection completed successfully! Applications Logged: %d (Saved in \\Inventory Folder)", swCount);
        UpdateStatus(msgBuf);
        LogMessage(msgBuf);
    }
    else {
        UpdateStatus("Failed to complete inventory collection.");
        LogMessage("Failed to complete inventory collection.");
    }

    return 0;
}

void RunInventoryCollection(HWND hParent) {
    HANDLE hThread = CreateThread(NULL, 0, InventoryThreadProc, (LPVOID)hParent, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
}