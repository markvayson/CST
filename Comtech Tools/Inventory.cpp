#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "Inventory.h"
#include <time.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

// --- CUSTOM DUAL INPUT BOX WNDPROC ---
static std::string g_inputDept;
static std::string g_inputOwner;
static bool g_inputDone = false;
static bool g_inputCancelled = false;
static HWND hEditDept;
static HWND hEditOwner;

static LRESULT CALLBACK InputBoxProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) { // OK Button
            char buf1[256] = { 0 };
            char buf2[256] = { 0 };
            GetWindowTextA(hEditDept, buf1, sizeof(buf1));
            GetWindowTextA(hEditOwner, buf2, sizeof(buf2));

            // Check for empty inputs
            if (strlen(buf1) == 0 || strlen(buf2) == 0) {
                MessageBoxA(hwnd, "Please enter both Department and Asset Owner.", "Input Required", MB_OK | MB_ICONWARNING);
                return 0; // Halt and wait for user
            }

            g_inputDept = buf1;
            g_inputOwner = buf2;
            g_inputDone = true;
            g_inputCancelled = false;
            DestroyWindow(hwnd);
        }
        break;
    case WM_CLOSE: // User clicked the X button
        g_inputDone = true;
        g_inputCancelled = true;
        DestroyWindow(hwnd);
        break;
    default:
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}
static bool AskUserDepartmentAndOwner(HWND hParent, std::string& outDept, std::string& outOwner) {
    g_inputDept = "";
    g_inputOwner = "";
    g_inputDone = false;
    g_inputCancelled = false; // Reset flag

    // 1. Register the Window Class
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = InputBoxProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "CustomInputDialog";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    // 2. Create the Window
    HWND hInputWnd = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "CustomInputDialog", "Enter Inventory Details",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        0, 0, 320, 200, hParent, NULL, GetModuleHandle(NULL), NULL);

    // Center the window relative to parent
    if (hParent) {
        RECT rcParent; GetWindowRect(hParent, &rcParent);
        SetWindowPos(hInputWnd, NULL,
            rcParent.left + (rcParent.right - rcParent.left) / 2 - 160,
            rcParent.top + (rcParent.bottom - rcParent.top) / 2 - 100,
            0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }

    // 3. Create Controls (Labels, Textboxes, Button)
    CreateWindowA("STATIC", "Department:", WS_VISIBLE | WS_CHILD, 20, 20, 100, 20, hInputWnd, NULL, NULL, NULL);
    hEditDept = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 120, 20, 150, 20, hInputWnd, NULL, NULL, NULL);

    CreateWindowA("STATIC", "Asset Owner:", WS_VISIBLE | WS_CHILD, 20, 60, 100, 20, hInputWnd, NULL, NULL, NULL);
    hEditOwner = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 120, 60, 150, 20, hInputWnd, NULL, NULL, NULL);

    CreateWindowA("BUTTON", "OK", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 110, 110, 80, 30, hInputWnd, (HMENU)1, NULL, NULL);

    // Disable parent to make it modal
    if (hParent) EnableWindow(hParent, FALSE);

    // 4. Message Loop (Halts execution here until user clicks OK or Close)
    MSG msg;
    while (!g_inputDone && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Restore parent window
    if (hParent) {
        EnableWindow(hParent, TRUE);
        SetForegroundWindow(hParent);
    }

    // If user clicked X, abort
    if (g_inputCancelled) {
        return false;
    }

    outDept = g_inputDept;
    outOwner = g_inputOwner;
    return true;
}

// Helper to read Registry Strings
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

// Helper to read Registry DWORDs
DWORD GetRegDword(HKEY hKey, const std::string& subKey, const std::string& value) {
    DWORD data = 0;
    DWORD dataSize = sizeof(data);
    if (RegGetValueA(hKey, subKey.c_str(), value.c_str(), RRF_RT_REG_DWORD, nullptr, &data, &dataSize) == ERROR_SUCCESS) {
        return data;
    }
    return 0;
}

// Helper to execute PowerShell silently using Windows API to prevent CMD window from popping up
std::string GetSerialNumber() {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "N/A";

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE; // Prevents the CMD window from popping up

    PROCESS_INFORMATION pi;
    char cmd[] = "powershell -NoProfile -Command \"(Get-CimInstance Win32_BIOS).SerialNumber\"";

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "N/A";
    }
    CloseHandle(hWrite); // Close write end so ReadFile unblocks when process exits

    std::string result = "";
    char buffer[128];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }

    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    result.erase(result.find_last_not_of(" \n\r\t") + 1); // Trim whitespace
    return result.empty() ? "N/A" : result;
}

struct SoftwareItem {
    std::string displayName;
    std::string displayVersion;
    std::string publisher;
    std::string installDate;
};

// Helper: Format CSV fields safely
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

// Scans Windows Uninstall registry keys for installed software
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

                // Exclude SystemComponent == 1
                DWORD sysComponent = 0;
                DWORD dwSize = sizeof(DWORD);
                if (RegQueryValueExA(hAppKey, "SystemComponent", NULL, NULL, (LPBYTE)&sysComponent, &dwSize) == ERROR_SUCCESS && sysComponent == 1) {
                    RegCloseKey(hAppKey);
                    continue;
                }

                // Exclude items with ParentKeyName
                char parentKey[256] = { 0 };
                dwSize = sizeof(parentKey);
                if (RegQueryValueExA(hAppKey, "ParentKeyName", NULL, NULL, (LPBYTE)parentKey, &dwSize) == ERROR_SUCCESS && strlen(parentKey) > 0) {
                    RegCloseKey(hAppKey);
                    continue;
                }

                // Must have a DisplayName
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

// Generates Software Inventory CSV files
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

// Generates Asset / Hardware Inventory CSV files
static bool CollectAssetInventory(const std::string& hostname, const std::string& scanDate, const std::string& inventoryFolder, const std::string& department, const std::string& assetOwner) {
    std::string assetFolder = inventoryFolder + "\\Asset Inventory";
    CreateDir(assetFolder);

    std::string mfr = ReadRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer");
    std::string model = ReadRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName");
    std::string serial = GetSerialNumber();
    std::string cpu = ReadRegString(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString");

    // Get Total RAM
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    double ramGb = 0.0;
    if (GlobalMemoryStatusEx(&statex)) {
        ramGb = (double)statex.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
    }

    // Query OS Details
    std::string osName = ReadRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
    std::string buildNum = ReadRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber");
    std::string displayVer = ReadRegString(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion");

    // Fix osName if running Windows 11 but registering as Windows 10
    if (atoi(buildNum.c_str()) >= 22000) {
        size_t pos = osName.find("Windows 10");
        if (pos != std::string::npos) osName.replace(pos, 10, "Windows 11");
    }

    std::string softwareVersionStr = osName + " " + displayVer;

    // Formatting Complete System Details uses osName instead of editionID, removed DeviceID, ProductID, and InstallDate
    char systemDetailsBuf[1024];
    snprintf(systemDetailsBuf, sizeof(systemDetailsBuf),
        "Device name: %s, Processor: %s, Installed RAM: %.2f GB, Windows Edition: %s, Windows Version: %s, OS Build: %s",
        hostname.c_str(), cpu.c_str(), ramGb, osName.c_str(), displayVer.c_str(), buildNum.c_str());

    // Query active IP & MAC Addresses via IPHLPAPI
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
                        snprintf(macBuf, sizeof(macBuf), "%02X-%02X-%02X-%02X-%02X-%02X",
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

static DWORD WINAPI InventoryThreadProc(LPVOID lpParam) {
    HWND hParent = (HWND)lpParam;

    std::string departmentInput;
    std::string ownerInput;

    if (!AskUserDepartmentAndOwner(hParent, departmentInput, ownerInput)) {
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
    bool assetSuccess = CollectAssetInventory(hostname, scanDate, inventoryFolder, departmentInput, ownerInput);

    char msgBuf[512];
    if (swCount > 0 || assetSuccess) {
        snprintf(msgBuf, sizeof(msgBuf), "Inventory collection completed successfully!\n\nApplications Logged: %d\nSaved in: \\Inventory Folder", swCount);
        MessageBoxA(hParent, msgBuf, "CSCsecure Inventory", MB_OK | MB_ICONINFORMATION);
    }
    else {
        MessageBoxA(hParent, "Failed to complete inventory collection.", "Error", MB_OK | MB_ICONERROR);
    }

    return 0;
}

void RunInventoryCollection(HWND hParent) {
    HANDLE hThread = CreateThread(NULL, 0, InventoryThreadProc, (LPVOID)hParent, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
}