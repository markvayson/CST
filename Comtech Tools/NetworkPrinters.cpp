#include "NetworkPrinters.h"
#include <windows.h>
#include <winspool.h>
#include <userenv.h>
#include <vector>
#include <string>

// Forward declarations for external logging and helper functions
void LogMessage(const std::string& msg);
bool RestartWin32Service(const char* serviceName);

std::vector<PrinterStatus> GetSystemPrintersInfo() {
    std::vector<PrinterStatus> printerList;
    DWORD cbNeeded = 0, cReturned = 0;

    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, NULL, 0, &cbNeeded, &cReturned);
    if (cbNeeded == 0) return printerList;

    std::vector<BYTE> buffer(cbNeeded);
    if (EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, buffer.data(), cbNeeded, &cbNeeded, &cReturned)) {
        PRINTER_INFO_2A* pPrinterInfo = reinterpret_cast<PRINTER_INFO_2A*>(buffer.data());

        for (DWORD i = 0; i < cReturned; i++) {
            PrinterStatus status;
            status.name = pPrinterInfo[i].pPrinterName ? pPrinterInfo[i].pPrinterName : "Unknown Printer";
            status.isShared = (pPrinterInfo[i].Attributes & PRINTER_ATTRIBUTE_SHARED) != 0;
            status.shareName = (status.isShared && pPrinterInfo[i].pShareName) ? pPrinterInfo[i].pShareName : "";
            printerList.push_back(status);
        }
    }
    return printerList;
}

bool IsSpoolerClientConnectionsDisabled() {
    HKEY hKey;
    DWORD value = 0;
    DWORD dwSize = sizeof(DWORD);
    LPCWSTR subKey = L"Software\\Policies\\Microsoft\\Windows NT\\Printers";

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"RegisterSpoolerRemoteRpcEndPoint", NULL, NULL, (LPBYTE)&value, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (value == 2);
        }
        RegCloseKey(hKey);
    }
    return false;
}

void SetSpoolerClientConnectionsPolicy(bool disableConnections) {
    HKEY hKey;
    LPCWSTR subKey = L"Software\\Policies\\Microsoft\\Windows NT\\Printers";

    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (status == ERROR_SUCCESS) {
        if (disableConnections) {
            DWORD value = 2;
            RegSetValueExW(hKey, L"RegisterSpoolerRemoteRpcEndPoint", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
            LogMessage("Policy 'Allow Print Spooler to accept client connections' set to Disabled.");
        }
        else {
            RegDeleteValueW(hKey, L"RegisterSpoolerRemoteRpcEndPoint");
            LogMessage("Policy 'Allow Print Spooler to accept client connections' reverted to Not Configured.");
        }
        RegCloseKey(hKey);
    }
    else {
        LogMessage("Failed to open or create registry key for Printer policies. Run as Administrator.");
        return;
    }

    LogMessage("Refreshing machine policy natively...");
    RefreshPolicyEx(TRUE, RP_FORCE);

    LogMessage("Restarting Print Spooler service natively...");
    if (RestartWin32Service("Spooler")) {
        LogMessage("Spooler client connection policy applied successfully.");
    }
    else {
        LogMessage("Failed to restart Spooler service natively.");
    }
}

void UnshareAllPrinters() {
    DWORD cbNeeded = 0, cReturned = 0;
    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, NULL, 0, &cbNeeded, &cReturned);
    if (cbNeeded == 0) return;

    std::vector<BYTE> buffer(cbNeeded);
    if (EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 2, buffer.data(), cbNeeded, &cbNeeded, &cReturned)) {
        PRINTER_INFO_2A* pPrinterInfo = reinterpret_cast<PRINTER_INFO_2A*>(buffer.data());

        for (DWORD i = 0; i < cReturned; i++) {
            if (pPrinterInfo[i].Attributes & PRINTER_ATTRIBUTE_SHARED) {
                HANDLE hPrinter = NULL;
                PRINTER_DEFAULTSA pd = { NULL, NULL, PRINTER_ACCESS_ADMINISTER };

                if (OpenPrinterA(pPrinterInfo[i].pPrinterName, &hPrinter, &pd)) {
                    pPrinterInfo[i].Attributes &= ~PRINTER_ATTRIBUTE_SHARED;
                    pPrinterInfo[i].pDevMode = NULL;
                    pPrinterInfo[i].pSecurityDescriptor = NULL;

                    if (!SetPrinterA(hPrinter, 2, (LPBYTE)&pPrinterInfo[i], 0)) {
                        DWORD err = GetLastError();
                        LogMessage("Failed to unshare printer: " + std::string(pPrinterInfo[i].pPrinterName) + " Error code: " + std::to_string(err));
                    }
                    else {
                        LogMessage("Successfully unshared printer: " + std::string(pPrinterInfo[i].pPrinterName));
                    }
                    ClosePrinter(hPrinter);
                }
                else {
                    DWORD err = GetLastError();
                    LogMessage("Failed to open printer: " + std::string(pPrinterInfo[i].pPrinterName) + " Error code: " + std::to_string(err));
                }
            }
        }
    }
}

void OnLockdownPrintersButtonClicked() {
    UnshareAllPrinters();
    SetSpoolerClientConnectionsPolicy(true);
}

void OnRevertPrintersButtonClicked() {
    SetSpoolerClientConnectionsPolicy(false);
}