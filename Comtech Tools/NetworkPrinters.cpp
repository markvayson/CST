#include "NetworkPrinters.h"
#include <windows.h>
#include <winspool.h>
#include <userenv.h>
#include <vector>
#include <string>


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
        }
        else {
            RegDeleteValueW(hKey, L"RegisterSpoolerRemoteRpcEndPoint");
       }
        RegCloseKey(hKey);
    }
    else {
        return;
    }

    RefreshPolicyEx(TRUE, RP_FORCE);

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
                    }
                    ClosePrinter(hPrinter);
                }
                else {
                    DWORD err = GetLastError();
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