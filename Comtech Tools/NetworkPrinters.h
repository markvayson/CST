#pragma once

#include <string>
#include <vector>

struct PrinterStatus {
    std::string name;
    std::string shareName;
    bool isShared = false;
};

std::vector<PrinterStatus> GetSystemPrintersInfo();
bool IsSpoolerClientConnectionsDisabled();
void SetSpoolerClientConnectionsPolicy(bool disableConnections);
void UnshareAllPrinters();
void OnLockdownPrintersButtonClicked();
void OnRevertPrintersButtonClicked();