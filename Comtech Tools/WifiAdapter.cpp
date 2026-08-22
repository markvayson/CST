#include "WifiAdapter.h"
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>

#pragma comment(lib, "setupapi.lib")

#ifndef DPC_ENABLE
#define DPC_ENABLE 0x00000001
#endif
#ifndef DPC_DISABLE
#define DPC_DISABLE 0x00000002
#endif
#ifndef DCPC_GLOBAL
#define DCPC_GLOBAL 0x00000001
#endif

// Helper function to check if adapter is physical Wi-Fi
static bool IsPhysicalWifiAdapter(HDEVINFO hDevInfo, PSP_DEVINFO_DATA pDevInfoData) {
    char friendlyName[256] = { 0 };
    if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, pDevInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName, sizeof(friendlyName), NULL)) {
        if ((strstr(friendlyName, "Wi-Fi") || strstr(friendlyName, "Wireless") || strstr(friendlyName, "WLAN") || strstr(friendlyName, "802.11")) &&
            !strstr(friendlyName, "Virtual") && !strstr(friendlyName, "Direct") && !strstr(friendlyName, "Hosted") && !strstr(friendlyName, "Hyper-V")) {
            return true;
        }
    }
    return false;
}

bool IsWifiAdapterEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT | DIGCF_PROFILE); //[cite: 6]
    if (hDevInfo == INVALID_HANDLE_VALUE) return false; //[cite: 6]

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) }; //[cite: 6]
    bool wifiEnabled = false;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) { //[cite: 6]
        if (IsPhysicalWifiAdapter(hDevInfo, &devInfoData)) { //[cite: 6]
            ULONG status = 0, problem = 0; //[cite: 6]
            if (CM_Get_DevNode_Status(&status, &problem, devInfoData.DevInst, 0) == CR_SUCCESS) { //[cite: 6]
                wifiEnabled = (problem != CM_PROB_DISABLED); //[cite: 6]
            }
            break; // Stop querying immediately after checking the physical Wi-Fi adapter[cite: 6]
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo); //[cite: 6]
    return wifiEnabled;
}
void SetWifiDeviceState(bool enable) {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT | DIGCF_PROFILE);
    if (hDevInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        if (IsPhysicalWifiAdapter(hDevInfo, &devInfoData)) {
            SP_PROPCHANGE_PARAMS pcp;
            pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
            pcp.StateChange = enable ? DPC_ENABLE : DPC_DISABLE;
            pcp.Scope = DCPC_GLOBAL;
            pcp.HwProfile = 0;

            if (SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &pcp.ClassInstallHeader, sizeof(pcp))) {
                SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);
            }
            break; // Targeted action: stop after modifying the main adapter
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
}