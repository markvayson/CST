#include "WifiAdapter.h"
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <bluetoothapis.h>

#include <devguid.h>
#include <winsvc.h>
#include <string>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Bthprops.lib")

#ifndef DPC_ENABLE
#define DPC_ENABLE 0x00000001
#endif
#ifndef DPC_DISABLE
#define DPC_DISABLE 0x00000002
#endif
#ifndef DCPC_GLOBAL
#define DCPC_GLOBAL 0x00000001
#endif





bool IsWifiAdapterEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    bool foundPhysicalWifi = false, wifiEnabled = false;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        char friendlyName[256] = { 0 };
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName, sizeof(friendlyName), NULL)) {
            if ((strstr(friendlyName, "Wi-Fi") || strstr(friendlyName, "Wireless") || strstr(friendlyName, "WLAN") || strstr(friendlyName, "802.11")) &&
                !strstr(friendlyName, "Virtual") && !strstr(friendlyName, "Direct") && !strstr(friendlyName, "Hosted")) {

                foundPhysicalWifi = true;
                ULONG status = 0, problem = 0;
                if (CM_Get_DevNode_Status(&status, &problem, devInfoData.DevInst, 0) == CR_SUCCESS) {
                    if (problem != CM_PROB_DISABLED) {
                        wifiEnabled = true;
                        break;
                    }
                }
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return foundPhysicalWifi ? wifiEnabled : false;

}

void SetWifiDeviceState(bool enable) {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
            char friendlyName[256] = { 0 };
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName, sizeof(friendlyName), NULL)) {
                if ((strstr(friendlyName, "Wi-Fi") || strstr(friendlyName, "Wireless") || strstr(friendlyName, "WLAN") || strstr(friendlyName, "802.11")) &&
                    !strstr(friendlyName, "Virtual") && !strstr(friendlyName, "Direct") && !strstr(friendlyName, "Hosted")) {

                    SP_PROPCHANGE_PARAMS pcp;
                    pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
                    pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
                    pcp.StateChange = enable ? DPC_ENABLE : DPC_DISABLE;
                    pcp.Scope = DCPC_GLOBAL;
                    pcp.HwProfile = 0;

                    if (SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &pcp.ClassInstallHeader, sizeof(pcp))) {
                        SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);
                    }
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
}