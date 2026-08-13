#include "Bluetooth.h"
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <bthsdpdef.h>
#include <bluetoothapis.h> // Required for checking connected BT devices

#include "ConfirmDialog.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "bthprops.lib") // Required for BluetoothFindFirstDevice

// Helper function to check if any Bluetooth device is actively connected
bool HasConnectedBluetoothDevices() {
    BLUETOOTH_DEVICE_SEARCH_PARAMS searchParams = { sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS) };
    searchParams.fReturnAuthenticated = TRUE;
    searchParams.fReturnRemembered = TRUE;
    searchParams.fReturnConnected = TRUE; // Only check active connections
    searchParams.fReturnUnknown = FALSE;
    searchParams.fIssueInquiry = FALSE; // Fast check without active scanning
    searchParams.cTimeoutMultiplier = 1;

    BLUETOOTH_DEVICE_INFO deviceInfo = { sizeof(BLUETOOTH_DEVICE_INFO) };
    HBLUETOOTH_DEVICE_FIND hFind = BluetoothFindFirstDevice(&searchParams, &deviceInfo);

    if (hFind != NULL) {
        do {
            if (deviceInfo.fConnected) {
                BluetoothFindDeviceClose(hFind);
                return true; // Found at least one connected device
            }
        } while (BluetoothFindNextDevice(hFind, &deviceInfo));

        BluetoothFindDeviceClose(hFind);
    }
    return false;
}

void HandleBluetoothToggle(HWND hParent) {
    // If Bluetooth is enabled, check for connected devices
    if (IsBluetoothEnabled()) {
        if (HasConnectedBluetoothDevices()) {
            const char* warningMsg =
                "Connected Bluetooth devices detected!\n\n"
                "Please manually turn off Bluetooth in Windows settings "
                "before clicking this button.";

            // Show OK-only dialog to instruct user to turn it off manually
            ShowDarkMessageDialog(
                hParent,
                "Bluetooth Action Required",
                warningMsg
            );
            return; // Exit without toggling state
        }
    }

    // No active connected devices (or turning Bluetooth back on), proceed with toggle
    bool isCurrentlySecured = !IsBluetoothEnabled(); // If disabled, we want to enable (true)
    SetBluetoothDeviceState(isCurrentlySecured);
}

bool IsBluetoothEnabled() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_BLUETOOTH, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
    bool anyEnabled = false, foundRadio = false;

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        ULONG status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, devInfoData.DevInst, 0) == CR_SUCCESS) {
            foundRadio = true;
            if (problem != CM_PROB_DISABLED) {
                anyEnabled = true;
                break;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return foundRadio ? anyEnabled : false;
}

void SetBluetoothDeviceState(bool enable) {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_BLUETOOTH, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
            SP_PROPCHANGE_PARAMS pcp = { 0 };
            pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;

            pcp.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;
            pcp.Scope = DICS_FLAG_GLOBAL;
            pcp.HwProfile = 0;

            if (SetupDiSetClassInstallParams(hDevInfo, &devInfoData, &pcp.ClassInstallHeader, sizeof(pcp))) {
                SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &devInfoData);
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
}