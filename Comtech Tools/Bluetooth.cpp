#include "Bluetooth.h"
#include "ui.h"
#include "ConfirmDialog.h"

#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <bthsdpdef.h>
#include <bluetoothapis.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "bthprops.lib")


bool HasConnectedBluetoothDevices() {
    BLUETOOTH_FIND_RADIO_PARAMS radioParams = { sizeof(BLUETOOTH_FIND_RADIO_PARAMS) };
    HANDLE hRadio = NULL;
    HBLUETOOTH_RADIO_FIND hFindRadio = BluetoothFindFirstRadio(&radioParams, &hRadio);

    if (hFindRadio != NULL) {
        do {
            BLUETOOTH_DEVICE_SEARCH_PARAMS searchParams = { sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS) };
            searchParams.hRadio = hRadio; // Bind search to the explicitly found radio
            searchParams.fReturnAuthenticated = TRUE;
            searchParams.fReturnRemembered = TRUE;
            searchParams.fReturnConnected = TRUE;
            searchParams.fReturnUnknown = FALSE;
            searchParams.fIssueInquiry = FALSE;
            searchParams.cTimeoutMultiplier = 1;

            BLUETOOTH_DEVICE_INFO deviceInfo = { sizeof(BLUETOOTH_DEVICE_INFO) };
            HBLUETOOTH_DEVICE_FIND hFindDevice = BluetoothFindFirstDevice(&searchParams, &deviceInfo);

            if (hFindDevice != NULL) {
                do {
                    if (deviceInfo.fConnected) {
                        BluetoothFindDeviceClose(hFindDevice);
                        CloseHandle(hRadio);
                        BluetoothFindRadioClose(hFindRadio);
                        return true;
                    }
                } while (BluetoothFindNextDevice(hFindDevice, &deviceInfo));

                BluetoothFindDeviceClose(hFindDevice);
            }
            CloseHandle(hRadio); // Close the radio handle after searching it
        } while (BluetoothFindNextRadio(hFindRadio, &hRadio));

        BluetoothFindRadioClose(hFindRadio);
    }
    return false;
}


void HandleBluetoothToggle(HWND hParent, SecurityControl* pCtrl) {
    bool isCurrentlyEnabled = IsBluetoothEnabled();

    // Check for active connected Bluetooth devices before disabling
    if (isCurrentlyEnabled && HasConnectedBluetoothDevices()) {
        const char* warningMsg =
            "Connected Bluetooth devices detected!\n\n"
            "Please manually turn off Bluetooth in Windows settings "
            "to proceed with disabling the Bluetooth adapter.";

        ShowDarkNoticeDialog(hParent, "Action Required", warningMsg);

        // Reset control status and re-enable application controls if action is aborted
        if (pCtrl) {
            pCtrl->statusLabel = "";
            PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
        }
        return;
    }

    bool targetEnableState = !isCurrentlyEnabled;

    if (pCtrl && pCtrl->hBtnAction) {
        UpdateControlLiveInfo(pCtrl, targetEnableState ? "Enabling Bluetooth..." : "Disabling Bluetooth...");

        ExecuteButtonActionWithSpinner(pCtrl->hBtnAction, pCtrl, [pCtrl, targetEnableState]() {
            SetBluetoothDeviceState(targetEnableState);

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            pCtrl->statusLabel = "";
            PostMessage(g_hMainWnd, WM_REFRESH_CONTROL_UI, 0, (LPARAM)pCtrl);
            });
    }
    else {
        SetBluetoothDeviceState(targetEnableState);
    }
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