#include "WifiAdapter.h"
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

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
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT); //[cite: 6]
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
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc))) {
        if (SUCCEEDED(hr)) CoUninitialize();
        return;
    }

    if (SUCCEEDED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc))) {
        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        // Target physical Wi-Fi adapters specifically
        IEnumWbemClassObject* pEnumerator = NULL;
        bstr_t query = L"SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID LIKE '%Wi-Fi%' OR AdapterTypeID = 9";

        if (SUCCEEDED(pSvc->ExecQuery(bstr_t("WQL"), query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator))) {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator) {
                pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn) break;

                VARIANT vtPath;
                pclsObj->Get(L"__RELPATH", 0, &vtPath, 0, 0);

                IWbemClassObject* pOutParams = NULL;
                const wchar_t* methodName = enable ? L"Enable" : L"Disable";

                pSvc->ExecMethod(vtPath.bstrVal, _bstr_t(methodName), 0, NULL, NULL, &pOutParams, NULL);

                if (pOutParams) pOutParams->Release();
                VariantClear(&vtPath);
                pclsObj->Release();
                break; // Stop after updating the primary Wi-Fi adapter
            }
            pEnumerator->Release();
        }
        pSvc->Release();
    }
    pLoc->Release();
    if (SUCCEEDED(hr)) CoUninitialize();
}


