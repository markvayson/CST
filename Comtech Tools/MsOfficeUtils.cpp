#include "MsOfficeUtils.h"
#include <winreg.h>
#include <shellapi.h>
#include <urlmon.h>
#include <fstream>
#include <vector>

#pragma comment(lib, "urlmon.lib")

bool GetInstalledOfficeVersion(int& outYear, std::wstring& outVersionStr) {
    outYear = 0;
    outVersionStr = L"None";
    HKEY hKey = NULL;

    // Direct registry check for Click-To-Run Office installs
    const wchar_t* ctrPath = L"SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ctrPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        wchar_t productBuf[256] = { 0 };
        DWORD dataSize = sizeof(productBuf);
        if (RegQueryValueExW(hKey, L"ProductReleaseIds", NULL, NULL, (LPBYTE)productBuf, &dataSize) == ERROR_SUCCESS) {
            std::wstring products = productBuf;
            if (products.find(L"2024") != std::wstring::npos) {
                outYear = 2024;
                outVersionStr = L"Office 2024";
            }
            else if (products.find(L"2021") != std::wstring::npos) {
                outYear = 2021;
                outVersionStr = L"Office 2021";
            }
            else if (products.find(L"2019") != std::wstring::npos) {
                outYear = 2019;
                outVersionStr = L"Office 2019";
            }
            else if (products.find(L"2016") != std::wstring::npos) {
                outYear = 2016;
                outVersionStr = L"Office 2016";
            }
            else if (products.find(L"O365") != std::wstring::npos || products.find(L"365") != std::wstring::npos) {
                outYear = 2024; // Microsoft 365 is compliant
                outVersionStr = L"Microsoft 365";
            }
            RegCloseKey(hKey);
            if (outYear > 0) return true;
        }
        RegCloseKey(hKey);
    }

    // Fallback check for legacy MSI installations
    const wchar_t* versionKeys[] = {
        L"SOFTWARE\\Microsoft\\Office\\16.0\\Common\\InstallRoot",
        L"SOFTWARE\\Microsoft\\Office\\15.0\\Common\\InstallRoot",
        L"SOFTWARE\\Microsoft\\Office\\14.0\\Common\\InstallRoot"
    };

    for (const auto& path : versionKeys) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (wcsstr(path, L"16.0")) { outYear = 2021; outVersionStr = L"Office 2016-2021"; }
            else if (wcsstr(path, L"15.0")) { outYear = 2013; outVersionStr = L"Office 2013"; }
            else if (wcsstr(path, L"14.0")) { outYear = 2010; outVersionStr = L"Office 2010"; }
            return true;
        }
    }

    return false;
}

void InstallOffice2024() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string baseDir = std::string(tempPath);

    std::string setupExePath = baseDir + "officedeploymenttool.exe";
    std::string uninstallXmlPath = baseDir + "uninstall_office.xml";
    std::string installXmlPath = baseDir + "install_office2024.xml";

    // 1. Generate local XML configurations on the fly
    std::ofstream uninstallFile(uninstallXmlPath);
    if (uninstallFile.is_open()) {
        uninstallFile << "<Configuration>\n"
            << "  <Remove All=\"TRUE\" />\n"
            << "  <Display Level=\"None\" AcceptEULA=\"TRUE\" />\n"
            << "</Configuration>\n";
        uninstallFile.close();
    }

    std::ofstream installFile(installXmlPath);
    if (installFile.is_open()) {
        installFile << "<Configuration>\n"
            << "  <Add OfficeClientEdition=\"64\" Channel=\"PerpetualVL2024\">\n"
            << "    <Product ID=\"ProPlus2024Volume\">\n"
            << "      <Language ID=\"en-us\" />\n"
            << "    </Product>\n"
            << "  </Add>\n"
            << "  <Display Level=\"None\" AcceptEULA=\"TRUE\" />\n"
            << "  <Property Name=\"AUTOACTIVATE\" Value=\"1\" />\n"
            << "</Configuration>\n";
        installFile.close();
    }

    // 2. Download Microsoft Office Deployment Tool setup directly to temp
    std::string odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-45E2-B11A-B1AC844822BF/officedeploymenttool_17328-20162.exe";
    HRESULT hr = URLDownloadToFileA(NULL, odtUrl.c_str(), setupExePath.c_str(), 0, NULL);

    if (SUCCEEDED(hr)) {
        // 3. Extract setup.exe from ODT package silently
        std::string extractCmd = "/c \"" + setupExePath + "\" /quiet /extract:\"" + baseDir + "\"";

        SHELLEXECUTEINFOA seiExtract = { sizeof(seiExtract) };
        seiExtract.cbSize = sizeof(seiExtract);
        seiExtract.lpVerb = "runas";
        seiExtract.lpFile = "cmd.exe";
        seiExtract.lpParameters = extractCmd.c_str();
        seiExtract.nShow = SW_HIDE;
        seiExtract.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExA(&seiExtract) && seiExtract.hProcess) {
            WaitForSingleObject(seiExtract.hProcess, INFINITE);
            CloseHandle(seiExtract.hProcess);
        }

        std::string extractedSetup = baseDir + "setup.exe";

        // 4. Silently uninstall older versions
        std::string uninstallCmd = "/c \"" + extractedSetup + "\" /configure \"" + uninstallXmlPath + "\"";
        SHELLEXECUTEINFOA seiUninstall = { sizeof(seiUninstall) };
        seiUninstall.cbSize = sizeof(seiUninstall);
        seiUninstall.lpVerb = "runas";
        seiUninstall.lpFile = "cmd.exe";
        seiUninstall.lpParameters = uninstallCmd.c_str();
        seiUninstall.nShow = SW_HIDE;
        seiUninstall.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExA(&seiUninstall) && seiUninstall.hProcess) {
            WaitForSingleObject(seiUninstall.hProcess, INFINITE);
            CloseHandle(seiUninstall.hProcess);
        }

        // 5. Silently install Office 2024
        std::string installCmd = "/c \"" + extractedSetup + "\" /configure \"" + installXmlPath + "\"";
        SHELLEXECUTEINFOA seiInstall = { sizeof(seiInstall) };
        seiInstall.cbSize = sizeof(seiInstall);
        seiInstall.lpVerb = "runas";
        seiInstall.lpFile = "cmd.exe";
        seiInstall.lpParameters = installCmd.c_str();
        seiInstall.nShow = SW_HIDE;
        seiInstall.fMask = SEE_MASK_NOCLOSEPROCESS;

        if (ShellExecuteExA(&seiInstall) && seiInstall.hProcess) {
            WaitForSingleObject(seiInstall.hProcess, INFINITE);
            CloseHandle(seiInstall.hProcess);
        }

        // Cleanup temporary files
        DeleteFileA(setupExePath.c_str());
        DeleteFileA(extractedSetup.c_str());
        DeleteFileA(uninstallXmlPath.c_str());
        DeleteFileA(installXmlPath.c_str());
    }

    Sleep(1000);
}