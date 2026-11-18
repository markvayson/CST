#include "MsOfficeUtils.h"
#include <winreg.h>
#include <shellapi.h>
#include <urlmon.h>
#include <fstream>
#include <vector>

#pragma comment(lib, "urlmon.lib")

namespace {
std::wstring TrimWhitespaceOffice(const std::wstring& s) {
    const size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return L"";
    const size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool QueryRegistryStringView(HKEY root, const wchar_t* subKey, const wchar_t* valueName, REGSAM samView, std::wstring& outValue) {
    outValue.clear();
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExW(root, subKey, 0, KEY_READ | samView, &hKey);
    if (rc != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    rc = RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &dataSize);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || dataSize < sizeof(wchar_t)) {
        RegCloseKey(hKey);
        return false;
    }

    std::wstring buffer(dataSize / sizeof(wchar_t), L'\0');
    rc = RegQueryValueExW(hKey, valueName, NULL, &type, reinterpret_cast<LPBYTE>(&buffer[0]), &dataSize);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        return false;
    }

    while (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    outValue = TrimWhitespaceOffice(buffer);
    return !outValue.empty();
}

bool DirectoryExistsOffice(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0);
}
}

bool GetInstalledOfficeVersion(int& outYear, std::wstring& outVersionStr) {
    outYear = 0;
    outVersionStr = L"None";

    // Direct registry check for Click-To-Run Office installs (validate install path to ignore stale remnants)
    const wchar_t* ctrPath = L"SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration";
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
    for (REGSAM view : views) {
        std::wstring products;
        if (!QueryRegistryStringView(HKEY_LOCAL_MACHINE, ctrPath, L"ProductReleaseIds", view, products)) {
            continue;
        }

        std::wstring installationPath;
        if (!QueryRegistryStringView(HKEY_LOCAL_MACHINE, ctrPath, L"InstallationPath", view, installationPath)) {
            QueryRegistryStringView(HKEY_LOCAL_MACHINE, ctrPath, L"ClientFolder", view, installationPath);
        }
        if (!DirectoryExistsOffice(installationPath)) {
            continue;
        }

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
        else {
            outYear = 0;
            outVersionStr = L"Microsoft Office (Click-to-Run)";
        }
        return true;
    }

    // Fallback check for legacy MSI installations (verify install path still exists)
    struct LegacyCheck { const wchar_t* path; int year; const wchar_t* label; };
    const LegacyCheck versionKeys[] = {
        { L"SOFTWARE\\Microsoft\\Office\\16.0\\Common\\InstallRoot", 2021, L"Office 2016-2021" },
        { L"SOFTWARE\\Microsoft\\Office\\15.0\\Common\\InstallRoot", 2013, L"Office 2013" },
        { L"SOFTWARE\\Microsoft\\Office\\14.0\\Common\\InstallRoot", 2010, L"Office 2010" }
    };

    for (const auto& entry : versionKeys) {
        for (REGSAM view : views) {
            std::wstring installPath;
            if (QueryRegistryStringView(HKEY_LOCAL_MACHINE, entry.path, L"Path", view, installPath) && DirectoryExistsOffice(installPath)) {
                outYear = entry.year;
                outVersionStr = entry.label;
                return true;
            }
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