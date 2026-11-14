#include "office2024.h"
#include "ConfirmDialog.h"

#include <shellapi.h>
#include <winreg.h>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>

// Control ID for an "Office 2024" button (if hosted as a standard control in a dialog/window).
#ifndef IDC_OFFICE2024_BTN
#define IDC_OFFICE2024_BTN 3014
#endif

namespace {

std::wstring GetSystemErrorMessage(DWORD errorCode) {
    if (errorCode == 0) {
        return L"Unknown error (0).";
    }

    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD langId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

    const DWORD length = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        langId,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring message;
    if (length != 0 && buffer != nullptr) {
        message.assign(buffer, length);
        LocalFree(buffer);
    } else {
        std::wostringstream oss;
        oss << L"System error code: " << errorCode;
        message = oss.str();
    }

    while (!message.empty()) {
        const wchar_t ch = message.back();
        if (ch == L'\r' || ch == L'\n' || ch == L' ' || ch == L'\t') {
            message.pop_back();
        } else {
            break;
        }
    }

    return message;
}

std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    const int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return std::string();
    std::string result(sizeNeeded, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), &result[0], sizeNeeded, nullptr, nullptr);
    return result;
}

void ShowThemedNotice(HWND hwndParent, const std::wstring& title, const std::wstring& message) {
    const std::string titleA = WideToUtf8(title);
    const std::string msgA = WideToUtf8(message);
    ShowDarkNoticeDialog(hwndParent, titleA.c_str(), msgA.c_str());
}

void ShowError(HWND hwndParent, const std::wstring& title, const std::wstring& details) {
    ShowThemedNotice(hwndParent, title, details);
}

bool GetTempBatchPath(std::wstring& outPath) {
    wchar_t tempDir[MAX_PATH] = { 0 };
    const DWORD len = GetTempPathW(MAX_PATH, tempDir);
    if (len == 0 || len >= MAX_PATH) {
        return false;
    }
    outPath.assign(tempDir);
    if (!outPath.empty() && outPath.back() != L'\\' && outPath.back() != L'/') {
        outPath.push_back(L'\\');
    }
    outPath += L"office_install.cmd";
    return true;
}

bool WriteUtf8File(const std::wstring& filePath, const std::string& content, std::wstring& errorDetails) {
    std::ofstream out(filePath.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::wostringstream oss;
        oss << L"Failed to open temporary file for writing:\n" << filePath;
        errorDetails = oss.str();
        return false;
    }

    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out.good()) {
        out.close();
        std::wostringstream oss;
        oss << L"Failed to write temporary batch script:\n" << filePath;
        errorDetails = oss.str();
        return false;
    }

    out.close();
    if (!out.good() && out.fail()) {
        std::wostringstream oss;
        oss << L"Failed to finalize temporary batch script:\n" << filePath;
        errorDetails = oss.str();
        return false;
    }

    return true;
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return s;
}

bool QueryRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, std::wstring& outValue) {
    outValue.clear();
    DWORD dataSize = 0;
    LONG rc = RegGetValueW(root, subKey, valueName, RRF_RT_REG_SZ, nullptr, nullptr, &dataSize);
    if (rc != ERROR_SUCCESS || dataSize < sizeof(wchar_t)) {
        return false;
    }

    std::wstring buffer(dataSize / sizeof(wchar_t), L'\0');
    rc = RegGetValueW(root, subKey, valueName, RRF_RT_REG_SZ, nullptr, &buffer[0], &dataSize);
    if (rc != ERROR_SUCCESS) {
        return false;
    }

    // Trim null terminators
    while (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    outValue = buffer;
    return true;
}

bool DetectOfficeInstallation(std::wstring& outLabel, bool& outIsOffice2024) {
    outLabel.clear();
    outIsOffice2024 = false;

    // Prefer Click-to-Run configuration for modern Office (2016/2019/2021/2024/M365)
    const wchar_t* ctrPath = L"SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration";
    std::wstring productReleaseIds;
    if (QueryRegistryString(HKEY_LOCAL_MACHINE, ctrPath, L"ProductReleaseIds", productReleaseIds) && !productReleaseIds.empty()) {
        const std::wstring lower = ToLower(productReleaseIds);

        if (lower.find(L"2024") != std::wstring::npos) {
            outLabel = L"Office 2024";
            outIsOffice2024 = true;
            return true;
        }

        if (lower.find(L"2021") != std::wstring::npos) { outLabel = L"Office 2021"; return true; }
        if (lower.find(L"2019") != std::wstring::npos) { outLabel = L"Office 2019"; return true; }
        if (lower.find(L"2016") != std::wstring::npos) { outLabel = L"Office 2016"; return true; }
        if (lower.find(L"o365") != std::wstring::npos || lower.find(L"365") != std::wstring::npos) {
            outLabel = L"Microsoft 365";
            return true;
        }

        // Unknown Click-to-Run product(s) present
        outLabel = L"Microsoft Office (Click-to-Run)";
        return true;
    }

    // Fallback for legacy MSI-based Office
    HKEY hKey = nullptr;
    struct LegacyCheck { const wchar_t* path; const wchar_t* label; };
    const LegacyCheck checks[] = {
        { L"SOFTWARE\\Microsoft\\Office\\16.0\\Common\\InstallRoot", L"Office 2016/2019/2021 (MSI)" },
        { L"SOFTWARE\\Microsoft\\Office\\15.0\\Common\\InstallRoot", L"Office 2013" },
        { L"SOFTWARE\\Microsoft\\Office\\14.0\\Common\\InstallRoot", L"Office 2010" }
    };
    for (const auto& c : checks) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, c.path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            outLabel = c.label;
            outIsOffice2024 = false;
            return true;
        }
    }

    return false;
}

bool RunEmbeddedBatchScript(HWND hwndParent, const std::string& scriptContent, const std::wstring& tempFileName, const wchar_t* runAsVerb, int showCmd, std::wstring& errorDetails) {
    wchar_t tempDir[MAX_PATH] = { 0 };
    const DWORD len = GetTempPathW(MAX_PATH, tempDir);
    if (len == 0 || len >= MAX_PATH) {
        errorDetails = L"Failed to resolve the system temporary directory.";
        return false;
    }

    std::wstring scriptPath = tempDir;
    if (!scriptPath.empty() && scriptPath.back() != L'\\' && scriptPath.back() != L'/') {
        scriptPath.push_back(L'\\');
    }
    scriptPath += tempFileName;

    std::wstring writeError;
    if (!WriteUtf8File(scriptPath, scriptContent, writeError)) {
        errorDetails = writeError;
        return false;
    }

    HINSTANCE result = ShellExecuteW(
        hwndParent,
        runAsVerb,
        scriptPath.c_str(),
        nullptr,
        nullptr,
        showCmd);

    const INT_PTR code = reinterpret_cast<INT_PTR>(result);
    if (code <= 32) {
        const DWORD lastError = GetLastError();
        std::wostringstream oss;
        oss << L"Failed to launch script:\n" << scriptPath << L"\nShellExecuteW returned: " << code;
        if (code == SE_ERR_ACCESSDENIED) {
            oss << L"\n\nThe elevation request was denied or blocked.";
        }
        if (lastError != ERROR_SUCCESS) {
            oss << L"\nGetLastError: " << lastError << L" (" << GetSystemErrorMessage(lastError) << L")";
        }
        errorDetails = oss.str();
        return false;
    }

    return true;
}

bool PromptAndUninstallOffice(HWND hwndParent, const std::wstring& detectedLabel) {
    std::wostringstream prompt;
    prompt << detectedLabel << L" was detected on this PC.\n\n"
           << L"Do you want to uninstall the existing Office installation before continuing with Office 2024?";
    const bool uninstallConfirmed = ShowDarkConfirmDialog(
        hwndParent,
        "Existing Office Detected",
        WideToUtf8(prompt.str()).c_str());
    if (!uninstallConfirmed) {
        ShowThemedNotice(hwndParent, L"Office 2024", L"Office 2024 installation was cancelled.");
        return false;
    }

    // Best-effort uninstall using Office Deployment Tool (ODT) with Remove All configuration.
    // This attempts to remove existing Office products before installing Office 2024.
    const std::string uninstallScript = R"BAT(@echo off
setlocal enabledelayedexpansion

set OfficeToolURL=https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_17830-20162.exe
set TempPath=%TEMP%\OfficeInstall
set OfficeToolPath=%TempPath%\OfficeDeploymentTool.exe
set UninstallConfig=%TempPath%\Uninstall-All.xml

if not exist "%TempPath%" mkdir "%TempPath%"

echo Downloading Office Deployment Tool...
curl -o "%OfficeToolPath%" "%OfficeToolURL%" -s --fail
if errorlevel 1 (
    echo ERROR: Failed to download Office Deployment Tool.
    exit /b 1
)

echo Extracting Office Deployment Tool...
"%OfficeToolPath%" /quiet /extract:"%TempPath%"
if errorlevel 1 (
    echo ERROR: Failed to extract Office Deployment Tool.
    exit /b 1
)

echo Creating uninstall configuration...
(
    echo ^<Configuration^>
    echo   ^<Remove All="TRUE" /^>
    echo   ^<Display Level="None" AcceptEULA="TRUE" /^>
    echo ^</Configuration^>
) > "%UninstallConfig%"

echo Uninstalling existing Office installation(s)...
if exist "%TempPath%\setup.exe" (
    "%TempPath%\setup.exe" /configure "%UninstallConfig%"
) else if exist "%TempPath%\Setup.exe" (
    "%TempPath%\Setup.exe" /configure "%UninstallConfig%"
) else (
    echo ERROR: ODT setup executable not found after extraction.
    exit /b 1
)

if errorlevel 1 (
    echo ERROR: Office uninstall failed. Please check Office/ODT logs.
    exit /b 1
)

echo Uninstall completed.
exit /b 0
)BAT";

    std::wstring err;
    if (!RunEmbeddedBatchScript(hwndParent, uninstallScript, L"office_uninstall.cmd", L"runas", SW_HIDE, err)) {
        std::wostringstream details;
        details << L"Failed to start the Office uninstall process.\n\n" << err
                << L"\n\nOffice 2024 installation will not continue.";
        ShowError(hwndParent, L"Office 2024 Install Error", details.str());
        return false;
    }

    ShowThemedNotice(
        hwndParent,
        L"Office 2024",
        L"The Office uninstall process has been started.\n\n"
        L"Please wait for it to complete, then run Office 2024 installation again if needed.\n"
        L"(Automatic continuation is not performed because uninstall can take several minutes.)");
    return false; // Do not continue automatically; uninstall runs asynchronously via script
}

} // namespace

bool RunOffice2024InstallAction(HWND hwndParent) {
    // Embedded Office 2024 installation batch script.
    const std::string kOffice2024BatchScript = R"BAT(@echo off
setlocal enabledelayedexpansion

REM Define URLs and paths
set OfficeToolURL=https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_17830-20162.exe
set TempPath=%TEMP%\OfficeInstall
set OfficeToolPath=%TempPath%\OfficeDeploymentTool.exe
set Config64Bit=%TempPath%\Configuration-64bit.xml

REM Ensure the temp folder exists
if not exist "%TempPath%" mkdir "%TempPath%"

REM Download the Office Deployment Tool
echo Downloading Office Deployment Tool...
curl -o "%OfficeToolPath%" "%OfficeToolURL%" -s --fail
if errorlevel 1 (
    echo ERROR: Failed to download Office Deployment Tool.
    exit /b 1
)

REM Extract the Office Deployment Tool
echo Extracting Office Deployment Tool...
"%OfficeToolPath%" /quiet /extract:"%TempPath%"
if errorlevel 1 (
    echo ERROR: Failed to extract Office Deployment Tool.
    exit /b 1
)

REM Create the configuration file
echo Creating the configuration file...
(
    echo ^<Configuration^>
    echo   ^<Add OfficeClientEdition="64" Channel="PerpetualVL2024"^>
    echo     ^<Product ID="ProPlus2024Volume"^>
    echo       ^<Language ID="en-us" /^>
    echo     ^</Product^>
    echo   ^</Add^>
    echo   ^<RemoveMSI /^>
    echo ^</Configuration^>
) > "%Config64Bit%"

REM Run the Office setup with the configuration file
echo Running Office setup...
"%TempPath%\Setup.exe" /configure "%Config64Bit%"
if errorlevel 1 (
    echo ERROR: Installation failed. Please check the logs.
    exit /b 1
)

echo Installation completed successfully!
exit /b 0
)BAT";

    // 1) Verify existing Office installation before downloading/installing
    std::wstring detectedLabel;
    bool isOffice2024 = false;
    if (DetectOfficeInstallation(detectedLabel, isOffice2024)) {
        if (isOffice2024) {
            ShowThemedNotice(hwndParent, L"Office 2024", L"Office 2024 is already installed on this PC.");
            return true;
        }

        // Lower/different version detected: ask user if they want to uninstall it before continuing
        if (!PromptAndUninstallOffice(hwndParent, detectedLabel)) {
            // User declined uninstall, uninstall failed to start, or uninstall was started asynchronously
            return false;
        }
        // If uninstall were performed synchronously in the future, installation could continue here.
    }

    // 2) No Office 2024 detected -> proceed with embedded install script
    std::wstring errorDetails;
    if (!RunEmbeddedBatchScript(hwndParent, kOffice2024BatchScript, L"office_install.cmd", L"runas", SW_HIDE, errorDetails)) {
        std::wostringstream details;
        details << L"Failed to launch the Office 2024 installer script with elevation.\n\n" << errorDetails;
        ShowError(hwndParent, L"Office 2024 Install Error", details.str());
        return false;
    }

    return true;
}

bool HandleOffice2024Command(HWND hwndParent, UINT commandId, UINT notificationCode) {
    if (commandId != IDC_OFFICE2024_BTN) {
        return false;
    }

    // For standard button controls, BN_CLICKED is 0. Accept 0 to be permissive.
    if (notificationCode != BN_CLICKED && notificationCode != 0) {
        return false;
    }

    RunOffice2024InstallAction(hwndParent);
    return true;
}