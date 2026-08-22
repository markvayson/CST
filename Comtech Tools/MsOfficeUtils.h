#pragma once
#include <windows.h>
#include <string>

// Checks registry to detect installed MS Office major release year/version
bool GetInstalledOfficeVersion(int& outYear, std::wstring& outVersionStr);

// Silent uninstallation of older Office versions and installation of Office 2024
void InstallOffice2024();