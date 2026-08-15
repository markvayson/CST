#pragma once
#include <windows.h>
#include <string>

bool GetWinRARVersion(std::wstring& outVersion);
std::wstring GetLatestWinRARVersionOnline();
bool IsVersionOlder(const std::wstring& installed, const std::wstring& latest);
void InstallLatestWinRAR();