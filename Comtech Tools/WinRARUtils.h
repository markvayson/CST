// WinRARUtils.h
#pragma once
#include <windows.h>
#include <string>
#include "CSCsecure.h"

extern HWND g_hMainWnd;

bool GetWinRARVersion(std::wstring& outVersion);
std::wstring GetLatestWinRARVersionOnline();
bool IsVersionOlder(const std::wstring& installed, const std::wstring& latest);
void InstallLatestWinRAR();
