#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

// Executes the Office 2024 installation action (writes embedded batch script to temp and runs it elevated).
// Returns true if the elevated launch request was successfully handed to ShellExecuteW, false otherwise.
bool RunOffice2024InstallAction(HWND hwndParent);

// Handles WM_COMMAND for the Office 2024 button/control.
// Returns true if the command was handled, false otherwise.
bool HandleOffice2024Command(HWND hwndParent, UINT commandId, UINT notificationCode);