#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

// Executes the test activation action (launches a PowerShell window with a harmless message).
// Returns true on success, false on failure. On failure, an error message box is shown.
bool RunActivationAction(HWND hwndParent);

// Handles WM_COMMAND for the Activation button/control.
// Returns true if the command was handled, false otherwise.
bool HandleActivationCommand(HWND hwndParent, UINT commandId, UINT notificationCode);