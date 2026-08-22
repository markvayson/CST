#pragma once
#pragma once
#include <windows.h>

#define ID_BTN_REFRESH 1007

extern HWND g_hBtnRefresh;

// Creates the owner-drawn Refresh button control
void CreateRefreshButton(HWND hParentWnd);

// Handles custom dark-mode drawing for the button
bool DrawRefreshButton(LPDRAWITEMSTRUCT pdis);

// Executes smooth zero-flicker app restart
void ExecuteAppRefresh(HWND hCurrentWnd);