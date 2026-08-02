#pragma once
#include <windows.h>

// Function declarations

extern HWND g_hBtnSearchPass;
void DrawSidebarButton(LPDRAWITEMSTRUCT pdis);
void CreateSidebarControls(HWND hwndParent);
bool IsSidebarButton(UINT ctlId);
bool HandleSidebarCommand(HWND hwnd, int wmId);
