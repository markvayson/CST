#pragma once
#include <windows.h>

// Function declaration



extern HWND g_hBtnSearchPass;
extern HWND g_hBtnSecureAll;
void DrawSidebarButton(LPDRAWITEMSTRUCT pdis);
void CreateSidebarControls(HWND hwndParent);
bool IsSidebarButton(UINT ctlId);
bool HandleSidebarCommand(HWND hwnd, int wmId);
