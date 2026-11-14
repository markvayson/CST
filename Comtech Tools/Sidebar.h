#pragma once
#include <windows.h>

extern HWND g_hBtnSecureAll;

void DrawSidebarButton(LPDRAWITEMSTRUCT pdis);
void CreateSidebarControls(HWND hwndParent);
bool IsSidebarButton(UINT ctlId);
bool HandleSidebarCommand(HWND hwnd, int wmId);
