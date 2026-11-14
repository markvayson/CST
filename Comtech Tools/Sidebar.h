#pragma once
#include <windows.h>
#include <string>

extern HWND g_hBtnSecureAll;

void DrawSidebarButton(LPDRAWITEMSTRUCT pdis);
void CreateSidebarControls(HWND hwndParent);
void LayoutSidebarControls(HWND hwndParent);
bool IsSidebarButton(UINT ctlId);
bool HandleSidebarCommand(HWND hwnd, int wmId);
std::string GetLocalIPAddress();
