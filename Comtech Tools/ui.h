#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "CSCsecure.h"

extern std::string g_appProductName;
extern std::string g_appVersion;

// Expose shared controls and global UI metrics
extern std::vector<SecurityControl> g_controls;
extern HWND g_hMainWnd;
extern HWND g_hBtnSecureAll;
extern HWND g_hChkSelectAll;

#define WM_REFRESH_CONTROL_UI (WM_USER + 102)

// Functions for managing UI lifecycle
void InitializeControls();
void PerformAuditAndHighlight();
void UpdateStatus(const std::string& msg);
void UpdateSecureAllButtonText();
void ResizeToFitControls(HWND hwnd);
void LoadVersionInfoFromResource();

void UpdateControlLiveInfo(SecurityControl* pCtrl, const std::string& infoText, const std::string& status = "Applying...");
void ExecuteButtonActionWithSpinner(HWND hBtn, SecurityControl* pCtrl, std::function<void()> action);


// UI Callback Handlers
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK HoverButtonProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);