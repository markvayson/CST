#pragma once
#include <windows.h>
#include <string>

// Call this from any file that includes ConfirmDialog.h
bool ShowDarkConfirmDialog(HWND hParent, const char* title, const char* msg);
bool ShowDarkPasswordDialog(HWND hParent, const char* msg);
bool ShowDarkRestartDialog(HWND hParent);
void ShowDarkMessageDialog(HWND hParent, const char* title, const char* msg);
void ShowDarkMessageDialog(HWND hParent, const char* msg);
