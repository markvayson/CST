#pragma once
#include <windows.h>
#include <string>

// Call this from any file that includes ConfirmDialog.h
bool ShowDarkConfirmDialog(HWND hParent, const char* msg);