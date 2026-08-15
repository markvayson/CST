#pragma once

#include <windows.h>

// Checks whether browser account sign-in and sync policies are locked across supported browsers
bool IsBrowserAccountLocked();

// Enforces or disables registry policies restricting browser account login/sync
void ConfigureBrowserAccountLock(bool lockAccounts);