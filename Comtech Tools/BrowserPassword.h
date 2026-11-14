#pragma once

#include <windows.h>
#include <string>

// Checks whether browser password saving is disabled by policy for supported browsers
bool IsBrowserPasswordLocked();

// Checks if any browser credential/password files exist on disk for any local user/profile
bool AreBrowserCredentialsPresent();

// Enforces or disables browser password manager policies and purges saved passwords on lock
void ConfigureBrowserPasswordLock(bool lockPasswords);
