#pragma once

#include <windows.h>
#include <string>

// Checks whether browser password saving is disabled across supported browsers and password vaults are clear
bool IsBrowserPasswordLocked();

// Checks if any browser credential files (Login Data, logins.json) contain stored data
bool AreBrowserCredentialsPresent();

// Enforces or disables browser password manager policies and purges saved passwords on lock
void ConfigureBrowserPasswordLock(bool lockPasswords);

// Safely deletes browser password credential files across user profiles
void PurgeBrowserCredentialDatabases();