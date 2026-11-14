#pragma once

#include <windows.h>
#include <string>

// Audits local user accounts and populates active count/flag metadata
std::string GetLocalUserAccountsInfo(int& outUserCount, bool& outAllDisabled, bool& outAllPasswordsExpire,
    bool& outAnyMustChangeAtLogon, bool& outAnyCannotChangePwd, bool& outAnyLockedOut);

// Enables or disables non-essential local user accounts and toggles password expiration/settings flags
void ConfigureLocalUsers(bool disableAccounts);