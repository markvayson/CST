#include "LocalAccounts.h"
#include <lm.h>
#include <vector>

#pragma comment(lib, "netapi32.lib")

std::string GetLocalUserAccountsInfo(int& outUserCount, bool& outAllDisabled, bool& outAllPasswordsExpire,
    bool& outAnyMustChangeAtLogon, bool& outAnyCannotChangePwd, bool& outAnyLockedOut) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    outUserCount = 0;
    outAllDisabled = true;
    outAllPasswordsExpire = true;
    outAnyMustChangeAtLogon = false;
    outAnyCannotChangePwd = false;
    outAnyLockedOut = false;
    std::vector<std::string> activeUsers;

    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            if (_stricmp(userName.c_str(), "Mark") == 0) continue;

            outUserCount++;

            if ((pBuf[i].usri1_flags & UF_ACCOUNTDISABLE) == 0) {
                outAllDisabled = false;
                activeUsers.push_back(userName);
            }
            if (pBuf[i].usri1_flags & UF_DONT_EXPIRE_PASSWD) {
                outAllPasswordsExpire = false;
            }
            if (pBuf[i].usri1_flags & UF_PASSWORD_EXPIRED) {
                outAnyMustChangeAtLogon = true;
            }
            if (pBuf[i].usri1_flags & UF_PASSWD_CANT_CHANGE) {
                outAnyCannotChangePwd = true;
            }
            if (pBuf[i].usri1_flags & UF_LOCKOUT) {
                outAnyLockedOut = true;
            }
        }
        NetApiBufferFree(pBuf);
    }

    if (outUserCount == 0) return "No local user accounts detected.";

    std::string baseMsg;
    if (outAllDisabled) {
        baseMsg = "Local Accounts disabled";
    }
    else if (activeUsers.size() == 1) {
        baseMsg = activeUsers[0] + " is Active";
    }
    else {
        char buf[128];
        snprintf(buf, sizeof(buf), "(%d) Local Accounts Active", (int)activeUsers.size());
        baseMsg = std::string(buf);
    }

    std::string warn;
    if (!outAllPasswordsExpire) warn += " Password never expires set;";
    if (outAnyMustChangeAtLogon) warn += " Must change at logon set;";
    if (outAnyCannotChangePwd) warn += " Cannot change password set;";
    if (outAnyLockedOut) warn += " Account locked out;";

    int scCount = 0;
    for (char c : warn) if (c == ';') scCount++;

    if (!warn.empty()) {
        if (!warn.empty() && warn.back() == ';') warn.pop_back();
        if (!warn.empty() && warn.back() == ' ') warn.pop_back();
        std::string warnMsg = "(" + std::to_string(scCount) + ") unsecured option" + (scCount == 1 ? " set" : "s set");
        return baseMsg + "; " + warnMsg;
    }
    if (outAllDisabled) {
        return "Local Accounts disabled; no unsecured settings";
    }
    return baseMsg;
}

void ConfigureLocalUsers(bool disableAccounts) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    if (nStatus == NERR_Success && pBuf != NULL) {
        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            if (_stricmp(userName.c_str(), "Mark") == 0) continue;

            USER_INFO_1008 ui1008;
            DWORD dwParmErr = 0;

            ui1008.usri1008_flags = pBuf[i].usri1_flags;
            // Enforce: untick must-change-at-logon, cannot-change, password-never-expires, and unlock
            ui1008.usri1008_flags &= ~(UF_PASSWORD_EXPIRED | UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD | UF_LOCKOUT);
            if (disableAccounts) {
                ui1008.usri1008_flags |= UF_ACCOUNTDISABLE;
            }
            else {
                ui1008.usri1008_flags &= ~UF_ACCOUNTDISABLE;
            }
            NetUserSetInfo(NULL, wUserName.c_str(), 1008, (LPBYTE)&ui1008, &dwParmErr);
        }
        NetApiBufferFree(pBuf);
    }
}