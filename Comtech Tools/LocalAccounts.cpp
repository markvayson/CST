#include "LocalAccounts.h"
#include <lm.h>
#include <vector>

#pragma comment(lib, "netapi32.lib")

std::string GetLocalUserAccountsInfo(int& outUserCount, bool& outAllDisabled, bool& outAllPasswordsExpire) {
    DWORD dwRead = 0, dwTotal = 0, dwResume = 0;
    PUSER_INFO_1 pBuf = NULL;
    NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);

    outUserCount = 0;
    outAllDisabled = true;
    outAllPasswordsExpire = true;
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
        }
        NetApiBufferFree(pBuf);
    }

    if (outUserCount == 0) return "No local user accounts detected.";

    std::string baseMsg;
    if (outAllDisabled) {
        baseMsg = "Non-essential user accounts are disabled.";
    }
    else if (activeUsers.size() == 1) {
        baseMsg = activeUsers[0] + " account is currently active.";
    }
    else {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s and %d other accounts are active.", activeUsers[0].c_str(), (int)(activeUsers.size() - 1));
        baseMsg = std::string(buf);
    }

    if (!outAllPasswordsExpire) {
        if (outAllDisabled) return "Accounts disabled, but 'Password never expires' is enabled.";
        return baseMsg + " (Pass never expires is ticked).";
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
            if (disableAccounts) {
                ui1008.usri1008_flags |= UF_ACCOUNTDISABLE;
                ui1008.usri1008_flags &= ~UF_DONT_EXPIRE_PASSWD;
            }
            else {
                ui1008.usri1008_flags &= ~UF_ACCOUNTDISABLE;
            }
            NetUserSetInfo(NULL, wUserName.c_str(), 1008, (LPBYTE)&ui1008, &dwParmErr);
        }
        NetApiBufferFree(pBuf);
    }
}