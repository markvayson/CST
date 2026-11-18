#include "LocalAccounts.h"
#include <lm.h>
#include <string>
#include <vector>

#pragma comment(lib, "netapi32.lib")

std::string GetLocalUserAccountsInfo(int& outUserCount, bool& outAllDisabled, bool& outAllPasswordsExpire,
    bool& outAnyMustChangeAtLogon, bool& outAnyCannotChangePwd, bool& outAnyLockedOut) {
    outUserCount = 0;
    outAllDisabled = true;
    outAllPasswordsExpire = true;
    outAnyMustChangeAtLogon = false;
    outAnyCannotChangePwd = false;
    outAnyLockedOut = false;
    std::vector<std::string> activeUsers;

    DWORD dwResume = 0;
    for (;;) {
        PUSER_INFO_1 pBuf = NULL;
        DWORD dwRead = 0, dwTotal = 0;
        NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);
        if (!(nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) || pBuf == NULL) {
            if (pBuf != NULL) NetApiBufferFree(pBuf);
            break;
        }

        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            std::string userName(wUserName.begin(), wUserName.end());

            outUserCount++;

            if ((pBuf[i].usri1_flags & UF_ACCOUNTDISABLE) == 0) {
                outAllDisabled = false;
                activeUsers.push_back(userName);
            }
            if (pBuf[i].usri1_flags & UF_DONT_EXPIRE_PASSWD) {
                outAllPasswordsExpire = false;
            }
            if (pBuf[i].usri1_flags & UF_PASSWD_CANT_CHANGE) {
                outAnyCannotChangePwd = true;
            }
            if (pBuf[i].usri1_flags & UF_LOCKOUT) {
                outAnyLockedOut = true;
            }

            PUSER_INFO_4 pInfo4 = NULL;
            if (NetUserGetInfo(NULL, wUserName.c_str(), 4, (LPBYTE*)&pInfo4) == NERR_Success && pInfo4 != NULL) {
                if (pInfo4->usri4_password_expired != 0) {
                    outAnyMustChangeAtLogon = true;
                }
                NetApiBufferFree(pInfo4);
            }
        }

        NetApiBufferFree(pBuf);
        if (nStatus == NERR_Success) {
            break;
        }
    }

    if (outUserCount == 0) return "No local accounts found";

    std::string baseMsg;
    if (outAllDisabled) {
        baseMsg = "Local accounts disabled";
    }
    else if (activeUsers.size() == 1) {
        baseMsg = activeUsers[0] + " active";
    }
    else {
        baseMsg = "Multiple local accounts active";
    }

    std::vector<std::string> issues;
    if (!outAllPasswordsExpire) issues.push_back("Pwd never expires");
    if (outAnyMustChangeAtLogon) issues.push_back("Must change pwd");
    if (outAnyCannotChangePwd) issues.push_back("Can't change pwd");
    if (outAnyLockedOut) issues.push_back("Locked out");

    if (outAllDisabled && !issues.empty()) {
        std::string msg;
        for (size_t i = 0; i < issues.size(); i++) {
            std::string next = msg.empty() ? issues[i] : msg + ", " + issues[i];
            if (next.size() <= 50) {
                msg = next;
            }
            else {
                std::string more = "+" + std::to_string(issues.size() - i) + " more";
                std::string withMore = msg.empty() ? more : msg + ", " + more;
                if (withMore.size() <= 50) {
                    msg = withMore;
                }
                else if (msg.empty()) {
                    msg = more.substr(0, 50);
                }
                break;
            }
        }
        if (msg.empty() && !issues.empty()) {
            msg = issues[0];
            if (msg.size() > 50) msg = msg.substr(0, 47) + "...";
        }
        return msg;
    }

    if (baseMsg.size() > 50) {
        baseMsg = baseMsg.substr(0, 47) + "...";
    }
    return baseMsg;
}

void ConfigureLocalUsers(bool disableAccounts) {
    DWORD dwResume = 0;
    for (;;) {
        PUSER_INFO_1 pBuf = NULL;
        DWORD dwRead = 0, dwTotal = 0;
        NET_API_STATUS nStatus = NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwRead, &dwTotal, &dwResume);
        if (!(nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) || pBuf == NULL) {
            if (pBuf != NULL) NetApiBufferFree(pBuf);
            break;
        }

        for (DWORD i = 0; i < dwRead; i++) {
            std::wstring wUserName = pBuf[i].usri1_name;
            DWORD dwParmErr = 0;

            USER_INFO_1008 ui1008;
            ui1008.usri1008_flags = pBuf[i].usri1_flags;
            // Unset: must-change-at-logon flag bit (if present), cannot-change, password-never-expires, and lockout
            ui1008.usri1008_flags &= ~(UF_PASSWORD_EXPIRED | UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD | UF_LOCKOUT);
            if (disableAccounts) {
                ui1008.usri1008_flags |= UF_ACCOUNTDISABLE;
            }
            else {
                ui1008.usri1008_flags &= ~UF_ACCOUNTDISABLE;
            }
            NetUserSetInfo(NULL, wUserName.c_str(), 1008, (LPBYTE)&ui1008, &dwParmErr);

            PUSER_INFO_4 pInfo4 = NULL;
            if (NetUserGetInfo(NULL, wUserName.c_str(), 4, (LPBYTE*)&pInfo4) == NERR_Success && pInfo4 != NULL) {
                if (pInfo4->usri4_password_expired != 0) {
                    pInfo4->usri4_password_expired = 0;
                    NetUserSetInfo(NULL, wUserName.c_str(), 4, (LPBYTE)pInfo4, &dwParmErr);
                }
                NetApiBufferFree(pInfo4);
            }
        }

        NetApiBufferFree(pBuf);
        if (nStatus == NERR_Success) {
            break;
        }
    }
}
