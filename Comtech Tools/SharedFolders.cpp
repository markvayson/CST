#include "SharedFolders.h"
#include <lm.h>
#include <sstream>

#pragma comment(lib, "netapi32.lib")

// Forward declaration for external logging if defined elsewhere in the project
void LogMessage(const std::string& msg);

bool GetSystemSharedFoldersInfo(std::string& outShareNames) {
    PSHARE_INFO_1 pBuf = NULL, pTmpBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS res;
    bool foundUserShare = false;
    outShareNames = "";

    do {
        res = NetShareEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            pTmpBuf = pBuf;
            for (DWORD i = 0; i < entriesRead; i++) {
                if ((pTmpBuf->shi1_type & STYPE_MASK) == STYPE_DISKTREE) {
                    std::wstring wShareName = pTmpBuf->shi1_netname;
                    if (!wShareName.empty() && wShareName.back() != L'$') {
                        foundUserShare = true;
                        char nameA[256] = { 0 };
                        WideCharToMultiByte(CP_ACP, 0, wShareName.c_str(), -1, nameA, sizeof(nameA), NULL, NULL);
                        if (!outShareNames.empty()) outShareNames += ", ";
                        outShareNames += nameA;
                    }
                }
                pTmpBuf++;
            }
            NetApiBufferFree(pBuf);
        }
    } while (res == ERROR_MORE_DATA);

    return foundUserShare;
}

void UnshareAllFolders() {
    PSHARE_INFO_1 pBuf = NULL, pTmpBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS res;

    do {
        res = NetShareEnum(NULL, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            pTmpBuf = pBuf;
            for (DWORD i = 0; i < entriesRead; i++) {
                if ((pTmpBuf->shi1_type & STYPE_MASK) == STYPE_DISKTREE) {
                    std::wstring wShareName = pTmpBuf->shi1_netname;
                    if (!wShareName.empty() && wShareName.back() != L'$') {
                        DWORD delRes = NetShareDel(NULL, (LMSTR)wShareName.c_str(), 0);

                        char nameA[256] = { 0 };
                        WideCharToMultiByte(CP_ACP, 0, wShareName.c_str(), -1, nameA, sizeof(nameA), NULL, NULL);

                        if (delRes == NERR_Success) {
                            LogMessage("Successfully unshared folder: " + std::string(nameA));
                        }
                        else {
                            LogMessage("Failed to unshare folder: " + std::string(nameA) + " Error code: " + std::to_string(delRes));
                        }
                    }
                }
                pTmpBuf++;
            }
            NetApiBufferFree(pBuf);
        }
    } while (res == ERROR_MORE_DATA);
}