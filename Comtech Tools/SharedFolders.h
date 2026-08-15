#pragma once

#include <windows.h>
#include <string>
#include <vector>

// Enumerates disk shared network folders, skipping administrative hidden shares ($).
// Returns true if at least one user share is found.
bool GetSystemSharedFoldersInfo(std::string& outShareNames);

// Unshares all user-defined network folder shares.
void UnshareAllFolders();