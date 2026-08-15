#pragma once

#include <windows.h>

// Audits whether network security policies (NTLMv2, SMB signing, Anonymous SAM restrictions, LDAP signing) are enforced
bool IsNetworkSecPoliciesHardened();

// Applies or reverts recommended network security registry policy configurations
void ConfigureNetworkSecPolicies(bool harden);