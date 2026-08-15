#pragma once

#include <windows.h>
#include <string>

// Checks whether legacy protocols (TLS 1.0/1.1, SSL 3.0), weak ciphers, and weak hashes are disabled in Schannel
bool IsSslTlsHardened();

// Checks if a specific key under SCHANNEL is disabled via registry
bool CheckSchannelKeyDisabled(const char* subKey);

// Invokes IIS Crypto CLI or custom logic to configure system TLS settings
void ConfigureSslTlsIISCrypto(bool harden);

// Extracts an embedded binary resource to a file (Used for bundling IISCryptoCli/Templates)
bool ExtractResourceToFile(int resourceID, const std::wstring& outputPath);

// Executes the embedded IIS Crypto CLI utility using specified templates
bool RunEmbeddedIISCrypto(bool useCustomTemplate);