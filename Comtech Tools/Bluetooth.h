#ifndef BLUETOOTH_H
#define BLUETOOTH_H

#include <windows.h>

struct SecurityControl; // Forward declaration

// Checks if the physical Bluetooth radio is enabled
bool IsBluetoothEnabled();

// Enables or disables the physical Bluetooth radio
void SetBluetoothDeviceState(bool enable);

// Handles toggling Bluetooth and updating the UI state
void HandleBluetoothToggle(HWND hParent, SecurityControl* pCtrl = nullptr);

#endif // BLUETOOTH_H