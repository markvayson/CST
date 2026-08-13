#pragma concept
#ifndef BLUETOOTH_H
#define BLUETOOTH_H

#include <windows.h> // <--- ADD THIS INCLUDE

// Checks if the physical Bluetooth radio is enabled
bool IsBluetoothEnabled();

// Enables or disables the physical Bluetooth radio
void SetBluetoothDeviceState(bool enable);

void HandleBluetoothToggle(HWND hParent);

#endif // BLUETOOTH_H