#ifndef NETWORK_CONNECTIONS_H
#define NETWORK_CONNECTIONS_H

// Auditing Functions
bool IsBluetoothEnabled();
bool IsWifiAdapterEnabled();

// Management Functions
void SetBluetoothDeviceState(bool enable);
void SetWifiDeviceState(bool enable);

#endif // NETWORK_CONNECTIONS_H