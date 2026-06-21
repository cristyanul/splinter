// BLE extended-advertising decoy engine.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialise NimBLE and start the decoy task. Reads tunables from config_get().
void decoys_ble_start(void);

// Successful ext-adv identity refreshes in the last second (for stats/UI).
uint32_t decoys_ble_rate(void);

#ifdef __cplusplus
}
#endif
