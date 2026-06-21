// 802.15.4 fake Zigbee PAN decoy engine.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialise the IEEE 802.15.4 radio and start the fake-PAN beacon task.
// Reads tunables from config_get(). Runs as a lower-priority task so it only
// uses airtime/CPU the BLE decoy task leaves idle.
void decoys_154_start(void);

// Fake beacon frames transmitted in the last second (for stats/UI).
uint32_t decoys_154_rate(void);

#ifdef __cplusplus
}
#endif
