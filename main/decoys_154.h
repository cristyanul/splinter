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

// Fake Zigbee beacon frames transmitted in the last second (for stats/UI).
uint32_t decoys_154_rate(void);

// Fake Thread/Matter frames (beacons + secured mesh data) transmitted in the
// last second. The coherent Thread home is driven from inside this task, which
// owns the 802.15.4 radio. See decoys_thread.{c,h}.
uint32_t decoys_154_thread_rate(void);

#ifdef __cplusplus
}
#endif
