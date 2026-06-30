// 802.15.4 fake Zigbee PAN decoy engine.
#pragma once

#include <stdint.h>
#include "jam_core.h"

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

// Snapshot-and-reset of the 802.15.4 energy-detect and TX-health interval
// counters. Called once per 1 Hz jam tick by jam_detect. Single-reader; safe
// to call from any task (reads/zeroes only volatile scalars, no lock needed
// given the single-reader contract).
void decoys_154_drain_ed(jam_ed_sample_t *out);

#ifdef __cplusplus
}
#endif
