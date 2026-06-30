// tracker_id.h — classify a BLE advertisement into a commercial-tracker kind.
//
// Pure (no ESP-IDF / NimBLE deps) so it compiles on the host for unit tests,
// mirroring detect_core.c. Used by sniff_ble.c to tag sightings, and the kinds
// feed detect_core's rotation-proof, baseline-aware tracker detection.
#pragma once
#include <stdint.h>
#include "detect_core.h"   // dc_tracker_t

#ifdef __cplusplus
extern "C" {
#endif

// Walk the advertisement's AD structures ([len][type][value...]) and return the
// dc_tracker_t for the first recognized commercial tracker signature, else
// DC_TRK_NONE. Deliberately tight to avoid false positives (e.g. a Galaxy phone's
// Samsung manufacturer data is NOT a SmartTag).
uint8_t tracker_classify(const uint8_t *adv, uint8_t len);

#ifdef __cplusplus
}
#endif
