#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "jam_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// One journaled jamming episode (rising edge).
typedef struct {
    uint16_t boot;
    uint16_t uptime_min;
    uint8_t  band;          // jam_band_t
    int8_t   peak_energy;   // 802.15.4 ED peak (dBm)
    uint16_t peak_rate;     // Wi-Fi flood peak (MGMT frames/s)
    uint16_t duration_s;
} jam_event_t;

void jam_detect_start(void);
bool jam_detect_alert(void);
bool jam_detect_wifi_trip(void);
void jam_detect_get_status(jam_status_t *out);
int  jam_detect_journal(jam_event_t *out, int max);   // newest-first, returns count

#ifdef __cplusplus
}
#endif
