#pragma once
#include "detect_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// A persisted threat-journal entry. Timestamps are relative (no RTC): `boot`
// orders events across reboots, `uptime_min` is minutes since that boot.
typedef struct {
    uint16_t boot;
    uint16_t uptime_min;
    uint8_t  kind;       // dc_tracker_t
    uint8_t  id[6];
    int8_t   rssi;
    uint16_t minutes;    // observed duration at confirmation
    uint8_t  scenes;     // scenes survived
} threat_log_t;

void     detector_start(void);
void     detector_report_sighting(const dc_sighting_t *s); // safe from task ctx
int      detector_threats(dc_threat_t *out, int max);
uint32_t detector_threat_count(void);
int      detector_radar(dc_radar_t *out, int max);
int      detector_allowlist(uint8_t (*out)[6], int max);
int      detector_kind_alerts(dc_kind_alert_t *out, int max);
int      detector_threatlog(threat_log_t *out, int max);   // newest-first
bool     detector_alert(void);   // local threat OR live peer report (drives the LED)
void     detector_allow(const uint8_t id[6], bool on);
void     detector_begin_safe(void);

#ifdef __cplusplus
}
#endif
