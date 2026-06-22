#pragma once
#include "detect_core.h"

#ifdef __cplusplus
extern "C" {
#endif

void     detector_start(void);
void     detector_report_sighting(const dc_sighting_t *s); // safe from task ctx
int      detector_threats(dc_threat_t *out, int max);
uint32_t detector_threat_count(void);
int      detector_radar(dc_radar_t *out, int max);
int      detector_allowlist(uint8_t (*out)[6], int max);
void     detector_allow(const uint8_t id[6], bool on);
void     detector_begin_safe(void);

#ifdef __cplusplus
}
#endif
