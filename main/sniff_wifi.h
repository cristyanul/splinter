#pragma once
#include "jam_core.h"
#ifdef __cplusplus
extern "C" {
#endif
void sniff_wifi_start(void);
void sniff_wifi_drain_health(jam_wifi_sample_t *out);
#ifdef __cplusplus
}
#endif
