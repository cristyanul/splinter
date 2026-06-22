#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void decoys_wifi_start(void);
uint32_t decoys_wifi_rate(void);

// Pause/resume the Wi-Fi decoy's radio activity (TX flood + channel hopping)
// so a Wi-Fi mode switch (e.g. raising the SoftAP) can't collide with it.
void decoys_wifi_set_paused(bool paused);

#ifdef __cplusplus
}
#endif
