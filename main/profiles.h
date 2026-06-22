#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Start the dynamic "breathing" density task. Safe to call unconditionally:
// it idles cheaply while profiles_enabled is false and reacts live to the
// toggle, so density modulation can be turned on/off from the web UI without
// a reboot.
void profiles_start(void);

// Current density multiplier, fixed-point x100 (100 = 1.0x = densest/base).
uint32_t profiles_density_x100(void);

// Scale a base inter-frame interval (ms) by the current density multiplier,
// clamped to >= min_ms. Decoy tasks call this each loop instead of using the
// raw config value, so "breathing" is applied at the radio without ever
// mutating the persisted configuration.
uint32_t profiles_scale_interval(uint32_t base_ms, uint32_t min_ms);

#ifdef __cplusplus
}
#endif
