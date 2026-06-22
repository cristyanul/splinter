// Splinter runtime configuration: an in-RAM active copy backed by NVS. All
// modules read the live copy via config_get(); the web UI edits and persists it.
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPLINTER_CFG_VERSION  3
typedef struct {
    uint8_t  version;

    // ---- BLE decoys ----
    bool     ble_enabled;
    uint16_t ble_adv_ms;        // per-decoy on-air advertising interval (ms)
    uint8_t  ble_name_prob;     // % chance a decoy advertises a device name
    uint8_t  ble_mfg_prob;      // % chance a decoy carries vendor mfg data
    uint16_t ble_refresh_ms;    // pacing between ext-adv identity refreshes (ms)

    // ---- 802.15.4 fake Zigbee PAN decoys ----
    bool     ieee154_enabled;
    uint32_t ieee154_chan_mask; // bit c set => use channel c (valid 11..26)
    uint16_t ieee154_beacon_ms; // interval between fake beacons (ms)
    bool     ieee154_respond;   // also answer beacon requests (keeps RX on)

    // ---- Wi-Fi decoys ----
    bool     wifi_enabled;
    uint16_t wifi_interval_ms;  // pacing between Wi-Fi probe requests (ms)

    // ---- Dynamic Profiles ----
    bool     profiles_enabled;  // dynamic "breathing" density mode
    bool     swarm_enabled;     // swarm behavior enabled

    // ---- Follower detection ----
    bool     detect_enabled;    // passive BLE+Wi-Fi tail detection

    // ---- SoftAP (maintenance mode) ----
    char     softap_ssid[33];
    char     softap_pass[65];
} splinter_cfg_t;

// Load config from NVS into the in-RAM active copy; writes defaults if absent or
// stale. Call once at boot (after nvs_flash_init).
void config_init(void);

// Pointer to the live active config; read by all modules.
splinter_cfg_t *config_get(void);

// Persist the active config to NVS.
esp_err_t config_save(void);

// Populate c with compile-time defaults (does not touch NVS).
void config_set_defaults(splinter_cfg_t *c);

#ifdef __cplusplus
}
#endif
