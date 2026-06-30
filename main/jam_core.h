#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JAM_ED_CHANS 16   // 802.15.4 channels 11..26 -> index 0..15

// One 1-second Wi-Fi health sample, drained from sniff_wifi each analyzer tick.
// NOTE: ESP32-C6 rx_ctrl.noise_floor is a hardcoded constant (HIL-confirmed: stays
// -96 dBm even under a -43 dBm flood), so there is no usable Wi-Fi RF-energy reading.
// RF-energy jamming on the 2.4 GHz band (incl. Wi-Fi channels) is caught by the
// 802.15.4 Energy-Detect path instead. The Wi-Fi sniffer detects MGMT-frame FLOODS
// (deauth/disassoc storms and beacon spam) — the active Wi-Fi attack class.
typedef struct {
    uint16_t good_frames;   // all MGMT frames seen this interval (flood signal)
    uint16_t deauth_frames; // deauth (0xC0) + disassoc (0xA0) frames this interval
    uint8_t  channel;       // channel the sniffer was on (for logging only)
} jam_wifi_sample_t;

// One 802.15.4 energy + TX-health sample, drained from task_154 each tick.
typedef struct {
    uint8_t  channel;       // 11..26 of the last ED dwell
    int8_t   energy;        // dBm from esp_ieee802154_energy_detect_done
    uint8_t  ed_valid;      // 1 if a fresh ED result is present
    uint16_t cca_busy;      // TX skipped (CCA busy) this interval
    uint16_t tx_done;       // TX confirmed this interval
} jam_ed_sample_t;

typedef enum { JAM_BAND_NONE=0, JAM_BAND_WIFI=1, JAM_BAND_154=2, JAM_BAND_BOTH=3 } jam_band_t;

typedef struct {
    bool     jammed;
    uint8_t  band;          // jam_band_t
    int8_t   peak_energy;   // 802.15.4 band: strongest ED energy (least-negative dBm)
    uint16_t peak_rate;     // Wi-Fi band: peak MGMT-frame flood rate (frames/s)
    uint16_t duration_s;    // current episode length, seconds
    bool     abnormal;      // baseline looked already-jammed at startup (see jam_core.c)
} jam_status_t;

typedef struct {
    // baseline (learned during the safe window)
    bool     learning;
    uint32_t learn_until_ms;
    uint16_t good_base;          // max wifi MGMT good-frames/sec seen (flood ceiling)
    int8_t   ed_base[JAM_ED_CHANS];
    bool     ed_base_set[JAM_ED_CHANS];
    bool     abnormal_boot;      // baseline looked already-jammed at startup

    // latest fed samples (the current second)
    jam_wifi_sample_t wifi;
    bool              wifi_fresh;
    jam_ed_sample_t   ed;
    bool              ed_fresh;

    // verdict state machine
    uint8_t  assert_secs;
    uint8_t  clear_secs;
    bool     jammed;
    uint8_t  band;
    int8_t   peak_energy;
    uint16_t peak_rate;          // peak Wi-Fi MGMT flood rate this episode (frames/s)
    uint16_t duration_s;
    bool     wifi_trip_now;      // last tick's wifi trip (drives ED cadence ramp)
} jam_state_t;

void jam_init(jam_state_t *s);
void jam_begin_safe(jam_state_t *s, uint32_t now_ms, uint32_t dur_ms);
void jam_feed_wifi(jam_state_t *s, const jam_wifi_sample_t *w, uint32_t now_ms);
void jam_feed_ed(jam_state_t *s, const jam_ed_sample_t *e, uint32_t now_ms);
void jam_tick(jam_state_t *s, uint32_t now_ms);
// Clear the verdict state machine (jammed/band/duration/counters) while preserving
// the learned baselines. Used when the feature is toggled off so a stale "jammed"
// verdict doesn't persist across a disable.
void jam_reset(jam_state_t *s);
bool jam_active(const jam_state_t *s);
bool jam_wifi_trip(const jam_state_t *s);
void jam_get_status(const jam_state_t *s, jam_status_t *out);

#ifdef __cplusplus
}
#endif
