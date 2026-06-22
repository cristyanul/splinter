// Wi-Fi decoys: a churning crowd of fake 802.11 probe requests.
//
// Realism is the point. Rather than spraying a fresh random MAC with one fixed
// Information-Element fingerprint on every frame (which a fingerprinter spots
// instantly — thousands of one-shot MACs that all share one signature), we keep
// a small POOL of virtual devices. Each has a stable identity for a while: a MAC
// (mostly locally-administered/randomized like modern phones, sometimes a real
// vendor OUI), a vendor PROFILE that drives its IE fingerprint and rates, and an
// optional "saved" SSID it occasionally probes for. Identities rotate on their
// own randomized lifetimes, the way real MAC randomization churns.
//
// With swarm mode on, a unit broadcasts one of its virtual devices so peers
// reproduce the exact same fake (MAC + profile + channel + SSID) — one coherent
// device seen from several vantage points.

#include "decoys_wifi.h"
#include "swarm.h"
#include "profiles.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "config.h"

static const char *TAG = "splinter-wifi";
static volatile uint32_t s_rate = 0;
static volatile bool s_paused = false;   // held true during a Wi-Fi mode switch

uint32_t decoys_wifi_rate(void) { return s_rate; }
void decoys_wifi_set_paused(bool paused) { s_paused = paused; }

// Swarm rendezvous: how often to park on SWARM_CHANNEL to exchange personas,
// and how long to dwell there listening for peers each time.
#define SWARM_RENDEZVOUS_MS 1000
#define SWARM_DWELL_MS      60

static void make_random_mac(uint8_t out[6]) {
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)(esp_random() & 0xff);
    out[0] = (out[0] | 0x02) & 0xfe; // locally-administered, unicast
}

// Real 2.4 GHz scans land mostly on the non-overlapping channels 1/6/11, with
// the rest of the band seen far less often. Weight our picks the same way.
static uint8_t weighted_channel(void) {
    uint32_t r = esp_random() % 100;
    if (r < 30) return 1;
    if (r < 60) return 6;
    if (r < 85) return 11;
    return 1 + (esp_random() % 13); // 15%: spread across the whole band
}

// A plausible mix of carrier, venue and home-router-default SSIDs across a few
// regions, so directed probes don't all look American or all look like one ISP.
static const char *COMMON_SSIDS[] = {
    "Starbucks WiFi", "xfinitywifi", "attwifi", "McDonalds Free WiFi",
    "Guest", "Hilton Honors", "Marriott_Guest", "DeltaWifi",
    "Google Starbucks", "eduroam", "NETGEAR", "Linksys",
    "TP-Link_2.4GHz", "XFINITY", "HOME-WiFi", "AndroidAP",
    "CableWiFi", "Boingo Hotspot", "Telekom", "FRITZ!Box 7530",
    "BTWiFi-with-FON", "VM1234567", "SKY1A2B3", "Vodafone-A1B2",
};
#define NUM_COMMON_SSIDS (sizeof(COMMON_SSIDS) / sizeof(COMMON_SSIDS[0]))

// ----------------------------------------------------------- vendor profiles
// Each profile fixes the device-fingerprinting surface: the Supported-Rates set
// and a "tail" of Information Elements (Extended Rates, HT Capabilities, Extended
// Capabilities, vendor-specific tags) appended after the mandatory SSID / rates /
// DS-parameter elements. The internal IE length bytes are hand-checked to match.
typedef struct {
    const char    *name;
    const uint8_t *rates;     // Supported-Rates IE body (<= 8 bytes)
    uint8_t        rates_len;
    const uint8_t *tail;      // extra IEs appended verbatim
    uint8_t        tail_len;
    uint8_t        oui[3];    // vendor OUI used when this device isn't randomized
    uint8_t        oui_prob;  // % chance a device of this profile uses the real OUI
} wifi_profile_t;

// 1, 2, 5.5, 11 (basic) + a profile-specific OFDM tail.
static const uint8_t RATES_APPLE[]   = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
static const uint8_t RATES_SAMSUNG[] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
static const uint8_t RATES_INTEL[]   = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x60};
static const uint8_t RATES_GENERIC[] = {0x82, 0x84, 0x8b, 0x96};

static const uint8_t TAIL_APPLE[] = {
    0x32, 0x04, 0x0c, 0x12, 0x18, 0x60,                         // Ext Supported Rates (4)
    0x2d, 0x1a, 0xef, 0x01, 0x1b, 0xff, 0xff, 0xff,             // HT Capabilities (26)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40, // Ext Capabilities (8)
    0xdd, 0x07, 0x00, 0x17, 0xf2, 0x0a, 0x00, 0x01, 0x04,       // Vendor: Apple (7)
};

static const uint8_t TAIL_SAMSUNG[] = {
    0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,                         // Ext Supported Rates (4)
    0x2d, 0x1a, 0xad, 0x01, 0x17, 0xff, 0xff, 0xff,             // HT Capabilities (26)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x08, 0x04, 0x00, 0x0a, 0x02, 0x01, 0x00, 0x00, 0x40, // Ext Capabilities (8)
    0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, // Vendor: Broadcom (9)
};

static const uint8_t TAIL_INTEL[] = {
    0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,                         // Ext Supported Rates (4)
    0x2d, 0x1a, 0x2c, 0x01, 0x03, 0xff, 0xff, 0x00,             // HT Capabilities (26)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0x0a, 0x04, 0x00, 0x08, 0x84, 0x00, 0x00,             // Ext Capabilities (10)
    0x00, 0x40, 0x00, 0x40,
};

static const wifi_profile_t PROFILES[] = {
    { "apple",   RATES_APPLE,   sizeof(RATES_APPLE),   TAIL_APPLE,   sizeof(TAIL_APPLE),   {0xac, 0xbc, 0x32}, 15 },
    { "samsung", RATES_SAMSUNG, sizeof(RATES_SAMSUNG), TAIL_SAMSUNG, sizeof(TAIL_SAMSUNG), {0x5c, 0x0a, 0x5b}, 15 },
    { "intel",   RATES_INTEL,   sizeof(RATES_INTEL),   TAIL_INTEL,   sizeof(TAIL_INTEL),   {0x5c, 0x51, 0x4f}, 25 },
    { "generic", RATES_GENERIC, sizeof(RATES_GENERIC), NULL,         0,                    {0x3c, 0x5a, 0xb4}, 65 },
};
#define NUM_PROFILES (sizeof(PROFILES) / sizeof(PROFILES[0]))

// ------------------------------------------------------- virtual device pool
#define WIFI_POOL_SIZE 8

typedef struct {
    uint8_t  mac[6];
    uint8_t  profile;
    char     ssid[32];
    uint8_t  ssid_len;   // 0 = no saved network (wildcard probes only)
    uint32_t born_ms;
    uint32_t life_ms;    // identity lifetime before the MAC/profile rotates
} vdev_t;

static vdev_t s_pool[WIFI_POOL_SIZE];
static bool   s_pool_ready = false;

static void vdev_spawn(vdev_t *d, uint32_t now) {
    d->profile = (uint8_t)(esp_random() % NUM_PROFILES);
    const wifi_profile_t *p = &PROFILES[d->profile];

    if ((esp_random() % 100) < p->oui_prob) {
        memcpy(d->mac, p->oui, 3);                           // real globally-administered OUI
        for (int i = 3; i < 6; i++) d->mac[i] = (uint8_t)(esp_random() & 0xff);
    } else {
        make_random_mac(d->mac);                             // randomized like a modern phone
    }

    if ((esp_random() % 100) < 45) {                         // ~45% "remember" a network
        const char *s = COMMON_SSIDS[esp_random() % NUM_COMMON_SSIDS];
        d->ssid_len = (uint8_t)strlen(s);
        memcpy(d->ssid, s, d->ssid_len);
    } else {
        d->ssid_len = 0;
    }

    d->born_ms = now;
    d->life_ms = 60000 + (esp_random() % 240000);            // 1..5 min identity
}

static void vdev_age(vdev_t *d, uint32_t now) {
    if (now - d->born_ms >= d->life_ms) vdev_spawn(d, now);
}

static void vdev_pool_init(uint32_t now) {
    if (s_pool_ready) return;
    for (int i = 0; i < WIFI_POOL_SIZE; i++) vdev_spawn(&s_pool[i], now);
    s_pool_ready = true;
}

// ----------------------------------------------------------- frame assembly
// Builds a probe request for `mac`/`prof` on `ch`, optionally directed at `ssid`.
// Returns the frame length (always <= ~140 bytes, well within `frame[256]`).
static int build_probe(uint8_t *frame, const uint8_t mac[6], const wifi_profile_t *prof,
                       const char *ssid, uint8_t ssid_len, uint8_t ch) {
    memset(frame, 0, 256);
    frame[0] = 0x40; // FC: Probe Request
    frame[1] = 0x00;
    memset(&frame[4], 0xff, 6);  // Dest: broadcast
    memcpy(&frame[10], mac, 6);  // Src
    memset(&frame[16], 0xff, 6); // BSSID: broadcast
    // frame[22..23] sequence: left 0; esp_wifi_80211_tx(en_sys_seq=true) fills it

    int idx = 24;

    frame[idx++] = 0x00;          // Tag: SSID
    frame[idx++] = ssid_len;
    if (ssid_len > 0) {
        memcpy(&frame[idx], ssid, ssid_len);
        idx += ssid_len;
    }

    frame[idx++] = 0x01;          // Tag: Supported Rates
    frame[idx++] = prof->rates_len;
    memcpy(&frame[idx], prof->rates, prof->rates_len);
    idx += prof->rates_len;

    frame[idx++] = 0x03;          // Tag: DS Parameter Set
    frame[idx++] = 0x01;
    frame[idx++] = ch;

    if (prof->tail_len > 0) {     // profile fingerprint (HT caps, vendor tags, ...)
        memcpy(&frame[idx], prof->tail, prof->tail_len);
        idx += prof->tail_len;
    }

    return idx;
}

static void task_wifi(void *arg) {
    ESP_LOGW(TAG, "Wi-Fi decoys starting (%u profiles, %d virtual devices)",
             (unsigned)NUM_PROFILES, WIFI_POOL_SIZE);
    uint8_t frame[256];
    uint32_t t0 = esp_log_timestamp();
    uint32_t sent = 0;
    uint32_t last_rendezvous = 0;
    uint32_t rr = 0; // round-robin cursor over the device pool

    for (;;) {
        const splinter_cfg_t *cfg = config_get();
        if (!cfg->wifi_enabled) {
            s_rate = 0;
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        if (s_paused) {                      // Wi-Fi mode switch in progress — keep off the radio
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        uint32_t now = esp_log_timestamp();
        vdev_pool_init(now);

        wifi_mode_t mode;
        bool ap_active = (esp_wifi_get_mode(&mode) == ESP_OK && mode == WIFI_MODE_APSTA);

        // ---- Swarm rendezvous ----
        // Park briefly on the shared channel to announce one of our virtual
        // devices and listen for peers, so ESP-NOW frames land. Skipped while
        // the maintenance AP pins us to channel 1.
        if (cfg->swarm_enabled && !ap_active) {
            if (now - last_rendezvous >= SWARM_RENDEZVOUS_MS) {
                esp_wifi_set_channel(SWARM_CHANNEL, WIFI_SECOND_CHAN_NONE);

                vdev_t *d = &s_pool[esp_random() % WIFI_POOL_SIZE];
                vdev_age(d, now);

                swarm_persona_t mine = {0};
                mine.type    = SWARM_MSG_WIFI_PROBE;
                memcpy(mine.mac, d->mac, 6);
                mine.profile = d->profile;
                mine.channel = 1 + (esp_random() % 13);
                if (d->ssid_len > 0) {
                    mine.ssid_len    = d->ssid_len;
                    memcpy(mine.ssid, d->ssid, d->ssid_len);
                    mine.is_directed = 1;
                }
                swarm_broadcast_persona(&mine);

                vTaskDelay(pdMS_TO_TICKS(SWARM_DWELL_MS)); // catch peers' broadcasts
                last_rendezvous = now;
            }
        }

        // ---- Pick this probe's identity ----
        // Mirror a peer's persona if one is queued (so the fleet reproduces the
        // same fake across locations), else use one of our own virtual devices.
        const wifi_profile_t *prof;
        const char *ssid = NULL;
        uint8_t ssid_len = 0;
        uint8_t mac[6];
        uint8_t ch;
        bool mirrored = false;

        swarm_persona_t rp;
        if (cfg->swarm_enabled && swarm_receive_persona(&rp)) {
            mirrored = true;
            memcpy(mac, rp.mac, 6);
            prof = &PROFILES[rp.profile % NUM_PROFILES];
            ch = rp.channel ? rp.channel : 1;
            if (rp.is_directed && rp.ssid_len > 0 && rp.ssid_len <= sizeof(rp.ssid)) {
                ssid = rp.ssid;
                ssid_len = rp.ssid_len;
            }
        } else {
            vdev_t *d = &s_pool[rr++ % WIFI_POOL_SIZE];
            vdev_age(d, now);
            memcpy(mac, d->mac, 6);
            prof = &PROFILES[d->profile];
            ch = weighted_channel();
            // A real device mostly sends wildcard probes; occasionally it asks
            // for a saved network by name.
            if (d->ssid_len > 0 && (esp_random() % 100) < 35) {
                ssid = d->ssid;
                ssid_len = d->ssid_len;
            }
        }

        // A real device doing an active scan fires a few probes across several
        // channels back-to-back, then goes quiet. Mirror/AP probes stay single
        // (their channel is fixed); our own devices burst ~30% of the time.
        int burst = 1;
        if (!ap_active && !mirrored && (esp_random() % 100) < 30) {
            burst = 2 + (esp_random() % 2); // 2-3 probes in the sweep
        }

        for (int b = 0; b < burst; b++) {
            uint8_t bch = ap_active ? 1 : (mirrored ? ch : weighted_channel());
            esp_wifi_set_channel(bch, WIFI_SECOND_CHAN_NONE);
            int len = build_probe(frame, mac, prof, ssid, ssid_len, bch);
            if (esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true) == ESP_OK) {
                sent++;
            }
            if (b + 1 < burst) {
                vTaskDelay(pdMS_TO_TICKS(5 + (esp_random() % 10))); // 5-14 ms intra-burst gap
            }
        }

        if (now - t0 >= 1000) {
            s_rate = sent;
            ESP_LOGW(TAG, "Wi-Fi: %lu fake probe requests/sec on-air", (unsigned long)sent);
            sent = 0;
            t0 = now;
        }

        // Base pacing, modulated by the dynamic "breathing" density multiplier.
        uint32_t delay = profiles_scale_interval(cfg->wifi_interval_ms, 10);

        // +/- 15% random jitter to mimic human/OS timing variation
        int32_t jitter = (int32_t)delay * 15 / 100;
        if (jitter > 0) {
            int32_t offset = (esp_random() % (jitter * 2 + 1)) - jitter;
            delay = (uint32_t)((int32_t)delay + offset);
        }

        vTaskDelay(pdMS_TO_TICKS(delay));
    }
}

void decoys_wifi_start(void) {
    // Priority 4 (same as 154) so it's below BLE. Swarm/ESP-NOW is initialized
    // once at boot in app_main, independent of whether Wi-Fi decoys run.
    xTaskCreate(task_wifi, "splinter_wifi", 4096, NULL, 4, NULL);
}
