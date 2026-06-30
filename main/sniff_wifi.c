#include "sniff_wifi.h"
#include "detector.h"
#include "config.h"
#include "jam_core.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "splinter-snwifi";

// Wi-Fi jam sensing counts MGMT frames per interval (a flood = an attack). The
// ESP32-C6 reports a constant rx_ctrl.noise_floor (HIL-confirmed), so RF-energy
// jamming is left to the 802.15.4 ED path; here we only count frames.
static volatile uint32_t s_good;        // all MGMT frames this interval
static volatile uint32_t s_deauth;      // deauth (0xC0) + disassoc (0xA0) this interval
static volatile uint8_t  s_last_ch;     // last channel a frame arrived on

// Hash a probe's OUI + a few IE-shape bytes into a 16-bit fingerprint.
static uint16_t wifi_fp(const uint8_t *src, const uint8_t *ies, int ies_len)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 3; i++) { h ^= src[i]; h *= 16777619u; }
    for (int i = 0; i < ies_len && i < 24; i++) { h ^= ies[i]; h *= 16777619u; }
    return (uint16_t)(h ^ (h >> 16));
}

static void rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    if (p->rx_ctrl.sig_len < 24) return;   // shorter than a full 802.11 MGMT header — malformed
    const uint8_t *f = p->payload;
    // Jam-sensing health stats — for ALL mgmt frames, independent of follower detection.
    // Runs before the detect_enabled gate so the jam detector keeps sensing the Wi-Fi
    // band even when follower detection is toggled off. Beacons (0x80) counted too.
    s_good++;
    s_last_ch = p->rx_ctrl.channel;
    if (f[0] == 0xC0 || f[0] == 0xA0) s_deauth++;   // deauth / disassoc
    // Follower detection (probe-only) — gated by its own flag.
    if (!config_get()->detect_enabled) return;   // detection toggled off — drop
    // Probe Request only: frame-control byte 0 == 0x40 (type=mgmt, subtype=probe-req).
    if (f[0] != 0x40) return;
    const uint8_t *src = &f[10]; // addr2 = transmitter
    int ies_len = p->rx_ctrl.sig_len - 24 - 4; // minus header and FCS
    if (ies_len > 256) ies_len = 256;
    const uint8_t *ies = (ies_len > 0) ? &f[24] : NULL;

    dc_sighting_t s = {0};
    s.radio   = DC_RADIO_WIFI;
    memcpy(s.id, src, 6);
    s.rssi    = p->rx_ctrl.rssi;
    s.channel = p->rx_ctrl.channel;
    s.fp      = ies ? wifi_fp(src, ies, ies_len) : 0;
    s.tracker_kind = DC_TRK_NONE;
    detector_report_sighting(&s);
}

void sniff_wifi_drain_health(jam_wifi_sample_t *out)
{
    uint32_t good = s_good, deauth = s_deauth;
    uint8_t  ch = s_last_ch;
    s_good = 0; s_deauth = 0;

    out->good_frames   = (good   > 0xFFFF) ? 0xFFFF : (uint16_t)good;
    out->deauth_frames = (deauth > 0xFFFF) ? 0xFFFF : (uint16_t)deauth;
    out->channel       = ch;
}

void sniff_wifi_start(void)
{
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(rx_cb);
    esp_wifi_set_promiscuous(true);
    ESP_LOGW(TAG, "Wi-Fi sniffer on (rides decoy channel hopping)");
}
