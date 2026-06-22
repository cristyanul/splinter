#include "sniff_wifi.h"
#include "detector.h"
#include "config.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "splinter-snwifi";

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
    if (!config_get()->detect_enabled) return;   // detection toggled off — drop
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    if (p->rx_ctrl.sig_len < 24) return;   // shorter than a full 802.11 MGMT header — malformed
    const uint8_t *f = p->payload;
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

void sniff_wifi_start(void)
{
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(rx_cb);
    esp_wifi_set_promiscuous(true);
    ESP_LOGW(TAG, "Wi-Fi sniffer on (rides decoy channel hopping)");
}
