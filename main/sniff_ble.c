#include "sniff_ble.h"
#include "detector.h"
#include "tracker_id.h"
#include "config.h"
#include "esp_log.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include <string.h>

static const char *TAG = "splinter-snble";

static uint16_t ble_fp(const uint8_t *data, uint8_t len)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < len && i < 24; i++) { h ^= data[i]; h *= 16777619u; }
    return (uint16_t)(h ^ (h >> 16));
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    const ble_addr_t *addr;
    int8_t rssi;
    const uint8_t *data;
    uint8_t len;
#if defined(CONFIG_BT_NIMBLE_EXT_ADV)
    // Extended-advertising builds deliver scan results as EXT_DISC events.
    if (event->type != BLE_GAP_EVENT_EXT_DISC) return 0;
    const struct ble_gap_ext_disc_desc *d = &event->ext_disc;
#else
    if (event->type != BLE_GAP_EVENT_DISC) return 0;
    const struct ble_gap_disc_desc *d = &event->disc;
#endif
    if (!config_get()->detect_enabled) return 0;  // detection toggled off — drop
    addr = &d->addr;
    rssi = d->rssi;
    data = d->data;
    len  = d->length_data;

    dc_sighting_t s = {0};
    s.radio = DC_RADIO_BLE;
    memcpy(s.id, addr->val, 6);
    s.rssi = rssi;
    s.channel = 37;
    if (len > 0 && data) {
        s.tracker_kind = tracker_classify(data, len);
        s.fp = ble_fp(data, len);
    }
    detector_report_sighting(&s);
    return 0;
}

void sniff_ble_start(void)
{
    // Scan with the controller's PUBLIC address (always present) so we don't
    // depend on a host random address being configured.
    int rc;
#if defined(CONFIG_BT_NIMBLE_EXT_ADV)
    // The decoy runs the controller in extended-advertising mode, so the legacy
    // ble_gap_disc() is rejected (HCI 0x12, Invalid Command Parameters). Use the
    // extended scan API instead.
    struct ble_gap_ext_disc_params uncoded = {
        .itvl    = 0x00A0,    // 100 ms scan interval (0.625 ms units)
        .window  = 0x0030,    // 30 ms scan window (~12% duty alongside adv)
        .passive = 1,         // listen only, no scan requests
    };
    rc = ble_gap_ext_disc(BLE_OWN_ADDR_PUBLIC,
                          0,     // duration: forever
                          0,     // period: continuous
                          0,     // filter_duplicates: off (want repeats)
                          0,     // filter_policy: no whitelist
                          0,     // limited: no
                          &uncoded, NULL, gap_event, NULL);
#else
    struct ble_gap_disc_params p = {0};
    p.passive = 1;
    p.itvl = 0x00A0;
    p.window = 0x0030;
    p.filter_duplicates = 0;
    rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &p, gap_event, NULL);
#endif
    if (rc != 0) ESP_LOGE(TAG, "BLE observer scan start failed rc=%d", rc);
    else ESP_LOGW(TAG, "BLE observer scan started (passive)");
}
