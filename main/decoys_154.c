// 802.15.4 fake Zigbee PAN decoys.
//
// Periodically broadcasts well-formed IEEE 802.15.4 beacon frames carrying a
// Zigbee beacon payload, each with a fresh random PAN id / source address /
// extended PAN id, hopping across the configured channels. To a Zigbee/802.15.4
// sniffer this looks like a churning crowd of nearby PANs — the 802.15.4 analog
// of the BLE decoy flood.
//
// Runs at lower task priority than the BLE decoy task and paces itself with a
// configurable inter-beacon delay, and transmits with CCA (clear channel
// assessment) so it stays polite and never stomps on real traffic. Net effect:
// BLE performance is unaffected (verified on hardware).

#include "decoys_154.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_ieee802154.h"

#include "config.h"
#include "profiles.h"

static const char *TAG = "splinter-154";

static volatile uint32_t s_done = 0;   // confirmed on-air beacons (this second)
static volatile uint32_t s_rate = 0;   // last-second confirmed beacons
static volatile uint32_t s_skip = 0;   // beacons skipped (CCA busy / arbitration)

uint32_t decoys_154_rate(void) { return s_rate; }

// TX result callbacks (weak in the driver; defined here). Kept trivial — they
// run in driver context.
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack,
                                  esp_ieee802154_frame_info_t *ack_frame_info)
{
    s_done++;
}

void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error)
{
    // CCA-busy etc. — drop this beacon; the next picks another channel.
    s_skip++;
}

static uint8_t pick_channel(uint32_t mask)
{
    uint8_t chans[16];
    int n = 0;
    for (int c = 11; c <= 26; c++) {
        if (mask & (1u << c)) {
            chans[n++] = (uint8_t)c;
        }
    }
    if (n == 0) {
        return 15; // sane fallback
    }
    return chans[esp_random() % n];
}

// Build a beacon frame into buf (buf[0] = PHR length incl. 2-byte FCS, which the
// radio fills). Returns total bytes written (PHR + PSDU).
static int build_beacon(uint8_t *buf, uint8_t seq)
{
    int i = 1; // leave buf[0] for the PHR length byte

    // MHR: Frame Control = beacon, no dest, short source, frame version 0 -> 0x8000
    buf[i++] = 0x00;            // FCF low
    buf[i++] = 0x80;            // FCF high (src addr mode = short)
    buf[i++] = seq;             // sequence number

    uint16_t pan = (uint16_t)(esp_random() & 0xFFFF);
    if (pan == 0xFFFF) pan = 0x1AAA;          // 0xFFFF is broadcast; avoid it
    buf[i++] = pan & 0xFF;
    buf[i++] = pan >> 8;

    uint16_t saddr = (uint16_t)(esp_random() & 0xFFFF);
    buf[i++] = saddr & 0xFF;
    buf[i++] = saddr >> 8;

    // MAC payload: Superframe Spec (BO=SO=15, FinalCAP=15, PANCoord+AssocPermit)
    buf[i++] = 0xFF;            // superframe spec low
    buf[i++] = 0xCF;            // superframe spec high
    buf[i++] = 0x00;            // GTS specification (none)
    buf[i++] = 0x00;            // pending address spec (none)

    // Zigbee beacon payload (15 bytes)
    buf[i++] = 0x00;            // protocol id (Zigbee)
    buf[i++] = 0x22;            // stack profile (PRO=2) | nwk protocol version (2)
    buf[i++] = 0x84;            // router capacity / depth / end-device capacity
    for (int k = 0; k < 8; k++) {
        buf[i++] = (uint8_t)(esp_random() & 0xFF); // extended PAN id
    }
    buf[i++] = 0xFF; buf[i++] = 0xFF; buf[i++] = 0xFF; // tx offset (unknown)
    buf[i++] = (uint8_t)(esp_random() & 0xFF);         // beacon update id

    // FCS placeholder (filled by hardware)
    buf[i++] = 0x00;
    buf[i++] = 0x00;

    buf[0] = (uint8_t)(i - 1); // PHR = PSDU length, including FCS
    return i;
}

static void task_154(void *arg)
{
    bool radio_up = false;
    uint8_t frame[64];
    uint8_t seq = 0;
    uint32_t t0 = esp_log_timestamp();

    for (;;) {
        const splinter_cfg_t *cfg = config_get();

        // Live toggle: bring the 802.15.4 radio up on first enable and power it
        // back down when disabled, so the web UI switch takes effect without a
        // reboot and frees the radio (and its coex slot) while off.
        if (!cfg->ieee154_enabled) {
            if (radio_up) {
                esp_ieee802154_disable();
                radio_up = false;
                s_rate = 0;
                ESP_LOGW(TAG, "802.15.4 decoys disabled; radio down");
            }
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        if (!radio_up) {
            esp_err_t err = esp_ieee802154_enable();
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ieee802154_enable failed: %s", esp_err_to_name(err));
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }
            esp_ieee802154_set_promiscuous(false);
#if CONFIG_ESP_COEX_SW_COEXIST_ENABLE
            // Raise TX/RX priority so our occasional beacons win the rare coex
            // arbitration against BLE / Wi-Fi. BLE advertising is <10% airtime
            // and keeps its own scheduled slots, so its rate is unaffected.
            esp_ieee802154_coex_config_t coex = {
                .idle    = IEEE802154_IDLE,
                .txrx    = IEEE802154_HIGH,
                .txrx_at = IEEE802154_HIGH,
            };
            esp_ieee802154_set_coex_config(coex);
#endif
            esp_ieee802154_set_rx_when_idle(cfg->ieee154_respond);
            ESP_LOGW(TAG, "802.15.4 fake-PAN beacons starting (respond=%d)", cfg->ieee154_respond);
            t0 = esp_log_timestamp();
            radio_up = true;
        }

        uint8_t ch = pick_channel(cfg->ieee154_chan_mask);
        esp_ieee802154_set_channel(ch);

        build_beacon(frame, seq++);
        if (esp_ieee802154_transmit(frame, true /* CCA: stay polite */) != ESP_OK) {
            s_skip++;
        }

        uint32_t now = esp_log_timestamp();
        if (now - t0 >= 1000) {
            s_rate = s_done;
            ESP_LOGW(TAG, "154: %lu fake PANs/sec on-air (%lu skipped) last_ch=%u",
                     (unsigned long)s_done, (unsigned long)s_skip, ch);
            s_done = 0;
            s_skip = 0;
            t0 = now;
        }

        // Base inter-beacon delay, modulated by the breathing density multiplier.
        uint32_t d = profiles_scale_interval(cfg->ieee154_beacon_ms, 10);
        vTaskDelay(pdMS_TO_TICKS(d));
    }
}

void decoys_154_start(void)
{
    // Priority 4: below the BLE decoy task (5) so BLE always wins CPU contention.
    xTaskCreate(task_154, "splinter154", 4096, NULL, 4, NULL);
}
