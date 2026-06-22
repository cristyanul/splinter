// splinter — BLE privacy / anti-tracking decoy engine (ESP-IDF + NimBLE)
//
// Continuously fabricates a churning crowd of plausible-but-fake BLE devices.
// Two build flavours, selected automatically by the target's BLE capability:
//   * Classic ESP32 (BT 4.2): ONE legacy advertiser, rotated at maximum rate.
//   * BLE-5 chips, e.g. ESP32-C6 / C5 / C3 (CONFIG_BT_NIMBLE_EXT_ADV): up to
//     CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES *concurrent* legacy-PDU advertising
//     sets, each with its own MAC, rotated round-robin.
//
// Decoys are NON-CONNECTABLE and never shaped like Apple Continuity / Microsoft
// Swift Pair / Google Fast Pair, so they create realistic presence without
// popping pairing dialogs on bystanders' devices.

#include "decoys_ble.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nimble/hci_common.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

#include "decoy_vendors.h"
#include "config.h"
#include "profiles.h"
#include "sniff_ble.h"

static const char *TAG = "splinter-ble";

// BLE advertising interval is expressed in 0.625 ms units.
#define ADV_ITVL_UNITS(ms)   ((uint16_t)(((ms) * 1000) / 625))

static volatile bool     s_host_synced = false;
static volatile uint32_t s_rate = 0;     // last-second successful refreshes

uint32_t decoys_ble_rate(void) { return s_rate; }

// Build a valid random-static address: 6 random bytes with the two most
// significant bits set. Regenerates the astronomically rare all-zero / all-ones
// random part that NimBLE would reject.
static void make_random_static_addr(uint8_t out[6])
{
    for (;;) {
        for (int i = 0; i < 6; i++) {
            out[i] = (uint8_t)(esp_random() & 0xff);
        }
        out[5] |= 0xc0;

        int ones = __builtin_popcount(out[5] & 0x3f);
        for (int i = 0; i < 5; i++) {
            ones += __builtin_popcount(out[i]);
        }
        if (ones != 0 && ones != 46) {
            return;
        }
    }
}

// Populate a non-connectable decoy's advertising fields. `mfg` must point to a
// >=10 byte scratch buffer that outlives the field's use/serialization.
static void build_decoy_fields(struct ble_hs_adv_fields *f, uint8_t *mfg)
{
    const splinter_cfg_t *cfg = config_get();
    const vendor_t *v = &VENDORS[esp_random() % VENDOR_COUNT];

    memset(f, 0, sizeof(*f));
    f->flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    bool used_name = false;
    if (v->name != NULL && (esp_random() % 100) < cfg->ble_name_prob) {
        f->name = (uint8_t *)v->name;
        f->name_len = strlen(v->name);
        f->name_is_complete = 1;
        used_name = true;
    }

    if ((esp_random() % 100) < cfg->ble_mfg_prob) {
        size_t body = used_name ? 3 : (3 + (esp_random() % 5));
        mfg[0] = (uint8_t)(v->company_id & 0xff);
        mfg[1] = (uint8_t)((v->company_id >> 8) & 0xff);
        for (size_t i = 0; i < body; i++) {
            mfg[2 + i] = (uint8_t)(esp_random() & 0xff);
        }
        f->mfg_data = mfg;
        f->mfg_data_len = 2 + body;
    }

    f->tx_pwr_lvl_is_present = 1;
#ifdef CONFIG_BT_NIMBLE_EXT_ADV
    // Extended-advertising path (ESP32-C5/C6/H2): per-instance TX power is set in
    // ble_gap_ext_adv_params.tx_power. Do NOT request AUTO here — AUTO makes
    // ble_hs_adv_set_fields() issue the legacy "LE Read Advertising Channel Tx
    // Power" HCI command, which the BLE-5 controller rejects (Command Disallowed,
    // 0x0C) in ext-adv mode, failing serialization (rc=524) so nothing advertises.
    f->tx_pwr_lvl = 9;   // dBm; cosmetic AD element only
#else
    f->tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;   // classic ESP32 legacy path
#endif
}

#ifdef CONFIG_BT_NIMBLE_EXT_ADV
// =========================================================================
// BLE 5 path: several CONCURRENT extended-advertising instances
// =========================================================================
#ifndef CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES
#define CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES 1
#endif
#define SPLINTER_INSTANCES   CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES

static int configure_instance(uint8_t instance)
{
    const splinter_cfg_t *cfg = config_get();
    struct ble_gap_ext_adv_params p;
    memset(&p, 0, sizeof(p));
    p.legacy_pdu    = 1;                 // legacy PDUs -> seen by all scanners
    p.connectable   = 0;
    p.scannable     = 0;
    p.own_addr_type = BLE_OWN_ADDR_RANDOM;
    p.primary_phy   = BLE_HCI_LE_PHY_1M;
    p.secondary_phy = BLE_HCI_LE_PHY_1M;
    p.sid           = instance;
    p.itvl_min      = ADV_ITVL_UNITS(cfg->ble_adv_ms);
    p.itvl_max      = ADV_ITVL_UNITS(cfg->ble_adv_ms + 30);
    p.tx_power      = 127;               // controller clamps to its max
    return ble_gap_ext_adv_configure(instance, &p, NULL, NULL, NULL);
}

static int refresh_instance(uint8_t instance)
{
    int rc;

    ble_gap_ext_adv_stop(instance);      // ok if it wasn't running

    uint8_t raw[6];
    make_random_static_addr(raw);
    ble_addr_t addr;
    addr.type = BLE_ADDR_RANDOM;
    memcpy(addr.val, raw, sizeof(raw));
    rc = ble_gap_ext_adv_set_addr(instance, &addr);
    if (rc != 0) return rc;

    struct ble_hs_adv_fields fields;
    uint8_t mfg[10];
    build_decoy_fields(&fields, mfg);

    uint8_t buf[BLE_HS_ADV_MAX_SZ];
    uint8_t buf_len = 0;
    rc = ble_hs_adv_set_fields(&fields, buf, &buf_len, sizeof(buf));
    if (rc != 0) return rc;

    struct os_mbuf *om = ble_hs_mbuf_from_flat(buf, buf_len);
    if (om == NULL) return BLE_HS_ENOMEM;
    rc = ble_gap_ext_adv_set_data(instance, om);   // consumes om
    if (rc != 0) return rc;

    return ble_gap_ext_adv_start(instance, 0, 0);  // duration 0 = forever
}

static void splinter_run(void)
{
    for (uint8_t i = 0; i < SPLINTER_INSTANCES; i++) {
        int rc = configure_instance(i);
        if (rc != 0) {
            ESP_LOGW(TAG, "configure instance %u failed rc=%d", i, rc);
        }
    }
    ESP_LOGW(TAG, "BLE5 flood: %d concurrent ext-adv instances, round-robin refresh",
             SPLINTER_INSTANCES);

    uint8_t inst = 0;
    bool advertising = true;
    uint32_t t0 = esp_log_timestamp(), ok = 0, fail = 0;
    for (;;) {
        const splinter_cfg_t *cfg = config_get();

        // Live toggle: stop all advertising sets when disabled (controller and
        // host stay up, so re-enabling resumes instantly without a reboot).
        if (!cfg->ble_enabled) {
            if (advertising) {
                for (uint8_t i = 0; i < SPLINTER_INSTANCES; i++) {
                    ble_gap_ext_adv_stop(i);
                }
                advertising = false;
                s_rate = 0;
                ESP_LOGW(TAG, "BLE decoys disabled; advertising stopped");
            }
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }
        advertising = true;

        if (refresh_instance(inst) == 0) {
            ok++;
        } else {
            fail++;
        }
        inst = (inst + 1) % SPLINTER_INSTANCES;

        uint32_t now = esp_log_timestamp();
        if (now - t0 >= 1000) {
            s_rate = ok;
            ESP_LOGW(TAG, "rate: %lu refreshes/sec, %d live instances (fail=%lu)",
                     (unsigned long)ok, SPLINTER_INSTANCES, (unsigned long)fail);
            ok = 0;
            fail = 0;
            t0 = now;
        }

        // Always yield: a tight loop starves the BLE host, the USB console and
        // the idle/WDT tasks. Instances keep advertising concurrently meanwhile.
        // This yield window is also where the 802.15.4 decoy task gets airtime.
        // Pacing is modulated by the breathing density multiplier (min 1 ms).
        vTaskDelay(pdMS_TO_TICKS(profiles_scale_interval(cfg->ble_refresh_ms, 1)));
    }
}

#else
// =========================================================================
// Classic ESP32 (BT 4.2) path: one legacy advertiser, rotated fast
// =========================================================================
static int start_one_decoy(void)
{
    const splinter_cfg_t *cfg = config_get();
    int rc;

    uint8_t addr[6];
    make_random_static_addr(addr);
    rc = ble_hs_id_set_rnd(addr);
    if (rc != 0) return rc;

    struct ble_hs_adv_fields fields;
    uint8_t mfg[10];
    build_decoy_fields(&fields, mfg);

    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) return rc;

    struct ble_gap_adv_params advp;
    memset(&advp, 0, sizeof(advp));
    advp.conn_mode = BLE_GAP_CONN_MODE_NON;
    advp.disc_mode = BLE_GAP_DISC_MODE_GEN;
    advp.itvl_min  = ADV_ITVL_UNITS(cfg->ble_adv_ms);
    advp.itvl_max  = ADV_ITVL_UNITS(cfg->ble_adv_ms + 30);

    return ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER,
                             &advp, NULL, NULL);
}

static void splinter_run(void)
{
    ESP_LOGW(TAG, "BENCHMARK/flood: rotating one legacy advertiser at max rate");
    uint32_t t0 = esp_log_timestamp(), ok = 0, fail = 0;
    for (;;) {
        const splinter_cfg_t *cfg = config_get();

        // Live toggle: stop advertising and idle while disabled.
        if (!cfg->ble_enabled) {
            ble_gap_adv_stop();
            s_rate = 0;
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        ble_gap_adv_stop();
        if (start_one_decoy() == 0) {
            ok++;
        } else {
            fail++;
        }
        uint32_t now = esp_log_timestamp();
        if (now - t0 >= 1000) {
            s_rate = ok;
            ESP_LOGW(TAG, "rate: %lu devices/sec (fail=%lu)",
                     (unsigned long)ok, (unsigned long)fail);
            ok = 0;
            fail = 0;
            t0 = now;
        }
    }
}
#endif // CONFIG_BT_NIMBLE_EXT_ADV

static void splinter_task(void *arg)
{
    while (!s_host_synced) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    splinter_run();
}

static void on_sync(void)
{
    s_host_synced = true;
    ESP_LOGI(TAG, "NimBLE host synced");

    sniff_ble_start();
}

static void on_reset(int reason)
{
    s_host_synced = false;
    ESP_LOGW(TAG, "NimBLE host reset, reason=%d", reason);
}

static void nimble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void decoys_ble_start(void)
{
    // NimBLE logs every GAP procedure at INFO; at high rotation rates that spam
    // would dominate and throttle the loop. Keep only warnings+.
    esp_log_level_set("NimBLE", ESP_LOG_WARN);

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ble_svc_gap_init();

    nimble_port_freertos_init(nimble_host_task);
    xTaskCreate(splinter_task, "splinter", 4096, NULL, 5, NULL);
}
