#include "config.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "splinter-cfg";
static const char *NS  = "splinter";

// Config is stored as one NVS key per field (not a single blob). This is
// forward/backward compatible: adding a field in a new firmware just means its
// key is absent on an upgraded device, so it keeps its compile-time default
// instead of wiping everything. "ver" marks that the per-key store exists;
// LEGACY_BLOB_KEY is the old single-blob key, migrated once on first boot.
#define CFG_KEY_VERSION   "ver"
static const char *LEGACY_BLOB_KEY = "cfg";

static splinter_cfg_t s_cfg;

void config_set_defaults(splinter_cfg_t *c)
{
    memset(c, 0, sizeof(*c));
    c->version = SPLINTER_CFG_VERSION;

    c->ble_enabled    = true;
    c->ble_adv_ms     = 100;   // matches the original SPLINTER_ADV_MS
    c->ble_name_prob  = 60;    // SPLINTER_NAME_PROB
    c->ble_mfg_prob   = 85;    // SPLINTER_MFG_PROB
    c->ble_refresh_ms = 20;    // SPLINTER_EXT_REFRESH_MS

    c->ieee154_enabled   = true;
    c->ieee154_chan_mask = 0x07FFF800u; // channels 11..26 inclusive
    c->ieee154_beacon_ms = 100;
    c->ieee154_respond   = false;       // default off: keeps RX (and radio) light
    c->thread_enabled    = true;        // coherent fake Thread/Matter home

    c->wifi_enabled      = true;
    c->wifi_interval_ms  = 200;
    c->awdl_enabled      = true;        // coherent Apple AWDL/AirDrop cast

    c->profiles_enabled  = true;
    c->swarm_enabled     = false;

    c->detect_enabled    = true;

    strncpy(c->softap_ssid, "Splinter-Setup",  sizeof(c->softap_ssid) - 1);
    strncpy(c->softap_pass, "splinter-setup",  sizeof(c->softap_pass) - 1);
}

// Read a bool stored as u8; leave *v untouched (default) if the key is absent.
static void load_bool(nvs_handle_t h, const char *k, bool *v)
{
    uint8_t b;
    if (nvs_get_u8(h, k, &b) == ESP_OK) *v = (b != 0);
}

// Overlay any stored fields onto the already-defaulted s_cfg. Missing keys (new
// fields on a freshly upgraded device) simply keep their defaults.
static void config_load_keys(nvs_handle_t h)
{
    load_bool  (h, "ble_en",   &s_cfg.ble_enabled);
    nvs_get_u16(h, "ble_adv",  &s_cfg.ble_adv_ms);
    nvs_get_u8 (h, "ble_name", &s_cfg.ble_name_prob);
    nvs_get_u8 (h, "ble_mfg",  &s_cfg.ble_mfg_prob);
    nvs_get_u16(h, "ble_ref",  &s_cfg.ble_refresh_ms);

    load_bool  (h, "g_en",     &s_cfg.ieee154_enabled);
    nvs_get_u32(h, "g_mask",   &s_cfg.ieee154_chan_mask);
    nvs_get_u16(h, "g_beac",   &s_cfg.ieee154_beacon_ms);
    load_bool  (h, "g_resp",   &s_cfg.ieee154_respond);
    load_bool  (h, "thr_en",   &s_cfg.thread_enabled);

    load_bool  (h, "wifi_en",  &s_cfg.wifi_enabled);
    nvs_get_u16(h, "wifi_int", &s_cfg.wifi_interval_ms);
    load_bool  (h, "awdl_en",  &s_cfg.awdl_enabled);

    load_bool  (h, "prof_en",  &s_cfg.profiles_enabled);
    load_bool  (h, "swarm_en", &s_cfg.swarm_enabled);
    load_bool  (h, "det_en",   &s_cfg.detect_enabled);

    size_t n;
    n = sizeof(s_cfg.softap_ssid);
    nvs_get_str(h, "ssid", s_cfg.softap_ssid, &n);
    n = sizeof(s_cfg.softap_pass);
    nvs_get_str(h, "pass", s_cfg.softap_pass, &n);
}

void config_init(void)
{
    config_set_defaults(&s_cfg);

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed (%s); using defaults", esp_err_to_name(err));
        return;
    }

    uint8_t ver;
    if (nvs_get_u8(h, CFG_KEY_VERSION, &ver) == ESP_OK) {
        config_load_keys(h);
        nvs_close(h);
        ESP_LOGI(TAG, "loaded config (per-key store, ver %u); SoftAP SSID='%s'", ver, s_cfg.softap_ssid);
        return;
    }

    // First boot on the per-key store. If a same-version legacy blob is present,
    // migrate it so the user keeps their settings; otherwise stay on defaults.
    splinter_cfg_t legacy;
    size_t sz = sizeof(legacy);
    if (nvs_get_blob(h, LEGACY_BLOB_KEY, &legacy, &sz) == ESP_OK &&
        sz == sizeof(legacy) && legacy.version == SPLINTER_CFG_VERSION) {
        s_cfg = legacy;
        ESP_LOGI(TAG, "migrated legacy config blob -> per-key store");
    } else {
        ESP_LOGI(TAG, "no compatible stored config; writing defaults");
    }
    nvs_erase_key(h, LEGACY_BLOB_KEY); // best effort; ignore if absent
    nvs_commit(h);
    nvs_close(h);

    config_save(); // persist in the per-key format (also writes "ver")
}

splinter_cfg_t *config_get(void)
{
    return &s_cfg;
}

esp_err_t config_save(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    s_cfg.version = SPLINTER_CFG_VERSION;

    nvs_set_u8 (h, CFG_KEY_VERSION, SPLINTER_CFG_VERSION);
    nvs_set_u8 (h, "ble_en",   s_cfg.ble_enabled);
    nvs_set_u16(h, "ble_adv",  s_cfg.ble_adv_ms);
    nvs_set_u8 (h, "ble_name", s_cfg.ble_name_prob);
    nvs_set_u8 (h, "ble_mfg",  s_cfg.ble_mfg_prob);
    nvs_set_u16(h, "ble_ref",  s_cfg.ble_refresh_ms);
    nvs_set_u8 (h, "g_en",     s_cfg.ieee154_enabled);
    nvs_set_u32(h, "g_mask",   s_cfg.ieee154_chan_mask);
    nvs_set_u16(h, "g_beac",   s_cfg.ieee154_beacon_ms);
    nvs_set_u8 (h, "g_resp",   s_cfg.ieee154_respond);
    nvs_set_u8 (h, "thr_en",   s_cfg.thread_enabled);
    nvs_set_u8 (h, "wifi_en",  s_cfg.wifi_enabled);
    nvs_set_u16(h, "wifi_int", s_cfg.wifi_interval_ms);
    nvs_set_u8 (h, "awdl_en",  s_cfg.awdl_enabled);
    nvs_set_u8 (h, "prof_en",  s_cfg.profiles_enabled);
    nvs_set_u8 (h, "swarm_en", s_cfg.swarm_enabled);
    nvs_set_u8 (h, "det_en",   s_cfg.detect_enabled);
    nvs_set_str(h, "ssid",     s_cfg.softap_ssid);
    nvs_set_str(h, "pass",     s_cfg.softap_pass);

    err = nvs_commit(h);
    nvs_close(h);
    return err;
}
