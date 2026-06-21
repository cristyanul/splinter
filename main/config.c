#include "config.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "splinter-cfg";
static const char *NS  = "splinter";
static const char *KEY = "cfg";

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

    strncpy(c->softap_ssid, "Splinter-Setup",  sizeof(c->softap_ssid) - 1);
    strncpy(c->softap_pass, "splinter-setup",  sizeof(c->softap_pass) - 1);
}

void config_init(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs_open failed (%s); using defaults", esp_err_to_name(err));
        config_set_defaults(&s_cfg);
        return;
    }

    size_t sz = sizeof(s_cfg);
    err = nvs_get_blob(h, KEY, &s_cfg, &sz);
    if (err != ESP_OK || sz != sizeof(s_cfg) || s_cfg.version != SPLINTER_CFG_VERSION) {
        ESP_LOGI(TAG, "no valid stored config; writing defaults");
        config_set_defaults(&s_cfg);
        nvs_set_blob(h, KEY, &s_cfg, sizeof(s_cfg));
        nvs_commit(h);
    } else {
        ESP_LOGI(TAG, "loaded config from NVS");
    }
    nvs_close(h);
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
    err = nvs_set_blob(h, KEY, &s_cfg, sizeof(s_cfg));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

uint8_t boot_mode_take(void)
{
    nvs_handle_t h;
    uint8_t mode = BOOT_MODE_NORMAL;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
        if (nvs_get_u8(h, "boot_mode", &mode) != ESP_OK) {
            mode = BOOT_MODE_NORMAL;
        }
        if (mode != BOOT_MODE_NORMAL) {
            nvs_set_u8(h, "boot_mode", BOOT_MODE_NORMAL); // one-shot
            nvs_commit(h);
        }
        nvs_close(h);
    }
    return mode;
}

void boot_mode_set(uint8_t mode)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "boot_mode", mode);
        nvs_commit(h);
        nvs_close(h);
    }
}
