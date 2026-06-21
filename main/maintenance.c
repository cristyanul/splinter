// Maintenance mode: Wi-Fi SoftAP + HTTP server for live config editing and OTA
// firmware upload. Reached only by rebooting with BOOT_MODE_MAINTENANCE set, so
// Wi-Fi runs alone here — the BLE / 802.15.4 decoy radios are never up in this
// mode, which keeps normal-mode RF performance untouched.

#include "maintenance.h"

#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"

#include "config.h"
#include "status_led.h"

static const char *TAG = "splinter-maint";

// ---------------------------------------------------------------- Wi-Fi SoftAP
static void wifi_softap_start(void)
{
    splinter_cfg_t *cfg = config_get();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t wic = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wic));

    wifi_config_t wc = { 0 };
    size_t slen = strnlen(cfg->softap_ssid, sizeof(wc.ap.ssid));
    memcpy(wc.ap.ssid, cfg->softap_ssid, slen);
    wc.ap.ssid_len = slen;
    wc.ap.channel = 1;
    wc.ap.max_connection = 4;
    if (strnlen(cfg->softap_pass, 64) >= 8) {
        memcpy(wc.ap.password, cfg->softap_pass, strnlen(cfg->softap_pass, sizeof(wc.ap.password)));
        wc.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        wc.ap.authmode = WIFI_AUTH_OPEN; // password too short for WPA2
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGW(TAG, "SoftAP up: SSID='%s' auth=%s  ->  http://192.168.4.1/",
             cfg->softap_ssid,
             wc.ap.authmode == WIFI_AUTH_OPEN ? "open" : "wpa2");
}

// --------------------------------------------------------------- HTTP helpers
// Read the whole request body into buf (NUL-terminated). Returns length or -1.
static int recv_body(httpd_req_t *req, char *buf, size_t maxlen)
{
    size_t total = 0;
    while (total < req->content_len && total + 1 < maxlen) {
        size_t want = req->content_len - total;
        if (want > maxlen - 1 - total) want = maxlen - 1 - total;
        int r = httpd_req_recv(req, buf + total, want);
        if (r <= 0) {
            if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
            return -1;
        }
        total += r;
    }
    buf[total] = '\0';
    return (int)total;
}

static bool form_str(const char *body, const char *key, char *out, size_t n)
{
    return httpd_query_key_value(body, key, out, n) == ESP_OK;
}

static int form_int(const char *body, const char *key, int def)
{
    char v[16];
    if (httpd_query_key_value(body, key, v, sizeof(v)) == ESP_OK) {
        return atoi(v);
    }
    return def;
}

// ------------------------------------------------------------------- handlers
static esp_err_t root_get(httpd_req_t *req)
{
    splinter_cfg_t *c = config_get();
    const esp_app_desc_t *app = esp_app_get_description();

    char *p = malloc(4096);
    if (!p) return httpd_resp_send_500(req);
    int n = snprintf(p, 4096,
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Splinter</title><style>"
        "body{font-family:system-ui,sans-serif;max-width:480px;margin:1.2rem auto;padding:0 1rem;background:#111;color:#eee}"
        "h1{font-size:1.3rem}h2{font-size:1rem;margin-top:1.4rem;border-bottom:1px solid #444;padding-bottom:.2rem}"
        "label{display:block;margin:.5rem 0}input[type=number],input[type=text],input[type=password]"
        "{width:100%%;padding:.4rem;background:#222;color:#eee;border:1px solid #555;border-radius:4px;box-sizing:border-box}"
        "button{margin-top:1rem;padding:.6rem 1rem;background:#2a7;color:#fff;border:0;border-radius:6px;font-size:1rem}"
        ".muted{color:#999;font-size:.85rem}</style></head><body>"
        "<h1>Splinter &mdash; maintenance</h1>"
        "<p class=muted>fw %s &middot; built %s</p>"
        "<form method=POST action=/save>"
        "<h2>BLE decoys</h2>"
        "<label><input type=checkbox name=ble_en %s> BLE enabled</label>"
        "<label>Advertising interval (ms)<input type=number name=ble_adv value=%u></label>"
        "<label>Name probability (%%)<input type=number name=ble_name value=%u></label>"
        "<label>Mfg-data probability (%%)<input type=number name=ble_mfg value=%u></label>"
        "<label>Refresh pacing (ms)<input type=number name=ble_ref value=%u></label>"
        "<h2>802.15.4 decoys</h2>"
        "<label><input type=checkbox name=g_en %s> 802.15.4 enabled</label>"
        "<label>Beacon interval (ms)<input type=number name=g_beac value=%u></label>"
        "<label><input type=checkbox name=g_resp %s> Answer beacon requests</label>"
        "<h2>SoftAP</h2>"
        "<label>SSID<input type=text name=ssid value='%s'></label>"
        "<label>Password (>=8 chars)<input type=password name=pass value='%s'></label>"
        "<button type=submit>Save &amp; keep running</button>"
        "</form>"
        "<h2>Firmware update</h2>"
        "<input type=file id=fw accept='.bin'>"
        "<button onclick=up()>Upload &amp; reboot</button>"
        "<p id=st class=muted></p>"
        "<form method=POST action=/reboot><button style='background:#555'>Reboot to normal (decoys)</button></form>"
        "<script>function up(){var f=document.getElementById('fw').files[0];if(!f){st.textContent='pick a .bin';return;}"
        "st.textContent='uploading '+f.name+'...';fetch('/ota',{method:'POST',body:f})"
        ".then(r=>r.text()).then(t=>{st.textContent=t;}).catch(e=>{st.textContent='error: '+e;});}</script>"
        "</body></html>",
        app->version, app->date,
        c->ble_enabled ? "checked" : "", c->ble_adv_ms, c->ble_name_prob, c->ble_mfg_prob, c->ble_refresh_ms,
        c->ieee154_enabled ? "checked" : "", c->ieee154_beacon_ms, c->ieee154_respond ? "checked" : "",
        c->softap_ssid, c->softap_pass);

    httpd_resp_set_type(req, "text/html");
    esp_err_t e = httpd_resp_send(req, p, n);
    free(p);
    return e;
}

static esp_err_t save_post(httpd_req_t *req)
{
    char body[512];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return httpd_resp_send_500(req);
    }
    splinter_cfg_t *c = config_get();

    // Checkboxes: present only when ticked.
    c->ble_enabled     = (strstr(body, "ble_en=") != NULL);
    c->ieee154_enabled = (strstr(body, "g_en=")   != NULL);
    c->ieee154_respond = (strstr(body, "g_resp=") != NULL);

    c->ble_adv_ms      = (uint16_t)form_int(body, "ble_adv",  c->ble_adv_ms);
    c->ble_name_prob   = (uint8_t) form_int(body, "ble_name", c->ble_name_prob);
    c->ble_mfg_prob    = (uint8_t) form_int(body, "ble_mfg",  c->ble_mfg_prob);
    c->ble_refresh_ms  = (uint16_t)form_int(body, "ble_ref",  c->ble_refresh_ms);
    c->ieee154_beacon_ms = (uint16_t)form_int(body, "g_beac", c->ieee154_beacon_ms);

    char tmp[65];
    if (form_str(body, "ssid", tmp, sizeof(tmp)) && tmp[0]) {
        strncpy(c->softap_ssid, tmp, sizeof(c->softap_ssid) - 1);
        c->softap_ssid[sizeof(c->softap_ssid) - 1] = '\0';
    }
    if (form_str(body, "pass", tmp, sizeof(tmp))) {
        strncpy(c->softap_pass, tmp, sizeof(c->softap_pass) - 1);
        c->softap_pass[sizeof(c->softap_pass) - 1] = '\0';
    }

    if (c->ble_name_prob > 100) c->ble_name_prob = 100;
    if (c->ble_mfg_prob  > 100) c->ble_mfg_prob  = 100;
    if (c->ble_refresh_ms < 1)  c->ble_refresh_ms = 1;

    esp_err_t err = config_save();
    ESP_LOGW(TAG, "config saved (%s)", esp_err_to_name(err));

    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t ota_post(httpd_req_t *req)
{
    status_led_set(LED_STATE_OTA);
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        status_led_set(LED_STATE_ERROR);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no OTA partition");
        return ESP_FAIL;
    }
    ESP_LOGW(TAG, "OTA -> %s (%lu bytes incoming)", part->label, (unsigned long)req->content_len);

    esp_ota_handle_t h;
    if (esp_ota_begin(part, OTA_SIZE_UNKNOWN, &h) != ESP_OK) {
        status_led_set(LED_STATE_ERROR);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ota_begin failed");
        return ESP_FAIL;
    }

    char buf[1024];
    int remaining = req->content_len;
    bool ok = true;
    while (remaining > 0) {
        int want = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
        int r = httpd_req_recv(req, buf, want);
        if (r <= 0) {
            if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
            ok = false;
            break;
        }
        if (esp_ota_write(h, buf, r) != ESP_OK) {
            ok = false;
            break;
        }
        remaining -= r;
    }

    if (ok && esp_ota_end(h) == ESP_OK && esp_ota_set_boot_partition(part) == ESP_OK) {
        httpd_resp_sendstr(req, "OK — rebooting into new firmware");
        ESP_LOGW(TAG, "OTA complete, rebooting");
        vTaskDelay(pdMS_TO_TICKS(800));
        esp_restart();
    } else {
        esp_ota_abort(h);
        status_led_set(LED_STATE_ERROR);
        ESP_LOGE(TAG, "OTA failed");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
    }
    return ESP_OK;
}

static esp_err_t reboot_post(httpd_req_t *req)
{
    httpd_resp_sendstr(req, "rebooting to normal mode...");
    ESP_LOGW(TAG, "reboot to normal requested");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

static void http_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;
    cfg.stack_size = 8192;
    httpd_handle_t srv = NULL;
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "http server start failed");
        return;
    }
    httpd_uri_t routes[] = {
        { .uri = "/",       .method = HTTP_GET,  .handler = root_get },
        { .uri = "/save",   .method = HTTP_POST, .handler = save_post },
        { .uri = "/ota",    .method = HTTP_POST, .handler = ota_post },
        { .uri = "/reboot", .method = HTTP_POST, .handler = reboot_post },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_register_uri_handler(srv, &routes[i]);
    }
    ESP_LOGW(TAG, "http server up with %d routes", (int)(sizeof(routes) / sizeof(routes[0])));
}

void maintenance_run(void)
{
    ESP_LOGW(TAG, "MAINTENANCE mode: decoys paused, bringing up Wi-Fi");
    wifi_softap_start();
    http_start();
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
