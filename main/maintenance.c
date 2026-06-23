// Web UI: Wi-Fi SoftAP + HTTP server for live config editing and OTA firmware
// upload, served from a LittleFS partition. Toggled on/off at runtime via the
// BOOT button (webui_start / webui_stop) WITHOUT rebooting — the BLE / 802.15.4
// / Wi-Fi decoys keep running underneath. Bringing the UI up switches Wi-Fi to
// AP+STA and raises the SoftAP; taking it down returns Wi-Fi to STA-only.

#include "maintenance.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_app_desc.h"
#include "esp_littlefs.h"

#include "config.h"
#include "status_led.h"
#include "decoys_ble.h"
#include "decoys_154.h"
#include "decoys_wifi.h"
#include "detector.h"

static const char *TAG = "splinter-maint";

// ---------------------------------------------------------------- Wi-Fi SoftAP
static void wifi_softap_start(void)
{
    splinter_cfg_t *cfg = config_get();

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

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wc));

    ESP_LOGW(TAG, "SoftAP up: SSID='%s' auth=%s  ->  http://192.168.4.1/",
             cfg->softap_ssid,
             wc.ap.authmode == WIFI_AUTH_OPEN ? "open" : "wpa2");
}

// --------------------------------------------------------------- HTTP helpers
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

static esp_err_t serve_file(httpd_req_t *req, const char *filepath, const char *content_type) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open file: %s", filepath);
        return httpd_resp_send_404(req);
    }
    httpd_resp_set_type(req, content_type);
    char chunk[1024];
    size_t chunksize;
    do {
        chunksize = fread(chunk, 1, sizeof(chunk), f);
        if (chunksize > 0) {
            if (httpd_resp_send_chunk(req, chunk, chunksize) != ESP_OK) {
                fclose(f);
                return ESP_FAIL;
            }
        }
    } while (chunksize != 0);
    fclose(f);
    return httpd_resp_send_chunk(req, NULL, 0); // End of stream
}

// ------------------------------------------------------------------- handlers
static esp_err_t index_get(httpd_req_t *req) { return serve_file(req, "/littlefs/index.html", "text/html"); }
static esp_err_t css_get(httpd_req_t *req)   { return serve_file(req, "/littlefs/app.css", "text/css"); }
static esp_err_t js_get(httpd_req_t *req)    { return serve_file(req, "/littlefs/app.js", "application/javascript"); }

static esp_err_t api_config_get(httpd_req_t *req) {
    splinter_cfg_t *c = config_get();
    char buf[1024];
    snprintf(buf, sizeof(buf), 
        "{\"ble_enabled\":%s,\"ieee154_enabled\":%s,\"wifi_enabled\":%s,\"profiles_enabled\":%s,\"swarm_enabled\":%s,"
        "\"thread_enabled\":%s,\"awdl_enabled\":%s,"
        "\"ble_adv_ms\":%u,\"ble_name_prob\":%u,\"ble_mfg_prob\":%u,\"ble_refresh_ms\":%u,"
        "\"ieee154_chan_mask\":%lu,\"ieee154_beacon_ms\":%u,\"ieee154_respond\":%s,"
        // softap_pass is deliberately NOT returned (it would leak the AP key to
        // anyone on the network); the UI sends a new one only to change it.
        "\"wifi_interval_ms\":%u,\"softap_ssid\":\"%s\",\"softap_pass\":\"\"}",
        c->ble_enabled?"true":"false", c->ieee154_enabled?"true":"false", c->wifi_enabled?"true":"false",
        c->profiles_enabled?"true":"false", c->swarm_enabled?"true":"false",
        c->thread_enabled?"true":"false", c->awdl_enabled?"true":"false",
        c->ble_adv_ms, c->ble_name_prob, c->ble_mfg_prob, c->ble_refresh_ms,
        (unsigned long)c->ieee154_chan_mask, c->ieee154_beacon_ms, c->ieee154_respond?"true":"false",
        c->wifi_interval_ms, c->softap_ssid);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

static esp_err_t api_config_post(httpd_req_t *req) {
    char body[1024];
    if (recv_body(req, body, sizeof(body)) < 0) return httpd_resp_send_500(req);

    // Sanity-gate: the booleans below are derived from key presence, so an empty
    // or non-JSON body would silently disable every decoy. Require a known key
    // before mutating anything.
    if (strstr(body, "\"ble_enabled\"") == NULL) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"status\":\"bad request\"}");
    }

    splinter_cfg_t *c = config_get();
    c->ble_enabled = (strstr(body, "\"ble_enabled\":true") != NULL);
    c->ieee154_enabled = (strstr(body, "\"ieee154_enabled\":true") != NULL);
    c->wifi_enabled = (strstr(body, "\"wifi_enabled\":true") != NULL);
    c->profiles_enabled = (strstr(body, "\"profiles_enabled\":true") != NULL);
    c->swarm_enabled = (strstr(body, "\"swarm_enabled\":true") != NULL);
    c->ieee154_respond = (strstr(body, "\"ieee154_respond\":true") != NULL);
    c->thread_enabled = (strstr(body, "\"thread_enabled\":true") != NULL);
    c->awdl_enabled = (strstr(body, "\"awdl_enabled\":true") != NULL);

    // Simple JSON parsing for numbers and strings
    char *p;
    if ((p = strstr(body, "\"ble_adv_ms\":"))) c->ble_adv_ms = atoi(p + 13);
    if ((p = strstr(body, "\"ble_name_prob\":"))) c->ble_name_prob = atoi(p + 16);
    if ((p = strstr(body, "\"ble_mfg_prob\":"))) c->ble_mfg_prob = atoi(p + 15);
    if ((p = strstr(body, "\"ble_refresh_ms\":"))) c->ble_refresh_ms = atoi(p + 17);
    if ((p = strstr(body, "\"ieee154_chan_mask\":"))) c->ieee154_chan_mask = strtoul(p + 20, NULL, 10);
    if ((p = strstr(body, "\"ieee154_beacon_ms\":"))) c->ieee154_beacon_ms = atoi(p + 20);
    if ((p = strstr(body, "\"wifi_interval_ms\":"))) c->wifi_interval_ms = atoi(p + 19);

    if ((p = strstr(body, "\"softap_ssid\":\""))) {
        p += 15;
        char *end = strchr(p, '\"');
        // Ignore an empty SSID so a blank field can't knock out the AP name.
        if (end && end > p && (end - p) < sizeof(c->softap_ssid)) {
            memcpy(c->softap_ssid, p, end - p);
            c->softap_ssid[end - p] = '\0';
        }
    }
    if ((p = strstr(body, "\"softap_pass\":\""))) {
        p += 15;
        char *end = strchr(p, '\"');
        // Only change the password when a non-empty value is supplied, so the
        // redacted (blank) field from the UI leaves the current key intact.
        if (end && end > p && (end - p) < sizeof(c->softap_pass)) {
            memcpy(c->softap_pass, p, end - p);
            c->softap_pass[end - p] = '\0';
        }
    }
    
    esp_err_t err = config_save();
    ESP_LOGW(TAG, "config saved via API (%s)", esp_err_to_name(err));

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
}

static esp_err_t api_status_get(httpd_req_t *req) {
    char buf[320];
    uint32_t uptime = esp_log_timestamp() / 1000;
    uint32_t heap = esp_get_free_heap_size();
    snprintf(buf, sizeof(buf),
        "{\"uptime\":%lu,\"free_heap\":%lu,"
        "\"ble_rate\":%lu,\"ieee154_rate\":%lu,\"wifi_rate\":%lu,"
        "\"thread_rate\":%lu,\"awdl_rate\":%lu,"
        "\"threats\":%lu}",
        (unsigned long)uptime, (unsigned long)heap,
        (unsigned long)decoys_ble_rate(),
        (unsigned long)decoys_154_rate(),
        (unsigned long)decoys_wifi_rate(),
        (unsigned long)decoys_154_thread_rate(),
        (unsigned long)decoys_wifi_awdl_rate(),
        (unsigned long)detector_threat_count());
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

static esp_err_t api_reboot_post(httpd_req_t *req) {
    httpd_resp_sendstr(req, "{\"status\":\"rebooting\"}");
    ESP_LOGW(TAG, "reboot to normal requested via API");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

// Bytes of image we must buffer before we can read the app descriptor:
// image header + first segment header + app description.
#define OTA_HEADER_NEED (sizeof(esp_image_header_t) + \
                         sizeof(esp_image_segment_header_t) + \
                         sizeof(esp_app_desc_t))

// Streams a raw firmware image (POST body) into the inactive OTA slot, then sets
// it bootable and reboots. Hardened: rejects empty/oversized uploads, validates
// the image + app-descriptor magic before committing, requires the full
// declared length to arrive, and lets esp_ota_end() verify the image checksum.
static esp_err_t api_ota_post(httpd_req_t *req)
{
    status_led_set(LED_STATE_OTA);

    int total = req->content_len;
    if (total <= 0) {
        status_led_set(LED_STATE_ERROR);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty upload");
        return ESP_FAIL;
    }

    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        status_led_set(LED_STATE_ERROR);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no OTA partition");
        return ESP_FAIL;
    }
    if ((uint32_t)total > part->size) {
        status_led_set(LED_STATE_ERROR);
        ESP_LOGE(TAG, "OTA image %d > partition %s (%lu)", total, part->label, (unsigned long)part->size);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "image too large for partition");
        return ESP_FAIL;
    }
    ESP_LOGW(TAG, "OTA -> %s (%d bytes incoming)", part->label, total);

    esp_ota_handle_t h;
    if (esp_ota_begin(part, total, &h) != ESP_OK) {
        status_led_set(LED_STATE_ERROR);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ota_begin failed");
        return ESP_FAIL;
    }

    char    buf[1024];
    char    head[OTA_HEADER_NEED];
    int     head_len = 0;
    int     received = 0;
    int     next_pct = 10;
    bool    ok = true;
    bool    header_ok = false;

    while (received < total) {
        int want = (total - received) < (int)sizeof(buf) ? (total - received) : (int)sizeof(buf);
        int r = httpd_req_recv(req, buf, want);
        if (r <= 0) {
            if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
            ESP_LOGE(TAG, "OTA recv error %d at %d/%d", r, received, total);
            ok = false;
            break;
        }

        // Validate the firmware header once enough bytes have arrived, before
        // we trust the rest of the stream.
        if (!header_ok) {
            int copy = r;
            if (head_len + copy > (int)sizeof(head)) copy = (int)sizeof(head) - head_len;
            memcpy(head + head_len, buf, copy);
            head_len += copy;
            if (head_len >= (int)sizeof(head)) {
                if ((uint8_t)head[0] != ESP_IMAGE_HEADER_MAGIC) {
                    ESP_LOGE(TAG, "bad image magic 0x%02x", (uint8_t)head[0]);
                    ok = false;
                    break;
                }
                esp_app_desc_t newd;
                memcpy(&newd, head + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t),
                       sizeof(newd));
                if (newd.magic_word != ESP_APP_DESC_MAGIC_WORD) {
                    ESP_LOGE(TAG, "bad app descriptor magic 0x%08lx", (unsigned long)newd.magic_word);
                    ok = false;
                    break;
                }
                const esp_app_desc_t *cur = esp_app_get_description();
                if (strncmp(newd.project_name, cur->project_name, sizeof(newd.project_name)) != 0) {
                    ESP_LOGW(TAG, "OTA project '%s' != running '%s' (flashing anyway)",
                             newd.project_name, cur->project_name);
                }
                ESP_LOGW(TAG, "OTA image OK: project='%s' version='%s'", newd.project_name, newd.version);
                header_ok = true;
            }
        }

        if (esp_ota_write(h, buf, r) != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed at %d/%d", received, total);
            ok = false;
            break;
        }
        received += r;

        int pct = (int)((int64_t)received * 100 / total);
        if (pct >= next_pct) {
            ESP_LOGW(TAG, "OTA %d%% (%d/%d)", pct, received, total);
            next_pct += 10;
        }
    }

    // Require: no error, the full declared length, and a validated header.
    if (ok && received == total && header_ok &&
        esp_ota_end(h) == ESP_OK && esp_ota_set_boot_partition(part) == ESP_OK) {
        httpd_resp_sendstr(req, "OK — rebooting into new firmware");
        ESP_LOGW(TAG, "OTA complete (%d bytes), rebooting", received);
        vTaskDelay(pdMS_TO_TICKS(800));
        esp_restart();
    } else {
        esp_ota_abort(h);
        status_led_set(LED_STATE_ERROR);
        ESP_LOGE(TAG, "OTA aborted (received %d/%d, ok=%d, header_ok=%d)",
                 received, total, ok, header_ok);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA failed");
    }
    return ESP_OK;
}

static const char *trk_name(uint8_t k) {
    switch (k) {
        case DC_TRK_APPLE_FINDMY: return "Apple Find My";
        case DC_TRK_SAMSUNG:      return "Samsung tag";
        case DC_TRK_TILE:         return "Tile";
        default:                  return "device";
    }
}

static esp_err_t api_threats_get(httpd_req_t *req) {
    dc_threat_t t[16];
    int n = detector_threats(t, 16);
    char buf[1024];
    int o = snprintf(buf, sizeof(buf), "{\"threats\":[");
    for (int i = 0; i < n; i++) {
        if (o > (int)sizeof(buf) - 160) break;   // ensure room for one entry + "]}"
        o += snprintf(buf + o, sizeof(buf) - o,
            "%s{\"id\":\"%02x%02x%02x%02x%02x%02x\",\"radio\":\"%s\",\"kind\":\"%s\","
            "\"rssi\":%d,\"minutes\":%u,\"scenes\":%u}",
            i ? "," : "",
            t[i].id[0], t[i].id[1], t[i].id[2], t[i].id[3], t[i].id[4], t[i].id[5],
            t[i].radio == DC_RADIO_BLE ? "ble" : "wifi",
            trk_name(t[i].tracker_kind), t[i].rssi, t[i].minutes, t[i].scenes);
    }
    if (o > (int)sizeof(buf) - 3) o = (int)sizeof(buf) - 3;
    o += snprintf(buf + o, sizeof(buf) - o, "]}");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static esp_err_t api_allow_post(httpd_req_t *req) {
    char body[128];
    if (recv_body(req, body, sizeof(body)) < 0) return httpd_resp_send_500(req);
    char *p = strstr(body, "\"id\":\"");
    if (!p) { httpd_resp_set_status(req, "400 Bad Request");
              return httpd_resp_sendstr(req, "{\"status\":\"bad id\"}"); }
    p += 6;
    // Ensure 12 hex chars are actually present before parsing so the loop below
    // (which reads p[0]..p[11]) cannot run past the NUL terminator of a short body.
    if (strnlen(p, 12) < 12) { httpd_resp_set_status(req, "400 Bad Request");
                               return httpd_resp_sendstr(req, "{\"status\":\"bad id\"}"); }
    uint8_t id[6];
    for (int i = 0; i < 6; i++) {
        int hi = hexval(p[i*2]), lo = hexval(p[i*2+1]);
        if (hi < 0 || lo < 0) { httpd_resp_set_status(req, "400 Bad Request");
                                return httpd_resp_sendstr(req, "{\"status\":\"bad id\"}"); }
        id[i] = (uint8_t)((hi << 4) | lo);
    }
    bool on = (strstr(body, "\"on\":false") == NULL); // default add
    detector_allow(id, on);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
}

static esp_err_t api_safe_post(httpd_req_t *req) {
    detector_begin_safe();
    ESP_LOGW(TAG, "safe/learning window started via API");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"status\":\"learning\"}");
}

// Radar feed: currently-heard followers + trusted devices (blips), plus the
// full allowlist (the trusted-device management list).
static esp_err_t api_radar_get(httpd_req_t *req) {
    dc_radar_t dev[20];
    int nd = detector_radar(dev, 20);
    uint8_t trust[32][6];
    int nt = detector_allowlist(trust, 32);

    char buf[3072];
    int o = snprintf(buf, sizeof(buf), "{\"devices\":[");
    for (int i = 0; i < nd; i++) {
        if (o > (int)sizeof(buf) - 160) break;
        o += snprintf(buf + o, sizeof(buf) - o,
            "%s{\"id\":\"%02x%02x%02x%02x%02x%02x\",\"radio\":\"%s\",\"kind\":\"%s\","
            "\"rssi\":%d,\"minutes\":%u,\"scenes\":%u,\"cat\":\"%s\"}",
            i ? "," : "",
            dev[i].id[0], dev[i].id[1], dev[i].id[2], dev[i].id[3], dev[i].id[4], dev[i].id[5],
            dev[i].radio == DC_RADIO_BLE ? "ble" : "wifi",
            trk_name(dev[i].tracker_kind), dev[i].rssi, dev[i].minutes, dev[i].scenes,
            dev[i].category == DC_CAT_THREAT ? "threat" : "trusted");
    }
    o += snprintf(buf + o, sizeof(buf) - o, "],\"trusted\":[");
    for (int i = 0; i < nt; i++) {
        if (o > (int)sizeof(buf) - 24) break;
        o += snprintf(buf + o, sizeof(buf) - o, "%s\"%02x%02x%02x%02x%02x%02x\"",
            i ? "," : "",
            trust[i][0], trust[i][1], trust[i][2], trust[i][3], trust[i][4], trust[i][5]);
    }
    if (o > (int)sizeof(buf) - 4) o = (int)sizeof(buf) - 4;
    o += snprintf(buf + o, sizeof(buf) - o, "]}");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

static httpd_handle_t srv = NULL;

static void http_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.lru_purge_enable = true;
    cfg.stack_size = 8192;
    cfg.max_uri_handlers = 16; // default is 8; we register 12 and want headroom
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "http server start failed");
        return;
    }
    httpd_uri_t routes[] = {
        { .uri = "/",           .method = HTTP_GET,  .handler = index_get },
        { .uri = "/app.css",    .method = HTTP_GET,  .handler = css_get },
        { .uri = "/app.js",     .method = HTTP_GET,  .handler = js_get },
        { .uri = "/api/config", .method = HTTP_GET,  .handler = api_config_get },
        { .uri = "/api/config", .method = HTTP_POST, .handler = api_config_post },
        { .uri = "/api/status", .method = HTTP_GET,  .handler = api_status_get },
        { .uri = "/api/reboot", .method = HTTP_POST, .handler = api_reboot_post },
        { .uri = "/api/ota",    .method = HTTP_POST, .handler = api_ota_post },
        { .uri = "/api/threats", .method = HTTP_GET,  .handler = api_threats_get },
        { .uri = "/api/allow",   .method = HTTP_POST, .handler = api_allow_post },
        { .uri = "/api/safe",    .method = HTTP_POST, .handler = api_safe_post },
        { .uri = "/api/radar",   .method = HTTP_GET,  .handler = api_radar_get },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_register_uri_handler(srv, &routes[i]);
    }
    ESP_LOGW(TAG, "http server up with %d routes", (int)(sizeof(routes) / sizeof(routes[0])));
}

static void littlefs_mount_once(void)
{
    static bool mounted = false;
    if (mounted) return;

    esp_vfs_littlefs_conf_t conf = {
        .base_path = "/littlefs",
        .partition_label = "ui",
        .format_if_mount_failed = false,
        .dont_mount = false,
    };
    esp_err_t err = esp_vfs_littlefs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "LittleFS mount failed: %s", esp_err_to_name(err));
        return;
    }
    mounted = true;
}

// The ONE guarded way to change Wi-Fi mode while the radios are live. It
// quiesces the decoy TX + promiscuous sniffer, waits for in-flight ops to drain,
// switches mode, then resumes. A bare esp_wifi_set_mode() concurrent with active
// TX/RX can hard-hang the Wi-Fi driver — so once the engines are running, mode
// changes MUST go through here, never esp_wifi_set_mode() directly.
static esp_err_t wifi_set_mode_safe(wifi_mode_t mode)
{
    decoys_wifi_set_paused(true);
    esp_wifi_set_promiscuous(false);
    vTaskDelay(pdMS_TO_TICKS(60));            // let in-flight TX/RX drain
    esp_err_t err = esp_wifi_set_mode(mode);
    esp_wifi_set_promiscuous(true);           // restore the always-on sniffer
    decoys_wifi_set_paused(false);
    return err;
}

void webui_start(void)
{
    if (srv != NULL) return;
    ESP_LOGW(TAG, "Starting Web UI...");

    littlefs_mount_once();

    ESP_ERROR_CHECK(wifi_set_mode_safe(WIFI_MODE_APSTA));
    wifi_softap_start();
    http_start();
}

void webui_stop(void)
{
    if (srv == NULL) return;
    ESP_LOGW(TAG, "Stopping Web UI...");

    httpd_stop(srv);
    srv = NULL;
    ESP_ERROR_CHECK(wifi_set_mode_safe(WIFI_MODE_STA));
}
