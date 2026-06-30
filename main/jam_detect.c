#include "jam_detect.h"
#include "config.h"
#include "sniff_wifi.h"
#include "decoys_154.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include <string.h>

static const char *TAG = "splinter-jam";
#define SAFE_WINDOW_MS 180000u
#define JAM_NS  "splinter-jam"
#define LOG_KEY "jlog"
#define BOOT_KEY "jboot"
#define JLOG_CAP 16

static jam_state_t       s_state;
static SemaphoreHandle_t s_lock;
static volatile bool     s_wifi_trip;   // mirror for the lock-free ED cadence reader

typedef struct { uint8_t count; uint8_t head; jam_event_t e[JLOG_CAP]; } jlog_t;
static jlog_t   s_log;
static uint16_t s_boot;

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

static void journal_load(void)
{
    nvs_handle_t h;
    if (nvs_open(JAM_NS, NVS_READWRITE, &h) != ESP_OK) return;
    size_t sz = sizeof(s_log);
    if (nvs_get_blob(h, LOG_KEY, &s_log, &sz) != ESP_OK || sz != sizeof(s_log)) memset(&s_log, 0, sizeof(s_log));
    s_boot = 0; nvs_get_u16(h, BOOT_KEY, &s_boot); s_boot++;
    nvs_set_u16(h, BOOT_KEY, s_boot); nvs_commit(h); nvs_close(h);
}

static void journal_append(const jam_status_t *st, uint32_t uptime_ms)
{
    jam_event_t *e = &s_log.e[s_log.head];
    memset(e, 0, sizeof(*e));
    e->boot = s_boot; e->uptime_min = (uint16_t)(uptime_ms / 60000u);
    e->band = st->band; e->peak_energy = st->peak_energy;
    e->peak_rate = st->peak_rate; e->duration_s = st->duration_s;
    s_log.head = (uint8_t)((s_log.head + 1) % JLOG_CAP);
    if (s_log.count < JLOG_CAP) s_log.count++;
    nvs_handle_t h;
    if (nvs_open(JAM_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_blob(h, LOG_KEY, &s_log, sizeof(s_log)); nvs_commit(h); nvs_close(h);
    }
}

bool jam_detect_wifi_trip(void) { return s_wifi_trip; }

bool jam_detect_alert(void)
{
    if (!s_lock) return false;
    bool a = false;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) { a = jam_active(&s_state); xSemaphoreGive(s_lock); }
    return a;
}

void jam_detect_get_status(jam_status_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!s_lock) return;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) { jam_get_status(&s_state, out); xSemaphoreGive(s_lock); }
}

int jam_detect_journal(jam_event_t *out, int max)
{
    if (!s_lock) return 0;
    int n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        int cnt = s_log.count;
        for (int i = 0; i < cnt && n < max; i++) {
            int idx = (s_log.head - 1 - i + 2 * JLOG_CAP) % JLOG_CAP;
            out[n++] = s_log.e[idx];
        }
        xSemaphoreGive(s_lock);
    }
    return n;
}

static void jam_task(void *arg)
{
    bool was_jammed = false;
    bool abnormal_logged = false;
    jam_status_t episode_st = {0};   // latest status of the in-progress episode
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (!config_get()->jam_detect_enabled) {
            // Toggled off: clear any standing verdict so the UI/LED don't show a
            // stale "jammed" until the feature is re-enabled.
            s_wifi_trip = false;
            if (was_jammed) {
                if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) { jam_reset(&s_state); xSemaphoreGive(s_lock); }
                was_jammed = false;
            }
            continue;
        }

        jam_wifi_sample_t w; jam_ed_sample_t e;
        sniff_wifi_drain_health(&w);
        decoys_154_drain_ed(&e);

        if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) continue;
        uint32_t t = now_ms();
        jam_feed_wifi(&s_state, &w, t);
        jam_feed_ed(&s_state, &e, t);
        jam_tick(&s_state, t);
        s_wifi_trip = jam_wifi_trip(&s_state);
        bool now_jammed = jam_active(&s_state);
        jam_status_t st; jam_get_status(&s_state, &st);
        xSemaphoreGive(s_lock);

        // Surface an untrustworthy baseline once. The heuristic still runs (the trip
        // tests clamp to a sane floor), but the operator should know it learned hot.
        if (st.abnormal && !abnormal_logged) {
            ESP_LOGW(TAG, "baseline learned under abnormal RF (possible jam at boot); using sane-floor fallback");
            abnormal_logged = true;
        }

        if (now_jammed) episode_st = st;   // track the live episode (max duration/peak)

        if (now_jammed && !was_jammed) {
            ESP_LOGW(TAG, "JAMMING detected: band=%u ED_peak=%ddBm wifi_rate=%u/s",
                     st.band, st.peak_energy, st.peak_rate);
        } else if (!now_jammed && was_jammed) {
            // Journal on the FALLING edge so the entry carries the episode's real
            // peak energy/rate and duration (at the rising edge duration is just 1 s).
            ESP_LOGW(TAG, "jamming cleared (band=%u ED_peak=%ddBm wifi_rate=%u/s dur=%us)",
                     episode_st.band, episode_st.peak_energy, episode_st.peak_rate, episode_st.duration_s);
            journal_append(&episode_st, t);
        }
        was_jammed = now_jammed;
    }
}

void jam_detect_start(void)
{
    if (s_lock) return;
    jam_init(&s_state);
    journal_load();
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) { ESP_LOGE(TAG, "alloc failed"); return; }
    jam_begin_safe(&s_state, now_ms(), SAFE_WINDOW_MS);
    xTaskCreate(jam_task, "splinter_jam", 4096, NULL, 4, NULL);
    ESP_LOGW(TAG, "jam detection started (learning %lus)", (unsigned long)(SAFE_WINDOW_MS / 1000));
}
