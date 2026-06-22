#include "detector.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "nvs.h"
#include <string.h>

static const char *TAG = "splinter-detect";

#define SAFE_WINDOW_MS   180000u   // 3 min learning window (boot + on demand)

#define DET_NS    "splinter-det"
#define DET_KEY   "allow"

static dc_state_t       s_state;
static QueueHandle_t    s_queue;
static SemaphoreHandle_t s_lock;   // guards s_state for UI reads

static void allow_load(void)
{
    nvs_handle_t h;
    if (nvs_open(DET_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t sz = sizeof(s_state.allow);
    uint8_t buf[sizeof(s_state.allow)];
    if (nvs_get_blob(h, DET_KEY, buf, &sz) == ESP_OK && (sz % 6) == 0) {
        int n = (int)(sz / 6);
        if (n > DC_ALLOW_MAX) n = DC_ALLOW_MAX;
        memcpy(s_state.allow, buf, n * 6);
        s_state.nallow = n;
    }
    nvs_close(h);
}

static void allow_save(void)
{
    nvs_handle_t h;
    if (nvs_open(DET_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, DET_KEY, s_state.allow, s_state.nallow * 6);
    nvs_commit(h);
    nvs_close(h);
}

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

void detector_report_sighting(const dc_sighting_t *s)
{
    if (s_queue) xQueueSend(s_queue, s, 0);
}

int detector_threats(dc_threat_t *out, int max)
{
    if (!s_lock) return 0;
    int n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        n = dc_threats(&s_state, out, max);
        xSemaphoreGive(s_lock);
    }
    return n;
}

int detector_radar(dc_radar_t *out, int max)
{
    if (!s_lock) return 0;
    int n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        n = dc_radar(&s_state, out, max);
        xSemaphoreGive(s_lock);
    }
    return n;
}

int detector_allowlist(uint8_t (*out)[6], int max)
{
    if (!s_lock) return 0;
    int n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        n = dc_allowlist(&s_state, out, max);
        xSemaphoreGive(s_lock);
    }
    return n;
}

uint32_t detector_threat_count(void)
{
    if (!s_lock) return 0;
    uint32_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        n = dc_threat_count(&s_state);
        xSemaphoreGive(s_lock);
    }
    return n;
}

void detector_allow(const uint8_t id[6], bool on)
{
    if (!s_lock) return;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        dc_allow(&s_state, id, on);
        allow_save();
        xSemaphoreGive(s_lock);
    }
}

void detector_begin_safe(void)
{
    if (!s_lock) return;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
        dc_begin_safe(&s_state, now_ms(), SAFE_WINDOW_MS);
        xSemaphoreGive(s_lock);
    }
}

static void detector_task(void *arg)
{
    dc_sighting_t sg;
    for (;;) {
        // Wait up to 1s for a sighting; either way fall through to scene/score.
        bool got = (xQueueReceive(s_queue, &sg, pdMS_TO_TICKS(1000)) == pdTRUE);
        if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) continue;
        uint32_t t = now_ms();
        int allow_before = s_state.nallow;
        if (got) dc_ingest(&s_state, &sg, t);
        if (dc_due_scene(&s_state, t)) dc_scene_tick(&s_state, t);
        dc_score(&s_state, t);
        // Auto-learn (the boot/safe window) grows the allowlist in RAM; persist
        // it so the learned home baseline survives a reboot or reflash. Growth
        // only happens during a safe window, so this is not a hot-path write.
        if (s_state.nallow != allow_before) allow_save();
        xSemaphoreGive(s_lock);
    }
}

void detector_start(void)
{
    if (s_queue) return;
    dc_init(&s_state);
    allow_load();
    s_lock  = xSemaphoreCreateMutex();
    s_queue = xQueueCreate(32, sizeof(dc_sighting_t));
    if (!s_lock || !s_queue) { ESP_LOGE(TAG, "alloc failed"); return; }
    s_state.scene_started_ms = now_ms();
    dc_begin_safe(&s_state, now_ms(), SAFE_WINDOW_MS); // learn at boot
    xTaskCreate(detector_task, "splinter_det", 4096, NULL, 4, NULL);
    ESP_LOGW(TAG, "follower detection started (learning %lus)",
             (unsigned long)(SAFE_WINDOW_MS / 1000));
}
