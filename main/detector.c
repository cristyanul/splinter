#include "detector.h"
#include "config.h"
#include "swarm.h"
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

// ---- threat journal: a persisted ring buffer of confirmed followers ----
#define LOG_CAP  24
#define LOG_KEY  "log"
#define BOOT_KEY "boot"
typedef struct { uint8_t count; uint8_t head; threat_log_t e[LOG_CAP]; } log_blob_t;
static log_blob_t s_log;
static uint16_t   s_boot;

// Load the journal and bump the boot counter (orders events across reboots).
static void journal_load(void)
{
    nvs_handle_t h;
    if (nvs_open(DET_NS, NVS_READWRITE, &h) != ESP_OK) return;
    size_t sz = sizeof(s_log);
    if (nvs_get_blob(h, LOG_KEY, &s_log, &sz) != ESP_OK || sz != sizeof(s_log)) {
        memset(&s_log, 0, sizeof(s_log));
    }
    s_boot = 0;
    nvs_get_u16(h, BOOT_KEY, &s_boot);
    s_boot++;
    nvs_set_u16(h, BOOT_KEY, s_boot);
    nvs_commit(h);
    nvs_close(h);
}

// Append a confirmed follower to the ring and persist. Called on the rising edge
// only (rare), so the NVS write is not a hot path.
static void journal_append(const dc_threat_t *t, uint32_t uptime_ms)
{
    threat_log_t *e = &s_log.e[s_log.head];
    memset(e, 0, sizeof(*e));
    e->boot       = s_boot;
    e->uptime_min = (uint16_t)(uptime_ms / 60000u);
    e->kind       = t->tracker_kind;
    memcpy(e->id, t->id, 6);
    e->rssi       = t->rssi;
    e->minutes    = t->minutes;
    e->scenes     = t->scenes;
    s_log.head = (uint8_t)((s_log.head + 1) % LOG_CAP);
    if (s_log.count < LOG_CAP) s_log.count++;

    nvs_handle_t h;
    if (nvs_open(DET_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_blob(h, LOG_KEY, &s_log, sizeof(s_log));
        nvs_commit(h);
        nvs_close(h);
    }
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

int detector_kind_alerts(dc_kind_alert_t *out, int max)
{
    if (!s_lock) return 0;
    int n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        n = dc_kind_alerts(&s_state, out, max);
        xSemaphoreGive(s_lock);
    }
    return n;
}

int detector_threatlog(threat_log_t *out, int max)
{
    if (!s_lock) return 0;
    int n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        int cnt = s_log.count;
        for (int i = 0; i < cnt && n < max; i++) {
            int idx = (s_log.head - 1 - i + 2 * LOG_CAP) % LOG_CAP; // newest-first
            out[n++] = s_log.e[idx];
        }
        xSemaphoreGive(s_lock);
    }
    return n;
}

bool detector_alert(void)
{
    if (!s_lock) return false;
    bool a = false;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
        // Local threat OR a live peer report — the latter makes the alert fire
        // swarm-wide so one node's detection lights every node.
        a = (dc_threat_count(&s_state) > 0) || (s_state.npeer > 0);
        xSemaphoreGive(s_lock);
    }
    return a;
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
    static uint8_t rep[16][6];   // threat ids already broadcast (rising-edge guard)
    static int nrep = 0;
    for (;;) {
        // Wait up to 1s for a sighting; either way fall through to scene/score.
        bool got = (xQueueReceive(s_queue, &sg, pdMS_TO_TICKS(1000)) == pdTRUE);
        if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) continue;
        uint32_t t = now_ms();
        int allow_before = s_state.nallow;
        if (got) dc_ingest(&s_state, &sg, t);

        // Swarm: ingest peer threat reports so they corroborate local sightings.
        uint8_t peer_ids[10][6];
        int npid = 0;
        swarm_threat_t pt;
        while (swarm_receive_threat(&pt)) {
            dc_ingest_peer(&s_state, pt.id, pt.tracker_kind, pt.fp, pt.rssi, t);
            if (npid < 10) memcpy(peer_ids[npid++], pt.id, 6);
        }

        if (dc_due_scene(&s_state, t)) dc_scene_tick(&s_state, t);
        dc_score(&s_state, t);

        // Swarm: broadcast newly-confirmed LOCAL threats once. Loop guard — never
        // re-broadcast a threat a peer reported this pass (peer_backed), and only
        // announce on the rising edge (not already in `rep`).
        dc_threat_t th[16];
        int nth = dc_threats(&s_state, th, 16);
        uint8_t newrep[16][6];
        int nnew = 0;
        for (int i = 0; i < nth; i++) {
            bool peer_backed = false;
            for (int j = 0; j < npid; j++)
                if (memcmp(peer_ids[j], th[i].id, 6) == 0) { peer_backed = true; break; }
            bool already = false;
            for (int j = 0; j < nrep; j++)
                if (memcmp(rep[j], th[i].id, 6) == 0) { already = true; break; }
            if (!already) {                       // rising edge: journal it once
                journal_append(&th[i], t);
                if (!peer_backed) {               // ...and announce locally-found ones
                    swarm_threat_t out = {0};
                    memcpy(out.id, th[i].id, 6);
                    out.tracker_kind = th[i].tracker_kind;
                    out.rssi = th[i].rssi;
                    out.fp = th[i].fp;
                    swarm_broadcast_threat(&out);
                }
            }
            if (nnew < 16) memcpy(newrep[nnew++], th[i].id, 6);
        }
        if (nnew) memcpy(rep, newrep, (size_t)nnew * 6);
        nrep = nnew;

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
    journal_load();
    s_lock  = xSemaphoreCreateMutex();
    s_queue = xQueueCreate(32, sizeof(dc_sighting_t));
    if (!s_lock || !s_queue) { ESP_LOGE(TAG, "alloc failed"); return; }
    s_state.scene_started_ms = now_ms();
    dc_begin_safe(&s_state, now_ms(), SAFE_WINDOW_MS); // learn at boot
    xTaskCreate(detector_task, "splinter_det", 4096, NULL, 4, NULL);
    ESP_LOGW(TAG, "follower detection started (learning %lus)",
             (unsigned long)(SAFE_WINDOW_MS / 1000));
}
