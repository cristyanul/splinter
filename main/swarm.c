#include "swarm.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "mbedtls/md.h"
#include <string.h>
#include <stddef.h>

static const char *TAG = "splinter-swarm";
static QueueHandle_t s_swarm_queue = NULL;   // personas (decoy sharing)
static QueueHandle_t s_threat_queue = NULL;  // peer threat reports
static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Shared fleet secret. CHANGE THIS to a unique 16-byte value per deployment so
// only your own splinters can inject personas. ESP-NOW broadcast frames cannot
// be link-encrypted, so authenticity is enforced at the application layer with
// a keyed HMAC tag over each persona.
static const uint8_t SWARM_KEY[16] = {
    0x53, 0x70, 0x6c, 0x69, 0x6e, 0x74, 0x65, 0x72,
    0x2d, 0x53, 0x77, 0x61, 0x72, 0x6d, 0x21, 0x5f,
};

// Truncated HMAC-SHA256 over a message's authenticated region (everything before
// its trailing auth field — pass auth_off = offsetof(struct, auth)). Both ends
// compute over the same fixed-size prefix, so it is deterministic as long as
// senders zero-initialize. Works for any swarm message type.
static void swarm_hmac(const void *msg, size_t auth_off, uint8_t out[8])
{
    uint8_t full[32];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL ||
        mbedtls_md_hmac(info, SWARM_KEY, sizeof(SWARM_KEY),
                        (const uint8_t *)msg, auth_off, full) != 0) {
        memset(out, 0, 8);
        return;
    }
    memcpy(out, full, 8);
}

// ESP-NOW invokes this from the Wi-Fi task (NOT an ISR). Drop frames while
// swarm is disabled, that fail the magic/type checks, or that fail HMAC auth —
// so foreign or spoofed personas never reach the decoy loop.
static void swarm_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len)
{
    if (!config_get()->swarm_enabled) {
        return;
    }
    if (len < 5) {
        return; // too short to carry the common magic+type header
    }

    // Both message types share a {magic(4), type(1)} header; dispatch on it.
    uint32_t magic;
    memcpy(&magic, data, sizeof(magic));
    if (magic != SWARM_PROTO_MAGIC) {
        return;
    }
    uint8_t type = data[4];

    if (type == SWARM_MSG_WIFI_PROBE && len == (int)sizeof(swarm_persona_t)) {
        swarm_persona_t persona;
        memcpy(&persona, data, sizeof(persona));
        uint8_t expect[8];
        swarm_hmac(&persona, offsetof(swarm_persona_t, auth), expect);
        if (memcmp(expect, persona.auth, 8) != 0) {
            return; // spoofed or corrupted — reject
        }
        if (s_swarm_queue) xQueueSend(s_swarm_queue, &persona, 0);
    } else if (type == SWARM_MSG_THREAT && len == (int)sizeof(swarm_threat_t)) {
        swarm_threat_t threat;
        memcpy(&threat, data, sizeof(threat));
        uint8_t expect[8];
        swarm_hmac(&threat, offsetof(swarm_threat_t, auth), expect);
        if (memcmp(expect, threat.auth, 8) != 0) {
            return;
        }
        if (s_threat_queue) xQueueSend(s_threat_queue, &threat, 0);
    }
}

// Initialize ESP-NOW once at boot, regardless of the current swarm_enabled
// setting. The transport is cheap to keep up and idle; swarm_broadcast_persona /
// swarm_recv_cb gate on swarm_enabled, so the toggle works live from the web UI
// without a reboot. Requires Wi-Fi to already be started.
void swarm_init(void)
{
    if (s_swarm_queue != NULL) {
        return; // already initialized
    }

    s_swarm_queue = xQueueCreate(20, sizeof(swarm_persona_t));
    s_threat_queue = xQueueCreate(10, sizeof(swarm_threat_t));
    if (!s_swarm_queue || !s_threat_queue) {
        ESP_LOGE(TAG, "swarm queue alloc failed");
        return;
    }

    esp_err_t err = esp_now_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_now_init failed: %d", err);
        vQueueDelete(s_swarm_queue);
        s_swarm_queue = NULL;
        return;
    }

    ESP_ERROR_CHECK(esp_now_register_recv_cb(swarm_recv_cb));

    esp_now_peer_info_t peer_info = {0};
    memcpy(peer_info.peer_addr, broadcast_mac, 6);
    peer_info.channel = 0;      // send on the current channel; we park on
    peer_info.ifidx   = WIFI_IF_STA; // SWARM_CHANNEL during the rendezvous window
    peer_info.encrypt = false;  // broadcast can't be encrypted; HMAC auth instead
    ESP_ERROR_CHECK(esp_now_add_peer(&peer_info));

    ESP_LOGI(TAG, "Swarm ESP-NOW ready on Wi-Fi STA (rendezvous ch %d, active when enabled)",
             SWARM_CHANNEL);
}

void swarm_broadcast_persona(swarm_persona_t *persona)
{
    if (!config_get()->swarm_enabled) {
        return;
    }

    persona->magic = SWARM_PROTO_MAGIC;
    swarm_hmac(persona, offsetof(swarm_persona_t, auth), persona->auth);

    esp_err_t err = esp_now_send(broadcast_mac, (const uint8_t *)persona, sizeof(*persona));
    if (err != ESP_OK) {
        // Debug only: the queue may be full or the RF busy.
        ESP_LOGD(TAG, "Swarm broadcast failed: %d", err);
    }
}

bool swarm_receive_persona(swarm_persona_t *out_persona)
{
    if (!s_swarm_queue) return false;
    return xQueueReceive(s_swarm_queue, out_persona, 0) == pdTRUE;
}

void swarm_broadcast_threat(swarm_threat_t *threat)
{
    if (!config_get()->swarm_enabled) {
        return;
    }
    threat->magic = SWARM_PROTO_MAGIC;
    threat->type  = SWARM_MSG_THREAT;
    swarm_hmac(threat, offsetof(swarm_threat_t, auth), threat->auth);

    esp_err_t err = esp_now_send(broadcast_mac, (const uint8_t *)threat, sizeof(*threat));
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Swarm threat broadcast failed: %d", err);
    }
}

bool swarm_receive_threat(swarm_threat_t *out_threat)
{
    if (!s_threat_queue) return false;
    return xQueueReceive(s_threat_queue, out_threat, 0) == pdTRUE;
}
