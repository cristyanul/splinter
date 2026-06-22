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
static QueueHandle_t s_swarm_queue = NULL;
static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Shared fleet secret. CHANGE THIS to a unique 16-byte value per deployment so
// only your own splinters can inject personas. ESP-NOW broadcast frames cannot
// be link-encrypted, so authenticity is enforced at the application layer with
// a keyed HMAC tag over each persona.
static const uint8_t SWARM_KEY[16] = {
    0x53, 0x70, 0x6c, 0x69, 0x6e, 0x74, 0x65, 0x72,
    0x2d, 0x53, 0x77, 0x61, 0x72, 0x6d, 0x21, 0x5f,
};

// Truncated HMAC-SHA256 over the persona's authenticated region (everything
// before the auth field). Both ends compute over the full fixed-size struct
// prefix, so it is deterministic as long as senders zero-initialize.
static void swarm_auth(const swarm_persona_t *p, uint8_t out[8])
{
    uint8_t full[32];
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL ||
        mbedtls_md_hmac(info, SWARM_KEY, sizeof(SWARM_KEY),
                        (const uint8_t *)p, offsetof(swarm_persona_t, auth),
                        full) != 0) {
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
    if (len != (int)sizeof(swarm_persona_t)) {
        return;
    }

    swarm_persona_t persona;
    memcpy(&persona, data, sizeof(persona));

    if (persona.magic != SWARM_PROTO_MAGIC || persona.type != SWARM_MSG_WIFI_PROBE) {
        return;
    }

    uint8_t expect[8];
    swarm_auth(&persona, expect);
    if (memcmp(expect, persona.auth, sizeof(expect)) != 0) {
        return; // spoofed or corrupted — reject
    }

    if (s_swarm_queue) {
        xQueueSend(s_swarm_queue, &persona, 0);
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
    if (!s_swarm_queue) {
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
    swarm_auth(persona, persona->auth);

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
