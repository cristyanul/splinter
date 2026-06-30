// splinter — top-level: init and wiring.
//
// One runtime mode. At boot the BLE, 802.15.4 and Wi-Fi decoy engines start
// (each gated by its config flag), Wi-Fi is brought up in STA so the Wi-Fi
// decoys / ESP-NOW swarm can transmit, and the dynamic "breathing" profile and
// swarm transport are initialized.
//
// Pressing BOOT (GPIO9) toggles the maintenance Web UI (SoftAP + HTTP config /
// OTA) on and off live, WITHOUT rebooting — the decoys keep running underneath
// it. Note: with Wi-Fi up, all three radios share the single RF front-end via
// IDF software coexistence; disabling the Wi-Fi decoys stops the probe flood
// and returns the airtime budget to BLE / 802.15.4.

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "config.h"
#include "status_led.h"
#include "decoys_ble.h"
#include "decoys_154.h"
#include "decoys_wifi.h"
#include "profiles.h"
#include "swarm.h"
#include "detector.h"
#include "jam_detect.h"
#include "sniff_wifi.h"
#include "maintenance.h"
static const char *TAG = "splinter";

// BOOT button on the ESP32-C6 SuperMini (active-low, also a strapping pin so we
// only read it after boot).
#define BTN_GPIO 9

static void button_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << BTN_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);
}

static bool button_pressed(void)
{
    if (gpio_get_level(BTN_GPIO) == 0) {
        vTaskDelay(pdMS_TO_TICKS(30)); // debounce
        if (gpio_get_level(BTN_GPIO) == 0) {
            // wait for release so it doesn't trigger multiple times
            while(gpio_get_level(BTN_GPIO) == 0) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            return true;
        }
    }
    return false;
}

// If we booted a freshly OTA'd image (PENDING_VERIFY), reaching this point means
// init succeeded — mark it valid so the bootloader keeps it. If the new image
// had instead crashed before here, the bootloader rolls back to the previous
// good app on reset (requires CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE).
static void ota_confirm_healthy(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGW(TAG, "new OTA image booted cleanly; marking valid");
        esp_ota_mark_app_valid_cancel_rollback();
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    config_init();
    status_led_init();

    // Centralized Wi-Fi Initialization (AP + STA)
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // ESP-NOW swarm transport (needs Wi-Fi started). Init once; it stays idle
    // until swarm_enabled is toggled on, so it's safe to set up unconditionally.
    swarm_init();

    ESP_LOGI(TAG, "starting decoy engines");
    // Every engine starts unconditionally and self-gates on its config flag, so
    // each enable toggle in the web UI takes effect live (no reboot). When
    // disabled an engine idles cheaply; BLE stops advertising and 802.15.4
    // powers its radio down, while Wi-Fi parks its probe flood.
    decoys_ble_start();
    decoys_154_start();
    decoys_wifi_start();
    profiles_start();
    detector_start();
    jam_detect_start();
    sniff_wifi_start();
    status_led_set(LED_STATE_RUNNING);

    ota_confirm_healthy(); // keep this image (or let the bootloader roll back)

    button_init();
    bool ui_active = false;
    for (;;) {
        if (button_pressed()) {
            ui_active = !ui_active;
            if (ui_active) {
                webui_start();
                status_led_set(LED_STATE_MAINTENANCE);
            } else {
                webui_stop();
                status_led_set(LED_STATE_RUNNING);
            }
        }
        if (!ui_active) {
            const splinter_cfg_t *c = config_get();
            led_state_t st = LED_STATE_RUNNING;
            // Jam (active spectrum attack) takes visual priority over a follower alert.
            if (c->jam_detect_enabled && jam_detect_alert())   st = LED_STATE_JAM;
            else if (c->detect_enabled && detector_alert())    st = LED_STATE_ALERT;
            status_led_set(st);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
