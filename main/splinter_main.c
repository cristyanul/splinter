// splinter — top-level: init, mode selection, and wiring.
//
// Two modes, selected at boot from a one-shot NVS flag:
//   * NORMAL      — BLE + 802.15.4 decoys run; no Wi-Fi (radio is theirs alone).
//   * MAINTENANCE — Wi-Fi SoftAP + web UI for OTA/config; no decoys.
// Pressing BOOT (GPIO9) during normal operation sets the flag and reboots into
// maintenance. A plain reset always returns to normal (the flag is one-shot).

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "config.h"
#include "status_led.h"
#include "decoys_ble.h"
#include "decoys_154.h"
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
            return true;
        }
    }
    return false;
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

    if (boot_mode_take() == BOOT_MODE_MAINTENANCE) {
        ESP_LOGW(TAG, "entering MAINTENANCE mode");
        status_led_set(LED_STATE_MAINTENANCE);
        maintenance_run(); // does not return
        return;
    }

    ESP_LOGI(TAG, "NORMAL mode: starting decoys");
    const splinter_cfg_t *cfg = config_get();
    if (cfg->ble_enabled) {
        decoys_ble_start();
    }
    if (cfg->ieee154_enabled) {
        decoys_154_start();
    }
    status_led_set(LED_STATE_RUNNING);

    button_init();
    for (;;) {
        if (button_pressed()) {
            ESP_LOGW(TAG, "BOOT pressed -> rebooting into maintenance mode");
            boot_mode_set(BOOT_MODE_MAINTENANCE);
            vTaskDelay(pdMS_TO_TICKS(150));
            esp_restart();
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
