#include "status_led.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "led_strip.h"

// ESP32-C6 SuperMini onboard WS2812 RGB LED. GPIO8 is also a boot strapping pin,
// so we only ever drive it after boot (never held during reset).
#define LED_GPIO 8

static const char *TAG = "splinter-led";
static led_strip_handle_t s_strip;
static volatile led_state_t s_state = LED_STATE_BOOT;

static void set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_strip) {
        return;
    }
    led_strip_set_pixel(s_strip, 0, r, g, b);
    led_strip_refresh(s_strip);
}

// Low-priority renderer: solid colour for most states, a gentle breathe for
// RUNNING. Wakes infrequently so it never competes with the BLE host.
static void led_task(void *arg)
{
    int phase = 0;
    for (;;) {
        switch (s_state) {
        case LED_STATE_RUNNING: {
            phase = (phase + 6) % 360;
            int level = (phase < 180) ? (phase * 18 / 180)
                                      : ((360 - phase) * 18 / 180);
            set_rgb(0, (uint8_t)(2 + level), 0);
            vTaskDelay(pdMS_TO_TICKS(30));
            break;
        }
        case LED_STATE_MAINTENANCE: set_rgb(0,  0, 20); vTaskDelay(pdMS_TO_TICKS(250)); break;
        case LED_STATE_OTA:         set_rgb(22, 13, 0); vTaskDelay(pdMS_TO_TICKS(120)); break;
        case LED_STATE_ERROR:       set_rgb(22, 0,  0); vTaskDelay(pdMS_TO_TICKS(300)); break;
        case LED_STATE_BOOT:
        default:                    set_rgb(2,  2,  2); vTaskDelay(pdMS_TO_TICKS(250)); break;
        }
    }
}

void status_led_init(void)
{
    led_strip_config_t strip_config = {
        .strip_gpio_num   = LED_GPIO,
        .max_leds         = 1,
        .led_pixel_format = LED_PIXEL_FORMAT_GRB,
        .led_model        = LED_MODEL_WS2812,
        .flags.invert_out = false,
    };
    led_strip_rmt_config_t rmt_config = {
        .clk_src       = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .flags.with_dma = false,
    };
    esp_err_t err = led_strip_new_rmt_device(&strip_config, &rmt_config, &s_strip);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "WS2812 init failed: %s (status LED disabled)", esp_err_to_name(err));
        s_strip = NULL;
        return;
    }
    set_rgb(2, 2, 2);
    xTaskCreate(led_task, "led", 2048, NULL, 2, NULL); // priority 2: below BLE (5)
}

void status_led_set(led_state_t state)
{
    s_state = state;
}
