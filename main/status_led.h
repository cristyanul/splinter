// Onboard WS2812 RGB status indicator (GPIO8 on the ESP32-C6 SuperMini).
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LED_STATE_BOOT = 0,    // dim white  — early boot
    LED_STATE_RUNNING,     // breathing green — normal decoying
    LED_STATE_MAINTENANCE, // solid blue — SoftAP / maintenance mode
    LED_STATE_OTA,         // solid amber — OTA in progress
    LED_STATE_ERROR,       // solid red — init / OTA failure
    LED_STATE_ALERT,       // pulsing red/purple — follower detected
    LED_STATE_JAM,         // rapid red double-blink — active RF jamming detected
} led_state_t;

void status_led_init(void);
void status_led_set(led_state_t state);

#ifdef __cplusplus
}
#endif
