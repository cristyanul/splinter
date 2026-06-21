idf_component_register(
    SRCS
        "splinter_main.c"
        "config.c"
        "status_led.c"
        "decoys_ble.c"
        "decoys_154.c"
        "maintenance.c"
    INCLUDE_DIRS "."
    REQUIRES bt nvs_flash esp_driver_gpio led_strip
             esp_wifi esp_event esp_netif esp_http_server app_update
             ieee802154
)
