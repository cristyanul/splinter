idf_component_register(
    SRCS
        "splinter_main.c"
        "config.c"
        "status_led.c"
        "decoys_ble.c"
        "decoys_154.c"
        "decoys_wifi.c"
        "decoys_awdl.c"
        "decoys_thread.c"
        "profiles.c"
        "maintenance.c"
        "swarm.c"
        "detect_core.c"
        "detector.c"
        "jam_core.c"
        "jam_detect.c"
        "tracker_id.c"
        "sniff_wifi.c"
        "sniff_ble.c"
    INCLUDE_DIRS "."
    REQUIRES bt nvs_flash esp_driver_gpio led_strip
             esp_wifi esp_event esp_netif esp_http_server app_update
             ieee802154 littlefs mbedtls
)

littlefs_create_partition_image(ui ../webui FLASH_IN_PROJECT)
