// Web UI: Wi-Fi SoftAP + HTTP server for live config editing and OTA
// firmware upload. Can be toggled on/off dynamically.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Mounts LittleFS, configures SoftAP interface, and starts the HTTP server.
void webui_start(void);

// Stops the HTTP server and brings down the SoftAP.
void webui_stop(void);

#ifdef __cplusplus
}
#endif
