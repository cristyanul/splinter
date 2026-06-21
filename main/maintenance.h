// Maintenance mode: Wi-Fi SoftAP + web UI for OTA firmware upload and config.
// Entered by rebooting with BOOT_MODE_MAINTENANCE set, so it runs Wi-Fi alone
// (the decoy radios never run in this mode).
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Bring up the SoftAP + HTTP server and serve until reboot. Does not return.
void maintenance_run(void);

#ifdef __cplusplus
}
#endif
