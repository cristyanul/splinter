// decoys_awdl.h — Apple AWDL (AirDrop) ecosystem spoofing.
//
// A small, COHERENT cast of fake Apple devices that periodically emit AWDL
// Master Indication Frames advertising the AirDrop service, so a passive logger
// (wardriver / Kismet) records iPhones & MacBooks "doing AirDrop". Wardrivers
// over-index on Apple, so this is high-value tracking-data pollution.
//
// This is APPEARANCE for passive observers, not protocol participation: the
// ESP32-C6 is 2.4 GHz-only (no full 5 GHz AWDL), and we only ever broadcast MIFs
// addressed among our own fake MACs — never the directed unicast service-request
// that would make a bystander's iPhone raise an AirDrop sheet. Presence, not
// pop-ups (the same ethic as the excluded BLE Continuity/Swift-Pair formats).
//
// Pure frame assembly + cast state, NO ESP-IDF dependencies, so it compiles on
// the host for unit tests (mirrors detect_core.c). The Wi-Fi task (decoys_wifi.c)
// owns the radio and drives emission on the 2.4 GHz AWDL social channel (6).
//
// Frame/TLV layout references: SEEMOO "Open Wireless Link" (owl) src/frame.h and
// the Wireshark `awdl` dissector (epan/dissectors/packet-awdl.c). Internal TLV
// body fields are best-effort to those references and should be confirmed against
// a live `tshark -Y awdl` capture.
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AWDL_CAST_SIZE    3    // coherent cast of Apple devices (element 0 = master)
#define AWDL_HOSTNAME_MAX 24
#define AWDL_FRAME_MAX    256  // an MIF is well under this

typedef struct {
    uint8_t  mac[6];                       // stable locally-administered (like the iOS AWDL iface)
    uint8_t  devclass;                     // VERSION TLV devclass (1=iOS, 2=macOS)
    uint8_t  version;                      // VERSION TLV version byte (hi.lo nibble)
    char     hostname[AWDL_HOSTNAME_MAX];  // ARPA TLV name, NUL-terminated, no ".local"
    uint16_t aw_seq;                       // Availability-Window sequence (advances per MIF)
    bool     offers_airdrop;               // include the AirDrop SERVICE_RESPONSE TLV
} awdl_device_t;

// Initialize a coherent cast of `n` Apple devices deterministically from
// `entropy` (entropy_len bytes). Firmware passes esp_random() output; tests pass
// a fixed array for reproducibility. Element 0 is the elected master and always
// offers AirDrop. No-op if entropy_len == 0.
void awdl_cast_init(awdl_device_t *cast, int n,
                    const uint8_t *entropy, size_t entropy_len);

// Pure: build a Master Indication Frame for `dev` into `buf` (>= AWDL_FRAME_MAX).
// `master_mac` is the cast master referenced in the sync/election TLVs (pass the
// device's own MAC for the master). `phy_tx`/`target_tx` are monotonic
// timestamps. Returns the frame length in bytes (excludes the FCS the radio
// appends). The 802.11 sequence-control field is left 0 for the HW to fill.
int  awdl_build_mif(uint8_t *buf, const awdl_device_t *dev,
                    const uint8_t master_mac[6], uint32_t phy_tx, uint32_t target_tx);

#ifdef __cplusplus
}
#endif
