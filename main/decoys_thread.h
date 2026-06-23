// decoys_thread.h — Thread / Matter mesh ecosystem spoofing.
//
// 1-2 COHERENT, stable Thread "homes". Each advertises itself as a named Thread
// network (a Thread-format 802.15.4 beacon) and generates realistic, encrypted-
// looking intra-mesh chatter (Thread-parametrized secured data frames), so a
// passive 802.15.4 sniffer records a believable smart home full of Matter
// devices rather than the existing random Zigbee-PAN churn.
//
// APPEARANCE, not participation: we hold no Thread network key, so we cannot
// produce decryptable MLE. A real Thread mesh's 6LoWPAN payload is encrypted, so
// to a keyless sniffer it is opaque ciphertext — which is exactly what we emit.
// The recognizable "this is Thread/Matter" signal is the beacon (network name +
// extended PAN id) plus Thread's exact MAC-security parameters on the data
// frames. The home advertises a network nobody else has credentials to join, so
// a real joiner that tries simply fails — harmless, like a locked Wi-Fi AP.
//
// Pure frame assembly + home state, NO ESP-IDF deps, so it compiles on the host
// for unit tests (mirrors detect_core.c). The 802.15.4 task (decoys_154.c) owns
// the radio and interleaves these frames with the existing Zigbee beacons, with
// CCA (never jamming).
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_HOME_COUNT 1     // coherent Thread homes (1 keeps airtime modest)
#define THREAD_MAX_NODES  8
#define THREAD_NETNAME_LEN 16   // Thread network name field is 16 bytes (NUL-padded)
#define THREAD_FRAME_MAX  128   // 802.15.4 PSDU <= 127 + 1 PHR byte

typedef struct {
    uint8_t  channel;                       // one fixed channel from the cfg mask (11..26)
    uint16_t pan_id;                        // stable PAN id
    uint8_t  ext_pan_id[8];                 // stable extended PAN id
    char     network_name[THREAD_NETNAME_LEN]; // NUL-padded to 16 on air
    uint8_t  ml_prefix[8];                  // mesh-local /64 prefix (fd..)
    uint8_t  nnodes;                        // 4..8 member nodes
    uint16_t rloc16[THREAD_MAX_NODES];      // node short addresses (RLOC16)
    uint8_t  eui64[THREAD_MAX_NODES][8];    // node extended addresses
    uint32_t frame_counter;                 // MAC security frame counter
} thread_home_t;

// Initialize `n` coherent Thread homes deterministically from `entropy`. Channels
// are drawn from `chan_mask` (same format as cfg->ieee154_chan_mask). Firmware
// passes esp_random() output; tests pass a fixed array. No-op if entropy_len==0.
void thread_home_init(thread_home_t *homes, int n, uint32_t chan_mask,
                      const uint8_t *entropy, size_t entropy_len);

// Build a Thread-format 802.15.4 beacon (the network advertisement) into `buf`
// (>= THREAD_FRAME_MAX). buf[0] is the PHR (PSDU length incl. the 2-byte FCS the
// radio fills). `seq` is the MAC sequence number. Returns total bytes (PHR+PSDU).
int thread_build_beacon(uint8_t *buf, const thread_home_t *h, uint8_t seq);

// Build a Thread-parametrized secured 802.15.4 data frame (encrypted-looking mesh
// chatter). `src_idx`/`dst_idx` index home nodes; dst_idx < 0 => broadcast
// (0xFFFF, the MLE-advertisement shape). `payload`/`plen` is the opaque
// ciphertext (caller supplies entropy). `frame_counter` is the MAC security
// counter (caller increments). Returns total bytes (PHR+PSDU).
int thread_build_data(uint8_t *buf, const thread_home_t *h, int src_idx, int dst_idx,
                      uint8_t seq, uint32_t frame_counter,
                      const uint8_t *payload, uint8_t plen);

#ifdef __cplusplus
}
#endif
