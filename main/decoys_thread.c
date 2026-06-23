// Thread / Matter decoys — pure frame assembly + coherent home state.
// See decoys_thread.h for the design. No ESP-IDF deps: this compiles on the host
// for test/thread_build_test.c.

#include "decoys_thread.h"
#include <string.h>

// ---------------------------------------------------------- coherent homes
static const char *THREAD_NAMES[] = {
    "MyHome-Thread", "HomeKit-Net", "Nest-Mesh",
    "Matter-Home", "SmartHome", "OpenThread-1",
};
#define NUM_THREAD_NAMES (sizeof(THREAD_NAMES) / sizeof(THREAD_NAMES[0]))

void thread_home_init(thread_home_t *homes, int n, uint32_t chan_mask,
                      const uint8_t *entropy, size_t elen)
{
    if (!homes || n <= 0 || !entropy || elen == 0) return;
    size_t ei = 0;
#define NEXT() (entropy[ei++ % elen])

    // Candidate channels from the mask (same encoding as cfg->ieee154_chan_mask).
    uint8_t chans[16];
    int nc = 0;
    for (int c = 11; c <= 26; c++)
        if (chan_mask & (1u << c)) chans[nc++] = (uint8_t)c;
    if (nc == 0) { chans[0] = 15; nc = 1; }

    for (int k = 0; k < n; k++) {
        thread_home_t *h = &homes[k];
        memset(h, 0, sizeof(*h));

        h->channel = chans[NEXT() % nc];
        uint8_t pan_hi = NEXT();                          // sequenced: NEXT() mutates ei
        uint8_t pan_lo = NEXT();
        h->pan_id  = (uint16_t)((pan_hi << 8) | pan_lo);
        if (h->pan_id == 0xFFFF) h->pan_id = 0x1234;     // 0xFFFF is broadcast
        for (int j = 0; j < 8; j++) h->ext_pan_id[j] = NEXT();

        const char *nm = THREAD_NAMES[NEXT() % NUM_THREAD_NAMES];
        strncpy(h->network_name, nm, THREAD_NETNAME_LEN - 1); // memset above NUL-pads the rest

        h->ml_prefix[0] = 0xfd;                          // ULA mesh-local /64
        for (int j = 1; j < 8; j++) h->ml_prefix[j] = NEXT();

        h->nnodes = 4 + (NEXT() % 5);                    // 4..8 nodes
        if (h->nnodes > THREAD_MAX_NODES) h->nnodes = THREAD_MAX_NODES;
        for (int j = 0; j < h->nnodes; j++) {
            if (j == 0)      h->rloc16[j] = 0x0000;          // leader / router 0
            else if (j < 3)  h->rloc16[j] = (uint16_t)(j << 10); // routers
            else             h->rloc16[j] = (uint16_t)((1 << 10) | j); // children of router 1
            for (int b = 0; b < 8; b++) h->eui64[j][b] = NEXT();
            h->eui64[j][0] |= 0x02;                       // locally-administered EUI64
        }

        uint8_t fc0 = NEXT();                            // sequenced byte-by-byte
        uint8_t fc1 = NEXT();
        uint8_t fc2 = NEXT();
        uint8_t fc3 = NEXT();
        h->frame_counter = ((uint32_t)fc0 << 24) | ((uint32_t)fc1 << 16) |
                           ((uint32_t)fc2 << 8) | fc3;
    }
#undef NEXT
}

// ---------------------------------------------------------- frame assembly
// 802.15.4 Frame Control field bits (low byte 0..7, high byte 8..15).
#define FT_DATA          0x1
#define FC_SEC_EN        (1u << 3)
#define FC_ACK_REQ       (1u << 5)
#define FC_PANID_COMP    (1u << 6)
#define ADDR_MODE_SHORT  0x2     // dest/src addressing mode = 16-bit short
#define FRAME_VER_2006   0x1

int thread_build_beacon(uint8_t *buf, const thread_home_t *h, uint8_t seq)
{
    if (!buf || !h) return 0;
    int i = 1;                                  // buf[0] = PHR, set last

    // MHR: beacon, no dest, short source (FCF 0x8000), like the Zigbee beacon path.
    buf[i++] = 0x00;                            // FCF low
    buf[i++] = 0x80;                            // FCF high (src addr mode = short)
    buf[i++] = seq;
    buf[i++] = h->pan_id & 0xff;                // source PAN id
    buf[i++] = h->pan_id >> 8;
    buf[i++] = h->rloc16[0] & 0xff;             // source short address
    buf[i++] = h->rloc16[0] >> 8;

    // Superframe / GTS / pending (same shape as a Zigbee beacon).
    buf[i++] = 0xff;                            // superframe spec low
    buf[i++] = 0xcf;                            // superframe spec high
    buf[i++] = 0x00;                            // GTS spec
    buf[i++] = 0x00;                            // pending address spec

    // Thread beacon payload: a sniffer recognizes Protocol ID 0x03 as Thread.
    buf[i++] = 0x03;                            // Protocol ID = Thread
    buf[i++] = 0x20;                            // version (2) << 4 | flags (0)
    memcpy(&buf[i], h->network_name, THREAD_NETNAME_LEN); i += THREAD_NETNAME_LEN;
    memcpy(&buf[i], h->ext_pan_id, 8);          i += 8;

    buf[i++] = 0x00;                            // FCS placeholder (HW fills)
    buf[i++] = 0x00;

    buf[0] = (uint8_t)(i - 1);                  // PHR = PSDU length incl. FCS
    return i;
}

int thread_build_data(uint8_t *buf, const thread_home_t *h, int src_idx, int dst_idx,
                      uint8_t seq, uint32_t frame_counter,
                      const uint8_t *payload, uint8_t plen)
{
    if (!buf || !h || h->nnodes == 0) return 0;
    if (plen > 100) plen = 100;                 // keep PSDU within the 127-byte limit
    bool bcast = (dst_idx < 0);

    uint16_t fcf = FT_DATA | FC_SEC_EN | FC_PANID_COMP
                 | (bcast ? 0 : FC_ACK_REQ)
                 | (ADDR_MODE_SHORT << 10)      // dest addr mode
                 | (FRAME_VER_2006 << 12)       // frame version 2006 (Thread)
                 | (ADDR_MODE_SHORT << 14);     // src addr mode

    int i = 1;                                  // buf[0] = PHR, set last
    buf[i++] = fcf & 0xff;
    buf[i++] = fcf >> 8;
    buf[i++] = seq;

    buf[i++] = h->pan_id & 0xff;                // dest PAN id
    buf[i++] = h->pan_id >> 8;
    uint16_t dst = bcast ? 0xFFFF : h->rloc16[dst_idx % h->nnodes];
    buf[i++] = dst & 0xff;                      // dest short address
    buf[i++] = dst >> 8;
    uint16_t src = h->rloc16[(src_idx < 0 ? 0 : src_idx) % h->nnodes];
    buf[i++] = src & 0xff;                      // source short address (src PAN compressed out)
    buf[i++] = src >> 8;

    // Auxiliary Security Header — Thread's exact params: security level 5
    // (ENC-MIC-32), key id mode 1 (1-byte key index).
    buf[i++] = 0x0d;                            // security control: (1<<3) | 5
    buf[i++] = frame_counter & 0xff;            // frame counter (LE)
    buf[i++] = (frame_counter >> 8) & 0xff;
    buf[i++] = (frame_counter >> 16) & 0xff;
    buf[i++] = (frame_counter >> 24) & 0xff;
    buf[i++] = 0x00;                            // key index (key id mode 1)

    // Opaque ciphertext — the real 6LoWPAN/IPHC is encrypted, so a keyless sniffer
    // sees only this. Caller supplies entropy.
    if (plen && payload) { memcpy(&buf[i], payload, plen); i += plen; }

    // 4-byte MIC (ENC-MIC-32). Opaque; derived from the counter so it is stable
    // for the unit tests but varies frame-to-frame on air.
    buf[i++] = (frame_counter ^ 0xA5) & 0xff;
    buf[i++] = (frame_counter >> 8) & 0xff;
    buf[i++] = (frame_counter >> 16) & 0xff;
    buf[i++] = ((frame_counter >> 24) ^ 0x5A) & 0xff;

    buf[i++] = 0x00;                            // FCS placeholder (HW fills)
    buf[i++] = 0x00;

    buf[0] = (uint8_t)(i - 1);                  // PHR = PSDU length incl. FCS
    return i;
}
