// Apple AWDL (AirDrop) decoys — pure frame assembly + coherent cast state.
// See decoys_awdl.h for the design and the reference sources. No ESP-IDF deps:
// this file compiles on the host for test/awdl_build_test.c.

#include "decoys_awdl.h"
#include <string.h>

// ---------------------------------------------------------- coherent cast
// Plausible Apple hostnames (ARPA TLV); all < AWDL_HOSTNAME_MAX chars.
static const char *AWDL_HOSTNAMES[] = {
    "iPhone", "MacBook-Pro", "iPad", "Johns-iPhone",
    "Air-of-Sarah", "iMac", "iPhone-15", "MacBook-Air",
};
#define NUM_AWDL_HOSTNAMES (sizeof(AWDL_HOSTNAMES) / sizeof(AWDL_HOSTNAMES[0]))

void awdl_cast_init(awdl_device_t *cast, int n, const uint8_t *entropy, size_t elen)
{
    if (!cast || n <= 0 || !entropy || elen == 0) return;
    size_t ei = 0;
#define NEXT() (entropy[ei++ % elen])
    for (int i = 0; i < n; i++) {
        awdl_device_t *d = &cast[i];
        memset(d, 0, sizeof(*d));
        for (int j = 0; j < 6; j++) d->mac[j] = NEXT();
        d->mac[0] = (d->mac[0] | 0x02) & 0xfe;          // locally-administered, unicast

        const char *h = AWDL_HOSTNAMES[NEXT() % NUM_AWDL_HOSTNAMES];
        strncpy(d->hostname, h, sizeof(d->hostname) - 1);
        d->hostname[sizeof(d->hostname) - 1] = '\0';

        d->devclass       = (NEXT() & 1) ? 0x01 : 0x02; // iOS / macOS
        d->version        = 0x3f;                        // AWDL VERSION TLV version byte
        d->aw_seq         = 0;
        d->offers_airdrop = (NEXT() % 100) < 70;         // most Apple devices do
    }
    cast[0].offers_airdrop = true;                       // a lively place always has AirDrop
#undef NEXT
}

// ---------------------------------------------------------- frame assembly
static const uint8_t AWDL_BSSID[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
static const uint8_t APPLE_OUI[3]  = {0x00, 0x17, 0xf2};

// AWDL TLV type codes (owl src/frame.h).
enum {
    AWDL_TLV_SERVICE_RESPONSE = 0x02,
    AWDL_TLV_SYNC_PARAMS      = 0x04,
    AWDL_TLV_ELECTION_PARAMS  = 0x05,
    AWDL_TLV_ARPA             = 0x10,
    AWDL_TLV_CHANNEL_SEQUENCE = 0x12,
    AWDL_TLV_VERSION          = 0x15,
};

// Append a TLV (type | length[2 LE] | value). Returns bytes written.
static int put_tlv(uint8_t *p, uint8_t type, const uint8_t *val, uint16_t len)
{
    p[0] = type;
    p[1] = (uint8_t)(len & 0xff);
    p[2] = (uint8_t)(len >> 8);
    if (len && val) memcpy(p + 3, val, len);
    return 3 + (int)len;
}

static int put_u16(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; return 2; }
static int put_u32(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
    return 4;
}

// Channel Sequence block: 16 slots, opclass encoding, all = channel 6. In AWDL
// this is embedded at the TAIL of the Synchronization Parameters tag, not a
// standalone TLV (the Wireshark sync-params dissector reads it from the bytes
// after ap_alignment to the tag end), so build_sync_params appends it.
static int build_chanseq(uint8_t *b)
{
    int i = 0;
    b[i++] = 15;                      // count (channels - 1 -> 16 slots)
    b[i++] = 3;                       // encoding (op-class)
    b[i++] = 0;                       // duplicate
    b[i++] = 0;                       // step_count
    i += put_u16(&b[i], 0xffff);      // fill_channel
    for (int s = 0; s < 16; s++) {    // each slot: {channel, op-class 81 = 2.4 GHz}
        b[i++] = 6;
        b[i++] = 81;
    }
    return i;                         // 38
}

// Synchronization Parameters TLV body: 33 fixed bytes (owl struct
// awdl_sync_params_tlv) followed by the embedded channel sequence (38 bytes) ->
// 71 bytes total. The trailing channel sequence is mandatory: the dissector
// always reads it from tag_end - 33.
static int build_sync_params(uint8_t *b, const uint8_t master_mac[6], uint16_t next_aw_seq)
{
    int i = 0;
    b[i++] = 6;                       // next_aw_channel (2.4 GHz social channel)
    i += put_u16(&b[i], 0);           // tx_down_counter
    b[i++] = 6;                       // master_channel
    b[i++] = 0;                       // guard_time
    i += put_u16(&b[i], 16);          // aw_period (TUs)
    i += put_u16(&b[i], 110);         // af_period (TUs)
    i += put_u16(&b[i], 0x1800);      // flags
    i += put_u16(&b[i], 16);          // aw_ext_length
    i += put_u16(&b[i], 16);          // aw_com_length
    i += put_u16(&b[i], 0);           // remaining_aw_length
    b[i++] = 3;                       // min_ext
    b[i++] = 3;                       // max_ext_multicast
    b[i++] = 3;                       // max_ext_unicast
    b[i++] = 3;                       // max_ext_af
    memcpy(&b[i], master_mac, 6); i += 6; // master_addr
    b[i++] = 4;                       // presence_mode
    b[i++] = 0;                       // reserved
    i += put_u16(&b[i], next_aw_seq); // next_aw_seq
    i += put_u16(&b[i], 0);           // ap_alignment
    i += build_chanseq(&b[i]);        // embedded channel sequence (38 bytes)
    return i;                         // 71
}

// Election Parameters TLV body (owl struct awdl_election_params_tlv, 21 bytes).
static int build_election(uint8_t *b, const uint8_t master_mac[6])
{
    int i = 0;
    b[i++] = 0;                       // flags
    i += put_u16(&b[i], 0);           // id
    b[i++] = 0;                       // distancetop
    b[i++] = 0;                       // unknown
    memcpy(&b[i], master_mac, 6); i += 6; // top_master_addr
    i += put_u32(&b[i], 60);          // top_master_metric
    i += put_u32(&b[i], 60);          // self_metric
    i += put_u16(&b[i], 0);           // pad
    return i;                         // 21
}

// ARPA (hostname) TLV body: flags, name_length, name, 2-byte suffix.
static int build_arpa(uint8_t *b, const char *hostname)
{
    int i = 0;
    uint8_t nl = (uint8_t)strlen(hostname);
    b[i++] = 0x03;                    // flags
    b[i++] = nl;                      // name_length
    memcpy(&b[i], hostname, nl); i += nl;
    i += put_u16(&b[i], 0x0000);      // suffix (".local" reference)
    return i;
}

// VERSION TLV body: version, devclass.
static int build_version(uint8_t *b, uint8_t version, uint8_t devclass)
{
    b[0] = version;
    b[1] = devclass;
    return 2;
}

// Service Response TLV body: a well-formed AWDL DNS-SD PTR record advertising
// AirDrop — the signal a sniffer reads as "this device does AirDrop". Structure
// per the Wireshark awdl dissector:
//   name_length(2 LE, includes the type byte) | name | type(1) |
//   data_len(2 LE) | unknown(2) | record-data
// Explicit DNS labels (not AWDL name compression) keep the literal
// "_airdrop._tcp.local" ASCII on the air, so even naive wardriving tools that
// string-match still flag AirDrop. The PTR target is <12-hex-from-MAC>.<service>,
// the AirDrop instance form, keeping it coherent per device.
static int build_airdrop_response(uint8_t *b, const awdl_device_t *dev)
{
    static const uint8_t AIRDROP_NAME[] = {   // _airdrop._tcp.local (no terminator)
        0x08, '_','a','i','r','d','r','o','p',
        0x04, '_','t','c','p',
        0x05, 'l','o','c','a','l',
    };
    static const char HEX[] = "0123456789abcdef";
    const uint16_t NL = (uint16_t)sizeof(AIRDROP_NAME);   // 20

    int i = 0;
    i += put_u16(&b[i], (uint16_t)(NL + 1));              // name_length (incl. type byte)
    memcpy(&b[i], AIRDROP_NAME, NL); i += NL;             // name: _airdrop._tcp.local
    b[i++] = 12;                                          // record type: PTR

    uint8_t data[64];                                     // PTR target: <inst>._airdrop._tcp.local
    int d = 0;
    data[d++] = 12;                                       // instance label length
    for (int k = 0; k < 6; k++) {                        // 12 hex chars from the device MAC
        data[d++] = (uint8_t)HEX[dev->mac[k] >> 4];
        data[d++] = (uint8_t)HEX[dev->mac[k] & 0x0f];
    }
    memcpy(&data[d], AIRDROP_NAME, NL); d += NL;          // ._airdrop._tcp.local

    i += put_u16(&b[i], (uint16_t)d);                     // data_len
    i += put_u16(&b[i], 0);                               // unknown
    memcpy(&b[i], data, d); i += d;                       // record data
    return i;
}

int awdl_build_mif(uint8_t *buf, const awdl_device_t *dev, const uint8_t master_mac[6],
                   uint32_t phy_tx, uint32_t target_tx)
{
    if (!buf || !dev || !master_mac) return 0;
    uint8_t *p = buf;

    // ---- 802.11 MAC header (24 bytes) ----
    *p++ = 0xd0; *p++ = 0x00;              // FC: management / Action
    *p++ = 0x00; *p++ = 0x00;             // Duration
    memset(p, 0xff, 6); p += 6;           // DA: broadcast
    memcpy(p, dev->mac, 6); p += 6;       // SA: device MAC
    memcpy(p, AWDL_BSSID, 6); p += 6;     // BSSID: AWDL
    *p++ = 0x00; *p++ = 0x00;             // Sequence control (HW fills with en_sys_seq)

    // ---- AWDL fixed action header (16 bytes) ----
    *p++ = 0x7f;                          // category: vendor-specific
    memcpy(p, APPLE_OUI, 3); p += 3;      // OUI: Apple
    *p++ = 0x08;                          // type: AWDL
    *p++ = 0x03;                          // version (compat)
    *p++ = 0x03;                          // subtype: MIF (Master Indication Frame)
    *p++ = 0x00;                          // reserved
    p += put_u32(p, phy_tx);              // PHY TX time
    p += put_u32(p, target_tx);           // target TX time

    // ---- TLVs ----
    uint8_t body[96];
    int n;

    // Sync params carries the channel sequence embedded at its tail (AWDL puts
    // it there, not in a standalone tag).
    n = build_sync_params(body, master_mac, dev->aw_seq);
    p += put_tlv(p, AWDL_TLV_SYNC_PARAMS, body, (uint16_t)n);

    n = build_election(body, master_mac);
    p += put_tlv(p, AWDL_TLV_ELECTION_PARAMS, body, (uint16_t)n);

    n = build_arpa(body, dev->hostname);
    p += put_tlv(p, AWDL_TLV_ARPA, body, (uint16_t)n);

    n = build_version(body, dev->version, dev->devclass);
    p += put_tlv(p, AWDL_TLV_VERSION, body, (uint16_t)n);

    if (dev->offers_airdrop) {
        n = build_airdrop_response(body, dev);
        p += put_tlv(p, AWDL_TLV_SERVICE_RESPONSE, body, (uint16_t)n);
    }

    return (int)(p - buf);
}
