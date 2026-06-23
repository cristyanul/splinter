// Host unit tests for the pure AWDL frame builder (decoys_awdl.c).
// Build & run:
//   gcc test/awdl_build_test.c main/decoys_awdl.c -I main -o /tmp/awdl_test && /tmp/awdl_test
//
// Asserts STRUCTURAL invariants (header markers, self-consistent TLV chain,
// presence of the AirDrop signal) rather than internal magic numbers that can
// only be confirmed against a live `tshark -Y awdl` capture.

#include "decoys_awdl.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

// AWDL TLV codes mirrored from decoys_awdl.c.
#define T_SERVICE_RESPONSE 0x02
#define T_SYNC_PARAMS      0x04
#define T_ELECTION         0x05
#define T_ARPA             0x10
#define T_CHANNEL_SEQUENCE 0x12
#define T_VERSION          0x15

static const uint8_t ENTROPY[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x07, 0x9a,
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
    0xa5, 0x5a, 0xc3, 0x3c, 0x77, 0x88, 0x99, 0xaa,
};

// Returns total TLV span length if the chain from `start` walks exactly to
// `end`; -1 if a TLV runs past the end (malformed). Records seen types.
static int walk_tlvs(const uint8_t *buf, int start, int end, uint8_t seen[256])
{
    int p = start;
    while (p + 3 <= end) {
        uint8_t type = buf[p];
        int len = buf[p + 1] | (buf[p + 2] << 8);
        if (p + 3 + len > end) return -1;
        seen[type] = 1;
        p += 3 + len;
    }
    return (p == end) ? (p - start) : -1;
}

static int contains(const uint8_t *buf, int len, const char *needle)
{
    int nl = (int)strlen(needle);
    for (int i = 0; i + nl <= len; i++)
        if (memcmp(buf + i, needle, nl) == 0) return 1;
    return 0;
}

// Find a top-level TLV by type; returns pointer to its value and sets *vlen, or
// NULL if absent. Walks from `start` (after the 40-byte fixed header).
static const uint8_t *find_tag(const uint8_t *buf, int start, int end, uint8_t type, int *vlen)
{
    int p = start;
    while (p + 3 <= end) {
        uint8_t t = buf[p];
        int len = buf[p + 1] | (buf[p + 2] << 8);
        if (p + 3 + len > end) return NULL;
        if (t == type) { if (vlen) *vlen = len; return buf + p + 3; }
        p += 3 + len;
    }
    return NULL;
}

static void test_mac_and_awdl_header(void)
{
    awdl_device_t cast[AWDL_CAST_SIZE];
    awdl_cast_init(cast, AWDL_CAST_SIZE, ENTROPY, sizeof(ENTROPY));

    uint8_t buf[AWDL_FRAME_MAX];
    int len = awdl_build_mif(buf, &cast[0], cast[0].mac, 0x11223344, 0x55667788);
    CHECK(len > 40);

    // 802.11 MAC header
    CHECK(buf[0] == 0xd0 && buf[1] == 0x00);                 // FC: mgmt / Action
    for (int i = 4; i < 10; i++) CHECK(buf[i] == 0xff);      // DA broadcast
    CHECK(memcmp(buf + 10, cast[0].mac, 6) == 0);            // SA = device MAC
    const uint8_t bssid[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    CHECK(memcmp(buf + 16, bssid, 6) == 0);                  // AWDL BSSID

    // AWDL fixed action header
    CHECK(buf[24] == 0x7f);                                  // vendor-specific category
    const uint8_t oui[3] = {0x00, 0x17, 0xf2};
    CHECK(memcmp(buf + 25, oui, 3) == 0);                    // Apple OUI
    CHECK(buf[28] == 0x08);                                  // type: AWDL
    CHECK(buf[30] == 0x03);                                  // subtype: MIF
    // timestamps are little-endian
    CHECK(buf[32] == 0x44 && buf[35] == 0x11);
    CHECK(buf[36] == 0x88 && buf[39] == 0x55);
}

static void test_tlv_chain_and_airdrop(void)
{
    awdl_device_t cast[AWDL_CAST_SIZE];
    awdl_cast_init(cast, AWDL_CAST_SIZE, ENTROPY, sizeof(ENTROPY));
    cast[0].offers_airdrop = true;

    uint8_t buf[AWDL_FRAME_MAX];
    int len = awdl_build_mif(buf, &cast[0], cast[0].mac, 1, 2);

    uint8_t seen[256] = {0};
    int span = walk_tlvs(buf, 40, len, seen);              // TLVs start after the 40-byte header
    CHECK(span >= 0);                                       // chain walks exactly to frame end
    CHECK(seen[T_SYNC_PARAMS]);
    CHECK(seen[T_ELECTION]);
    CHECK(seen[T_ARPA]);
    CHECK(seen[T_VERSION]);
    CHECK(seen[T_SERVICE_RESPONSE]);                       // AirDrop present
    CHECK(contains(buf, len, "_airdrop"));                 // ...and it's actually AirDrop

    // Channel sequence is embedded at the tail of sync params (33 fixed bytes +
    // 38-byte channel sequence = 71), NOT a standalone tag — this is what the
    // Wireshark sync-params dissector requires.
    CHECK(!seen[T_CHANNEL_SEQUENCE]);                      // not a top-level tag
    int sp_len = 0;
    const uint8_t *sp = find_tag(buf, 40, len, T_SYNC_PARAMS, &sp_len);
    CHECK(sp != NULL);
    CHECK(sp_len == 71);                                   // 33 fixed + 38 channel sequence
    CHECK(sp[33] == 15);                                   // embedded chanseq: count (16 slots - 1)
    CHECK(sp[34] == 3);                                    // embedded chanseq: op-class encoding
}

static void test_no_airdrop_omits_service_response(void)
{
    awdl_device_t cast[AWDL_CAST_SIZE];
    awdl_cast_init(cast, AWDL_CAST_SIZE, ENTROPY, sizeof(ENTROPY));
    cast[1].offers_airdrop = false;

    uint8_t buf[AWDL_FRAME_MAX];
    int len = awdl_build_mif(buf, &cast[1], cast[0].mac, 1, 2);

    uint8_t seen[256] = {0};
    CHECK(walk_tlvs(buf, 40, len, seen) >= 0);
    CHECK(!seen[T_SERVICE_RESPONSE]);
    CHECK(!contains(buf, len, "_airdrop"));
    CHECK(seen[T_SYNC_PARAMS]);                            // core TLVs still present
    CHECK(seen[T_VERSION]);
}

static void test_cast_is_coherent(void)
{
    awdl_device_t a[AWDL_CAST_SIZE], b[AWDL_CAST_SIZE];
    awdl_cast_init(a, AWDL_CAST_SIZE, ENTROPY, sizeof(ENTROPY));
    awdl_cast_init(b, AWDL_CAST_SIZE, ENTROPY, sizeof(ENTROPY));
    // Same entropy -> identical coherent cast (stable identities, not churn).
    CHECK(memcmp(a, b, sizeof(a)) == 0);
    // Distinct devices within the cast.
    CHECK(memcmp(a[0].mac, a[1].mac, 6) != 0);
    CHECK(a[0].offers_airdrop);                            // master always offers AirDrop
}

int main(void)
{
    test_mac_and_awdl_header();
    test_tlv_chain_and_airdrop();
    test_no_airdrop_omits_service_response();
    test_cast_is_coherent();
    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("OK\n");
    return 0;
}
