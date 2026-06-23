// Host unit tests for the pure Thread frame builders (decoys_thread.c).
// Build & run:
//   gcc test/thread_build_test.c main/decoys_thread.c -I main -o /tmp/thread_test && /tmp/thread_test

#include "decoys_thread.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static const uint8_t ENTROPY[] = {
    0x3c, 0xa5, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
};
#define MASK_11_26 0x07FFF800u

static void test_beacon_is_thread_and_coherent(void)
{
    thread_home_t h1, h2;
    thread_home_init(&h1, 1, MASK_11_26, ENTROPY, sizeof(ENTROPY));
    thread_home_init(&h2, 1, MASK_11_26, ENTROPY, sizeof(ENTROPY));
    CHECK(memcmp(&h1, &h2, sizeof(h1)) == 0);            // same entropy -> identical home (coherent)
    CHECK(h1.channel >= 11 && h1.channel <= 26);
    CHECK(h1.nnodes >= 4 && h1.nnodes <= THREAD_MAX_NODES);
    CHECK(h1.ml_prefix[0] == 0xfd);                      // mesh-local ULA

    uint8_t a[THREAD_FRAME_MAX], b[THREAD_FRAME_MAX];
    int la = thread_build_beacon(a, &h1, 7);
    int lb = thread_build_beacon(b, &h1, 7);
    CHECK(la == lb && memcmp(a, b, la) == 0);            // builder is deterministic/stable

    CHECK(a[0] == (uint8_t)(la - 1));                    // PHR = PSDU length
    CHECK(a[1] == 0x00 && a[2] == 0x80);                 // beacon FCF
    CHECK(a[3] == 7);                                    // sequence number
    CHECK(a[12] == 0x03);                                // Thread beacon payload Protocol ID
    CHECK(memcmp(a + 14, h1.network_name, THREAD_NETNAME_LEN) == 0); // network name
    CHECK(memcmp(a + 30, h1.ext_pan_id, 8) == 0);        // extended PAN id
}

static void test_data_frame_thread_security(void)
{
    thread_home_t h;
    thread_home_init(&h, 1, MASK_11_26, ENTROPY, sizeof(ENTROPY));

    uint8_t payload[24];
    for (int i = 0; i < 24; i++) payload[i] = (uint8_t)(i * 7 + 1);

    uint8_t buf[THREAD_FRAME_MAX];
    int len = thread_build_data(buf, &h, 0, 1, 0x11, 0xCAFEBABE, payload, sizeof(payload));
    CHECK(len > 16);
    CHECK(buf[0] == (uint8_t)(len - 1));                 // PHR
    CHECK(buf[1] == 0x69);                               // FCF low: Data|Sec|AckReq|PANcomp
    CHECK(buf[2] == 0x98);                               // FCF high: dst short, ver 2006, src short
    CHECK(buf[3] == 0x11);                               // sequence number
    CHECK((buf[4] | (buf[5] << 8)) == h.pan_id);         // dest PAN id
    CHECK((buf[6] | (buf[7] << 8)) == h.rloc16[1]);      // dest = node 1
    CHECK((buf[8] | (buf[9] << 8)) == h.rloc16[0]);      // src  = node 0
    CHECK(buf[10] == 0x0d);                              // security control: level 5 | key-id-mode 1
    uint32_t fc = buf[11] | (buf[12] << 8) | (buf[13] << 16) | ((uint32_t)buf[14] << 24);
    CHECK(fc == 0xCAFEBABE);                             // frame counter (LE)
    CHECK(buf[15] == 0x00);                              // key index
    CHECK(memcmp(buf + 16, payload, sizeof(payload)) == 0); // opaque ciphertext body
}

static void test_data_frame_broadcast(void)
{
    thread_home_t h;
    thread_home_init(&h, 1, MASK_11_26, ENTROPY, sizeof(ENTROPY));

    uint8_t buf[THREAD_FRAME_MAX];
    int len = thread_build_data(buf, &h, 2, -1, 0x01, 1, NULL, 0); // broadcast (MLE-adv shape)
    CHECK(len > 0);
    CHECK(buf[1] == 0x49);                               // FCF low: AckReq cleared for broadcast
    CHECK(buf[2] == 0x98);
    CHECK(buf[6] == 0xff && buf[7] == 0xff);             // dest = 0xFFFF broadcast
}

static void test_frame_counter_varies(void)
{
    thread_home_t h;
    thread_home_init(&h, 1, MASK_11_26, ENTROPY, sizeof(ENTROPY));

    uint8_t p[8] = {0};
    uint8_t a[THREAD_FRAME_MAX], b[THREAD_FRAME_MAX];
    int la = thread_build_data(a, &h, 0, 1, 5, 100, p, sizeof(p));
    int lb = thread_build_data(b, &h, 0, 1, 5, 101, p, sizeof(p));
    CHECK(la == lb);
    CHECK(memcmp(a, b, la) != 0);                        // different counter -> different frame
}

int main(void)
{
    test_beacon_is_thread_and_coherent();
    test_data_frame_thread_security();
    test_data_frame_broadcast();
    test_frame_counter_varies();
    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("OK\n");
    return 0;
}
