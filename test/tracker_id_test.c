// Host unit tests for tracker_classify (tracker_id.c).
//   gcc test/tracker_id_test.c main/tracker_id.c -I main -o /tmp/trk_test && /tmp/trk_test

#include "tracker_id.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static void test_find_my_separated(void)
{
    // AD: len, type=0xFF mfg, company 0x004C, payload type 0x12, len 0x19, + body.
    uint8_t adv[32];
    int i = 0;
    adv[i++] = 0x1e;                 // AD length = 1 + 29
    adv[i++] = 0xFF;                 // Manufacturer Specific Data
    adv[i++] = 0x4C; adv[i++] = 0x00;// Apple
    adv[i++] = 0x12; adv[i++] = 0x19;// Find My separated, len 25
    for (int k = 0; k < 25; k++) adv[i++] = (uint8_t)(0xA0 + k); // opaque key/status
    CHECK(tracker_classify(adv, (uint8_t)i) == DC_TRK_APPLE_FINDMY);
}

static void test_samsung_smarttag(void)
{
    uint8_t adv[] = { 0x03, 0x16, 0x5A, 0xFD };   // Service Data UUID 0xFD5A
    CHECK(tracker_classify(adv, sizeof(adv)) == DC_TRK_SAMSUNG);
}

static void test_tile(void)
{
    uint8_t adv[] = { 0x03, 0x16, 0xED, 0xFE };   // Service Data UUID 0xFEED
    CHECK(tracker_classify(adv, sizeof(adv)) == DC_TRK_TILE);
}

static void test_galaxy_phone_is_not_a_tracker(void)
{
    // Samsung company id 0x0075 with arbitrary payload — a phone/earbud, NOT a tag.
    uint8_t adv[] = { 0x06, 0xFF, 0x75, 0x00, 0x42, 0x01, 0x99 };
    CHECK(tracker_classify(adv, sizeof(adv)) == DC_TRK_NONE);
}

static void test_apple_nearby_is_not_a_tracker(void)
{
    // Apple "nearby" 0x10 (handoff/continuity), not a separated Find My tag.
    uint8_t adv[] = { 0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x01, 0x02, 0x03 };
    CHECK(tracker_classify(adv, sizeof(adv)) == DC_TRK_NONE);
}

static void test_junk_and_empty(void)
{
    uint8_t junk[] = { 0x02, 0x01, 0x06, 0x05, 0x09, 'h', 'i', '!' }; // flags + name
    CHECK(tracker_classify(junk, sizeof(junk)) == DC_TRK_NONE);
    CHECK(tracker_classify(NULL, 0) == DC_TRK_NONE);
    uint8_t bad[] = { 0xFF, 0x16, 0x01 };   // length byte overruns buffer -> no crash, NONE
    CHECK(tracker_classify(bad, sizeof(bad)) == DC_TRK_NONE);
}

int main(void)
{
    test_find_my_separated();
    test_samsung_smarttag();
    test_tile();
    test_galaxy_phone_is_not_a_tracker();
    test_apple_nearby_is_not_a_tracker();
    test_junk_and_empty();
    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("OK\n");
    return 0;
}
