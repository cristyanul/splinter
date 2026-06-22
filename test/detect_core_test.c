#include "detect_core.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static dc_sighting_t mk(uint8_t last, int8_t rssi, dc_radio_t r) {
    dc_sighting_t s = {0};
    s.radio = r; s.rssi = rssi; s.channel = 6;
    uint8_t base[6] = {0x02, 0x11, 0x22, 0x33, 0x44, last};
    memcpy(s.id, base, 6);
    return s;
}

// Drive `dev` through `n` scene changes so scenes_survived == n. Each round
// swaps in two fresh close decoys and drops the previous pair, turning the
// close-set over >50% (a scene change) while `dev` stays present in both
// scenes. This is how a real follower accrues "survived" credit: it stays with
// you as your surroundings change.
static void survive(dc_state_t *s, const dc_sighting_t *dev, int n) {
    s->scene_ms = 1000;
    uint32_t t = 100;
    dc_ingest(s, dev, t);
    dc_sighting_t a = mk(0x80, -50, DC_RADIO_WIFI); dc_ingest(s, &a, t);
    dc_sighting_t b = mk(0x81, -50, DC_RADIO_WIFI); dc_ingest(s, &b, t);
    dc_scene_tick(s, t + 900);                       // baseline scene, no survival
    for (int i = 0; i < n; i++) {
        t += 1000;
        dc_ingest(s, dev, t);
        dc_sighting_t c = mk((uint8_t)(0x82 + 2 * i), -50, DC_RADIO_WIFI); dc_ingest(s, &c, t);
        dc_sighting_t d = mk((uint8_t)(0x83 + 2 * i), -50, DC_RADIO_WIFI); dc_ingest(s, &d, t);
        dc_scene_tick(s, t + 900);
    }
}

static void test_ingest_adds_and_updates(void) {
    dc_state_t s; dc_init(&s);
    dc_sighting_t a = mk(0x01, -50, DC_RADIO_WIFI);
    dc_ingest(&s, &a, 1000);
    CHECK(s.ndev == 1);
    dc_dev_t *d = dc_find(&s, a.id);
    CHECK(d != NULL);
    CHECK(d->sightings == 1);
    CHECK(d->first_seen_ms == 1000);
    CHECK(d->last_seen_ms == 1000);
    // second sighting of same id updates, does not add
    dc_ingest(&s, &a, 2000);
    CHECK(s.ndev == 1);
    CHECK(d->sightings == 2);
    CHECK(d->last_seen_ms == 2000);
    // a different id adds a new record
    dc_sighting_t b = mk(0x02, -60, DC_RADIO_BLE);
    dc_ingest(&s, &b, 2500);
    CHECK(s.ndev == 2);
}

static void test_scene_survival(void) {
    dc_state_t s; dc_init(&s);
    s.scene_ms = 1000; // shrink for the test
    // Scene 1 @ t=0..1000: devices 1,2,3 all close
    for (uint8_t i = 1; i <= 3; i++) { dc_sighting_t x = mk(i, -50, DC_RADIO_WIFI); dc_ingest(&s, &x, 100); }
    CHECK(dc_due_scene(&s, 1000) == true);
    dc_scene_tick(&s, 1000); // first tick: establishes baseline, no survival yet
    // Scene 2: only device 1 stays; 4,5 are new (big turnover -> scene change)
    dc_sighting_t d1 = mk(1, -50, DC_RADIO_WIFI); dc_ingest(&s, &d1, 1100);
    dc_sighting_t d4 = mk(4, -50, DC_RADIO_WIFI); dc_ingest(&s, &d4, 1100);
    dc_sighting_t d5 = mk(5, -50, DC_RADIO_WIFI); dc_ingest(&s, &d5, 1100);
    dc_scene_tick(&s, 2000);
    CHECK(dc_find(&s, d1.id)->scenes_survived == 1); // survived the move
    CHECK(dc_find(&s, d4.id)->scenes_survived == 0); // newcomer
}

static void test_scoring(void) {
    // A close device that merely sits in range for a long time but never moves
    // with you (scenes_survived == 0) is NOT a follower -> not a threat. This is
    // the stationary-at-home false positive we explicitly reject.
    {
        dc_state_t s; dc_init(&s);
        dc_sighting_t still = mk(0x09, -55, DC_RADIO_WIFI);
        dc_ingest(&s, &still, 0);
        dc_ingest(&s, &still, 3600000);   // present an hour, but 0 scenes survived
        dc_score(&s, 3600000);
        CHECK(!(dc_find(&s, still.id)->flags & DC_F_THREAT));
        CHECK(dc_threat_count(&s) == 0);
    }
    // A close device that stays with you across scene changes -> threat.
    {
        dc_state_t s; dc_init(&s);
        dc_sighting_t f = mk(0x09, -55, DC_RADIO_WIFI);
        survive(&s, &f, 3);
        dc_score(&s, 100000);
        CHECK(dc_find(&s, f.id)->flags & DC_F_THREAT);
        CHECK(dc_threat_count(&s) == 1);
        // Allowlisted identical device -> not a threat
        dc_allow(&s, f.id, true);
        dc_score(&s, 100000);
        CHECK(!(dc_find(&s, f.id)->flags & DC_F_THREAT));
    }
    // A tracker tag that moved with you (survived scenes) but now reads far ->
    // still a threat via the kind path (proximity not required once it has
    // tracked you across scenes).
    {
        dc_state_t s; dc_init(&s);
        dc_sighting_t t = mk(0x0a, -68, DC_RADIO_BLE); t.tracker_kind = DC_TRK_APPLE_FINDMY;
        survive(&s, &t, 3);
        for (int k = 0; k < 6; k++) {     // pull EWMA below "close" without ticking
            dc_sighting_t far = mk(0x0a, -95, DC_RADIO_BLE); far.tracker_kind = DC_TRK_APPLE_FINDMY;
            dc_ingest(&s, &far, 5000 + k);
        }
        dc_dev_t *td = dc_find(&s, t.id);
        CHECK(td->rssi_ewma < s.rssi_close);   // genuinely "far" now
        CHECK(td->scenes_survived >= 3);
        dc_score(&s, 6000);
        CHECK(td->flags & DC_F_THREAT);
    }
    // A far tracker tag that NEVER moved with you (the neighbour's tag through a
    // wall, the exact -97 dBm false positive) -> NOT a threat.
    {
        dc_state_t s; dc_init(&s);
        dc_sighting_t amb = mk(0x0b, -95, DC_RADIO_BLE); amb.tracker_kind = DC_TRK_SAMSUNG;
        dc_ingest(&s, &amb, 0);
        dc_ingest(&s, &amb, 3600000);
        dc_score(&s, 3600000);
        CHECK(!(dc_find(&s, amb.id)->flags & DC_F_THREAT));
        CHECK(dc_threat_count(&s) == 0);
    }
}

static void test_safe_window_autolearn(void) {
    dc_state_t s; dc_init(&s);
    dc_begin_safe(&s, 0, 5000);          // safe for 5s
    dc_sighting_t mine = mk(0x20, -40, DC_RADIO_BLE);
    dc_ingest(&s, &mine, 1000);          // close + within window -> auto-trust
    CHECK(dc_find(&s, mine.id)->flags & DC_F_ALLOW);
    // after the window, a new close device is NOT auto-trusted
    dc_sighting_t other = mk(0x21, -40, DC_RADIO_BLE);
    dc_ingest(&s, &other, 6000);
    CHECK(!(dc_find(&s, other.id)->flags & DC_F_ALLOW));
}

static void test_radar_and_allowlist(void) {
    dc_state_t s; dc_init(&s);
    dc_sighting_t f = mk(0x30, -55, DC_RADIO_WIFI);          // follower: close + moved with you
    survive(&s, &f, 3);
    dc_sighting_t t = mk(0x31, -45, DC_RADIO_BLE);           // trusted + present
    dc_ingest(&s, &t, 5000);
    dc_allow(&s, t.id, true);
    uint8_t absent[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x99}; // trusted but never seen
    dc_allow(&s, absent, true);
    dc_score(&s, 5000);

    dc_radar_t r[8];
    int n = dc_radar(&s, r, 8);
    CHECK(n == 2);                                           // follower + trusted-present
    int th = 0, tr = 0;
    for (int i = 0; i < n; i++) {
        if (r[i].category == DC_CAT_THREAT)  th++;
        if (r[i].category == DC_CAT_TRUSTED) tr++;
    }
    CHECK(th == 1);
    CHECK(tr == 1);

    uint8_t al[8][6];
    int na = dc_allowlist(&s, al, 8);
    CHECK(na == 2);                                          // both trusted MACs (present + absent)
}

int main(void) {
    test_ingest_adds_and_updates();
    test_scene_survival();
    test_scoring();
    test_safe_window_autolearn();
    test_radar_and_allowlist();
    if (g_fail) { printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("OK\n"); return 0;
}
