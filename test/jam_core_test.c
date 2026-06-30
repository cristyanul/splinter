#include "jam_core.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

// Wi-Fi sample: MGMT good-frame rate + deauth/disassoc rate (noise_floor is a constant
// on real hardware, so it's gone — the Wi-Fi band detects frame floods, not RF energy).
static jam_wifi_sample_t wsamp(uint16_t good, uint16_t deauth) {
    jam_wifi_sample_t w = {0};
    w.good_frames = good; w.deauth_frames = deauth; w.channel = 6;
    return w;
}
static jam_ed_sample_t esamp(uint8_t ch, int8_t energy, uint8_t edv, uint16_t busy, uint16_t done) {
    jam_ed_sample_t e = {0};
    e.channel = ch; e.energy = energy; e.ed_valid = edv; e.cca_busy = busy; e.tx_done = done;
    return e;
}

// `secs` seconds of healthy traffic: normal ~10 MGMT/s, 0 deauth, quiet 15.4.
static uint32_t feed_healthy(jam_state_t *s, uint32_t t, int secs) {
    for (int i = 0; i < secs; i++) {
        jam_wifi_sample_t w = wsamp(10, 0);
        jam_ed_sample_t   e = esamp(15, -90, 1, 0, 5);
        jam_feed_wifi(s, &w, t); jam_feed_ed(s, &e, t); jam_tick(s, t); t += 1000;
    }
    return t;
}

// Wi-Fi MGMT flood (beacon spam / mgmt storm), 15.4 healthy.
static uint32_t feed_wifi_flood(jam_state_t *s, uint32_t t, int secs) {
    for (int i = 0; i < secs; i++) {
        jam_wifi_sample_t w = wsamp(300, 0);
        jam_ed_sample_t   e = esamp(15, -90, 1, 0, 5);
        jam_feed_wifi(s, &w, t); jam_feed_ed(s, &e, t); jam_tick(s, t); t += 1000;
    }
    return t;
}

// 802.15.4 jam: ED energy spike + CCA blocking TX; Wi-Fi healthy.
static uint32_t feed_154_jam(jam_state_t *s, uint32_t t, int secs) {
    for (int i = 0; i < secs; i++) {
        jam_wifi_sample_t w = wsamp(10, 0);
        jam_ed_sample_t   e = esamp(15, -60, 1, 30, 0);
        jam_feed_wifi(s, &w, t); jam_feed_ed(s, &e, t); jam_tick(s, t); t += 1000;
    }
    return t;
}

static void test_quiet_never_alerts(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    t = feed_healthy(&s, t, 30);
    CHECK(!jam_active(&s));
}

static void test_baseline_learns(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = 0;
    for (int i = 0; i < 5; i++) {
        jam_wifi_sample_t w = wsamp((uint16_t)(10 + i), 0);          // max = 14
        jam_ed_sample_t   e = esamp(15, (int8_t)(-90 + (i % 2)), 1, 0, 5);
        jam_feed_wifi(&s, &w, t); jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    jam_tick(&s, t);
    CHECK(s.good_base == 14);             // learned MGMT ceiling
    CHECK(s.ed_base_set[15 - 11]);
    CHECK(s.ed_base[15 - 11] == -90);
    CHECK(!s.abnormal_boot);
}

// abnormal-at-boot is a 15.4 concept now (Wi-Fi noise floor is constant): learning
// under a loud 15.4 channel flags it, and the sane-floor clamp keeps it detectable.
static void test_abnormal_boot_flagged(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 3000);
    uint32_t t = 0;
    for (int i = 0; i < 3; i++) {
        jam_ed_sample_t e = esamp(15, -55, 1, 30, 0);   // 15.4 loud the whole window
        jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    jam_tick(&s, t);
    CHECK(s.abnormal_boot);
}

static void test_wifi_flood_asserts_then_clears(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    t = feed_wifi_flood(&s, t, 2);
    CHECK(!jam_active(&s));                // 2s < JAM_ASSERT_SECS
    t = feed_wifi_flood(&s, t, 1);
    CHECK(jam_active(&s));                 // 3rd consecutive -> assert
    CHECK(s.band == JAM_BAND_WIFI);
    jam_status_t st; jam_get_status(&s, &st);
    CHECK(st.peak_rate >= 300);            // flood intensity recorded
    t = feed_healthy(&s, t, 9);
    CHECK(jam_active(&s));
    t = feed_healthy(&s, t, 1);
    CHECK(!jam_active(&s));                // cleared after JAM_CLEAR_SECS
}

static void test_wifi_deauth_storm_asserts(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    for (int i = 0; i < 3; i++) {          // deauth flood (good rate normal, deauth high)
        jam_wifi_sample_t w = wsamp(15, 40);
        jam_ed_sample_t   e = esamp(15, -90, 1, 0, 5);
        jam_feed_wifi(&s, &w, t); jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    CHECK(jam_active(&s));
    CHECK(s.band & JAM_BAND_WIFI);
}

static void test_wifi_flood_blip_does_not_assert(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    t = feed_wifi_flood(&s, t, 2);         // 2s blip
    t = feed_healthy(&s, t, 5);
    CHECK(!jam_active(&s));
}

// A merely BUSY environment (high learned ceiling) must not false-positive: the flood
// threshold scales with the learned normal rate.
static void test_busy_env_no_false_positive(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = 0;
    for (int i = 0; i < 5; i++) {          // learn a busy site: ~50 MGMT/s normal
        jam_wifi_sample_t w = wsamp(50, 0);
        jam_ed_sample_t   e = esamp(15, -90, 1, 0, 5);
        jam_feed_wifi(&s, &w, t); jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    jam_tick(&s, t); t += 1000;
    for (int i = 0; i < 6; i++) {          // 150/s — busy but < 4x the 50/s ceiling
        jam_wifi_sample_t w = wsamp(150, 0);
        jam_ed_sample_t   e = esamp(15, -90, 1, 0, 5);
        jam_feed_wifi(&s, &w, t); jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    CHECK(!jam_active(&s));
}

static void test_154_jam_asserts(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    t = feed_154_jam(&s, t, 3);
    CHECK(jam_active(&s));
    CHECK(s.band & JAM_BAND_154);
}

static void test_energy_without_tx_block_is_quiet(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    for (int i = 0; i < 6; i++) {
        jam_wifi_sample_t w = wsamp(10, 0);
        jam_ed_sample_t   e = esamp(15, -55, 1, 2, 5);   // loud but TX completing fine
        jam_feed_wifi(&s, &w, t); jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    CHECK(!jam_active(&s));
}

// HIL-derived: the 15.4 radio transmits only a few frames/sec. A real jam blocks most
// of them (skips dominate confirms) but tx_done rarely hits exactly 0. With strong ED
// energy this must still assert.
static void test_154_low_txrate_jam_asserts(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    for (int i = 0; i < 4; i++) {
        jam_wifi_sample_t w = wsamp(10, 0);
        jam_ed_sample_t   e = esamp(15, -58, 1, 4, 1);   // loud, 4 skips vs 1 confirm
        jam_feed_wifi(&s, &w, t); jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    CHECK(jam_active(&s));
    CHECK(s.band & JAM_BAND_154);
}

// A 15.4 jammer blasting during the learning window teaches a corrupt (loud) per-channel
// baseline; the sane-floor clamp must keep it detectable and the flag must surface.
static void test_jammer_at_boot_154_still_detected(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = 0;
    for (int i = 0; i < 5; i++) {
        jam_ed_sample_t e = esamp(15, -60, 1, 30, 0);
        jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    jam_tick(&s, t); t += 1000;
    for (int i = 0; i < 4; i++) {
        jam_ed_sample_t e = esamp(15, -60, 1, 30, 0);
        jam_feed_ed(&s, &e, t); jam_tick(&s, t); t += 1000;
    }
    CHECK(jam_active(&s));
    CHECK(s.band & JAM_BAND_154);
    jam_status_t st; jam_get_status(&s, &st);
    CHECK(st.abnormal);
}

static void test_status_reports_band_peak_and_duration(void) {
    jam_state_t s; jam_init(&s);
    jam_begin_safe(&s, 0, 5000);
    uint32_t t = feed_healthy(&s, 0, 5);
    t = feed_154_jam(&s, t, 5);
    jam_status_t st; jam_get_status(&s, &st);
    CHECK(st.jammed);
    CHECK(st.band & JAM_BAND_154);
    CHECK(st.duration_s >= 3);
    CHECK(st.peak_energy >= -60);
}

int main(void) {
    test_quiet_never_alerts();
    test_baseline_learns();
    test_abnormal_boot_flagged();
    test_wifi_flood_asserts_then_clears();
    test_wifi_deauth_storm_asserts();
    test_wifi_flood_blip_does_not_assert();
    test_busy_env_no_false_positive();
    test_154_jam_asserts();
    test_energy_without_tx_block_is_quiet();
    test_154_low_txrate_jam_asserts();
    test_jammer_at_boot_154_still_detected();
    test_status_reports_band_peak_and_duration();
    if (g_fail) { printf("%d FAILED\n", g_fail); return 1; }
    printf("OK\n");
    return 0;
}
