// Pure-logic jam / RF-barrage analyzer. No FreeRTOS, no esp_* — compiles host-side
// for unit tests (see test/jam_core_test.c). Driven at 1 Hz by jam_detect, which
// pulls aggregate health samples from the Wi-Fi sniffer and the 802.15.4 task.
//
// Core signature, per band: ENERGY UP *AND* DECODE DOWN. That separates a jammer
// (lots of RF energy, nothing decodes / TX never completes) from a quiet channel
// (no energy) and a busy-but-healthy channel (energy + decodes fine). A hysteresis
// state machine rides out brief blips and avoids flapping.

#include "jam_core.h"
#include <string.h>

// ---- tunables (single tuning surface) ----
// HIL data (ESP32-C6, on-air): a quiet 802.15.4 channel reads ~-100..-108 dBm but normal
// readings swing up to ~-89 dBm (≈20 dB span) from ambient 2.4 GHz traffic. A 12 dB margin
// trips inside that normal swing, so the ED margin is 25 dB — only clearly-anomalous energy
// (a real barrage pushes ED to ~-60 dBm) counts as "energy up".
#define JAM_ED_MARGIN_DB   25     // 802.15.4 ED rise over per-channel baseline
// Sane floor must sit >= JAM_ED_MARGIN_DB below a detectable jam (~-60 dBm), so a baseline
// learned under a jam-at-boot (clamped to this floor) still clears the margin.
#define JAM_ED_SANE_DBM   (-90)   // a learned-quiet 15.4 channel louder than this == abnormal at boot
#define JAM_ASSERT_SECS     3     // consecutive trip-seconds to assert jammed
#define JAM_CLEAR_SECS     10     // consecutive quiet-seconds to clear
// HIL data: the 15.4 decoy transmits only ~5-7 frames/s and CCA legitimately reports the
// channel busy often (skipped frequently >= confirmed even when healthy), so the old
// "cca_busy>=5 AND tx_done==0" almost never held. TX-impaired now means "skips dominate
// confirms" — cheap to satisfy under a real jam, while the strong ED margin above is the
// specific gate that keeps normal contention from tripping.
#define JAM_CCA_BUSY_MIN    2     // min CCA-busy events in an interval to consider TX contended
// Wi-Fi attack detection (ESP32-C6 noise_floor is a constant, HIL-confirmed; see jam_core.h).
// HIL: normal received MGMT is ~6-20 frames/s; a flood reads 60-518/s. A deauth/disassoc
// storm is unambiguous (normal networks emit ~0/s).
#define JAM_WIFI_DEAUTH_MIN  8    // deauth+disassoc/s above this = attack
#define JAM_WIFI_FLOOD_MIN  80    // MGMT good-frames/s floor for a flood (absolute guard)
#define JAM_WIFI_FLOOD_MULT  4    // ...and must exceed the learned normal ceiling by this factor

static int8_t ed_idx(uint8_t ch) { return (ch >= 11 && ch <= 26) ? (int8_t)(ch - 11) : -1; }

void jam_init(jam_state_t *s)
{
    memset(s, 0, sizeof(*s));
}

void jam_begin_safe(jam_state_t *s, uint32_t now_ms, uint32_t dur_ms)
{
    s->learning       = true;
    s->learn_until_ms = now_ms + dur_ms;
}

// Close the learning window (once) and run the at-boot sanity check.
static void maybe_end_learning(jam_state_t *s, uint32_t now_ms)
{
    if (!s->learning) return;
    if ((int32_t)(now_ms - s->learn_until_ms) < 0) return;
    s->learning = false;
    // If even the quietest 15.4 energy we ever saw on a channel is loud, the band was
    // abnormal the whole window. ed_trip clamps to the sane floor so the jam stays
    // detectable; this flag surfaces that the baseline is untrustworthy. (Wi-Fi has no
    // equivalent — its noise_floor is a constant, so there's no baseline to distrust.)
    for (int i = 0; i < JAM_ED_CHANS; i++)
        if (s->ed_base_set[i] && s->ed_base[i] > JAM_ED_SANE_DBM) s->abnormal_boot = true;
}

void jam_reset(jam_state_t *s)
{
    s->jammed = false;
    s->band = JAM_BAND_NONE;
    s->peak_energy = 0;
    s->peak_rate = 0;
    s->duration_s = 0;
    s->assert_secs = 0;
    s->clear_secs = 0;
    s->wifi_trip_now = false;
    s->wifi_fresh = false;
    s->ed_fresh = false;
}

bool jam_active(const jam_state_t *s)    { return s->jammed; }
bool jam_wifi_trip(const jam_state_t *s) { return s->wifi_trip_now; }

void jam_get_status(const jam_state_t *s, jam_status_t *out)
{
    out->jammed      = s->jammed;
    out->band        = s->band;
    out->peak_energy = s->peak_energy;
    out->peak_rate   = s->peak_rate;
    out->duration_s  = s->duration_s;
    out->abnormal    = s->abnormal_boot;
}

void jam_feed_wifi(jam_state_t *s, const jam_wifi_sample_t *w, uint32_t now_ms)
{
    if (s->learning && (int32_t)(now_ms - s->learn_until_ms) < 0) {
        // Learn the normal MGMT-frame ceiling so a flood can be measured against it.
        if (w->good_frames > s->good_base) s->good_base = w->good_frames;
        return;
    }
    s->wifi = *w;
    s->wifi_fresh = true;
}

void jam_feed_ed(jam_state_t *s, const jam_ed_sample_t *e, uint32_t now_ms)
{
    if (s->learning && (int32_t)(now_ms - s->learn_until_ms) < 0) {
        if (e->ed_valid) {
            int8_t i = ed_idx(e->channel);
            if (i >= 0 && (!s->ed_base_set[i] || e->energy < s->ed_base[i])) {
                s->ed_base[i] = e->energy; s->ed_base_set[i] = true;
            }
        }
        return;
    }
    s->ed = *e;
    s->ed_fresh = true;
}

static bool wifi_trip(const jam_state_t *s)
{
    if (!s->wifi_fresh) return false;
    // A deauth/disassoc storm is an unambiguous Wi-Fi attack — normal networks emit
    // ~0/s, so any sustained rate is hostile.
    if (s->wifi.deauth_frames >= JAM_WIFI_DEAUTH_MIN) return true;
    // A MGMT-frame flood (beacon spam / mgmt storm) reads far above the learned normal
    // ceiling. The absolute floor guards a small good_base; the multiple keeps a merely
    // busy environment from tripping. (RF-energy jamming is handled by the ED path.)
    if (s->wifi.good_frames >= JAM_WIFI_FLOOD_MIN &&
        s->wifi.good_frames >= (uint16_t)(s->good_base * JAM_WIFI_FLOOD_MULT))
        return true;
    return false;
}

static bool ed_trip(const jam_state_t *s)
{
    if (!s->ed_fresh || !s->ed.ed_valid) return false;
    int8_t i = ed_idx(s->ed.channel);
    if (i < 0 || !s->ed_base_set[i]) return false;
    // Same sane-floor clamp as wifi_trip so a jammer present during the learning
    // window can't teach a loud per-channel baseline that hides the ongoing jam.
    int8_t base = (s->ed_base[i] > JAM_ED_SANE_DBM) ? JAM_ED_SANE_DBM : s->ed_base[i];
    bool energy_up = (s->ed.energy - base >= JAM_ED_MARGIN_DB);
    // TX impaired = CCA-busy dominates confirmed TX (skips >= confirms), at the device's
    // low 15.4 TX rate. Paired with the specific energy_up gate above.
    bool tx_down   = (s->ed.cca_busy >= JAM_CCA_BUSY_MIN) && (s->ed.cca_busy >= s->ed.tx_done);
    return energy_up && tx_down;
}

void jam_tick(jam_state_t *s, uint32_t now_ms)
{
    maybe_end_learning(s, now_ms);
    if (s->learning) { s->wifi_fresh = s->ed_fresh = false; return; }

    bool wt = wifi_trip(s);
    bool et = ed_trip(s);
    s->wifi_trip_now = wt;
    bool trip = wt || et;

    if (trip) {
        s->clear_secs = 0;
        if (s->assert_secs < 255) s->assert_secs++;
        if (s->assert_secs >= JAM_ASSERT_SECS) {
            if (!s->jammed) { s->jammed = true; s->band = JAM_BAND_NONE; s->peak_energy = -128; s->peak_rate = 0; s->duration_s = 0; }
            s->band |= (uint8_t)((wt ? JAM_BAND_WIFI : 0) | (et ? JAM_BAND_154 : 0));
            // peak_energy is the 802.15.4 ED energy (dBm); peak_rate is the Wi-Fi flood
            // intensity (MGMT frames/s) — different units, so they're tracked separately.
            if (et && s->ed.energy > s->peak_energy) s->peak_energy = s->ed.energy;
            if (wt && s->wifi.good_frames > s->peak_rate) s->peak_rate = s->wifi.good_frames;
        }
    } else {
        s->assert_secs = 0;
        if (s->clear_secs < 255) s->clear_secs++;
        if (s->jammed && s->clear_secs >= JAM_CLEAR_SECS) {
            s->jammed = false; s->band = JAM_BAND_NONE; s->duration_s = 0;
        }
    }
    // Count every second of an active episode exactly once, regardless of which
    // branch ran (a transient quiet second mid-episode still counts toward duration).
    if (s->jammed && s->duration_s < 0xFFFF) s->duration_s++;
    s->wifi_fresh = s->ed_fresh = false;   // consume the samples
}
