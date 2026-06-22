#include "detect_core.h"

void dc_init(dc_state_t *s)
{
    memset(s, 0, sizeof(*s));
    s->rssi_close     = -70;
    s->scene_ms       = 45000;
    s->persist_scenes = 3;        // scene changes a device must survive to flag
    s->jaccard_pct    = 50;
}

dc_dev_t *dc_find(dc_state_t *s, const uint8_t id[6])
{
    for (int i = 0; i < s->ndev; i++) {
        if (memcmp(s->dev[i].id, id, 6) == 0) return &s->dev[i];
    }
    return NULL;
}

// Evict the stalest record (oldest last_seen) to make room.
static dc_dev_t *evict_one(dc_state_t *s)
{
    int oldest = 0;
    for (int i = 1; i < s->ndev; i++) {
        if (s->dev[i].last_seen_ms < s->dev[oldest].last_seen_ms) oldest = i;
    }
    return &s->dev[oldest];
}

static bool is_allowed(const dc_state_t *s, const uint8_t id[6])
{
    for (int i = 0; i < s->nallow; i++) {
        if (memcmp(s->allow[i], id, 6) == 0) return true;
    }
    return false;
}

void dc_ingest(dc_state_t *s, const dc_sighting_t *sg, uint32_t now_ms)
{
    dc_dev_t *d = dc_find(s, sg->id);
    if (!d) {
        if (s->ndev < DC_MAX_DEVICES) {
            d = &s->dev[s->ndev++];
        } else {
            d = evict_one(s);
        }
        memset(d, 0, sizeof(*d));
        memcpy(d->id, sg->id, 6);
        d->radio        = sg->radio;
        d->fp           = sg->fp;
        d->tracker_kind = sg->tracker_kind;
        d->rssi_ewma    = sg->rssi;
        d->first_seen_ms = now_ms;
        if (is_allowed(s, sg->id)) d->flags |= DC_F_ALLOW;
    }
    // EWMA proximity: ewma += (rssi - ewma)/4
    d->rssi_ewma = (int8_t)(d->rssi_ewma + (sg->rssi - d->rssi_ewma) / 4);
    d->last_seen_ms = now_ms;
    if (d->sightings < 0xFFFF) d->sightings++;
    if (sg->tracker_kind != DC_TRK_NONE) d->tracker_kind = sg->tracker_kind;
    d->in_curr_scene |= (sg->rssi >= s->rssi_close) ? 1 : 0;
    // Auto-learn: trust devices seen close during a safe window.
    if (now_ms < s->safe_until_ms && sg->rssi >= s->rssi_close &&
        !(d->flags & DC_F_ALLOW)) {
        dc_allow(s, d->id, true);
    }
}

bool dc_due_scene(const dc_state_t *s, uint32_t now_ms)
{
    return (now_ms - s->scene_started_ms) >= s->scene_ms;
}

// Close a scene window: compare the "close" set now vs the previous scene. If
// the set turned over substantially (low Jaccard), treat it as movement and
// credit devices present in both scenes with a survived transition.
void dc_scene_tick(dc_state_t *s, uint32_t now_ms)
{
    int prev = 0, curr = 0, both = 0;
    for (int i = 0; i < s->ndev; i++) {
        if (s->dev[i].in_prev_scene) prev++;
        if (s->dev[i].in_curr_scene) curr++;
        if (s->dev[i].in_prev_scene && s->dev[i].in_curr_scene) both++;
    }
    int uni = prev + curr - both;
    // jaccard% = both/union*100; guard the first tick (prev==0 -> baseline only)
    bool scene_change = (prev > 0) && (uni > 0) &&
                        ((both * 100 / uni) < s->jaccard_pct);
    if (scene_change) {
        for (int i = 0; i < s->ndev; i++) {
            dc_dev_t *d = &s->dev[i];
            if (d->in_prev_scene && d->in_curr_scene) {
                if (d->scenes_survived < 0xFF) d->scenes_survived++;
            } else if (!d->in_curr_scene && d->scenes_survived > 0) {
                d->scenes_survived--; // decay devices that dropped out
            }
        }
    }
    // roll the window
    for (int i = 0; i < s->ndev; i++) {
        s->dev[i].in_prev_scene = s->dev[i].in_curr_scene;
        s->dev[i].in_curr_scene = 0;
    }
    s->scene_started_ms = now_ms;
}

void dc_allow(dc_state_t *s, const uint8_t id[6], bool on)
{
    dc_dev_t *d = dc_find(s, id);
    if (on) {
        if (d) d->flags |= DC_F_ALLOW;
        // record in the persistent allowlist if room and not present
        for (int i = 0; i < s->nallow; i++) {
            if (memcmp(s->allow[i], id, 6) == 0) return;
        }
        if (s->nallow < DC_ALLOW_MAX) memcpy(s->allow[s->nallow++], id, 6);
    } else {
        if (d) d->flags &= ~DC_F_ALLOW;
        for (int i = 0; i < s->nallow; i++) {
            if (memcmp(s->allow[i], id, 6) == 0) {
                s->allow[i][0] = 0; // tombstone via shift-down
                memmove(&s->allow[i], &s->allow[i + 1], (s->nallow - i - 1) * 6);
                s->nallow--;
                break;
            }
        }
    }
}

void dc_begin_safe(dc_state_t *s, uint32_t now_ms, uint32_t dur_ms)
{
    s->safe_until_ms = now_ms + dur_ms;
}

// "Following" means a device stays with you as your surroundings change — not
// merely that it has been in range for a while. A stationary device (yours or a
// neighbour's) sitting near a fixed location racks up duration without ever
// tracking you, so we require survived scene transitions and never a raw
// elapsed duration. No movement in the environment => nothing can be a follower.
static bool persistent(const dc_state_t *s, const dc_dev_t *d)
{
    return d->scenes_survived >= s->persist_scenes;
}

void dc_score(dc_state_t *s, uint32_t now_ms)
{
    (void)now_ms;
    for (int i = 0; i < s->ndev; i++) {
        dc_dev_t *d = &s->dev[i];
        bool threat = false;
        if (!(d->flags & DC_F_ALLOW)) {
            bool close = d->rssi_ewma >= s->rssi_close;
            bool persist = persistent(s, d);
            // standard path: close AND persistent
            if (close && persist) threat = true;
            // tracker-kind path: an unknown tag that persists, even if not close
            if (d->tracker_kind != DC_TRK_NONE && persist) threat = true;
        }
        if (threat) d->flags |= DC_F_THREAT; else d->flags &= ~DC_F_THREAT;
    }
}

uint32_t dc_threat_count(const dc_state_t *s)
{
    uint32_t n = 0;
    for (int i = 0; i < s->ndev; i++) if (s->dev[i].flags & DC_F_THREAT) n++;
    return n;
}

int dc_threats(const dc_state_t *s, dc_threat_t *out, int max)
{
    int n = 0;
    for (int i = 0; i < s->ndev && n < max; i++) {
        const dc_dev_t *d = &s->dev[i];
        if (!(d->flags & DC_F_THREAT)) continue;
        memcpy(out[n].id, d->id, 6);
        out[n].radio        = d->radio;
        out[n].tracker_kind = d->tracker_kind;
        out[n].rssi         = d->rssi_ewma;
        out[n].minutes      = (uint16_t)((d->last_seen_ms - d->first_seen_ms) / 60000u);
        out[n].scenes       = d->scenes_survived;
        n++;
    }
    return n;
}

int dc_radar(const dc_state_t *s, dc_radar_t *out, int max)
{
    int n = 0;
    for (int i = 0; i < s->ndev && n < max; i++) {
        const dc_dev_t *d = &s->dev[i];
        uint8_t cat;
        if (d->flags & DC_F_THREAT)     cat = DC_CAT_THREAT;
        else if (d->flags & DC_F_ALLOW) cat = DC_CAT_TRUSTED;
        else continue;
        memcpy(out[n].id, d->id, 6);
        out[n].radio        = d->radio;
        out[n].tracker_kind = d->tracker_kind;
        out[n].rssi         = d->rssi_ewma;
        out[n].minutes      = (uint16_t)((d->last_seen_ms - d->first_seen_ms) / 60000u);
        out[n].scenes       = d->scenes_survived;
        out[n].category     = cat;
        n++;
    }
    return n;
}

int dc_allowlist(const dc_state_t *s, uint8_t out[][6], int max)
{
    int n = s->nallow;
    if (n > max) n = max;
    for (int i = 0; i < n; i++) memcpy(out[i], s->allow[i], 6);
    return n;
}
