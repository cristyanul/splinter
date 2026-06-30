#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DC_MAX_DEVICES 96
#define DC_ALLOW_MAX   32

typedef enum { DC_RADIO_BLE = 0, DC_RADIO_WIFI = 1 } dc_radio_t;
typedef enum { DC_TRK_NONE = 0, DC_TRK_APPLE_FINDMY, DC_TRK_SAMSUNG, DC_TRK_TILE } dc_tracker_t;
#define DC_TRK_COUNT 4   // number of dc_tracker_t values (index by the enum)

// device-record flags
#define DC_F_ALLOW   0x01u   // trusted ("my device")
#define DC_F_THREAT  0x02u   // currently scored as a follower

typedef struct {
    dc_radio_t radio;
    uint8_t    id[6];
    int8_t     rssi;
    uint8_t    channel;
    uint16_t   fp;            // fingerprint (BLE payload / Wi-Fi OUI+IE hash)
    uint8_t    tracker_kind;  // dc_tracker_t
} dc_sighting_t;

typedef struct {
    uint8_t  id[6];
    uint8_t  radio;
    uint16_t fp;
    uint8_t  tracker_kind;
    int8_t   rssi_ewma;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    uint16_t sightings;
    uint8_t  scenes_survived;
    uint8_t  flags;
    uint8_t  in_prev_scene;   // scene-model scratch
    uint8_t  in_curr_scene;
} dc_dev_t;

typedef struct {
    uint8_t  id[6];
    uint8_t  radio;
    uint8_t  tracker_kind;
    int8_t   rssi;
    uint16_t minutes;   // observed duration, minutes
    uint8_t  scenes;
    uint16_t fp;        // fingerprint (for kind+fp peer matching across MAC churn)
} dc_threat_t;

typedef enum { DC_CAT_THREAT = 0, DC_CAT_TRUSTED = 1, DC_CAT_PEER = 2 } dc_category_t;

// A kind-level tracker alert: an unexplained number of trackers of one kind have
// stayed close across scene changes (rotation-proof; survives MAC churn).
typedef struct {
    uint8_t kind;       // dc_tracker_t
    uint8_t present;    // distinct close devices of this kind in the latest scene
    uint8_t baseline;   // learned normal count (yours)
    uint8_t scenes;     // scene changes survived above baseline
} dc_kind_alert_t;

// A threat reported by a swarm peer (shared over ESP-NOW). Used to corroborate:
// a local device matching a fresh peer report is confirmed immediately.
#define DC_PEER_MAX 8
typedef struct {
    uint8_t  id[6];
    uint16_t fp;
    uint8_t  tracker_kind;
    int8_t   rssi;
    uint32_t last_ms;     // when this report was last received
    uint8_t  matched;     // scratch: matched a local device in the last dc_score
} dc_peer_t;

// A device to plot on the radar: a currently-heard follower or trusted device.
typedef struct {
    uint8_t  id[6];
    uint8_t  radio;
    uint8_t  tracker_kind;
    int8_t   rssi;
    uint16_t minutes;
    uint8_t  scenes;
    uint8_t  category;  // dc_category_t
} dc_radar_t;

typedef struct {
    dc_dev_t dev[DC_MAX_DEVICES];
    int      ndev;
    uint8_t  allow[DC_ALLOW_MAX][6];
    int      nallow;
    uint32_t scene_started_ms;
    uint32_t safe_until_ms;
    // tunables (set by dc_init)
    int8_t   rssi_close;      // dBm; >= is "close"
    uint32_t scene_ms;        // scene window length
    uint8_t  persist_scenes;  // scenes_survived threshold to flag a follower
    uint8_t  jaccard_pct;     // < this (intersection/union %) = scene change

    // Kind-level tracker tracking (rotation-proof; indexed by dc_tracker_t).
    // A commercial tracker (AirTag/SmartTag/Tile) rotates its MAC, so per-MAC
    // persistence never accrues. Instead we count distinct CLOSE devices per kind
    // each scene, learn a per-kind baseline (your own) during the safe window, and
    // flag a kind whose close count stays ABOVE baseline across scene changes.
    uint8_t  kind_baseline[DC_TRK_COUNT];
    uint8_t  kind_curr_close[DC_TRK_COUNT];
    uint8_t  kind_prev_close[DC_TRK_COUNT];
    uint8_t  kind_scenes_survived[DC_TRK_COUNT];
    uint8_t  kind_flag[DC_TRK_COUNT];

    // Swarm peer-reported threats (corroboration across nodes).
    dc_peer_t peer[DC_PEER_MAX];
    int       npeer;
    uint32_t  peer_ttl_ms;    // how long a peer report stays live (set by dc_init)
} dc_state_t;

void      dc_init(dc_state_t *s);
void      dc_ingest(dc_state_t *s, const dc_sighting_t *sg, uint32_t now_ms);
dc_dev_t *dc_find(dc_state_t *s, const uint8_t id[6]);
bool dc_due_scene(const dc_state_t *s, uint32_t now_ms);
void dc_scene_tick(dc_state_t *s, uint32_t now_ms);

void     dc_score(dc_state_t *s, uint32_t now_ms);
int      dc_threats(const dc_state_t *s, dc_threat_t *out, int max);
uint32_t dc_threat_count(const dc_state_t *s);
void     dc_allow(dc_state_t *s, const uint8_t id[6], bool on);
void dc_begin_safe(dc_state_t *s, uint32_t now_ms, uint32_t dur_ms);

// Currently-heard devices flagged THREAT or ALLOW (mutually exclusive), with
// their category. For the radar blips. Returns count (<= max).
int dc_radar(const dc_state_t *s, dc_radar_t *out, int max);

// The full allowlist MACs (0..nallow, capped at max), including devices not in
// the live store. For the trusted-device management list. Returns count.
int dc_allowlist(const dc_state_t *s, uint8_t out[][6], int max);

// Currently-flagged kind-level tracker alerts (count <= max). For the web UI
// summary ("Find My: 2 present, 1 expected").
int dc_kind_alerts(const dc_state_t *s, dc_kind_alert_t *out, int max);

// Ingest a threat reported by a swarm peer. Upserts into the peer table (keyed by
// id) and prunes expired entries. A local device matching a live peer report
// (same id, or same tracker_kind+fp) is confirmed a threat by dc_score.
void dc_ingest_peer(dc_state_t *s, const uint8_t id[6], uint8_t kind,
                    uint16_t fp, int8_t rssi, uint32_t now_ms);

#ifdef __cplusplus
}
#endif
