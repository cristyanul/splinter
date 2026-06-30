#pragma once
#include <stdint.h>
#include <stdbool.h>

#define SWARM_MSG_WIFI_PROBE 0x01
#define SWARM_MSG_THREAT     0x02

// Protocol magic ("SPL3"). Bump when the wire format changes; rejects stray /
// mismatched frames early.
#define SWARM_PROTO_MAGIC 0x53504C33u

// Fixed rendezvous channel for ESP-NOW persona exchange. The single radio can
// only be on one channel at a time, so swarm members periodically park here to
// broadcast / receive — otherwise frames almost never land, because both ends
// are busy hopping channels to flood probes.
#define SWARM_CHANNEL 6

typedef struct {
    uint32_t magic;       // SWARM_PROTO_MAGIC
    uint8_t  type;        // SWARM_MSG_*
    uint8_t  mac[6];      // fake device MAC to reproduce
    uint8_t  channel;     // channel the fake should appear on (1..13)
    uint8_t  ssid_len;    // 0 = wildcard (broadcast) probe
    char     ssid[32];    // directed-probe SSID (first ssid_len bytes)
    uint8_t  is_directed; // non-zero if ssid is meaningful
    uint8_t  profile;     // vendor fingerprint index (keeps fakes consistent)
    uint8_t  auth[8];     // truncated HMAC-SHA256 over the preceding fields
} __attribute__((packed)) swarm_persona_t;

// A follower confirmed by one node, shared so peers corroborate it across
// vantage points. Same authenticated-broadcast scheme as the persona: a
// truncated HMAC over the preceding fields gates out foreign/spoofed reports.
typedef struct {
    uint32_t magic;        // SWARM_PROTO_MAGIC
    uint8_t  type;         // SWARM_MSG_THREAT
    uint8_t  tracker_kind; // dc_tracker_t (0 = unknown)
    int8_t   rssi;         // last RSSI at the reporting node
    uint8_t  id[6];        // follower MAC
    uint16_t fp;           // fingerprint (for MAC-rotating trackers)
    uint8_t  auth[8];      // truncated HMAC-SHA256 over the preceding fields
} __attribute__((packed)) swarm_threat_t;

// Initialize the ESP-NOW transport once at boot (requires Wi-Fi started). Safe
// to call unconditionally; broadcast/receive no-op until swarm is enabled.
void swarm_init(void);

// Stamp magic + auth and broadcast a confirmed local threat. No-op unless swarm
// is enabled. The struct is mutated (magic/auth filled in).
void swarm_broadcast_threat(swarm_threat_t *threat);

// Pop one authenticated peer threat from the RX queue. Returns false if none.
bool swarm_receive_threat(swarm_threat_t *out_threat);

// Stamp magic + auth tag onto the persona, then broadcast it. No-op unless
// swarm is enabled. The persona is mutated (magic/auth filled in).
void swarm_broadcast_persona(swarm_persona_t *persona);

// Pop one authenticated persona from the RX queue. Returns false if none.
bool swarm_receive_persona(swarm_persona_t *out_persona);
