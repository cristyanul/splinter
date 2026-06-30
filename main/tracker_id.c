// BLE tracker classification — pure, host-testable. See tracker_id.h.

#include "tracker_id.h"

uint8_t tracker_classify(const uint8_t *data, uint8_t len)
{
    if (!data) return DC_TRK_NONE;

    // AD structures: [len][type][value(len-1)]...
    for (int i = 0; i + 1 < len; ) {
        uint8_t l = data[i];
        if (l == 0 || i + 1 + l > len) break;
        uint8_t t = data[i + 1];
        const uint8_t *v = &data[i + 2];
        int vl = l - 1;                       // bytes of value after the type

        if (t == 0xFF && vl >= 2) {           // Manufacturer Specific Data
            uint16_t company = (uint16_t)(v[0] | (v[1] << 8));
            // Apple Find My, separated / offline-finding advert: after the 0x004C
            // company id, payload type 0x12 with length 0x19 (25). This is the
            // unpaired-AirTag/Chipolo signal — NOT "nearby" (0x10) Apple chatter.
            if (company == 0x004C && vl >= 4 && v[2] == 0x12 && v[3] == 0x19)
                return DC_TRK_APPLE_FINDMY;
            // Note: a bare Samsung company id (0x0075) is deliberately NOT treated
            // as a tracker — it covers every Galaxy phone/earbud. SmartTags are
            // recognized by their service-data UUID below instead.
        }

        if (t == 0x16 && vl >= 2) {           // Service Data - 16-bit UUID
            uint16_t uuid = (uint16_t)(v[0] | (v[1] << 8));
            if (uuid == 0xFD5A) return DC_TRK_SAMSUNG;  // Samsung SmartTag (offline finding)
            if (uuid == 0xFEED) return DC_TRK_TILE;     // Tile
        }

        i += 1 + l;
    }
    return DC_TRK_NONE;
}
