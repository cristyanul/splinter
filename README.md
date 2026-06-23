# splinter
"Let me tell you why you're here. You're here because you know something. What you know you can't explain, but you feel it. You've felt it your entire life, that there's something wrong with the world. You don't know what it is, but it's there, like a splinter in your mind, driving you mad." — Morpheus

<img width="1625" height="1077" alt="image" src="https://github.com/user-attachments/assets/b2bd80d8-875c-45b5-8e96-a5309474d132" />

---

A multi-radio **privacy / anti-tracking decoy** for the ESP32-C6. It continuously
fabricates a churning crowd of plausible-but-fake wireless devices so that, in a space you
control, a tracking or scanning system sees lots of ordinary-looking traffic and your real
device(s) don't stand out.

It now uses **three radios at once**:

- **Bluetooth LE** — a flood of fake, non-connectable BLE devices (the original behaviour).
- **IEEE 802.15.4** — fake Zigbee-style PANs on the Thread/Zigbee radio (new in this fork).
- **Wi-Fi** — fake 802.11 Probe Requests from a pool of virtual devices, each with a stable
  rotating MAC, a per-vendor IE fingerprint (Apple / Samsung / Intel / generic), and realistic
  channel-weighted scan bursts — so it reads as a crowd of real phones, not one synthetic source.
- **Apple AWDL / AirDrop** — a *coherent* cast of fake Apple devices emitting AWDL Master
  Indication Frames that advertise the AirDrop service, so wardrivers (which over-index on Apple)
  log iPhones/MacBooks "doing AirDrop". Appearance for passive loggers, not protocol participation.
- **Thread / Matter** — 1–2 *stable* fake Thread "homes", each advertising a named network and
  generating encrypted-looking mesh chatter, so the space reads as a smart home full of Matter
  devices — alongside the existing Zigbee PAN churn on the same radio.
- **Dynamic Profiles** — optional "Breathing" mode that randomly scales decoy density over time to simulate organic crowd movement.
- **Swarm (ESP-NOW)** — optional coordination so multiple splinters share decoy personas over the air instead of overlapping.
- **Detection (passive)** — beyond emitting decoys, splinter watches BLE + Wi-Fi for a
  device that persists with you across time and location (an unknown AirTag/SmartTag/Tile,
  or a tailing phone) and warns you — LED alert + a live **Threat Radar** in the web UI
  that plots followers and trusted devices by signal strength (with MAC/RSSI and allowlist management).

Plus quality-of-life upgrades: **persistent configuration**, a **Wi-Fi maintenance mode**
with a web UI for **over-the-air (OTA) firmware updates** and live config, and an onboard
**RGB status LED**.

## BLE decoys

splinter continuously retires the current advertisement and mints a new decoy with:

- a fresh **random-static MAC** — exactly what modern phones, watches and earbuds already
  do for privacy, so the churn looks realistic;
- a random vendor drawn from `main/decoy_vendors.h`, surfaced via the **Company ID in
  manufacturer-specific data** (the spec-defined vendor signal a scanner actually reads);
- an optional short device name and a benign random payload.

On a BLE-5 chip like the C6 it runs **4 concurrent extended-advertising instances**, each
with its own MAC, rotated round-robin — so a scanner sampling over a few seconds logs
dozens of distinct, vendor-attributed devices appearing and disappearing.

## 802.15.4 fake Zigbee PANs (Thread/Zigbee radio)

Using the C6's IEEE 802.15.4 radio — the same radio Thread and Zigbee run on — splinter
broadcasts well-formed **802.15.4 beacon frames carrying a Zigbee beacon payload**, each
with a fresh random PAN id, source address and extended PAN id, hopping across channels
11–26. To a Zigbee/802.15.4 sniffer this looks like a churning crowd of nearby PANs — the
802.15.4 analog of the BLE flood.

It runs as its own lower-priority task and only raises its radio-coexistence priority for
the brief beacon burst, so **BLE performance is unaffected** while both radios run together.

> Scope note: this emits Zigbee-style beacon PANs; it does **not** impersonate a real,
> secured **Thread** network. Thread protects its MLE traffic with the network key, so a
> fake Thread network would just be ignored by real Thread devices.

## Apple AWDL / AirDrop spoofing (Wi-Fi radio)

On top of the Wi-Fi probe flood, splinter keeps a small **coherent cast** of fake Apple
devices (stable randomized MACs and hostnames, like a real AirDrop neighbourhood). Each one
periodically broadcasts an **AWDL Master Indication Frame** on the 2.4 GHz AWDL social channel
(6) — an Apple vendor-specific 802.11 action frame (OUI `00:17:f2`, type `0x08`) carrying the
synchronization / channel-sequence / version TLVs a sniffer reads, plus a **Service Response
TLV advertising `_airdrop._tcp.local`**. To a wardriver or Kismet this logs as iPhones and
MacBooks actively doing AirDrop — and because wardriving tools heavily prioritise Apple
devices, it's high-value pollution of their tracking data.

This is **appearance for passive loggers, not protocol participation**: the C6 is 2.4 GHz-only
(real AWDL also channel-hops into 5 GHz), and the frames are only ever broadcast among
splinter's own fake MACs. splinter **never** emits the directed unicast service-request that
would make a bystander's iPhone raise an AirDrop sheet — presence, not pop-ups (the same ethic
as the excluded BLE Continuity / Swift-Pair / Fast-Pair formats). Frame layout follows the
SEEMOO "Open Wireless Link" project and the Wireshark `awdl` dissector.

## Thread / Matter mesh simulation (Thread/Zigbee radio)

Beyond the random Zigbee PAN churn, splinter can maintain 1–2 **coherent, stable Thread
"homes"** on the 802.15.4 radio. Each home has a fixed channel, PAN id, extended PAN id, a
named network and a handful of member nodes, and emits two kinds of frame, interleaved with
the Zigbee beacons and transmitted **with CCA**:

- a periodic **Thread-format beacon** (Protocol ID `0x03`, network name, extended PAN id) — the
  recognisable "this is a Thread/Matter network" advertisement; and
- **Thread-parametrized secured data frames** (security level 5, key-id mode 1) carrying opaque
  ciphertext, with occasional broadcasts shaped like MLE advertisements — realistic encrypted
  mesh chatter among the home's nodes.

To an 802.15.4 / Thread sniffer the space reads as a smart home full of Matter devices that
persists and evolves slowly, rather than random churn.

> Scope note: same honesty as above — we hold no Thread **network key**, so the mesh payload is
> *encrypted-looking* (exactly how a real keyless capture appears), not decryptable MLE, and the
> advertised network has credentials nobody else holds, so a real joiner that tries to join
> simply fails. **No jamming, ever.**

## What it deliberately does NOT do (non-intrusive)

- BLE advertising is **non-connectable** and the payload is never shaped like
  Apple Continuity (`0x004C`), Microsoft Swift Pair (`0x0006`), or Google Fast Pair
  (`0xFE2C`). Those formats trigger pairing pop-ups on bystanders' phones/PCs — a decoy
  needs realistic *presence*, not pop-up spam, so those payloads are never emitted.
- 802.15.4 beacons transmit **with CCA** (clear channel assessment), so they back off
  instead of stomping on real traffic. **No jamming, ever.**

> Intended for privacy/anti-tracking use in a space you control. Don't point it at other
> people's devices.

## Status LED

The onboard WS2812 RGB LED (GPIO8 on the C6 SuperMini) shows state at a glance:

| Colour | Meaning |
|--------|---------|
| Breathing green | Normal — decoys running |
| Solid blue | Maintenance mode (SoftAP up) |
| Amber | OTA update in progress |
| Red | Error (init / OTA failure) |

## Hardware

- **ESP32-C6 SuperMini** (RISC-V, BLE 5 + Wi-Fi 6 + 802.15.4, 4 MB flash, native
  USB-Serial/JTAG). WS2812 RGB LED on GPIO8, BOOT button on GPIO9.
- A single USB-C cable handles flashing, logging and power.

(The classic ESP32 still builds — `idf.py set-target esp32` — but BLE-only; it has no
802.15.4 radio.)

## Build & flash

Requires ESP-IDF v5.4 (installed at `~/esp/esp-idf`). The C6 defaults
(`sdkconfig.defaults.esp32c6`) enable extended advertising, the native USB-Serial/JTAG
console, and a 4 MB OTA partition table.

```bash
. ~/esp/esp-idf/export.sh          # load the IDF environment into this shell
idf.py set-target esp32c6          # one-time; generates sdkconfig from the defaults
idf.py build
idf.py -p <PORT> flash monitor
```

`<PORT>` is the native USB port — `/dev/cu.usbmodem*` on macOS, `/dev/ttyACM0` on Linux.
After the first cable flash, you never need the cable again — use **maintenance mode** below
for over-the-air updates.

## Maintenance web UI (live config + OTA)

The decoys (BLE, 802.15.4 and Wi-Fi) run continuously. The maintenance web UI is a
SoftAP + HTTP server you can **toggle on and off live, without rebooting** — the decoys
keep running underneath it. With Wi-Fi up, all radios share the single RF front-end via
software coexistence; turning off the Wi-Fi decoys returns that airtime to BLE / 802.15.4.

**To toggle it:** tap the **BOOT** button while splinter is running. The first tap brings
the SoftAP + web UI up (LED turns **solid blue**); the next tap takes it back down (LED
returns to **breathing green**). No reboot, no one-shot flag — it is a plain live toggle.

**To use it:**

1. Join the Wi-Fi network **`Splinter-Setup`** (default password `splinter-setup`).
2. Open **`http://192.168.4.1/`** in a browser.
3. From the page you can:
   - **Edit configuration** — all settings below; saved to flash, so they persist across
     reboots and apply live.
   - **Update firmware (OTA)** — pick a `build/splinter.bin` and upload (with a live
     progress bar); the device validates the image header before committing, writes it
     to the spare app slot, and reboots into the new firmware. If the new image fails
     to boot cleanly, the bootloader **rolls back** to the previous one automatically.
   - **Reboot Device** — restart into decoy mode.

The page also shows **live health** — uptime, free heap, and the real per-radio on-air rates
(BLE refreshes/s, Zigbee PANs/s, Wi-Fi probes/s) so you can confirm each engine at a glance.

The SoftAP SSID/password are configurable on that page. For safety the current password is
**never sent back** to the browser (the field shows blank); leave it blank to keep the existing
key, or type a new one to change it. Pick a password ≥ 8 characters — shorter than that and the
AP falls back to **open** (unencrypted), which exposes config + OTA to anyone in range.

## Swarm mode (ESP-NOW)

Off by default. When two or more splinters are in radio range, **swarm mode** lets
them coordinate over **ESP-NOW** so the fake devices they emit look like one
coherent crowd seen from several vantage points, instead of each unit inventing
its own overlapping set.

How it works:

- **Rendezvous channel.** The single radio can only sit on one channel at a time,
  and the decoys spend their time hopping to flood probes — so left alone, ESP-NOW
  frames would almost never line up. Each unit therefore parks briefly on a fixed
  **rendezvous channel** (`SWARM_CHANNEL`, default 6) about once a second to
  broadcast one persona and listen for peers. Peers reproduce that persona
  (same MAC, vendor fingerprint, channel, SSID), so the same "device" appears
  from multiple units.
- **Authentication.** ESP-NOW broadcast frames can't be link-encrypted, so each
  persona carries a truncated **HMAC-SHA256** tag keyed by a shared fleet secret.
  Personas that fail the tag (or come from a different key) are dropped, so an
  outsider can't inject fake devices into your swarm.

> **Set your own key.** Before deploying more than one unit, change `SWARM_KEY`
> in `main/swarm.c` to a unique 16-byte value shared only by your fleet. Units
> with different keys simply ignore each other.

Enable it from the web UI (**ESP-NOW Swarm Mode** toggle). It applies live.

## Follower detection (passive)

On by default (`Detection` toggle). splinter passively listens — Wi-Fi via promiscuous
sniffing that rides the decoy channel hopping, BLE via a low-duty observer scan — and
scores nearby devices by **proximity** and **persistence across location changes**
(inferred from how much the surrounding device set churns, no GPS needed). A device that
stays close and survives several environment changes, or an unknown tracking tag that
lingers, raises an alert: the LED pulses red/purple and the **Threat Radar** plots it (red),
with your trusted devices in green. Tap a blip for its MAC/RSSI and to trust/untrust it; the
"Trusted devices" list manages your allowlist, including devices not currently in range.
The radar is honest about the hardware: distance = signal strength, direction is not measured.

Your own devices are auto-trusted during a ~3-minute learning window at boot — or press
**"I'm safe — learn surroundings"** any time to re-learn. You can also **Ignore** any
detection to allowlist it permanently (stored in NVS).

**Limits (be honest):** modern phones and AirTags rotate their MAC, so some followers are
tracked at the device-kind/fingerprint level rather than a pinned address. Detection rides
a single low-power 2.4 GHz radio shared with the decoys; it catches casual and
consumer-grade tracking, not a determined adversary using PHY-layer evasion.

## Configuration

Settings are stored in NVS (one key per field) and editable live from the web UI. Because
each field is stored separately, a **firmware upgrade keeps your settings** — a new build
that adds a field just uses that field's default while preserving everything else. Compile-time
**defaults** live in `main/config.c` (used the first time, before anything is saved):

| Setting | Default | Effect |
|---------|---------|--------|
| BLE enabled | on | Run the BLE decoy flood |
| BLE advertising interval | 100 ms | On-air advertising interval per decoy |
| BLE name probability | 60 % | Chance a decoy advertises a device name |
| BLE mfg-data probability | 85 % | Chance a decoy carries vendor manufacturer data |
| BLE refresh pacing | 20 ms | How fast identities churn (lower = denser crowd) |
| 802.15.4 enabled | on | Run the fake Zigbee PAN beacons |
| 802.15.4 beacon interval | 100 ms | Time between fake PAN beacons |
| 802.15.4 answer beacon requests | off | Reply to active scans (keeps RX on) |
| 802.15.4 channel mask | 11–26 | Channels the beacons hop across |
| Thread/Matter home | on | Emit a coherent fake Thread/Matter mesh on the 802.15.4 radio (needs 802.15.4 enabled) |
| Wi-Fi enabled | on | Run the Wi-Fi decoy flood (Probe Requests) |
| Wi-Fi probe interval | 200 ms | Time between fake Wi-Fi probe requests |
| Apple AWDL / AirDrop | on | Emit a coherent fake Apple AirDrop cast on the Wi-Fi radio (needs Wi-Fi enabled) |
| Dynamic Profiles | on | Enable "Breathing mode" to dynamically scale density |
| SoftAP SSID / password | `Splinter-Setup` / `splinter-setup` | Maintenance Wi-Fi |

The number of concurrent BLE advertising instances is a build-time setting
(`CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES`, default 4). Add more vendors/names to
`main/decoy_vendors.h` for a denser, more varied crowd (keep names ≤ 12 chars to stay
within the 31-byte advertising budget).

## Project layout

| File | Responsibility |
|------|----------------|
| `main/splinter_main.c` | Init, decoy wire-up, BOOT-button web-UI toggle |
| `main/config.{c,h}` | NVS-backed config + compile-time defaults |
| `main/decoys_ble.{c,h}` | BLE extended-advertising decoy engine |
| `main/decoys_154.{c,h}` | 802.15.4 fake Zigbee PAN engine (+ Thread home driver) |
| `main/decoys_wifi.{c,h}` | Wi-Fi 802.11 Probe Request spoofer engine (+ AWDL cast driver) |
| `main/decoys_awdl.{c,h}` | Apple AWDL/AirDrop frame builder + coherent cast (pure, host-tested) |
| `main/decoys_thread.{c,h}` | Thread/Matter frame builders + coherent home (pure, host-tested) |
| `main/profiles.{c,h}` | Dynamic "Breathing" mode density scalar |
| `main/swarm.{c,h}` | ESP-NOW swarm transport (shared decoy personas) |
| `main/maintenance.{c,h}` | Wi-Fi SoftAP + web UI (config + OTA) |
| `main/status_led.{c,h}` | WS2812 status LED |
| `partitions.csv` | 4 MB dual-slot OTA layout |

## Troubleshooting

- **No serial output after flashing the C6** — the console is on native USB-Serial/JTAG
  (set in `sdkconfig.defaults.esp32c6`); make sure you're connected to the C6's USB-C port
  and using its `/dev/cu.usbmodem*` / `/dev/ttyACM*` device.
- **Pressing BOOT does nothing** — press it *while running* (a quick tap). Holding BOOT
  during reset instead drops the chip into ROM download mode.
- **802.15.4 beacons report 0 on-air** — they need the coexistence TX priority raised (done
  in `decoys_154.c` via `esp_ieee802154_set_coex_config`); without it the BLE flood wins
  every arbitration.
- **`fatal error: nimble/nimble_port.h: No such file`** — `main/CMakeLists.txt` lists the
  required components (already set here).
