# splinter
"Let me tell you why you're here. You're here because you know something. What you know you can't explain, but you feel it. You've felt it your entire life, that there's something wrong with the world. You don't know what it is, but it's there, like a splinter in your mind, driving you mad." — Morpheus

<img width="1625" height="1077" alt="image" src="https://github.com/user-attachments/assets/b2bd80d8-875c-45b5-8e96-a5309474d132" />

---

A multi-radio **privacy / anti-tracking decoy** for the ESP32-C6. It continuously
fabricates a churning crowd of plausible-but-fake wireless devices so that, in a space you
control, a tracking or scanning system sees lots of ordinary-looking traffic and your real
device(s) don't stand out.

It now uses **two radios at once**:

- **Bluetooth LE** — a flood of fake, non-connectable BLE devices (the original behaviour).
- **IEEE 802.15.4** — fake Zigbee-style PANs on the Thread/Zigbee radio (new in this fork).

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

## Maintenance mode (live config + OTA)

splinter has two modes. Normal mode runs the decoys with **no Wi-Fi** (the radio is theirs
alone). Maintenance mode pauses the decoys and brings up **Wi-Fi only**, so updating never
competes with or disturbs the decoy radios.

**To enter it:** press the **BOOT** button while splinter is running. It saves a one-shot
flag and reboots into maintenance (LED turns **solid blue**). A plain reset (RST), or the
web UI's *Reboot to normal* button, returns to decoy mode.

**To use it:**

1. Join the Wi-Fi network **`Splinter-Setup`** (default password `splinter-setup`).
2. Open **`http://192.168.4.1/`** in a browser.
3. From the page you can:
   - **Edit configuration** — all settings below; saved to flash, so they persist across
     reboots.
   - **Update firmware (OTA)** — pick a `build/splinter.bin` and upload; the device writes
     it to the spare app slot and reboots into the new firmware.
   - **Reboot to normal** — go back to decoying.

The SSID/password are themselves configurable on that page.

## Configuration

Settings are stored in NVS and editable live in maintenance mode. Compile-time **defaults**
live in `main/config.c` (used the first time, before anything is saved):

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
| SoftAP SSID / password | `Splinter-Setup` / `splinter-setup` | Maintenance Wi-Fi |

The number of concurrent BLE advertising instances is a build-time setting
(`CONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES`, default 4). Add more vendors/names to
`main/decoy_vendors.h` for a denser, more varied crowd (keep names ≤ 12 chars to stay
within the 31-byte advertising budget).

## Project layout

| File | Responsibility |
|------|----------------|
| `main/splinter_main.c` | Init, mode select (NVS boot flag + BOOT button), wire-up |
| `main/config.{c,h}` | NVS-backed config + compile-time defaults |
| `main/decoys_ble.{c,h}` | BLE extended-advertising decoy engine |
| `main/decoys_154.{c,h}` | 802.15.4 fake Zigbee PAN engine |
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
