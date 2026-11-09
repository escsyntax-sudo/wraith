# WRAITH

Wireless assessment firmware for the ESP32. Passive scan, deauthentication, beacon flood, WPA handshake and PMKID capture, and a captive portal. Controlled from a serial console or a browser panel served by the device itself.

```
  WRAITH
  esp32 wireless assessment firmware
```

## Capabilities

| Area | What it does |
|---|---|
| Scan | Passive promiscuous scan over channels 1 to 13. Builds an access point table with SSID, BSSID, RSSI, channel, and security type. Learns clients from probe requests, data frames, and management traffic. |
| Deauth | Targeted 802.11 deauthentication and disassociation injection. Broadcast or single client. Continuous or a fixed frame count. Selectable reason code. |
| Beacon flood | Injects beacon frames with generated or fixed SSIDs on a locally administered MAC per frame. Open and WPA2 capability sets alternate. |
| Capture | Sniffs EAPOL traffic, tracks M1 to M4 per station pair, extracts PMKID from message 1, and writes a libpcap file plus hashcat 22000 lines. |
| Portal | SoftAP captive portal. DNS wildcard redirect, configurable SSID, credential capture to flash or SD. |
| Control | Browser panel on port 8080, serial CLI on USB. |

## Hardware

- ESP32-WROOM-32 devkit (classic ESP32). 4 MB flash minimum.
- Optional microSD card on VSPI. Without it, captures and credentials go to LittleFS.
- Optional: a second ESP32 for a dedicated monitor. One radio cannot sniff and transmit on different channels at the same time.

Default SD wiring (change in `include/config.h`):

| Signal | GPIO |
|---|---|
| CS | 5 |
| SCK | 18 |
| MISO | 19 |
| MOSI | 23 |

The status LED is GPIO2.

`default.csv` is the partition table: 1.3 MB application plus 1.4 MB LittleFS. The panel assets always live in LittleFS, even when an SD card takes over captures and credentials.

ESP32-S3 also builds with the `esp32s3` environment. Adjust the SD and LED pins for your board.

## Build

Install PlatformIO Core, then:

```bash
git clone https://github.com/escsyntax-sudo/wraith.git
cd wraith
pio run
pio run -e esp32s3          # optional: ESP32-S3 board
pio run --target upload
pio run --target uploadfs
```

`uploadfs` writes the panel assets from `data/` to LittleFS. The firmware runs without it, but the browser panel returns 404 until the filesystem is flashed once.

For a board without SD, set `SD_ENABLED 0` in `include/config.h` and rebuild.

## First boot

1. Flash firmware and filesystem.
2. Join the access point `wraith`, password `wraith1234`.
3. Open `http://192.168.4.1:8080`.
4. The serial console runs at 115200 baud.

The panel has five sections:

- **Scan**: channel selection, channel hopping, live AP and client tables. The `Target` button on an AP row locks it for Strike.
- **Strike**: deauthentication and beacon flood against the locked target.
- **Capture**: EAPOL and PMKID capture with live counters, handshake table, and file downloads.
- **Portal**: captive portal control and captured credential list.
- **Console**: device event log.

## Serial CLI

```
help
scan [channel|hop]
capture [channel|hop]
deauth <bssid> [ch] [reason] [count]
beacon [count] [channel] [ssid]
portal <ssid>
stop | halt
aps | clients | hs
creds
status
clear
```

`count 0` means continuous.

## Capture workflow

Capture writes `hs_<millis>.pcap` in `CAPTURE_DIR` on SD or LittleFS. It holds beacon frames and EAPOL frames, which is what `hcxtools` and Wireshark need to reconstruct a handshake.

PMKID lines are appended to `captures/pmkid.22000` in hashcat 22000 format:

```
WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<ssid_hex>***
```

Crack with:

```bash
hashcat -m 22000 captures/pmkid.22000 wordlist.txt
```

Handshake pcaps convert to 22000 with:

```bash
hcxpcapngtool -o handshake.22000 hs_12345.pcap
```

Download files from the Capture section of the panel, or pull them off the SD card.

## Radio notes

- The ESP32 has one 2.4 GHz radio. The control AP, the sniffer, and the injector share it.
- With channel hopping on, the control AP follows the radio. The panel connection can drop while it moves. Set a fixed channel when you need a stable panel.
- The AP starts on channel 1. A target on channel 6 or 11 requires selecting that channel or hopping.
- Captures are limited by free heap and the capture ring. The ring drops frames under sustained high traffic; the drop counter is in `/api/status`.
- Only 2.4 GHz. No 5 GHz.
- Starting the portal rebroadcasts the control AP under the portal SSID as an open network, which disconnects the panel. The control server keeps running on port 8080: reconnect to the portal SSID, reopen the panel, then hit Stop to restore the `wraith` AP.

## Source map

```
include/          headers and build configuration
src/main.cpp      boot, loop, status LED
src/wifi_utils    radio init, channel control, MAC helpers
src/sniffer       promiscuous callback, 802.11 parsing, EAPOL and PMKID, pcap queue
src/deauther      deauth and disassoc frame injection
src/beacon        beacon frame construction and flood
src/portal        captive portal, DNS wildcard, credential store
src/webui         control panel HTTP server and JSON API
src/commands      serial CLI
src/storage       SD and LittleFS mount, pcap writer
src/log           ring buffer log
data/             panel assets served from LittleFS
```

## HTTP API

Read endpoints:

```
GET  /api/status
GET  /api/aps
GET  /api/clients
GET  /api/handshakes
GET  /api/creds
GET  /api/captures
GET  /api/download?file=/captures/<name>
```

Action endpoints (POST, query parameters):

```
/api/scan?channel=1&hop=0
/api/capture?channel=1&hop=0
/api/deauth?bssid=aa:bb:cc:dd:ee:ff&channel=6&reason=7&continuous=1&count=0
/api/beacon?ssid=test&count=0&channel=1
/api/portal?ssid=Free%20WiFi
/api/sniff/stop
/api/deauth/stop
/api/beacon/stop
/api/portal/stop
/api/halt
/api/clear
```

## Panel design notes

Reading this as: embedded field-instrument control panel for a security operator, in a graphite-and-amber instrumentation language, dial ENERGY 2 / RHYTHM 2 / MOTION 1.

The panel is built for one job: reading state and issuing a short command under time pressure. The decisions follow from that.

- **Palette**: graphite surfaces with a single amber signal color. Amber is the active-transmit color in field equipment and reads as a warning without a full alarm palette. Semantic green and red appear only on state, never as decoration.
- **Type**: the operating system UI face for reading, a monospace face for MAC addresses, channels, counters, and frame numbers. Tabular figures keep columns aligned. No webfont is loaded because the device is an offline access point.
- **Layout**: an instrument panel, not a landing page. A fixed rail for sections, a status strip for radio state, and one data surface per view. The primary action in each view is the only amber button.
- **Motion**: hover and focus transitions only. Nothing else moves. `prefers-reduced-motion` disables those too.
- **Theme**: fixed dark. The panel is used in the field, often at night, and a second theme would double the CSS and flash cost for no operational gain.
- **Signature**: the numbered section markers and the tick strip under the wordmark echo a signal trace. Both are repeated across the panel and nowhere else.
- **Icons and tags**: there is no icon set. Numbered markers carry section identity, and tags or chips only ever display real device state, never a label for decoration.
- **Access**: visible focus rings, 44 px class tap targets on mobile, labels on every field, keyboard reachable controls, and table scroll confined to its own container.

## Panel development

The panel is plain HTML, CSS, and JavaScript. To work on it without hardware, serve it with the mock API:

```bash
python tools/mock_panel.py
```

Open `http://127.0.0.1:8099`. The mock answers every panel endpoint with sample state and never touches a radio.

## Limitations

- 802.11 injection depends on the ESP32 WiFi driver and is not guaranteed against every AP or client chipset.
- PMKID capture requires a client that sends RSN PMKID in message 1. Many clients do not.
- WPA3 SAE handshakes are not crackable from this capture path.
- The portal is a credential capture page for authorized assessments. It does not proxy traffic.
- LittleFS is small. Long captures should use SD.

## License

MIT. See `LICENSE`.
