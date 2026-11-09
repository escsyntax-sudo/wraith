#include "sniffer.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include "log.h"
#include "storage.h"
#include "wifi_utils.h"

// ---------------------------------------------------------------------------
// Shared tables. Written from the promiscuous callback, read from loop code.
// Every access goes through g_mux: the callback runs in the WiFi task, the
// readers run in loop().
// ---------------------------------------------------------------------------
static portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;

static ApRecord g_aps[MAX_APS];
static volatile uint16_t g_ap_count = 0;

static ClientRecord g_clients[MAX_CLIENTS];
static volatile uint16_t g_client_count = 0;

static HandshakeRecord g_handshakes[MAX_HANDSHAKES];
static volatile uint16_t g_handshake_count = 0;

static CaptureStats g_capture;
static volatile uint32_t g_frame_total = 0;

static PendingFrame g_pending[MAX_CAPTURE_FRAMES];
static volatile uint8_t g_head = 0;
static volatile uint8_t g_tail = 0;
static volatile uint32_t g_drops = 0;

static PcapWriter g_pcap;
static bool g_promisc = false;
static uint8_t g_channel = 1;
static bool g_hop = false;
static uint32_t g_last_hop = 0;
static OpMode g_mode = MODE_IDLE;

// ---------------------------------------------------------------------------
// Table helpers (callers hold g_mux)
// ---------------------------------------------------------------------------
static int ap_find_locked(const uint8_t *bssid) {
  for (uint16_t i = 0; i < g_ap_count; i++) {
    if (g_aps[i].used && wifi_mac_equal(g_aps[i].bssid, bssid)) return i;
  }
  return -1;
}

static int ap_slot_locked() {
  for (uint16_t i = 0; i < MAX_APS; i++) {
    if (!g_aps[i].used) return i;
  }
  int oldest = 0;
  uint32_t best = 0xFFFFFFFF;
  for (uint16_t i = 0; i < MAX_APS; i++) {
    if (g_aps[i].last_seen < best) {
      best = g_aps[i].last_seen;
      oldest = i;
    }
  }
  return oldest;
}

static int client_find_locked(const uint8_t *mac) {
  for (uint16_t i = 0; i < g_client_count; i++) {
    if (g_clients[i].used && wifi_mac_equal(g_clients[i].mac, mac)) return i;
  }
  return -1;
}

static int client_slot_locked() {
  for (uint16_t i = 0; i < MAX_CLIENTS; i++) {
    if (!g_clients[i].used) return i;
  }
  int oldest = 0;
  uint32_t best = 0xFFFFFFFF;
  for (uint16_t i = 0; i < MAX_CLIENTS; i++) {
    if (g_clients[i].last_seen < best) {
      best = g_clients[i].last_seen;
      oldest = i;
    }
  }
  return oldest;
}

static int hs_find_locked(const uint8_t *bssid, const uint8_t *sta) {
  for (uint16_t i = 0; i < g_handshake_count; i++) {
    if (g_handshakes[i].used && wifi_mac_equal(g_handshakes[i].bssid, bssid) &&
        wifi_mac_equal(g_handshakes[i].sta, sta)) {
      return i;
    }
  }
  return -1;
}

// ---------------------------------------------------------------------------
// 802.11 parsing
// ---------------------------------------------------------------------------
static uint8_t classify_encryption(const uint8_t *ies, uint16_t len, bool privacy) {
  bool rsn = false, wpa = false, sae = false;
  uint16_t i = 0;
  while (i + 2 <= len) {
    uint8_t id = ies[i];
    uint8_t ilen = ies[i + 1];
    if (i + 2 + ilen > len) break;
    const uint8_t *data = ies + i + 2;
    if (id == 48) {
      rsn = true;
      for (uint8_t j = 0; j + 3 < ilen; j++) {
        if (data[j] == 0x00 && data[j + 1] == 0x0F && data[j + 2] == 0xAC && data[j + 3] == 0x08) {
          sae = true;
        }
      }
    } else if (id == 221 && ilen >= 4) {
      if (data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 && data[3] == 0x01) wpa = true;
    }
    i = static_cast<uint16_t>(i + 2 + ilen);
  }
  if (rsn) return sae ? ENC_WPA3 : ENC_WPA2;
  if (wpa) return ENC_WPA;
  if (privacy) return ENC_WEP;
  return ENC_OPEN;
}

static void ap_upsert(const uint8_t *bssid, const char *ssid, int8_t rssi, uint8_t channel, uint8_t enc) {
  portENTER_CRITICAL(&g_mux);
  int idx = ap_find_locked(bssid);
  if (idx < 0) {
    idx = ap_slot_locked();
    if (idx >= 0) {
      ApRecord &r = g_aps[idx];
      memset(&r, 0, sizeof(r));
      memcpy(r.bssid, bssid, 6);
      r.used = true;
      if (idx >= g_ap_count) g_ap_count = static_cast<uint16_t>(idx + 1);
    }
  }
  if (idx >= 0) {
    ApRecord &r = g_aps[idx];
    if (ssid && ssid[0]) {
      strncpy(r.ssid, ssid, sizeof(r.ssid) - 1);
      r.ssid[sizeof(r.ssid) - 1] = '\0';
    }
    if (r.ssid[0] == '\0') strncpy(r.ssid, "<hidden>", sizeof(r.ssid) - 1);
    r.rssi = rssi;
    if (channel) r.channel = channel;
    r.enc = enc;
    r.last_seen = millis();
    r.frames++;
  }
  portEXIT_CRITICAL(&g_mux);
}

static void client_upsert(const uint8_t *mac, const uint8_t *bssid, int8_t rssi, uint8_t channel) {
  portENTER_CRITICAL(&g_mux);
  int idx = client_find_locked(mac);
  if (idx < 0) {
    idx = client_slot_locked();
    if (idx >= 0) {
      ClientRecord &c = g_clients[idx];
      memset(&c, 0, sizeof(c));
      memcpy(c.mac, mac, 6);
      c.used = true;
      if (idx >= g_client_count) g_client_count = static_cast<uint16_t>(idx + 1);
    }
  }
  if (idx >= 0) {
    ClientRecord &c = g_clients[idx];
    if (bssid) {
      memcpy(c.bssid, bssid, 6);
      c.bound = true;
    }
    c.rssi = rssi;
    if (channel) c.channel = channel;
    c.last_seen = millis();
    c.frames++;
  }
  portEXIT_CRITICAL(&g_mux);
}

static void handshake_update(const uint8_t *bssid, const uint8_t *sta, bool m1, bool m2, bool m3,
                             bool m4, const uint8_t *pmkid, int8_t rssi, uint8_t channel) {
  portENTER_CRITICAL(&g_mux);
  int idx = hs_find_locked(bssid, sta);
  if (idx < 0) {
    for (uint16_t i = 0; i < MAX_HANDSHAKES; i++) {
      if (!g_handshakes[i].used) {
        idx = i;
        break;
      }
    }
    if (idx >= 0) {
      HandshakeRecord &h = g_handshakes[idx];
      memset(&h, 0, sizeof(h));
      memcpy(h.bssid, bssid, 6);
      memcpy(h.sta, sta, 6);
      h.used = true;
      h.first_seen = millis();
      h.channel = channel;
      if (idx >= g_handshake_count) g_handshake_count = static_cast<uint16_t>(idx + 1);
    }
  }
  if (idx >= 0) {
    HandshakeRecord &h = g_handshakes[idx];
    int ap_idx = ap_find_locked(bssid);
    if (ap_idx >= 0) {
      strncpy(h.ssid, g_aps[ap_idx].ssid, sizeof(h.ssid) - 1);
      h.ssid[sizeof(h.ssid) - 1] = '\0';
      h.channel = g_aps[ap_idx].channel ? g_aps[ap_idx].channel : h.channel;
    }
    if (m1) h.m1 = true;
    if (m2) h.m2 = true;
    if (m3) h.m3 = true;
    if (m4) h.m4 = true;
    if (pmkid) {
      memcpy(h.pmkid_bytes, pmkid, 16);
      h.pmkid = true;
    }
    h.last_seen = millis();
    bool was_complete = h.complete;
    h.complete = (h.m1 && h.m2) || (h.m2 && h.m3);
    if (h.complete && !was_complete) g_capture.handshakes++;
  }
  portEXIT_CRITICAL(&g_mux);
}

// ---------------------------------------------------------------------------
// Capture ring. The callback is the only producer, loop() the only consumer.
// ---------------------------------------------------------------------------
static void queue_frame(const uint8_t *data, uint16_t len) {
  uint8_t next = static_cast<uint8_t>((g_head + 1) % MAX_CAPTURE_FRAMES);
  if (next == g_tail) {
    g_drops++;
    return;
  }
  PendingFrame &slot = g_pending[g_head];
  if (len > MAX_FRAME_LEN) len = MAX_FRAME_LEN;
  slot.len = len;
  uint32_t ms = millis();
  slot.sec = ms / 1000;
  slot.usec = (ms % 1000) * 1000;
  memcpy(slot.data, data, len);
  g_head = next;
}

static void process_eapol(const uint8_t *frame, uint16_t len, uint16_t off, const uint8_t *ap,
                          const uint8_t *sta, int8_t rssi, uint8_t channel) {
  if (off + 99 > len) return;
  if (frame[off + 1] != 3) return;  // EAPOL-Key
  uint16_t key_info = static_cast<uint16_t>((frame[off + 5] << 8) | frame[off + 6]);
  bool ack = key_info & 0x0080;
  bool mic = key_info & 0x0100;
  bool install = key_info & 0x0040;
  bool secure = key_info & 0x0200;

  bool m1 = ack && !mic;
  bool m2 = !ack && mic && !secure;
  bool m3 = ack && mic && install;
  bool m4 = mic && secure && !ack;
  if (!(m1 || m2 || m3 || m4)) return;

  const uint8_t *pmkid = nullptr;
  uint16_t kd_len = static_cast<uint16_t>((frame[off + 97] << 8) | frame[off + 98]);
  if (off + 99 + kd_len <= len) {
    const uint8_t *kd = frame + off + 99;
    for (uint16_t i = 0; i + 6 + 16 <= kd_len; i++) {
      if (kd[i] == 0xDD && kd[i + 2] == 0x00 && kd[i + 3] == 0x0F && kd[i + 4] == 0xAC &&
          kd[i + 5] == 0x04) {
        pmkid = kd + i + 6;
        break;
      }
    }
  }

  g_capture.eapol++;
  if (pmkid) g_capture.pmkid++;
  handshake_update(ap, sta, m1, m2, m3, m4, pmkid, rssi, channel);
}

static void handle_mgmt(const uint8_t *p, uint16_t len, int8_t rssi, uint8_t channel) {
  uint8_t subtype = (p[0] >> 4) & 0x0F;
  const uint8_t *bssid = p + 16;

  if (subtype == 8 || subtype == 5) {  // beacon, probe response
    if (len < 36) return;
    const uint8_t *ies = p + 36;
    uint16_t ielen = static_cast<uint16_t>(len - 36);
    char ssid[33] = {0};
    uint8_t ds = channel;
    uint16_t i = 0;
    while (i + 2 <= ielen) {
      uint8_t id = ies[i];
      uint8_t ilen = ies[i + 1];
      if (i + 2 + ilen > ielen) break;
      if (id == 0) {
        uint8_t n = ilen > 32 ? 32 : ilen;
        memcpy(ssid, ies + i + 2, n);
        ssid[n] = '\0';
      } else if (id == 3 && ilen >= 1) {
        ds = ies[i + 2];
      }
      i = static_cast<uint16_t>(i + 2 + ilen);
    }
    bool privacy = (p[34] & 0x10) != 0;
    uint8_t enc = classify_encryption(ies, ielen, privacy);
    if (!ds) ds = channel;
    ap_upsert(bssid, ssid, rssi, ds, enc);
    if (g_capture.active) queue_frame(p, len);
    return;
  }

  if (subtype == 4) {  // probe request
    const uint8_t *sa = p + 10;
    if (wifi_mac_multicast(sa)) return;
    client_upsert(sa, nullptr, rssi, channel);
    return;
  }

  if (subtype == 12 || subtype == 10 || subtype == 11) {  // deauth, disassoc, auth
    const uint8_t *sa = p + 10;
    const uint8_t *da = p + 4;
    if (!wifi_mac_multicast(sa) && !wifi_mac_equal(sa, bssid)) client_upsert(sa, bssid, rssi, channel);
    if (!wifi_mac_multicast(da) && !wifi_mac_equal(da, bssid)) client_upsert(da, bssid, rssi, channel);
    return;
  }
}

static void handle_data(const uint8_t *p, uint16_t len, int8_t rssi, uint8_t channel) {
  if (len < 24) return;
  uint8_t subtype = (p[0] >> 4) & 0x0F;
  uint16_t hdr = (subtype & 0x08) ? 26 : 24;
  if (len < hdr + 8) return;

  uint8_t tods = p[1] & 0x01;
  uint8_t fromds = p[1] & 0x02;
  const uint8_t *a1 = p + 4;
  const uint8_t *a2 = p + 10;
  const uint8_t *a3 = p + 16;
  const uint8_t *ap = nullptr;
  const uint8_t *sta = nullptr;
  if (fromds) {
    ap = a2;
    sta = a1;
  } else if (tods) {
    ap = a1;
    sta = a2;
  } else {
    ap = a3;
    sta = a2;
  }

  if (!wifi_mac_multicast(sta) && !wifi_mac_zero(sta) && !wifi_mac_equal(sta, ap)) {
    client_upsert(sta, ap, rssi, channel);
  }

  if (p[hdr] == 0xAA && p[hdr + 1] == 0xAA && p[hdr + 2] == 0x03 && p[hdr + 6] == 0x88 &&
      p[hdr + 7] == 0x8E) {
    process_eapol(p, len, static_cast<uint16_t>(hdr + 8), ap, sta, rssi, channel);
    if (g_capture.active) queue_frame(p, len);
  }
}

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = static_cast<wifi_promiscuous_pkt_t *>(buf);
  const uint8_t *p = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len > MAX_FRAME_LEN) len = MAX_FRAME_LEN;
  if (len < 24) return;

  g_frame_total++;
  g_capture.frames++;

  int8_t rssi = pkt->rx_ctrl.rssi;
  uint8_t channel = pkt->rx_ctrl.channel ? pkt->rx_ctrl.channel : g_channel;
  uint8_t fc0 = p[0];
  uint8_t vtype = (fc0 >> 2) & 0x03;

  if (vtype == 0) {
    handle_mgmt(p, len, rssi, channel);
  } else if (vtype == 2) {
    handle_data(p, len, rssi, channel);
  }
}

// ---------------------------------------------------------------------------
// PCAP and PMKID flush (loop context)
// ---------------------------------------------------------------------------
static void to_hex(const uint8_t *data, size_t len, char *out) {
  static const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = digits[data[i] >> 4];
    out[i * 2 + 1] = digits[data[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

static void flush_pmkid() {
  char ap_hex[13], sta_hex[13], pmk_hex[33], ssid_hex[65];
  for (uint16_t i = 0; i < MAX_HANDSHAKES; i++) {
    HandshakeRecord h;
    portENTER_CRITICAL(&g_mux);
    if (!g_handshakes[i].used) {
      portEXIT_CRITICAL(&g_mux);
      continue;
    }
    memcpy(&h, &g_handshakes[i], sizeof(h));
    portEXIT_CRITICAL(&g_mux);
    if (!h.pmkid || h.pmkid_saved) continue;
    to_hex(h.bssid, 6, ap_hex);
    to_hex(h.sta, 6, sta_hex);
    to_hex(h.pmkid_bytes, 16, pmk_hex);
    size_t slen = strlen(h.ssid);
    to_hex(reinterpret_cast<const uint8_t *>(h.ssid), slen, ssid_hex);

    String path = String(CAPTURE_DIR) + "/pmkid.22000";
    File f = storage_fs().open(path, FILE_APPEND);
    if (f) {
      char line[200];
      snprintf(line, sizeof(line), "WPA*01*%s*%s*%s*%s***\n", pmk_hex, ap_hex, sta_hex, ssid_hex);
      f.print(line);
      f.close();
      portENTER_CRITICAL(&g_mux);
      g_handshakes[i].pmkid_saved = true;
      portEXIT_CRITICAL(&g_mux);
      log_print("pmkid captured bssid=%s sta=%s", wifi_mac_str(h.bssid).c_str(),
                wifi_mac_str(h.sta).c_str());
    }
  }
}

static void drain_capture() {
  while (g_tail != g_head) {
    PendingFrame &slot = g_pending[g_tail];
    if (g_pcap.is_open()) {
      g_pcap.write(slot.data, slot.len, slot.sec, slot.usec);
      g_capture.bytes = g_pcap.bytes();
    }
    g_tail = static_cast<uint8_t>((g_tail + 1) % MAX_CAPTURE_FRAMES);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void sniffer_begin() {
  memset(g_aps, 0, sizeof(g_aps));
  memset(g_clients, 0, sizeof(g_clients));
  memset(g_handshakes, 0, sizeof(g_handshakes));
  memset(&g_capture, 0, sizeof(g_capture));
  sniffer_clear_tables();
}

static void radio_sniff_on() {
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_promiscuous(true);
  g_promisc = true;
}

void sniffer_start_scan(uint8_t channel, bool hop) {
  if (g_capture.active) return;
  sniffer_stop();
  g_mode = MODE_SCAN;
  g_hop = hop || channel == 0;
  g_channel = channel ? channel : 1;
  wifi_set_channel(g_channel);
  radio_sniff_on();
  log_print("scan started channel=%u hop=%u", g_channel, g_hop ? 1 : 0);
}

void sniffer_start_capture(uint8_t channel, bool hop) {
  sniffer_stop();
  g_mode = MODE_CAPTURE;
  g_hop = hop || channel == 0;
  g_channel = channel ? channel : 1;
  wifi_set_channel(g_channel);
  g_capture.active = true;
  g_capture.started_at = millis();
  String path = capture_path("hs");
  if (g_pcap.open(path)) {
    log_print("capture open %s", path.c_str());
  } else {
    log_print("capture open failed, frames counted only");
  }
  radio_sniff_on();
}

void sniffer_stop() {
  if (g_promisc) {
    esp_wifi_set_promiscuous(false);
    g_promisc = false;
  }
  if (g_pcap.is_open()) {
    g_pcap.close();
    log_print("capture closed bytes=%lu", static_cast<unsigned long>(g_capture.bytes));
  }
  g_capture.active = false;
  g_hop = false;
  g_mode = MODE_IDLE;
}

void sniffer_tick() {
  drain_capture();
  flush_pmkid();

  if (g_hop && (g_mode == MODE_SCAN || g_mode == MODE_CAPTURE || g_mode == MODE_SNIFF)) {
    uint32_t now = millis();
    if (now - g_last_hop >= CHANNEL_HOP_MS) {
      g_last_hop = now;
      uint8_t next = g_channel + 1;
      if (next > 13) next = 1;
      g_channel = next;
      wifi_set_channel(g_channel);
    }
  }
}

bool sniffer_active() { return g_mode == MODE_SCAN || g_mode == MODE_CAPTURE || g_mode == MODE_SNIFF; }
bool sniffer_is_capturing() { return g_capture.active; }
uint8_t sniffer_channel() { return g_channel; }
uint32_t sniffer_frame_total() { return g_frame_total; }
uint16_t sniffer_pending_drops() { return static_cast<uint16_t>(g_drops & 0xFFFF); }
const CaptureStats &capture_stats() { return g_capture; }

uint16_t ap_count() { return g_ap_count; }

bool ap_at(uint16_t index, ApRecord *out) {
  bool ok = false;
  portENTER_CRITICAL(&g_mux);
  if (index < MAX_APS && g_aps[index].used) {
    memcpy(out, &g_aps[index], sizeof(ApRecord));
    ok = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return ok;
}

int ap_index_of(const uint8_t *bssid) {
  int idx = -1;
  portENTER_CRITICAL(&g_mux);
  idx = ap_find_locked(bssid);
  portEXIT_CRITICAL(&g_mux);
  return idx;
}

uint16_t client_count() { return g_client_count; }

bool client_at(uint16_t index, ClientRecord *out) {
  bool ok = false;
  portENTER_CRITICAL(&g_mux);
  if (index < MAX_CLIENTS && g_clients[index].used) {
    memcpy(out, &g_clients[index], sizeof(ClientRecord));
    ok = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return ok;
}

uint16_t handshake_count() { return g_handshake_count; }

bool handshake_at(uint16_t index, HandshakeRecord *out) {
  bool ok = false;
  portENTER_CRITICAL(&g_mux);
  if (index < MAX_HANDSHAKES && g_handshakes[index].used) {
    memcpy(out, &g_handshakes[index], sizeof(HandshakeRecord));
    ok = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return ok;
}

void sniffer_clear_tables() {
  portENTER_CRITICAL(&g_mux);
  memset(g_aps, 0, sizeof(g_aps));
  memset(g_clients, 0, sizeof(g_clients));
  memset(g_handshakes, 0, sizeof(g_handshakes));
  g_ap_count = 0;
  g_client_count = 0;
  g_handshake_count = 0;
  portEXIT_CRITICAL(&g_mux);
  g_frame_total = 0;
}
