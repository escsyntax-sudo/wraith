#include "beacon.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_random.h>
#include "config.h"
#include "log.h"
#include "wifi_utils.h"

static bool g_active = false;
static uint32_t g_sent = 0;
static uint32_t g_max = 0;
static uint32_t g_last = 0;
static uint8_t g_channel = 1;
static String g_custom;
static uint8_t g_seq = 0;

static const char *SEEDS[] = {
    "Free WiFi",       "Guest Network",   "Airport_Free_WiFi", "eduroam",
    "Hotel_Guest",     "Cafe_WiFi",       "Public Hotspot",    "Library_Guest",
    "Terminal_Free",   "Conference_WiFi", "City_Free_WiFi",    "Transit_Guest",
};
static const uint8_t SEED_COUNT = sizeof(SEEDS) / sizeof(SEEDS[0]);

static uint16_t build_beacon(uint8_t *buf, const uint8_t *mac, const char *ssid, bool wpa) {
  uint16_t i = 0;
  buf[i++] = 0x80;  // beacon
  buf[i++] = 0x00;
  buf[i++] = 0x00;
  buf[i++] = 0x00;
  memset(buf + i, 0xFF, 6);
  i += 6;
  memcpy(buf + i, mac, 6);
  i += 6;
  memcpy(buf + i, mac, 6);
  i += 6;
  buf[i++] = static_cast<uint8_t>(g_seq & 0x0F);
  buf[i++] = static_cast<uint8_t>((g_seq >> 4) & 0xFF);
  g_seq++;
  memset(buf + i, 0x00, 8);  // timestamp
  i += 8;
  buf[i++] = 0x64;  // beacon interval 100 TU
  buf[i++] = 0x00;
  buf[i++] = wpa ? 0x11 : 0x01;  // capability: ESS, optional privacy
  buf[i++] = 0x00;

  uint8_t slen = static_cast<uint8_t>(strlen(ssid));
  if (slen > 32) slen = 32;
  buf[i++] = 0x00;  // SSID
  buf[i++] = slen;
  memcpy(buf + i, ssid, slen);
  i += slen;

  const uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
  memcpy(buf + i, rates, sizeof(rates));
  i += sizeof(rates);

  buf[i++] = 0x03;  // DS parameter
  buf[i++] = 0x01;
  buf[i++] = g_channel;

  if (wpa) {
    const uint8_t rsn[] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00,
                           0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x0C, 0x00};
    memcpy(buf + i, rsn, sizeof(rsn));
    i += sizeof(rsn);
  }
  return i;
}

void beacon_begin() {
  g_active = false;
  g_sent = 0;
}

bool beacon_start(uint32_t max_frames, const String &ssid, uint8_t channel) {
  if (channel < 1 || channel > 14) return false;
  g_custom = ssid;
  g_custom.trim();
  if (g_custom.length() > 32) g_custom = g_custom.substring(0, 32);
  g_channel = channel;
  g_max = max_frames;
  g_sent = 0;
  g_last = 0;
  g_active = true;
  wifi_set_channel(channel);
  log_print("beacon start channel=%u max=%lu custom=%s", channel,
            static_cast<unsigned long>(max_frames), g_custom.length() ? g_custom.c_str() : "-");
  return true;
}

void beacon_stop() {
  if (g_active) log_print("beacon stop sent=%lu", static_cast<unsigned long>(g_sent));
  g_active = false;
}

void beacon_tick() {
  if (!g_active) return;
  uint32_t now = millis();
  if (now - g_last < BEACON_BURST_INTERVAL_MS) return;
  g_last = now;

  uint8_t frame[320];
  for (int i = 0; i < BEACON_FRAMES_PER_BURST; i++) {
    uint8_t mac[6];
    wifi_random_mac(mac);
    char ssid[40];
    if (g_custom.length()) {
      strncpy(ssid, g_custom.c_str(), sizeof(ssid) - 1);
      ssid[sizeof(ssid) - 1] = '\0';
    } else {
      const char *seed = SEEDS[esp_random() % SEED_COUNT];
      snprintf(ssid, sizeof(ssid), "%s_%04X", seed, static_cast<unsigned>(esp_random() & 0xFFFF));
    }
    bool wpa = (esp_random() & 1) != 0;
    uint16_t len = build_beacon(frame, mac, ssid, wpa);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
    g_sent++;
    if (g_max && g_sent >= g_max) {
      beacon_stop();
      return;
    }
  }
}

bool beacon_active() { return g_active; }
uint32_t beacon_sent() { return g_sent; }
