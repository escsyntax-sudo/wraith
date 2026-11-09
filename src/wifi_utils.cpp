#include "wifi_utils.h"
#include <WiFi.h>
#include <esp_random.h>

void wifi_radio_init() {
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.setSleep(false);
  WiFi.softAP(CONTROL_AP_SSID, CONTROL_AP_PASS, 1, 0, 4);
  WiFi.disconnect();
}

void wifi_set_channel(uint8_t channel) {
  if (channel < 1 || channel > 14) return;
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

uint8_t wifi_freq_to_channel(uint16_t freq) {
  if (freq == 2484) return 14;
  if (freq < 2412 || freq > 2484) return 0;
  return static_cast<uint8_t>((freq - 2407) / 5);
}

uint16_t wifi_channel_to_freq(uint8_t channel) {
  if (channel == 14) return 2484;
  if (channel < 1 || channel > 13) return 2412;
  return static_cast<uint16_t>(2407 + channel * 5);
}

String wifi_mac_str(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

static uint8_t hex_nibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
  return 0xFF;
}

bool wifi_parse_mac(const String &text, uint8_t out[6]) {
  char clean[13];
  uint8_t n = 0;
  for (size_t i = 0; i < text.length() && n < 12; i++) {
    char c = text[i];
    if (c == ':' || c == '-' || c == '.') continue;
    if (hex_nibble(c) == 0xFF) return false;
    clean[n++] = c;
  }
  if (n != 12) return false;
  for (uint8_t i = 0; i < 6; i++) {
    out[i] = static_cast<uint8_t>((hex_nibble(clean[i * 2]) << 4) | hex_nibble(clean[i * 2 + 1]));
  }
  return true;
}

bool wifi_mac_multicast(const uint8_t *mac) {
  return (mac[0] & 0x01) != 0;
}

bool wifi_mac_zero(const uint8_t *mac) {
  for (int i = 0; i < 6; i++) {
    if (mac[i]) return false;
  }
  return true;
}

bool wifi_mac_equal(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

const char *wifi_enc_label(uint8_t enc) {
  switch (enc) {
    case ENC_OPEN: return "OPEN";
    case ENC_WEP: return "WEP";
    case ENC_WPA: return "WPA";
    case ENC_WPA2: return "WPA2";
    case ENC_WPA3: return "WPA3";
    case ENC_WPA2_ENT: return "WPA2-ENT";
    default: return "?";
  }
}

const char *wifi_mode_label(OpMode mode) {
  switch (mode) {
    case MODE_IDLE: return "idle";
    case MODE_SCAN: return "scan";
    case MODE_DEAUTH: return "deauth";
    case MODE_BEACON: return "beacon";
    case MODE_SNIFF: return "sniff";
    case MODE_CAPTURE: return "capture";
    case MODE_PORTAL: return "portal";
    default: return "?";
  }
}

void wifi_random_mac(uint8_t *mac) {
  for (int i = 0; i < 6; i++) mac[i] = static_cast<uint8_t>(esp_random() & 0xFF);
  mac[0] &= 0xFC;  // clear multicast and locally-administered bits
  mac[0] |= 0x02;  // set locally-administered: plausible virtual AP
}
