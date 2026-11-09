#pragma once
#include <Arduino.h>
#include "config.h"

enum OpMode : uint8_t {
  MODE_IDLE = 0,
  MODE_SCAN,
  MODE_DEAUTH,
  MODE_BEACON,
  MODE_SNIFF,
  MODE_CAPTURE,
  MODE_PORTAL
};

enum EncType : uint8_t {
  ENC_OPEN = 0,
  ENC_WEP,
  ENC_WPA,
  ENC_WPA2,
  ENC_WPA3,
  ENC_WPA2_ENT
};

struct ApRecord {
  uint8_t bssid[6];
  char ssid[33];
  int8_t rssi;
  uint8_t channel;
  uint8_t enc;
  uint16_t frames;
  uint32_t last_seen;
  bool used;
};

struct ClientRecord {
  uint8_t mac[6];
  uint8_t bssid[6];
  bool bound;          // true when the client was seen talking to a known BSSID
  int8_t rssi;
  uint8_t channel;
  uint16_t frames;
  uint32_t last_seen;
  bool used;
};

struct HandshakeRecord {
  uint8_t bssid[6];
  uint8_t sta[6];
  char ssid[33];
  bool m1;
  bool m2;
  bool m3;
  bool m4;
  bool pmkid;
  bool pmkid_saved;
  uint8_t pmkid_bytes[16];
  uint8_t channel;
  uint32_t first_seen;
  uint32_t last_seen;
  bool complete;
  bool used;
};

struct CaptureStats {
  bool active;
  uint32_t frames;
  uint32_t eapol;
  uint32_t pmkid;
  uint32_t handshakes;
  uint32_t bytes;
  uint32_t started_at;
};

struct AttackConfig {
  uint8_t bssid[6];
  uint8_t client[6];
  bool has_target;
  bool has_client;
  uint8_t channel;
  uint16_t reason;
  bool continuous;
  uint32_t max_frames;
  uint32_t started_at;
  uint32_t sent;
};

struct PendingFrame {
  uint16_t len;
  uint32_t sec;
  uint32_t usec;
  uint8_t data[MAX_FRAME_LEN];
};

struct LogRing {
  char lines[MAX_LOG_LINES][96];
  uint8_t head;
  uint8_t count;
};
