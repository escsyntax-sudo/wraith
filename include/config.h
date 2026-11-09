#pragma once
#include <Arduino.h>

// ---------------------------------------------------------------------------
// Build identity
// ---------------------------------------------------------------------------
#ifndef WRAITH_VERSION
#define WRAITH_VERSION "1.0.0"
#endif

// ---------------------------------------------------------------------------
// Control access point. The operator joins this and opens the panel.
// ---------------------------------------------------------------------------
#define CONTROL_AP_SSID "wraith"
#define CONTROL_AP_PASS "wraith1234"
#define CONTROL_HTTP_PORT 8080

// ---------------------------------------------------------------------------
// Captive portal listener. Served on the same AP, separate port.
// ---------------------------------------------------------------------------
#define PORTAL_HTTP_PORT 80

// ---------------------------------------------------------------------------
// microSD over VSPI. Set SD_ENABLED to 0 to run entirely on LittleFS.
// ---------------------------------------------------------------------------
#define SD_ENABLED 1
#define SD_CS_PIN 5
#define SD_SCK_PIN 18
#define SD_MISO_PIN 19
#define SD_MOSI_PIN 23

// Onboard status LED. Most WROOM devkits wire it to GPIO2.
#ifndef STATUS_LED_PIN
#define STATUS_LED_PIN 2
#endif

// ---------------------------------------------------------------------------
// Table and buffer limits. Sized for the 320 KB SRAM on the classic ESP32.
// ---------------------------------------------------------------------------
#define MAX_APS 64
#define MAX_CLIENTS 96
#define MAX_HANDSHAKES 16
#define MAX_CAPTURE_FRAMES 16
#define MAX_FRAME_LEN 384
#define MAX_LOG_LINES 64
#define CHANNEL_HOP_MS 350
#define MAX_RANDOM_SSIDS 64

// ---------------------------------------------------------------------------
// Storage paths
// ---------------------------------------------------------------------------
#define CAPTURE_DIR "/captures"
#define CRED_FILE "/creds.txt"
#define LOG_FILE "/wraith.log"

// ---------------------------------------------------------------------------
// Radio behaviour
// ---------------------------------------------------------------------------
#define DEAUTH_BURST_INTERVAL_MS 40
#define DEAUTH_FRAMES_PER_BURST 8
#define BEACON_BURST_INTERVAL_MS 35
#define BEACON_FRAMES_PER_BURST 6
