#include <Arduino.h>
#include <WiFi.h>
#include "beacon.h"
#include "commands.h"
#include "config.h"
#include "deauther.h"
#include "log.h"
#include "portal.h"
#include "sniffer.h"
#include "storage.h"
#include "webui.h"
#include "wifi_utils.h"

static uint32_t g_last_led = 0;
static bool g_led_on = false;

static void status_led_tick() {
  uint32_t now = millis();
  bool busy = sniffer_is_capturing() || deauth_active() || beacon_active() || portal_active();
  uint32_t interval = busy ? 120 : 900;
  if (now - g_last_led < interval) return;
  g_last_led = now;
  g_led_on = !g_led_on;
  digitalWrite(STATUS_LED_PIN, g_led_on ? HIGH : LOW);
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(50);
  delay(150);

  pinMode(STATUS_LED_PIN, OUTPUT);
  digitalWrite(STATUS_LED_PIN, LOW);

  log_init();

  Serial.println();
  Serial.println("  WRAITH " WRAITH_VERSION);
  Serial.println("  esp32 wireless assessment firmware");
  Serial.println();

  if (storage_begin()) {
    log_print("storage ready: %s", storage_kind());
  } else {
    log_print("storage unavailable: captures are memory only");
  }

  wifi_radio_init();
  log_print("control AP: %s at %s:%u", CONTROL_AP_SSID,
            WiFi.softAPIP().toString().c_str(), CONTROL_HTTP_PORT);

  sniffer_begin();
  deauth_begin();
  beacon_begin();
  portal_begin();
  webui_begin();
  commands_begin();
}

void loop() {
  commands_tick();
  sniffer_tick();
  deauth_tick();
  beacon_tick();
  portal_tick();
  webui_tick();
  status_led_tick();
  delay(1);
}
