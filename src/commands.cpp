#include "commands.h"
#include <WiFi.h>
#include "beacon.h"
#include "config.h"
#include "deauther.h"
#include "log.h"
#include "portal.h"
#include "sniffer.h"
#include "storage.h"
#include "webui.h"
#include "wifi_utils.h"

static String g_line;

static void print_help() {
  Serial.println();
  Serial.println("wraith commands");
  Serial.println("  scan [channel|hop]         passive AP and client scan");
  Serial.println("  capture [channel|hop]      capture handshakes and PMKID to pcap");
  Serial.println("  deauth <bssid> [ch] [reason] [count]   count 0 = continuous");
  Serial.println("  beacon [count] [channel] [ssid]        count 0 = continuous");
  Serial.println("  portal <ssid>              start captive portal");
  Serial.println("  stop | halt                stop the active operation");
  Serial.println("  aps | clients | hs         list tables");
  Serial.println("  creds                      list captured portal credentials");
  Serial.println("  status                     subsystem state");
  Serial.println("  clear                      clear tables and log");
  Serial.println();
}

static void cmd_scan(bool capture) {
  sniffer_stop();
  if (capture) {
    sniffer_start_capture(1, true);
  } else {
    sniffer_start_scan(1, true);
  }
}

static void cmd_status() {
  const CaptureStats &cap = capture_stats();
  Serial.printf("mode=%s channel=%u heap=%u storage=%s\n", sniffer_active() ? "radio" : "idle",
                sniffer_channel(), ESP.getFreeHeap(), storage_kind());
  Serial.printf("aps=%u clients=%u handshakes=%u frames=%lu\n", ap_count(), client_count(),
                handshake_count(), static_cast<unsigned long>(sniffer_frame_total()));
  Serial.printf("capture active=%u eapol=%lu pmkid=%lu hs=%lu bytes=%lu\n", cap.active ? 1 : 0,
                static_cast<unsigned long>(cap.eapol), static_cast<unsigned long>(cap.pmkid),
                static_cast<unsigned long>(cap.handshakes), static_cast<unsigned long>(cap.bytes));
  Serial.printf("deauth active=%u sent=%lu beacon active=%u sent=%lu\n", deauth_active() ? 1 : 0,
                static_cast<unsigned long>(deauth_config().sent), beacon_active() ? 1 : 0,
                static_cast<unsigned long>(beacon_sent()));
  Serial.printf("portal active=%u ssid=%s creds=%u\n", portal_active() ? 1 : 0,
                portal_ssid().c_str(), portal_cred_count());
}

static void cmd_aps() {
  Serial.println("bssid              rssi ch enc      ssid");
  for (uint16_t i = 0; i < MAX_APS; i++) {
    ApRecord r;
    if (!ap_at(i, &r)) continue;
    Serial.printf("%s %4d %2u %-8s %s\n", wifi_mac_str(r.bssid).c_str(), r.rssi, r.channel,
                  wifi_enc_label(r.enc), r.ssid);
  }
}

static void cmd_clients() {
  Serial.println("mac                rssi ch bssid              frames");
  for (uint16_t i = 0; i < MAX_CLIENTS; i++) {
    ClientRecord r;
    if (!client_at(i, &r)) continue;
    String b = r.bound ? wifi_mac_str(r.bssid) : "-";
    Serial.printf("%s %4d %2u %s %u\n", wifi_mac_str(r.mac).c_str(), r.rssi, r.channel, b.c_str(),
                  r.frames);
  }
}

static void cmd_handshakes() {
  Serial.println("bssid              sta                ssid                  m1 m2 m3 m4 pmkid ok");
  for (uint16_t i = 0; i < MAX_HANDSHAKES; i++) {
    HandshakeRecord r;
    if (!handshake_at(i, &r)) continue;
    Serial.printf("%s %s %-20s %d  %d  %d  %d  %d     %d\n", wifi_mac_str(r.bssid).c_str(),
                  wifi_mac_str(r.sta).c_str(), r.ssid, r.m1 ? 1 : 0, r.m2 ? 1 : 0, r.m3 ? 1 : 0,
                  r.m4 ? 1 : 0, r.pmkid ? 1 : 0, r.complete ? 1 : 0);
  }
}

static void cmd_creds() {
  File f = storage_fs().open(CRED_FILE, FILE_READ);
  if (!f) {
    Serial.println("no credentials captured");
    return;
  }
  while (f.available()) Serial.write(f.read());
  f.close();
}

static void execute(char *line) {
  char *save = nullptr;
  char *cmd = strtok_r(line, " \t", &save);
  if (!cmd) return;

  if (!strcmp(cmd, "help") || !strcmp(cmd, "?")) {
    print_help();
  } else if (!strcmp(cmd, "scan")) {
    cmd_scan(false);
  } else if (!strcmp(cmd, "capture")) {
    cmd_scan(true);
  } else if (!strcmp(cmd, "status")) {
    cmd_status();
  } else if (!strcmp(cmd, "aps")) {
    cmd_aps();
  } else if (!strcmp(cmd, "clients")) {
    cmd_clients();
  } else if (!strcmp(cmd, "hs")) {
    cmd_handshakes();
  } else if (!strcmp(cmd, "creds")) {
    cmd_creds();
  } else if (!strcmp(cmd, "clear")) {
    sniffer_clear_tables();
    log_clear();
    Serial.println("cleared");
  } else if (!strcmp(cmd, "stop") || !strcmp(cmd, "halt")) {
    deauth_stop();
    beacon_stop();
    sniffer_stop();
    portal_stop();
    Serial.println("stopped");
  } else if (!strcmp(cmd, "deauth")) {
    char *bssid_text = strtok_r(nullptr, " \t", &save);
    uint8_t bssid[6];
    if (!bssid_text || !wifi_parse_mac(bssid_text, bssid)) {
      Serial.println("usage: deauth <bssid> [channel] [reason] [count]");
      return;
    }
    char *ch_text = strtok_r(nullptr, " \t", &save);
    char *reason_text = strtok_r(nullptr, " \t", &save);
    char *count_text = strtok_r(nullptr, " \t", &save);
    uint8_t channel = ch_text ? static_cast<uint8_t>(atoi(ch_text)) : 1;
    uint16_t reason = reason_text ? static_cast<uint16_t>(atoi(reason_text)) : 7;
    uint32_t count = count_text ? static_cast<uint32_t>(atol(count_text)) : 0;
    sniffer_stop();
    beacon_stop();
    portal_stop();
    deauth_start(bssid, nullptr, channel, reason, count == 0, count);
  } else if (!strcmp(cmd, "beacon")) {
    char *count_text = strtok_r(nullptr, " \t", &save);
    char *ch_text = strtok_r(nullptr, " \t", &save);
    char *ssid_text = save;
    while (ssid_text && (*ssid_text == ' ' || *ssid_text == '\t')) ssid_text++;
    uint32_t count = count_text ? static_cast<uint32_t>(atol(count_text)) : 0;
    uint8_t channel = ch_text ? static_cast<uint8_t>(atoi(ch_text)) : 1;
    String ssid = ssid_text ? String(ssid_text) : String();
    sniffer_stop();
    deauth_stop();
    portal_stop();
    beacon_start(count, ssid, channel);
  } else if (!strcmp(cmd, "portal")) {
    char *ssid_text = save;
    while (ssid_text && (*ssid_text == ' ' || *ssid_text == '\t')) ssid_text++;
    if (!ssid_text) {
      Serial.println("usage: portal <ssid>");
      return;
    }
    sniffer_stop();
    deauth_stop();
    beacon_stop();
    portal_start(String(ssid_text));
  } else {
    Serial.printf("unknown command: %s\n", cmd);
  }
}

void commands_begin() {
  g_line.reserve(96);
  Serial.println();
  Serial.println("type 'help' for commands, panel on http://192.168.4.1:8080");
  Serial.print("wraith> ");
}

void commands_tick() {
  while (Serial.available()) {
    char c = static_cast<char>(Serial.read());
    if (c == '\r') continue;
    if (c == '\n') {
      g_line.trim();
      if (g_line.length()) {
        char buf[96];
        strncpy(buf, g_line.c_str(), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        execute(buf);
      }
      g_line = "";
      Serial.print("wraith> ");
    } else if (g_line.length() < 90) {
      g_line += c;
    }
  }
}
