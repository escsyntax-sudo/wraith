#include "webui.h"
#include <ArduinoJson.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>
#include <WiFi.h>
#include "beacon.h"
#include "config.h"
#include "deauther.h"
#include "log.h"
#include "portal.h"
#include "sniffer.h"
#include "storage.h"
#include "wifi_utils.h"

static AsyncWebServer g_server(CONTROL_HTTP_PORT);

static String qparam(AsyncWebServerRequest *request, const char *key, const char *fallback = "") {
  if (request->hasParam(key)) return request->getParam(key)->value();
  return String(fallback);
}

static uint32_t qnum(AsyncWebServerRequest *request, const char *key, uint32_t fallback) {
  if (!request->hasParam(key)) return fallback;
  String v = request->getParam(key)->value();
  return static_cast<uint32_t>(v.toInt());
}

static bool truthy(const String &v) {
  return v == "1" || v == "true" || v == "on" || v == "yes";
}

static const char *current_mode() {
  if (portal_active()) return "portal";
  if (deauth_active()) return "deauth";
  if (beacon_active()) return "beacon";
  if (sniffer_is_capturing()) return "capture";
  if (sniffer_active()) return "scan";
  return "idle";
}

void webui_halt_all() {
  deauth_stop();
  beacon_stop();
  sniffer_stop();
  portal_stop();
}

static void send_json(AsyncWebServerRequest *request, JsonDocument &doc) {
  String out;
  serializeJson(doc, out);
  request->send(200, "application/json", out);
}

// ---------------------------------------------------------------------------
// Read endpoints
// ---------------------------------------------------------------------------
static void handle_status(AsyncWebServerRequest *request) {
  JsonDocument doc;
  doc["version"] = WRAITH_VERSION;
  doc["mode"] = current_mode();
  doc["channel"] = sniffer_channel();
  doc["uptime"] = millis() / 1000;
  doc["heap"] = ESP.getFreeHeap();
  doc["storage"] = storage_kind();
  doc["ip"] = WiFi.softAPIP().toString();
  doc["aps"] = ap_count();
  doc["clients"] = client_count();
  doc["handshakes"] = handshake_count();
  doc["frames"] = sniffer_frame_total();
  doc["drops"] = sniffer_pending_drops();

  const CaptureStats &cap = capture_stats();
  JsonObject capture = doc["capture"].to<JsonObject>();
  capture["active"] = cap.active;
  capture["frames"] = cap.frames;
  capture["eapol"] = cap.eapol;
  capture["pmkid"] = cap.pmkid;
  capture["handshakes"] = cap.handshakes;
  capture["bytes"] = cap.bytes;

  const AttackConfig &atk = deauth_config();
  JsonObject deauth = doc["deauth"].to<JsonObject>();
  deauth["active"] = deauth_active();
  deauth["bssid"] = atk.has_target ? wifi_mac_str(atk.bssid) : "";
  deauth["sent"] = atk.sent;

  JsonObject beacon = doc["beacon"].to<JsonObject>();
  beacon["active"] = beacon_active();
  beacon["sent"] = beacon_sent();

  JsonObject portal = doc["portal"].to<JsonObject>();
  portal["active"] = portal_active();
  portal["ssid"] = portal_ssid();
  portal["creds"] = portal_cred_count();

  JsonArray log = doc["log"].to<JsonArray>();
  JsonDocument logDoc;
  if (deserializeJson(logDoc, log_json()) == DeserializationError::Ok) {
    for (JsonVariant line : logDoc.as<JsonArray>()) log.add(line.as<String>());
  }
  send_json(request, doc);
}

static void handle_aps(AsyncWebServerRequest *request) {
  JsonDocument doc;
  JsonArray arr = doc["aps"].to<JsonArray>();
  for (uint16_t i = 0; i < MAX_APS; i++) {
    ApRecord r;
    if (!ap_at(i, &r)) continue;
    JsonObject o = arr.add<JsonObject>();
    o["bssid"] = wifi_mac_str(r.bssid);
    o["ssid"] = r.ssid;
    o["rssi"] = r.rssi;
    o["ch"] = r.channel;
    o["enc"] = wifi_enc_label(r.enc);
    o["frames"] = r.frames;
    o["age"] = (millis() - r.last_seen) / 1000;
  }
  send_json(request, doc);
}

static void handle_clients(AsyncWebServerRequest *request) {
  JsonDocument doc;
  JsonArray arr = doc["clients"].to<JsonArray>();
  for (uint16_t i = 0; i < MAX_CLIENTS; i++) {
    ClientRecord r;
    if (!client_at(i, &r)) continue;
    JsonObject o = arr.add<JsonObject>();
    o["mac"] = wifi_mac_str(r.mac);
    o["bssid"] = r.bound ? wifi_mac_str(r.bssid) : "";
    o["rssi"] = r.rssi;
    o["ch"] = r.channel;
    o["frames"] = r.frames;
    o["age"] = (millis() - r.last_seen) / 1000;
  }
  send_json(request, doc);
}

static void handle_handshakes(AsyncWebServerRequest *request) {
  JsonDocument doc;
  JsonArray arr = doc["handshakes"].to<JsonArray>();
  for (uint16_t i = 0; i < MAX_HANDSHAKES; i++) {
    HandshakeRecord r;
    if (!handshake_at(i, &r)) continue;
    JsonObject o = arr.add<JsonObject>();
    o["bssid"] = wifi_mac_str(r.bssid);
    o["sta"] = wifi_mac_str(r.sta);
    o["ssid"] = r.ssid;
    o["m1"] = r.m1;
    o["m2"] = r.m2;
    o["m3"] = r.m3;
    o["m4"] = r.m4;
    o["pmkid"] = r.pmkid;
    o["complete"] = r.complete;
    o["ch"] = r.channel;
  }
  send_json(request, doc);
}

static void handle_creds(AsyncWebServerRequest *request) {
  request->send(200, "application/json", portal_creds_json());
}

static void handle_captures(AsyncWebServerRequest *request) {
  JsonDocument doc;
  JsonArray arr = doc["files"].to<JsonArray>();
  File dir = storage_fs().open(CAPTURE_DIR);
  if (dir && dir.isDirectory()) {
    File f = dir.openNextFile();
    while (f) {
      String name = f.name();
      int slash = name.lastIndexOf('/');
      if (slash >= 0) name = name.substring(slash + 1);
      if (!f.isDirectory()) {
        JsonObject o = arr.add<JsonObject>();
        o["name"] = name;
        o["size"] = f.size();
      }
      f = dir.openNextFile();
    }
    dir.close();
  }
  send_json(request, doc);
}

// ---------------------------------------------------------------------------
// Action endpoints
// ---------------------------------------------------------------------------
static void start_scan_common(AsyncWebServerRequest *request, bool capture) {
  uint8_t channel = static_cast<uint8_t>(qnum(request, "channel", 1));
  bool hop = truthy(qparam(request, "hop", "0"));
  deauth_stop();
  beacon_stop();
  portal_stop();
  sniffer_stop();
  if (capture) {
    sniffer_start_capture(channel, hop);
  } else {
    sniffer_start_scan(channel, hop);
  }
  JsonDocument doc;
  doc["ok"] = true;
  doc["mode"] = capture ? "capture" : "scan";
  doc["channel"] = channel;
  doc["hop"] = hop;
  send_json(request, doc);
}

static void handle_deauth(AsyncWebServerRequest *request) {
  String bssid_text = qparam(request, "bssid");
  uint8_t bssid[6];
  if (!wifi_parse_mac(bssid_text, bssid)) {
    request->send(400, "application/json", "{\"ok\":false,\"error\":\"bad bssid\"}");
    return;
  }
  uint8_t channel = static_cast<uint8_t>(qnum(request, "channel", 1));
  uint16_t reason = static_cast<uint16_t>(qnum(request, "reason", 7));
  bool continuous = truthy(qparam(request, "continuous", "1"));
  uint32_t count = qnum(request, "count", 0);

  uint8_t client[6];
  bool has_client = false;
  String client_text = qparam(request, "client");
  if (client_text.length() && wifi_parse_mac(client_text, client)) has_client = true;

  sniffer_stop();
  beacon_stop();
  portal_stop();

  bool ok = deauth_start(bssid, has_client ? client : nullptr, channel, reason, continuous,
                         count ? count : 0);
  JsonDocument doc;
  doc["ok"] = ok;
  send_json(request, doc);
}

static void handle_beacon(AsyncWebServerRequest *request) {
  uint32_t count = qnum(request, "count", 0);
  uint8_t channel = static_cast<uint8_t>(qnum(request, "channel", 1));
  String ssid = qparam(request, "ssid");
  sniffer_stop();
  deauth_stop();
  portal_stop();
  bool ok = beacon_start(count, ssid, channel);
  JsonDocument doc;
  doc["ok"] = ok;
  send_json(request, doc);
}

static void handle_portal(AsyncWebServerRequest *request) {
  String ssid = qparam(request, "ssid");
  if (ssid.length() == 0) ssid = "Free WiFi";
  sniffer_stop();
  deauth_stop();
  beacon_stop();
  bool ok = portal_start(ssid);
  JsonDocument doc;
  doc["ok"] = ok;
  send_json(request, doc);
}

static void handle_download(AsyncWebServerRequest *request) {
  String file = qparam(request, "file");
  if (!file.startsWith("/captures/") && file != CRED_FILE) {
    request->send(403, "text/plain", "forbidden");
    return;
  }
  if (file.indexOf("..") >= 0) {
    request->send(403, "text/plain", "forbidden");
    return;
  }
  if (!storage_fs().exists(file)) {
    request->send(404, "text/plain", "not found");
    return;
  }
  AsyncWebServerResponse *response =
      request->beginResponse(storage_fs(), file, "application/octet-stream", true);
  request->send(response);
}

void webui_begin() {
  g_server.on("/api/status", HTTP_GET, handle_status);
  g_server.on("/api/aps", HTTP_GET, handle_aps);
  g_server.on("/api/clients", HTTP_GET, handle_clients);
  g_server.on("/api/handshakes", HTTP_GET, handle_handshakes);
  g_server.on("/api/creds", HTTP_GET, handle_creds);
  g_server.on("/api/captures", HTTP_GET, handle_captures);
  g_server.on("/api/download", HTTP_GET, handle_download);

  g_server.on("/api/scan", HTTP_POST, [](AsyncWebServerRequest *r) { start_scan_common(r, false); });
  g_server.on("/api/capture", HTTP_POST, [](AsyncWebServerRequest *r) { start_scan_common(r, true); });
  g_server.on("/api/deauth", HTTP_POST, handle_deauth);
  g_server.on("/api/beacon", HTTP_POST, handle_beacon);
  g_server.on("/api/portal", HTTP_POST, handle_portal);

  g_server.on("/api/deauth/stop", HTTP_POST, [](AsyncWebServerRequest *r) {
    deauth_stop();
    r->send(200, "application/json", "{\"ok\":true}");
  });
  g_server.on("/api/beacon/stop", HTTP_POST, [](AsyncWebServerRequest *r) {
    beacon_stop();
    r->send(200, "application/json", "{\"ok\":true}");
  });
  g_server.on("/api/sniff/stop", HTTP_POST, [](AsyncWebServerRequest *r) {
    sniffer_stop();
    r->send(200, "application/json", "{\"ok\":true}");
  });
  g_server.on("/api/portal/stop", HTTP_POST, [](AsyncWebServerRequest *r) {
    portal_stop();
    r->send(200, "application/json", "{\"ok\":true}");
  });
  g_server.on("/api/halt", HTTP_POST, [](AsyncWebServerRequest *r) {
    webui_halt_all();
    r->send(200, "application/json", "{\"ok\":true}");
  });
  g_server.on("/api/clear", HTTP_POST, [](AsyncWebServerRequest *r) {
    sniffer_clear_tables();
    log_clear();
    r->send(200, "application/json", "{\"ok\":true}");
  });

  g_server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html").setCacheControl("no-store");
  g_server.onNotFound([](AsyncWebServerRequest *r) {
    if (r->url().startsWith("/api/")) {
      r->send(404, "application/json", "{\"ok\":false,\"error\":\"no route\"}");
    } else {
      r->send(404, "text/plain", "not found");
    }
  });
  g_server.begin();
  log_print("control panel http://%s:%u", WiFi.softAPIP().toString().c_str(), CONTROL_HTTP_PORT);
}

void webui_tick() {
  // Reserved for future background work. State is served on demand.
}
