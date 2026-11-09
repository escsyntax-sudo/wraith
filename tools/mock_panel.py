#!/usr/bin/env python3
"""Serve the Wraith panel with a fake API for layout and interaction work.

This is a development aid only. It never touches a radio. Run it from the
repository root:

    python tools/mock_panel.py

Then open http://127.0.0.1:8099
"""

import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

STATE = {
    "version": "1.0.0",
    "mode": "idle",
    "channel": 1,
    "uptime": 317,
    "heap": 187240,
    "storage": "sd",
    "ip": "192.168.4.1",
    "frames": 18422,
    "drops": 0,
    "capture": {"active": False, "frames": 18422, "eapol": 6, "pmkid": 1, "handshakes": 1, "bytes": 48120},
    "deauth": {"active": False, "bssid": "", "sent": 0},
    "beacon": {"active": False, "sent": 0},
    "portal": {"active": False, "ssid": "Free WiFi", "creds": 2},
    "aps": [
        {"ssid": "Harbor_Guest", "bssid": "a4:2b:8c:11:6f:02", "rssi": -41, "ch": 6, "enc": "WPA2", "frames": 214, "age": 2},
        {"ssid": "Cafe_WiFi", "bssid": "8c:3b:ad:70:12:9e", "rssi": -63, "ch": 1, "enc": "WPA2", "frames": 88, "age": 4},
        {"ssid": "Terminal_Free", "bssid": "f0:9f:c2:aa:03:71", "rssi": -74, "ch": 11, "enc": "OPEN", "frames": 31, "age": 9},
        {"ssid": "<hidden>", "bssid": "04:18:d6:5c:22:0b", "rssi": -81, "ch": 3, "enc": "WPA3", "frames": 12, "age": 14},
    ],
    "clients": [
        {"mac": "62:11:aa:03:7d:41", "bssid": "a4:2b:8c:11:6f:02", "rssi": -45, "ch": 6, "frames": 41, "age": 2},
        {"mac": "de:82:9c:44:10:77", "bssid": "8c:3b:ad:70:12:9e", "rssi": -66, "ch": 1, "frames": 19, "age": 5},
        {"mac": "7a:30:b1:88:2e:5c", "bssid": "", "rssi": -72, "ch": 11, "frames": 7, "age": 11},
    ],
    "handshakes": [
        {"bssid": "a4:2b:8c:11:6f:02", "sta": "62:11:aa:03:7d:41", "ssid": "Harbor_Guest", "m1": True, "m2": True, "m3": True, "m4": True, "pmkid": True, "complete": True, "ch": 6},
        {"bssid": "8c:3b:ad:70:12:9e", "sta": "de:82:9c:44:10:77", "ssid": "Cafe_WiFi", "m1": True, "m2": False, "m3": False, "m4": False, "pmkid": False, "complete": False, "ch": 1},
    ],
    "files": [
        {"name": "hs_48210.pcap", "size": 48120},
        {"name": "pmkid.22000", "size": 214},
    ],
    "creds": [
        {"at": 84, "identity": "night.operator@example.test", "secret": "hunter2"},
        {"at": 209, "identity": "guest-04", "secret": "letmein"},
    ],
    "log": [
        "storage ready: sd",
        "control AP: wraith at 192.168.4.1:8080",
        "scan started channel=1 hop=0",
        "ap upsert bssid=a4:2b:8c:11:6f:02 ch=6 wpa2",
        "eapol m1 bssid=a4:2b:8c:11:6f:02 sta=62:11:aa:03:7d:41",
        "eapol m2 bssid=a4:2b:8c:11:6f:02 sta=62:11:aa:03:7d:41",
        "pmkid captured bssid=a4:2b:8c:11:6f:02",
        "capture open /captures/hs_48210.pcap",
    ],
}


def refresh_counts():
    STATE["aps_count"] = len(STATE["aps"])
    STATE["clients_count"] = len(STATE["clients"])
    STATE["hs_count"] = len(STATE["handshakes"])


def status_payload():
    refresh_counts()
    return {
        "version": STATE["version"],
        "mode": STATE["mode"],
        "channel": STATE["channel"],
        "uptime": STATE["uptime"],
        "heap": STATE["heap"],
        "storage": STATE["storage"],
        "ip": STATE["ip"],
        "aps": STATE["aps_count"],
        "clients": STATE["clients_count"],
        "handshakes": STATE["hs_count"],
        "frames": STATE["frames"],
        "drops": STATE["drops"],
        "capture": STATE["capture"],
        "deauth": STATE["deauth"],
        "beacon": STATE["beacon"],
        "portal": STATE["portal"],
        "log": STATE["log"],
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        pass

    def json(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/status":
            return self.json(status_payload())
        if path == "/api/aps":
            return self.json({"aps": STATE["aps"]})
        if path == "/api/clients":
            return self.json({"clients": STATE["clients"]})
        if path == "/api/handshakes":
            return self.json({"handshakes": STATE["handshakes"]})
        if path == "/api/captures":
            return self.json({"files": STATE["files"]})
        if path == "/api/creds":
            return self.json(STATE["creds"])
        if path == "/api/download":
            body = b"mock capture\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="mock.bin"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/api/scan":
            STATE["mode"] = "scan"
            STATE["channel"] = int(query.get("channel", ["1"])[0])
            STATE["log"].append("scan started channel=%s" % STATE["channel"])
        elif path == "/api/capture":
            STATE["mode"] = "capture"
            STATE["capture"]["active"] = True
            STATE["log"].append("capture started")
        elif path == "/api/deauth":
            STATE["mode"] = "deauth"
            STATE["deauth"]["active"] = True
            STATE["deauth"]["bssid"] = query.get("bssid", [""])[0]
            STATE["deauth"]["sent"] = 240
            STATE["log"].append("deauth start bssid=%s" % STATE["deauth"]["bssid"])
        elif path == "/api/beacon":
            STATE["mode"] = "beacon"
            STATE["beacon"]["active"] = True
            STATE["beacon"]["sent"] = 900
            STATE["log"].append("beacon start")
        elif path == "/api/portal":
            STATE["mode"] = "portal"
            STATE["portal"]["active"] = True
            STATE["portal"]["ssid"] = query.get("ssid", ["Free WiFi"])[0]
            STATE["log"].append("portal live ssid=%s" % STATE["portal"]["ssid"])
        elif path.endswith("/stop"):
            if path == "/api/deauth/stop":
                STATE["deauth"]["active"] = False
            elif path == "/api/beacon/stop":
                STATE["beacon"]["active"] = False
            elif path == "/api/portal/stop":
                STATE["portal"]["active"] = False
            else:
                STATE["capture"]["active"] = False
            if not any(
                [
                    STATE["deauth"]["active"],
                    STATE["beacon"]["active"],
                    STATE["portal"]["active"],
                    STATE["capture"]["active"],
                ]
            ):
                STATE["mode"] = "idle"
            STATE["log"].append("stopped")
        elif path == "/api/halt":
            STATE["mode"] = "idle"
            STATE["deauth"]["active"] = False
            STATE["beacon"]["active"] = False
            STATE["portal"]["active"] = False
            STATE["capture"]["active"] = False
            STATE["log"].append("all operations halted")
        elif path == "/api/clear":
            STATE["log"] = []
        else:
            return self.json({"ok": False, "error": "no route"}, 404)
        return self.json({"ok": True})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8099), Handler)
    print("panel mock on http://127.0.0.1:8099")
    server.serve_forever()
