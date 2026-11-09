"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const titles = { scan: "Scan", strike: "Strike", capture: "Capture", portal: "Portal", console: "Console" };

const state = {
  view: "scan",
  target: null,
  status: null,
  lastLog: "",
  pollTimer: null,
  loaded: { scan: false, capture: false, portal: false },
  sigs: { scan: "", capture: "", portal: "" },
};

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function toast(message, bad = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("bad", bad);
  box.classList.add("show");
  clearTimeout(box._t);
  box._t = setTimeout(() => box.classList.remove("show"), 2600);
}

async function api(path, method = "GET") {
  const res = await fetch(path, { method, cache: "no-store" });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

async function post(path, okMessage) {
  try {
    const data = await api(path, "POST");
    if (data && data.ok === false) {
      toast(data.error || "Request rejected", true);
      return false;
    }
    if (okMessage) toast(okMessage);
    poll();
    return true;
  } catch (err) {
    toast("Request failed: " + err.message, true);
    return false;
  }
}

function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h) return h + ":" + String(m).padStart(2, "0") + ":" + String(r).padStart(2, "0");
  return m + ":" + String(r).padStart(2, "0");
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(1) + " MB";
}

function show(view, moveFocus = true) {
  state.view = view;
  $$(".view").forEach((node) => {
    node.hidden = node.id !== "view-" + view;
  });
  $$(".nav").forEach((node) => {
    if (node.dataset.view === view) node.setAttribute("aria-current", "page");
    else node.setAttribute("aria-current", "false");
  });
  const title = $("#page-title");
  title.textContent = titles[view] || "Scan";
  if (moveFocus) title.focus();

  if (view === "scan") loadScan();
  if (view === "capture") loadCapture();
  if (view === "portal") loadCreds();
  if (view === "strike") renderTarget();
}

function setLink(live) {
  const dot = $("#linkdot");
  const label = $("#linklabel");
  dot.classList.toggle("live", live);
  label.textContent = live ? "panel linked" : "link lost";
}

function renderStatus(s) {
  const modeText = $("#modetext");
  modeText.textContent = s.mode;
  $("#modechip").classList.toggle("live", s.mode !== "idle");

  $("#ro-channel").textContent = s.channel;
  $("#ro-uptime").textContent = fmtUptime(s.uptime);
  $("#ro-heap").textContent = Math.round(s.heap / 1024);
  $("#ro-storage").textContent = s.storage;

  $("#deauth-state").textContent = s.deauth.active ? "transmitting" : "idle";
  $("#deauth-state").classList.toggle("live", s.deauth.active);
  $("#deauth-sent").textContent = s.deauth.sent;

  $("#beacon-state").textContent = s.beacon.active ? "transmitting" : "idle";
  $("#beacon-state").classList.toggle("live", s.beacon.active);
  $("#beacon-sent").textContent = s.beacon.sent;

  $("#portal-state").textContent = s.portal.active ? "live" : "idle";
  $("#portal-state").classList.toggle("live", s.portal.active);
  $("#cred-count").textContent = s.portal.creds;

  $("#cap-frames").textContent = s.capture.frames;
  $("#cap-eapol").textContent = s.capture.eapol;
  $("#cap-pmkid").textContent = s.capture.pmkid;
  $("#cap-hs").textContent = s.capture.handshakes;
  $("#cap-bytes").textContent = fmtBytes(s.capture.bytes);

  $("#ap-count").textContent = s.aps;
  $("#client-count").textContent = s.clients;
  $("#hs-count").textContent = s.handshakes;

  renderLog(s.log);
}

function renderLog(lines) {
  const joined = Array.isArray(lines) ? lines.join("\n") : "";
  if (joined === state.lastLog) return;
  state.lastLog = joined;
  const box = $("#log");
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.textContent = joined || "no events yet";
  if (nearBottom) box.scrollTop = box.scrollHeight;
}

function emptyRow(tbody, cols, text) {
  const tr = el("tr", "empty");
  const td = el("td", "", text);
  td.colSpan = cols;
  tr.appendChild(td);
  tbody.replaceChildren(tr);
}

async function loadScan() {
  if (!state.loaded.scan) {
    emptyRow($("#ap-body"), 7, "Reading access points...");
    emptyRow($("#client-body"), 5, "Reading clients...");
  }
  try {
    const [aps, clients] = await Promise.all([api("/api/aps"), api("/api/clients")]);
    const sig = JSON.stringify(aps.aps || []) + JSON.stringify(clients.clients || []);
    if (sig !== state.sigs.scan) {
      state.sigs.scan = sig;
      renderAps(aps.aps || []);
      renderClients(clients.clients || []);
    }
    state.loaded.scan = true;
  } catch (err) {
    emptyRow($("#ap-body"), 7, "Could not read the access point table.");
    emptyRow($("#client-body"), 5, "Could not read the client table.");
  }
}

function renderAps(rows) {
  const body = $("#ap-body");
  if (!rows.length) {
    emptyRow(body, 7, "No access points yet. Start a scan.");
    return;
  }
  const active = document.activeElement;
  const keep = active && active.classList.contains("rowbtn") && body.contains(active) ? active.dataset.bssid : null;
  const frag = document.createDocumentFragment();
  for (const ap of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", "", ap.ssid || "<hidden>"));
    tr.appendChild(el("td", "mono", ap.bssid));
    tr.appendChild(el("td", "num", String(ap.rssi)));
    tr.appendChild(el("td", "num", String(ap.ch)));
    tr.appendChild(el("td", "", ap.enc));
    tr.appendChild(el("td", "num", ap.age + "s"));
    const cell = el("td");
    const btn = el("button", "btn rowbtn", "Target");
    btn.type = "button";
    btn.dataset.bssid = ap.bssid;
    btn.dataset.ssid = ap.ssid || "";
    btn.dataset.ch = String(ap.ch);
    btn.setAttribute("aria-label", "Target " + (ap.ssid || ap.bssid));
    btn.addEventListener("click", () => {
      state.target = { bssid: ap.bssid, ssid: ap.ssid || "", ch: ap.ch };
      renderTarget();
      show("strike");
      toast("Target set: " + (ap.ssid || ap.bssid));
    });
    cell.appendChild(btn);
    tr.appendChild(cell);
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
  if (keep) {
    const again = Array.from(body.querySelectorAll("button.rowbtn")).find((b) => b.dataset.bssid === keep);
    if (again) again.focus();
  }
}

function renderClients(rows) {
  const body = $("#client-body");
  if (!rows.length) {
    emptyRow(body, 5, "No clients seen yet.");
    return;
  }
  const frag = document.createDocumentFragment();
  for (const c of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", c.mac));
    tr.appendChild(el("td", "num", String(c.rssi)));
    tr.appendChild(el("td", "num", String(c.ch)));
    tr.appendChild(el("td", "mono", c.bssid || "unassociated"));
    tr.appendChild(el("td", "num", String(c.frames)));
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
}

function renderTarget() {
  const t = state.target;
  $("#target-ssid").textContent = t ? t.ssid || "<hidden>" : "not selected";
  $("#target-bssid").textContent = t ? t.bssid : "-";
  $("#target-ch").textContent = t ? String(t.ch) : "-";
  const tag = $("#target-state");
  tag.textContent = t ? "locked" : "none";
  tag.classList.toggle("live", Boolean(t));
}

async function loadCapture() {
  if (!state.loaded.capture) {
    emptyRow($("#hs-body"), 10, "Reading handshake table...");
    $("#file-list").replaceChildren(el("li", "empty", "Reading capture folder..."));
  }
  try {
    const [hs, files] = await Promise.all([api("/api/handshakes"), api("/api/captures")]);
    const sig = JSON.stringify(hs.handshakes || []) + JSON.stringify(files.files || []);
    if (sig !== state.sigs.capture) {
      state.sigs.capture = sig;
      renderHandshakes(hs.handshakes || []);
      renderFiles(files.files || []);
    }
    state.loaded.capture = true;
  } catch (err) {
    emptyRow($("#hs-body"), 10, "Could not read the handshake table.");
    $("#file-list").replaceChildren(el("li", "empty", "Could not read the capture folder."));
  }
}

function flagCell(on) {
  return el("td", on ? "flag on" : "flag", on ? "1" : "0");
}

function renderHandshakes(rows) {
  const body = $("#hs-body");
  if (!rows.length) {
    emptyRow(body, 10, "No EAPOL traffic yet.");
    return;
  }
  const frag = document.createDocumentFragment();
  for (const h of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", h.bssid));
    tr.appendChild(el("td", "mono", h.sta));
    tr.appendChild(el("td", "", h.ssid || "<hidden>"));
    tr.appendChild(el("td", "num", String(h.ch)));
    tr.appendChild(flagCell(h.m1));
    tr.appendChild(flagCell(h.m2));
    tr.appendChild(flagCell(h.m3));
    tr.appendChild(flagCell(h.m4));
    tr.appendChild(flagCell(h.pmkid));
    const st = el("td", h.complete ? "state-ok" : "state-wait", h.complete ? "complete" : "partial");
    tr.appendChild(st);
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
}

function renderFiles(rows) {
  const list = $("#file-list");
  $("#file-count").textContent = rows.length;
  if (!rows.length) {
    list.replaceChildren(el("li", "empty", "No captures on disk."));
    return;
  }
  const active = document.activeElement;
  const keep = active && active.tagName === "A" && list.contains(active) ? active.getAttribute("download") : null;
  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const li = el("li");
    const link = el("a", "", f.name);
    link.href = "/api/download?file=" + encodeURIComponent("/captures/" + f.name);
    link.setAttribute("download", f.name);
    li.appendChild(link);
    li.appendChild(el("span", "fsize", fmtBytes(f.size)));
    frag.appendChild(li);
  }
  list.replaceChildren(frag);
  if (keep) {
    const again = Array.from(list.querySelectorAll("a")).find((a) => a.getAttribute("download") === keep);
    if (again) again.focus();
  }
}

async function loadCreds() {
  if (!state.loaded.portal) emptyRow($("#cred-body"), 3, "Reading credential table...");
  try {
    const rows = await api("/api/creds");
    const body = $("#cred-body");
    state.loaded.portal = true;
    const sig = JSON.stringify(rows);
    if (sig === state.sigs.portal) return;
    state.sigs.portal = sig;
    if (!rows.length) {
      emptyRow(body, 3, "Nothing submitted yet.");
      return;
    }
    const frag = document.createDocumentFragment();
    for (const c of rows) {
      const tr = el("tr");
      tr.appendChild(el("td", "num", "t+" + c.at + "s"));
      tr.appendChild(el("td", "", c.identity));
      tr.appendChild(el("td", "mono", c.secret));
      frag.appendChild(tr);
    }
    body.replaceChildren(frag);
  } catch (err) {
    emptyRow($("#cred-body"), 3, "Could not read captured credentials.");
  }
}

async function poll() {
  try {
    const s = await api("/api/status");
    state.status = s;
    $("#ver").textContent = "v" + s.version;
    setLink(true);
    renderStatus(s);
    if (state.view === "scan") await loadScan();
    if (state.view === "capture") await loadCapture();
    if (state.view === "portal") await loadCreds();
  } catch (err) {
    setLink(false);
  }
}

function bindActions() {
  $$(".nav").forEach((btn) => {
    btn.addEventListener("click", () => show(btn.dataset.view));
  });

  $("#scan-start").addEventListener("click", () => {
    const channel = $("#scan-channel").value || "1";
    const hop = $("#scan-hop").checked ? "1" : "0";
    post("/api/scan?channel=" + encodeURIComponent(channel) + "&hop=" + hop, "Scan started");
  });
  $("#scan-stop").addEventListener("click", () => post("/api/sniff/stop", "Scan stopped"));

  $("#deauth-start").addEventListener("click", () => {
    if (!state.target) {
      toast("Pick a target in Scan first", true);
      show("scan");
      return;
    }
    const continuous = $("#deauth-cont").checked ? "1" : "0";
    let count = $("#deauth-count").value || "0";
    if (continuous === "0" && count === "0") count = "200";
    const reason = $("#deauth-reason").value;
    const url =
      "/api/deauth?bssid=" + encodeURIComponent(state.target.bssid) +
      "&channel=" + encodeURIComponent(state.target.ch) +
      "&reason=" + encodeURIComponent(reason) +
      "&continuous=" + continuous +
      "&count=" + encodeURIComponent(count);
    post(url, "Deauth transmitting");
  });
  $("#deauth-stop").addEventListener("click", () => post("/api/deauth/stop", "Deauth stopped"));

  $("#beacon-start").addEventListener("click", () => {
    const ssid = $("#beacon-ssid").value.trim();
    const count = $("#beacon-count").value || "0";
    const channel = $("#beacon-channel").value || "1";
    const url =
      "/api/beacon?ssid=" + encodeURIComponent(ssid) +
      "&count=" + encodeURIComponent(count) +
      "&channel=" + encodeURIComponent(channel);
    post(url, "Beacon flood started");
  });
  $("#beacon-stop").addEventListener("click", () => post("/api/beacon/stop", "Beacon flood stopped"));

  $("#cap-start").addEventListener("click", () => {
    const channel = $("#cap-channel").value || "1";
    const hop = $("#cap-hop").checked ? "1" : "0";
    post("/api/capture?channel=" + encodeURIComponent(channel) + "&hop=" + hop, "Capture started");
  });
  $("#cap-stop").addEventListener("click", () => post("/api/sniff/stop", "Capture stopped"));

  $("#portal-start").addEventListener("click", () => {
    const ssid = $("#portal-ssid").value.trim() || "Free WiFi";
    post("/api/portal?ssid=" + encodeURIComponent(ssid), "Portal live on " + ssid);
  });
  $("#portal-stop").addEventListener("click", () => post("/api/portal/stop", "Portal stopped"));

  $("#halt").addEventListener("click", () => post("/api/halt", "All operations halted"));
  $("#log-clear").addEventListener("click", () => post("/api/clear", "Log cleared"));
}

function boot() {
  bindActions();
  show("scan", false);
  poll();
  state.pollTimer = setInterval(poll, 1500);
}

document.addEventListener("DOMContentLoaded", boot);
