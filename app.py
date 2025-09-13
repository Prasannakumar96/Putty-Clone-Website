#!/usr/bin/env python3
import os
import io
import sys
import json
import shutil
import tempfile
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from typing import Optional

from flask import Flask, request, Response, render_template_string
from flask_sock import Sock

import paramiko
import threading
import time

import uuid
import json

from flask import jsonify

def load_profiles():
    if not os.path.exists(PROFILES_JSON):
        return []
    try:
        with open(PROFILES_JSON, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_profiles(items):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PROFILES_JSON, "w") as f:
        json.dump(items, f, indent=2)

def save_uploaded_key(file_storage):
    # Returns saved path (relative) or None
    if not file_storage or not file_storage.filename:
        return None
    data = file_storage.read()
    if len(data) > MAX_KEY_SIZE:
        raise RuntimeError("Key file too large")
    ext = ".ppk" if file_storage.filename.lower().endswith(".ppk") else ".pem"
    fname = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(KEYS_DIR, fname)
    with open(path, "wb") as f:
        f.write(data)
    return os.path.join("keys", fname)

def build_pkey_from_path(rel_path, passphrase: Optional[str]):
    # Load key from saved path, auto-convert if .ppk
    full = os.path.join(DATA_DIR, rel_path)
    with open(full, "rb") as f:
        data = f.read()
    if rel_path.lower().endswith(".ppk"):
        data = convert_ppk_to_openssh(data, passphrase if passphrase else None)
    return load_pkey_from_bytes(data, passphrase if passphrase else None)


# ---- Config ----

APP_HOST = "127.0.0.1"
APP_PORT = 5000
MAX_KEY_SIZE = 1024 * 1024  # 1 MB
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")


DATA_DIR = "data"
KEYS_DIR = os.path.join(DATA_DIR, "keys")
PROFILES_JSON = os.path.join(DATA_DIR, "profiles.json")
os.makedirs(KEYS_DIR, exist_ok=True)


app = Flask(__name__)
sock = Sock(app)

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    app_logger = logging.getLogger()
    app_logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    app_logger.addHandler(sh)

    fh = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    app_logger.addHandler(fh)

    # Paramiko debug logs (very verbose: key exchange, auth attempts)
    paramiko.util.log_to_file(LOG_FILE, level=logging.DEBUG)

setup_logging()
log = logging.getLogger("webssh")

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Web SSH</title>
  <link rel="stylesheet" href="https://unpkg.com/xterm/css/xterm.css" />
  <script src="https://unpkg.com/xterm/lib/xterm.js"></script>
  <script src="https://unpkg.com/xterm-addon-fit/lib/xterm-addon-fit.js"></script>
  <style>
    :root {
      --sidebar-w: 30vw;
      --content-w: 70vw;
      --gap: 16px;
      --pad: 14px;
      --hdr: 48px;
      --radius: 12px;
      --border: #e5e7eb;
      --muted: #6b7280;
      --bg: #ffffff;
      --bg-soft: #f9fafb;
      --fg: #111827;
      --accent: #0b5ed7;
      --danger: #c0392b;
      --dark: #0b0b0b;
    }
    html, body { height: 100%; }
    body {
      margin: 0; color: var(--fg); background: var(--bg-soft);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    }
    .shell {
      display: grid;
      grid-template-columns: var(--sidebar-w) var(--content-w);
      height: 100vh;
      overflow: hidden;
    }
    .sidebar {
      background: var(--bg);
      border-right: 1px solid var(--border);
      padding: var(--pad);
      display: flex; flex-direction: column; gap: var(--gap);
      position: sticky; top: 0; height: 100vh; overflow: auto;
    }
    .content {
      height: 100vh;
      overflow: auto;
      padding: var(--pad);
    }
    .section { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--pad); }
    h2, h3 { margin: 0 0 8px 0; font-weight: 700; }
    .stack { display: grid; gap: 10px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .note { color: var(--muted); font-size: .95rem; }
    input, select, button, a.button {
      font: inherit; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: #fff;
    }
    input:focus, select:focus, button:focus, a.button:focus { outline: 2px solid var(--accent); outline-offset: 2px; }
    button.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
    button.secondary { background: #374151; color: #fff; border-color: #374151; }
    button.ghost { background: #2d3436; color: #fff; border-color: #2d3436; }
    button.danger { background: var(--danger); color: #fff; border-color: var(--danger); }
    button[disabled] { opacity: .6; cursor: not-allowed; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    hr { border: none; border-top: 1px solid var(--border); margin: 8px 0; }

    #connectPanel, #termCard { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--pad); }
    #terminal, #terminalFS {
      width: 100%; height: 72vh; background: var(--dark); color: #f3f3f3;
      border-radius: 10px; overflow: hidden; border: 1px solid #1c1c1c;
    }
    .hidden { display: none !important; }

    .accordion { display: grid; gap: 8px; }
    details.ac-item {
      border: 1px solid var(--border); border-radius: 10px; background: #fff;
    }
    details.ac-item[open] { box-shadow: 0 2px 10px rgba(0,0,0,.04); }
    summary.ac-summary {
      cursor: pointer; list-style: none; padding: 10px 12px; display: flex; align-items: center; justify-content: space-between;
    }
    summary.ac-summary::-webkit-details-marker { display: none; }
    .ac-meta { display: grid; gap: 4px; }
    .ac-name { font-weight: 600; }
    .ac-sub { color: var(--muted); font-size: .92rem; }
    .ac-actions { padding: 10px 12px; border-top: 1px solid var(--border); display: flex; gap: 8px; flex-wrap: wrap; }

    .connection-info {
      background: #f0f9ff; border: 1px solid #0ea5e9; border-radius: 10px; padding: 12px;
      margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between;
    }
    .connection-info .status { font-weight: 600; color: #0ea5e9; }

    #fsOverlay.hidden { display: none; }
    #fsOverlay {
      position: fixed; inset: 0; z-index: 9999; display: flex; flex-direction: column; background: #0e0f12;
    }
    #fsHeader {
      height: var(--hdr); min-height: var(--hdr); display: flex; align-items: center; justify-content: space-between;
      padding: 0 12px; background: var(--accent); color: #fff; border-bottom: 1px solid rgba(255,255,255,.15);
      position: sticky; top: 0;
    }
    #fsHeader .info { display: flex; gap: 10px; align-items: baseline; }
    #fsHeader .dim { opacity: .9; }
    #fsTerminalWrap { flex: 1; padding: 10px; }
    #terminalFS { height: calc(100vh - var(--hdr) - 20px); }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="section">
        <div class="actions" style="justify-content: space-between; align-items:center;">
          <h3 style="margin:0;">Saved Clients</h3>
          <button id="refreshBtn" class="ghost" type="button">Refresh</button>
        </div>
        <div id="accordion" class="accordion" style="margin-top:10px;"></div>
      </div>

      <div class="section">
        <button id="newConnectionBtn" class="primary" type="button" style="width:100%;">+ New Connection</button>
        <p class="note" style="margin-top:8px;">Create a new SSH connection or manage saved clients above.</p>
      </div>
    </aside>

    <main class="content">
      <div id="connectPanel">
        <h2>Connect to SSH Server</h2>
        <form id="connForm" enctype="multipart/form-data" class="stack">
          <div class="row">
            <label>Host/IP <input name="host" placeholder="203.0.113.10" required></label>
            <label>Port <input name="port" type="number" value="22" required></label>
          </div>
          <div class="row">
            <label>Username <input name="username" placeholder="ubuntu" required></label>
            <label>Password (optional) <input name="password" type="password"></label>
          </div>
          <label>Private key (.pem or .ppk) <input name="pkey" type="file" accept=".pem,.ppk,.key,.txt"></label>
          <label>Key passphrase <input name="passphrase" type="password"></label>
          <p class="note">.ppk converts via puttygen (brew install putty). Use Test only first. View logs for details.</p>
          <div class="actions">
            <button id="connectBtn" class="primary" type="submit">Connect</button>
            <button id="testBtn" class="secondary" type="button">Test only</button>
            <a class="button" href="/logs" target="_blank">View logs</a>
          </div>
          <hr>
          <h3>Save as Client</h3>
          <div class="row">
            <label>Client name <input name="client_name" placeholder="Prod-EC2-1"></label>
            <label>Save password?
              <select name="save_password">
                <option value="no" selected>No</option>
                <option value="yes">Yes (plain JSON)</option>
              </select>
            </label>
          </div>
          <p class="note">Keys saved under data/keys and referenced in profiles.json.</p>
          <div class="actions">
            <button id="saveClientBtn" class="button" type="button">Save/Update</button>
          </div>
        </form>
      </div>

      <div id="termCard" class="hidden">
        <div class="connection-info">
          <div class="status" id="connectionStatus">Connected to server</div>
          <div class="actions">
            <button id="fullscreenBtn" class="ghost" type="button">Fullscreen</button>
            <button id="disconnectBtn" class="danger" type="button">Disconnect</button>
          </div>
        </div>
        <div id="terminal"></div>
      </div>
    </main>
  </div>

  <div id="fsOverlay" class="hidden" role="dialog" aria-modal="true" aria-label="Terminal Fullscreen">
    <div id="fsHeader">
      <div class="info">
        <strong>Connected:</strong><span id="fsUserHost" class="dim"></span>
      </div>
      <div class="actions">
        <button id="fsDisconnectBtn" class="danger" type="button">Disconnect</button>
        <button id="fsExitBtn" class="secondary" type="button">Leave Fullscreen</button>
      </div>
    </div>
    <div id="fsTerminalWrap">
      <div id="terminalFS"></div>
    </div>
  </div>

  <script>
    const fitAddon = new window.FitAddon.FitAddon();
    const term = new window.Terminal({ 
      cursorBlink: true, 
      convertEol: true, 
      fontSize: 14, 
      theme: { background: '#0b0b0b' },
      disableStdin: false
    });
    term.loadAddon(fitAddon);

    const form = document.getElementById('connForm');
    const connectBtn = document.getElementById('connectBtn');
    const testBtn = document.getElementById('testBtn');
    const disconnectBtn = document.getElementById('disconnectBtn');
    const fullscreenBtn = document.getElementById('fullscreenBtn');
    const connectPanel = document.getElementById('connectPanel');
    const termCard = document.getElementById('termCard');
    const accordion = document.getElementById('accordion');
    const refreshBtn = document.getElementById('refreshBtn');
    const saveClientBtn = document.getElementById('saveClientBtn');
    const newConnectionBtn = document.getElementById('newConnectionBtn');
    const connectionStatus = document.getElementById('connectionStatus');

    const fsOverlay = document.getElementById('fsOverlay');
    const fsUserHost = document.getElementById('fsUserHost');
    const fsDisconnectBtn = document.getElementById('fsDisconnectBtn');
    const fsExitBtn = document.getElementById('fsExitBtn');
    const terminalNormal = document.getElementById('terminal');
    const terminalFS = document.getElementById('terminalFS');

    let ws;
    let currentSid = null;
    let inFullscreen = false;
    let lastUser = '';
    let lastHost = '';
    let lastPort = '22';
    let dataHandler = null;

    function showConnectPanel() {
      connectPanel.classList.remove('hidden');
      termCard.classList.add('hidden');
    }

    function showTerminalPanel(connectionInfo = '') {
      connectPanel.classList.add('hidden');
      termCard.classList.remove('hidden');
      if (connectionInfo) {
        connectionStatus.textContent = connectionInfo;
      }
    }

    function mountTerminal(hostFS=false) {
      const target = hostFS ? terminalFS : terminalNormal;
      if (!term.element || term.element.parentElement !== target) {
        target.innerHTML = '';
        term.open(target);
      }
      setTimeout(() => fitAddon.fit(), 40);
      term.focus();
    }

    function connectWS(sessionId) {
      currentSid = sessionId;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const wsUrl = `${proto}://${location.host}/ws?sid=${encodeURIComponent(sessionId)}`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        showTerminalPanel(`Connected to ${lastUser}@${lastHost}:${lastPort}`);
        mountTerminal(false);
        term.write("\\x1b[32mConnected.\\x1b[0m\\r\\n");
        window.addEventListener('resize', () => fitAddon.fit());
        
        // Remove any existing data handler to prevent duplicates
        if (dataHandler) {
          term.onData.dispose();
        }
        
        // Set up input handler - only send to WebSocket, don't echo locally
        dataHandler = term.onData((data) => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(data);
          }
        });
      };
      
      ws.onmessage = (ev) => {
        // Only write server output to terminal, no local echo
        term.write(ev.data);
      };
      
      ws.onclose = () => {
        term.write("\\r\\n\\x1b[31mDisconnected.\\x1b[0m\\r\\n");
        showConnectPanel();
        if (inFullscreen) exitFullscreen();
        currentSid = null;
        
        // Clean up data handler
        if (dataHandler) {
          dataHandler.dispose();
          dataHandler = null;
        }
      };
    }

    async function disconnectSession() {
      try { if (ws && ws.readyState === WebSocket.OPEN) ws.close(); } catch (e) {}
      if (currentSid) { try { await fetch(`/close?sid=${encodeURIComponent(currentSid)}`, { method: 'POST' }); } catch (e) {} }
      showConnectPanel();
      if (inFullscreen) exitFullscreen();
    }

    function enterFullscreen() {
      inFullscreen = true;
      fsUserHost.textContent = `${lastUser}@${lastHost}:${lastPort}`;
      fsOverlay.classList.remove('hidden');
      mountTerminal(true);
    }
    function exitFullscreen() {
      inFullscreen = false;
      fsOverlay.classList.add('hidden');
      mountTerminal(false);
    }

    async function renderAccordion() {
      const res = await fetch('/profiles');
      const items = await res.json();
      accordion.innerHTML = '';
      if (!items.length) {
        accordion.innerHTML = '<div class="note">No saved clients yet.</div>';
        return;
      }
      for (const it of items) {
        const el = document.createElement('details');
        el.className = 'ac-item';
        const id = it.id;
        el.innerHTML = `
          <summary class="ac-summary" aria-controls="panel-${id}">
            <div class="ac-meta">
              <div class="ac-name">${it.name}</div>
              <div class="ac-sub">${it.username}@${it.host}:${it.port} ${it.key_path ? '(key)' : (it.password ? '(password)' : '')}</div>
            </div>
            <span aria-hidden="true">▸</span>
          </summary>
          <div id="panel-${id}" class="ac-actions" role="region" aria-labelledby="summary-${id}">
            <button class="primary" data-connect="${id}">Connect</button>
            <button class="danger" data-del="${id}">Delete</button>
          </div>
        `;
        const caret = el.querySelector('span[aria-hidden="true"]');
        el.addEventListener('toggle', () => { caret.textContent = el.open ? '▾' : '▸'; });

        el.querySelector('[data-connect]').addEventListener('click', async () => {
          lastUser = it.username; lastHost = it.host; lastPort = String(it.port);
          const r = await fetch('/connect_profile', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
          });
          const txt = await r.text();
          if (!r.ok) { alert('Error: ' + txt); return; }
          const { sessionId } = JSON.parse(txt);
          connectWS(sessionId);
        });
        el.querySelector('[data-del]').addEventListener('click', async () => {
          if (!confirm('Delete this client?')) return;
          const r = await fetch('/profiles/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
          });
          if (!r.ok) { alert('Delete failed'); return; }
          renderAccordion();
        });

        accordion.appendChild(el);
      }
    }

    newConnectionBtn.addEventListener('click', () => showConnectPanel());
    fullscreenBtn.addEventListener('click', () => { if (currentSid) enterFullscreen(); });
    fsExitBtn.addEventListener('click', () => exitFullscreen());
    fsDisconnectBtn.addEventListener('click', () => disconnectSession());
    disconnectBtn.addEventListener('click', () => disconnectSession());

    refreshBtn.addEventListener('click', renderAccordion);

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      lastUser = (form.username.value || '').trim();
      lastHost = (form.host.value || '').trim();
      lastPort = (form.port.value || '22').trim();
      const fd = new FormData(form);
      const res = await fetch('/start', { method: 'POST', body: fd });
      const txt = await res.text();
      if (!res.ok) { alert('Error: ' + txt); return; }
      const { sessionId } = JSON.parse(txt);
      connectWS(sessionId);
    });

    testBtn.addEventListener('click', async () => {
      const fd = new FormData(form);
      const res = await fetch('/test', { method: 'POST', body: fd });
      const txt = await res.text();
      if (!res.ok) { alert('Test failed: ' + txt); return; }
      alert('Test OK: ' + txt);
    });

    saveClientBtn.addEventListener('click', async () => {
      const name = (form.client_name.value || '').trim();
      if (!name) return alert('Enter a Client name');
      const fd = new FormData(form);
      fd.append('name', name);
      fd.append('want_save_password', (form.save_password.value || 'no'));
      const res = await fetch('/profiles', { method: 'POST', body: fd });
      const txt = await res.text();
      if (!res.ok) { alert('Save failed: ' + txt); return; }
      alert('Saved');
      renderAccordion();
    });

    renderAccordion();
  </script>
</body>
</html>
"""

@dataclass
class SSHSession:
    client: paramiko.SSHClient
    channel: paramiko.Channel

sessions = {}
sessions_lock = threading.Lock()

def convert_ppk_to_openssh(ppk_bytes: bytes, passphrase: Optional[str]) -> bytes:
    puttygen = shutil.which("puttygen")
    if not puttygen:
        raise RuntimeError("puttygen not found. Install with: brew install putty")

    with tempfile.TemporaryDirectory() as td:
        ppk_path = os.path.join(td, "in.ppk")
        out_path = os.path.join(td, "out.pem")
        with open(ppk_path, "wb") as f:
            f.write(ppk_bytes)

        cmd = [puttygen, ppk_path, "-O", "private-openssh", "-o", out_path]
        try:
            log.debug("Running puttygen to convert .ppk: %s", " ".join(cmd))
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
        except subprocess.CalledProcessError as e:
            out = e.output.decode(errors="ignore")
            log.error("puttygen failed: %s", out)
            raise RuntimeError(f"puttygen failed: {out}")
        except subprocess.TimeoutExpired:
            log.error("puttygen timed out")
            raise RuntimeError("puttygen timed out converting the key")

        with open(out_path, "rb") as f:
            pem = f.read()
            log.info("Converted .ppk to OpenSSH successfully (%d bytes)", len(pem))
            return pem

def load_pkey_from_bytes(key_bytes: bytes, passphrase: Optional[str]):
    pw = None if not passphrase else passphrase.encode()
    text = key_bytes.decode("utf-8", errors="ignore")

    for loader in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
        try:
            return loader.from_private_key(io.StringIO(text), password=pw)
        except Exception as e:
            continue

    # Fallback via temp file path
    with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
        tf.write(key_bytes)
        temp_path = tf.name
    try:
        return paramiko.PKey.from_private_key_file(temp_path, password=pw)
    except Exception as e:
        raise RuntimeError(f"Could not parse private key: {e}")
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass

def build_pkey_from_upload(upload_file, passphrase: Optional[str]):
    if not upload_file or not upload_file.filename:
        return None
    data = upload_file.read()
    if len(data) > MAX_KEY_SIZE:
        raise RuntimeError("Key file too large")

    fn = upload_file.filename.lower()
    if fn.endswith(".ppk"):
        data = convert_ppk_to_openssh(data, passphrase if passphrase else None)
    return load_pkey_from_bytes(data, passphrase if passphrase else None)

def test_credentials(host, port, username, password, pkey_obj):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username,
            password=(password or None), pkey=pkey_obj,
            allow_agent=True, look_for_keys=False,
            timeout=20, auth_timeout=20, banner_timeout=20,
        )
        return None
    except paramiko.ssh_exception.PartialAuthentication as e:
        return f"Partial authentication (server expects: {', '.join(e.allowed_types)})"
    except paramiko.AuthenticationException:
        return "Authentication failed (wrong username/password/passphrase, or key not authorized)"
    except paramiko.ssh_exception.SSHException as e:
        return f"SSH error: {e}"
    except Exception as e:
        return f"Error: {e}"
    finally:
        try: client.close()
        except Exception: pass

# In /start, replace the client.connect(...) try/except with:
    try:
        client.connect(
            hostname=host, port=port, username=username,
            password=(password or None), pkey=pkey_obj,
            allow_agent=True, look_for_keys=False,
            timeout=20, auth_timeout=20, banner_timeout=20,
        )
    except paramiko.ssh_exception.PartialAuthentication as e:
        log.exception("Partial auth, expected: %s", e.allowed_types)
        return Response(f"SSH connect error: partial auth (server expects: {', '.join(e.allowed_types)})", status=400)
    except paramiko.AuthenticationException:
        log.exception("Authentication failed (bad creds or key not accepted)")
        return Response("SSH connect error: Authentication failed (check username, passphrase, authorized_keys)", status=400)
    except paramiko.ssh_exception.SSHException as e:
        log.exception("SSHException")
        return Response(f"SSH connect error: {e}", status=400)
    except Exception as e:
        log.exception("Unexpected error")
        return Response(f"SSH connect error: {e}", status=400)

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.post("/test")
def test():
    host = request.form.get("host", "").strip()
    port = int(request.form.get("port", "22"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    passphrase = request.form.get("passphrase", "")

    if not host or not username:
        return Response("host and username are required", status=400)

    try:
        pkey_obj = build_pkey_from_upload(request.files.get("pkey"), passphrase if passphrase else None)
        reason = test_credentials(host, port, username, password, pkey_obj)
        if reason is None:
            return Response("Authentication OK", status=200)
        return Response(reason, status=400)
    except Exception as e:
        log.exception("Test failed")
        return Response(f"{e}", status=400)

@app.post("/start")
def start():
    host = request.form.get("host", "").strip()
    port = int(request.form.get("port", "22"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    passphrase = request.form.get("passphrase", "")

    if not host or not username:
        return Response("host and username are required", status=400)

    try:
        pkey_obj = build_pkey_from_upload(request.files.get("pkey"), passphrase if passphrase else None)
    except Exception as e:
        log.exception("Key processing error")
        return Response(f"Key error: {e}", status=400)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=(password or None),
            pkey=pkey_obj,
            allow_agent=True,
            look_for_keys=False,
            timeout=20,
            auth_timeout=20,
            banner_timeout=20,
        )
    except Exception as e:
        log.exception("SSH connect error")
        return Response(f"SSH connect error: {e}", status=400)

    try:
        chan = client.invoke_shell(term='xterm', width=120, height=30)
        chan.settimeout(0.0)
    except Exception as e:
        log.exception("Failed to open shell")
        try:
            client.close()
        except Exception:
            pass
        return Response(f"Failed to open shell: {e}", status=400)

    session_id = os.urandom(16).hex()
    with sessions_lock:
        sessions[session_id] = SSHSession(client=client, channel=chan)

    log.info("Session %s established to %s@%s:%d", session_id, username, host, port)
    return Response(json.dumps({"sessionId": session_id}), mimetype="application/json")

@app.post("/close")
def close_session():
    sid = request.args.get("sid", "")
    if not sid:
        return Response("missing sid", status=400)
    with sessions_lock:
        s = sessions.pop(sid, None)
    if not s:
        return Response("ok", status=200)
    try:
        try:
            s.channel.close()
        except Exception:
            pass
        try:
            s.client.close()
        except Exception:
            pass
        # Optional: log closure
    except Exception:
        pass
    return Response("ok", status=200)


@app.get("/profiles")
def profiles_list():
    return jsonify(load_profiles())

@app.post("/profiles")
def profiles_add():
    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port = int(request.form.get("port", "22"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    passphrase = request.form.get("passphrase", "")
    want_save_password = (request.form.get("save_password", "no").lower() == "yes")

    if not name or not host or not username:
        return Response("name, host, username required", status=400)

    key_file = request.files.get("pkey")
    key_path = None
    try:
        key_path = save_uploaded_key(key_file) if key_file and key_file.filename else None
    except Exception as e:
        return Response(f"Key save error: {e}", status=400)

    items = load_profiles()
    # update if name exists, else add new
    existing = next((x for x in items if x.get("name") == name), None)
    payload = {
        "id": existing["id"] if existing else uuid.uuid4().hex,
        "name": name,
        "host": host,
        "port": port,
        "username": username,
        "key_path": key_path if key_path else (existing.get("key_path") if existing else None),
        "passphrase": passphrase if passphrase else "",  # optional; plain text in demo
        "password": (password if want_save_password else ""),
    }
    if existing:
        # merge update
        existing.update(payload)
    else:
        items.append(payload)

    save_profiles(items)
    return Response("ok", status=200)

@app.post("/profiles/delete")
def profiles_delete():
    data = request.get_json(silent=True) or {}
    pid = data.get("id", "")
    items = load_profiles()
    new_items = [x for x in items if x.get("id") != pid]
    if len(new_items) == len(items):
        return Response("not found", status=404)
    save_profiles(new_items)
    return Response("ok", status=200)

@app.post("/connect_profile")
def connect_profile():
    data = request.get_json(silent=True) or {}
    pid = data.get("id", "")
    items = load_profiles()
    p = next((x for x in items if x.get("id") == pid), None)
    if not p:
        return Response("profile not found", status=404)

    pkey_obj = None
    try:
        if p.get("key_path"):
            pkey_obj = build_pkey_from_path(p["key_path"], p.get("passphrase") or "")
    except Exception as e:
        return Response(f"Key error: {e}", status=400)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=p["host"],
            port=int(p.get("port", 22)),
            username=p["username"],
            password=(p.get("password") or None),
            pkey=pkey_obj,
            allow_agent=True,
            look_for_keys=False,
            timeout=20,
            auth_timeout=20,
            banner_timeout=20,
        )
    except Exception as e:
        return Response(f"SSH connect error: {e}", status=400)

    try:
        chan = client.invoke_shell(term='xterm', width=120, height=30)
        chan.settimeout(0.0)
    except Exception as e:
        try: client.close()
        except Exception: pass
        return Response(f"Failed to open shell: {e}", status=400)

    session_id = os.urandom(16).hex()
    with sessions_lock:
        sessions[session_id] = SSHSession(client=client, channel=chan)
    return Response(json.dumps({"sessionId": session_id}), mimetype="application/json")

@sock.route("/ws")
def ws(ws):
    sid = request.args.get("sid", "")
    with sessions_lock:
        s = sessions.get(sid)
    if not s:
        ws.close()
        return

    chan = s.channel

    def reader():
        try:
            while True:
                if chan.recv_ready():
                    data = chan.recv(65535)
                    if not data:
                        break
                    try:
                        ws.send(data.decode("utf-8", errors="ignore"))
                    except Exception:
                        break
                else:
                    time.sleep(0.01)
        finally:
            try:
                chan.close()
            except Exception:
                pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            try:
                chan.send(msg)
            except Exception:
                break
    finally:
        try:
            chan.close()
        except Exception:
            pass
        try:
            s.client.close()
        except Exception:
            pass
        with sessions_lock:
            sessions.pop(sid, None)
        log.info("Session %s closed", sid)

@app.route("/logs")
def logs_view():
    try:
        with open(LOG_FILE, "r") as f:
            content = f.read()[-200000:]
        return Response(content, mimetype="text/plain")
    except Exception as e:
        return Response(f"Log read error: {e}", status=500)

if __name__ == "__main__":
    print(f"Starting Web SSH on http://{APP_HOST}:{APP_PORT}")
    app.run(host=APP_HOST, port=APP_PORT, debug=False)
