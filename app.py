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

# ---- Config ----
APP_HOST = "127.0.0.1"
APP_PORT = 5000
MAX_KEY_SIZE = 1024 * 1024  # 1 MB
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

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
<html>
<head>
  <meta charset="utf-8" />
  <title>Web SSH</title>
  <style>
    :root { --pad: 16px; --hdr: 48px; }
    html, body { height: 100%; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0; }
    .container { max-width: 960px; margin: 24px auto; padding: 0 var(--pad); }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: var(--pad); }
    label { display: block; margin-top: 10px; font-weight: 600; }
    input, select { width: 100%; padding: 8px; margin-top: 6px; }
    .row { display: flex; gap: 12px; }
    .col { flex: 1; }
    .btn { margin-top: 16px; padding: 10px 14px; background: #0b5ed7; color: #fff; border: none; border-radius: 6px; cursor: pointer; }
    .btn.secondary { background: #555; }
    .btn.warn { background: #c0392b; }
    .btn.ghost { background: #2d3436; }
    .btn:disabled { background: #9bbaf0; }
    .note { color: #555; font-size: 0.9em; }
    #terminal { width: 100%; height: 70vh; background: #000; color: #fff; margin-top: var(--pad); border-radius: 8px; overflow: hidden; }
    .hidden { display: none; }
    .row-inline { display:flex; gap: 8px; align-items:center; flex-wrap: wrap; }
    .row-inline a { text-decoration: none; }
    /* Fullscreen overlay just for terminal */
    #fsOverlay.hidden { display: none; }
    #fsOverlay {
      position: fixed; inset: 0;
      background: #111; z-index: 9999; display: flex; flex-direction: column;
    }
    #fsHeader {
      height: var(--hdr); min-height: var(--hdr); display: flex; align-items: center; justify-content: space-between;
      padding: 0 var(--pad); color: #fff; background: #0b5ed7;
      font-weight: 600;
    }
    #fsHeader .info { display: flex; align-items: baseline; gap: 12px; }
    #fsHeader .info .dim { opacity: 0.85; font-weight: 500; }
    #fsHeader .actions { display: flex; gap: 8px; }
    #fsHeader .actions .btn { margin-top: 0; border-radius: 6px; }
    #fsTerminalWrap { flex: 1; padding: 8px; }
    #terminalFS {
      width: 100%; height: calc(100vh - var(--hdr) - 16px);
      background: #000; color: #fff; border-radius: 6px; overflow: hidden;
    }
  </style>
  <link rel="stylesheet" href="https://unpkg.com/xterm/css/xterm.css" />
  <script src="https://unpkg.com/xterm/lib/xterm.js"></script>
  <script src="https://unpkg.com/xterm-addon-fit/lib/xterm-addon-fit.js"></script>
</head>
<body>
  <div id="wrap" class="container">
    <h2>Web SSH (PuTTY-like)</h2>
    <div class="card">
      <form id="connForm" enctype="multipart/form-data">
        <div class="row">
          <div class="col">
            <label>Host/IP</label>
            <input name="host" required placeholder="e.g. 203.0.113.10">
          </div>
          <div class="col">
            <label>Port</label>
            <input name="port" type="number" value="22" required>
          </div>
        </div>
        <div class="row">
          <div class="col">
            <label>Username</label>
            <input name="username" required placeholder="e.g. ubuntu">
          </div>
          <div class="col">
            <label>Password (optional if using key)</label>
            <input name="password" type="password" placeholder="">
          </div>
        </div>
        <label>Private key (OpenSSH .pem or PuTTY .ppk)</label>
        <input name="pkey" type="file" accept=".pem,.ppk,.key,.txt">
        <label>Key passphrase (if the private key is encrypted)</label>
        <input name="passphrase" type="password">
        <p class="note">
          .ppk will be converted via puttygen; install with: brew install putty. Use “Test only” first; check “View logs” for details if it fails.
        </p>
        <div class="row-inline">
          <button class="btn" type="submit" id="connectBtn">Connect</button>
          <button class="btn secondary" type="button" id="testBtn" title="Test credentials without opening a terminal">Test only</button>
          <button class="btn warn hidden" type="button" id="disconnectBtn">Disconnect</button>
          <button class="btn ghost hidden" type="button" id="fullscreenBtn">Fullscreen</button>
          <a class="note" href="/logs" target="_blank">View logs</a>
        </div>
      </form>
    </div>
    <div id="termCard" class="card hidden">
      <div id="terminal"></div>
    </div>
  </div>

  <!-- Fullscreen overlay just for the terminal pane -->
  <div id="fsOverlay" class="hidden">
    <div id="fsHeader">
      <div class="info">
        <div>Connected:</div>
        <div id="fsUserHost" class="dim"></div>
      </div>
      <div class="actions">
        <button class="btn warn" type="button" id="fsDisconnectBtn">Disconnect</button>
        <button class="btn secondary" type="button" id="fsExitBtn">Leave Fullscreen</button>
      </div>
    </div>
    <div id="fsTerminalWrap">
      <div id="terminalFS"></div>
    </div>
  </div>

  <script>
    const fitAddon = new window.FitAddon.FitAddon();
    const term = new window.Terminal({ cursorBlink: true, convertEol: true, fontSize: 14 });
    term.loadAddon(fitAddon);

    const form = document.getElementById('connForm');
    const connectBtn = document.getElementById('connectBtn');
    const testBtn = document.getElementById('testBtn');
    const disconnectBtn = document.getElementById('disconnectBtn');
    const fullscreenBtn = document.getElementById('fullscreenBtn');
    const termCard = document.getElementById('termCard');

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

    function updateUI(connected) {
      disconnectBtn.classList.toggle('hidden', !connected);
      fullscreenBtn.classList.toggle('hidden', !connected);
      termCard.classList.toggle('hidden', !connected);
      connectBtn.disabled = connected;
      testBtn.disabled = connected;
    }

    function openTerminalInNormalPane() {
      // Mount terminal into normal card
      if (!term.element || term.element.parentElement !== terminalNormal) {
        terminalNormal.innerHTML = '';
        term.open(terminalNormal);
      }
      setTimeout(() => fitAddon.fit(), 50);
      term.focus();
    }

    function openTerminalInFullscreenPane() {
      // Move terminal into fullscreen container
      if (!term.element || term.element.parentElement !== terminalFS) {
        terminalFS.innerHTML = '';
        term.open(terminalFS);
      }
      setTimeout(() => fitAddon.fit(), 50);
      term.focus();
    }

    function connectWS(sessionId) {
      currentSid = sessionId;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const wsUrl = `${proto}://${location.host}/ws?sid=${encodeURIComponent(sessionId)}`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        openTerminalInNormalPane();
        term.write("\\x1b[32mConnected.\\x1b[0m\\r\\n");
        window.addEventListener('resize', () => fitAddon.fit());
        updateUI(true);
      };

      ws.onmessage = (ev) => term.write(ev.data);

      ws.onclose = () => {
        term.write("\\r\\n\\x1b[31mDisconnected.\\x1b[0m\\r\\n");
        updateUI(false);
        if (inFullscreen) exitFullscreen();
        currentSid = null;
      };

      term.onData((d) => {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(d);
      });
    }

    async function disconnectSession() {
      try { if (ws && ws.readyState === WebSocket.OPEN) ws.close(); } catch (e) {}
      if (currentSid) {
        try { await fetch(`/close?sid=${encodeURIComponent(currentSid)}`, { method: 'POST' }); } catch (e) {}
      }
      updateUI(false);
      if (inFullscreen) exitFullscreen();
    }

    function enterFullscreen() {
      inFullscreen = true;
      fsUserHost.textContent = `${lastUser}@${lastHost}:${lastPort}`;
      fsOverlay.classList.remove('hidden');
      openTerminalInFullscreenPane();
    }

    function exitFullscreen() {
      inFullscreen = false;
      fsOverlay.classList.add('hidden');
      openTerminalInNormalPane();
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      // Cache current user/host for header
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

    fullscreenBtn.addEventListener('click', () => {
      if (!currentSid) return;
      enterFullscreen();
    });

    fsExitBtn.addEventListener('click', () => {
      exitFullscreen();
    });

    fsDisconnectBtn.addEventListener('click', () => {
      disconnectSession();
    });

    disconnectBtn.addEventListener('click', disconnectSession);
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
