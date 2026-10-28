"""
Remote Chrome di Streamlit (Xvfb + x11vnc + noVNC + remote debugging port) + LOGIN.

=== INSTALL (di server Debian/Ubuntu) ===
    sudo apt-get update
    sudo apt-get install -y xvfb x11vnc novnc websockify fluxbox xdotool chromium
    #  (Ubuntu: lebih stabil pakai Google Chrome .deb daripada chromium snap)
    pip install streamlit

=== JALANKAN ===
    export APP_PASSWORD='password-login-streamlit-kamu'
    streamlit run remote_chrome_app.py --server.address 127.0.0.1

  (alternatif: isi .streamlit/secrets.toml ->  APP_PASSWORD = "..." )

=== AKSES DARI LAPTOP (SSH tunnel) ===
    ssh -L 8501:127.0.0.1:8501 -L 6080:127.0.0.1:6080 -L 9222:127.0.0.1:9222 user@IP_SERVER
    buka  http://localhost:8501
"""
import hmac
import json
import os
import secrets
import shutil
import signal
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

RUN_DIR = Path.home() / ".remote_chrome_streamlit"
LOG_DIR = RUN_DIR / "logs"
PROFILE_DIR = RUN_DIR / "chrome-profile"
for d in (RUN_DIR, LOG_DIR, PROFILE_DIR):
    d.mkdir(parents=True, exist_ok=True)

SERVICES = ["xvfb", "wm", "x11vnc", "novnc", "chrome"]

st.set_page_config(page_title="Remote Chrome", page_icon="🖥️", layout="wide")


# =====================================================================
# LOGIN
# =====================================================================
def get_app_password():
    pw = os.environ.get("APP_PASSWORD", "")
    if not pw:
        try:
            pw = st.secrets.get("APP_PASSWORD", "")
        except Exception:
            pw = ""
    return pw


@st.cache_resource
def login_state():
    # dibagi lintas sesi supaya brute-force lewat tab baru tidak lolos
    return {"fails": 0, "locked_until": 0.0}


def require_login():
    app_pw = get_app_password()
    if not app_pw:
        # Tanpa APP_PASSWORD -> langsung masuk (tanpa login).
        st.session_state["auth_ok"] = True
        st.session_state["no_login_mode"] = True
        return

    if st.session_state.get("auth_ok"):
        return

    ls = login_state()
    st.title("🔐 Login")
    remaining = ls["locked_until"] - time.time()
    if remaining > 0:
        st.error(f"Terlalu banyak percobaan gagal. Coba lagi dalam {int(remaining)} detik.")
        st.stop()

    with st.form("login"):
        pw = st.text_input("Password", type="password")
        ok = st.form_submit_button("Masuk")
    if ok:
        if hmac.compare_digest(pw.encode(), app_pw.encode()):
            ls["fails"] = 0
            st.session_state["auth_ok"] = True
            st.rerun()
        else:
            ls["fails"] += 1
            if ls["fails"] >= 5:
                ls["locked_until"] = time.time() + 60
                ls["fails"] = 0
            time.sleep(1)
            st.error("Password salah.")
    st.stop()


require_login()


# =====================================================================
# HELPERS & MANAGER
# =====================================================================
def find_bin(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def find_novnc_dir():
    for d in ("/usr/share/novnc", "/opt/novnc"):
        if os.path.isfile(os.path.join(d, "vnc.html")):
            return d
    return None


class Manager:
    """Menyimpan proses; hidup selama server Streamlit hidup (cache_resource)."""

    def __init__(self):
        self.procs = {}
        # x11vnc hanya memakai 8 karakter pertama password
        self.default_vnc_pass = os.environ.get("VNC_PASS") or secrets.token_urlsafe(6)[:8]

    def running(self, name):
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def _spawn(self, name, cmd, env=None):
        if self.running(name):
            return
        log = open(LOG_DIR / f"{name}.log", "w")
        self.procs[name] = subprocess.Popen(
            cmd, stdout=log, stderr=subprocess.STDOUT, env=env,
            start_new_session=True,  # supaya bisa dibunuh satu grup
        )

    def start(self, cfg):
        xvfb = find_bin("Xvfb")
        wm = find_bin("fluxbox", "openbox", "icewm")
        x11vnc = find_bin("x11vnc")
        websockify = find_bin("websockify")
        chrome = cfg["chrome_bin"] or find_bin(
            "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"
        )
        novnc_dir = find_novnc_dir()

        missing = [label for label, val in [
            ("Xvfb", xvfb), ("window manager (fluxbox)", wm), ("x11vnc", x11vnc),
            ("websockify", websockify), ("Chrome/Chromium", chrome),
            ("noVNC (/usr/share/novnc)", novnc_dir)] if not val]
        if missing:
            return "Belum terpasang: " + ", ".join(missing)

        disp = cfg["display"]
        env = dict(os.environ, DISPLAY=disp)
        w, h = cfg["width"], cfg["height"]

        self._spawn("xvfb", [xvfb, disp, "-screen", "0", f"{w}x{h}x24", "-nolisten", "tcp"])
        time.sleep(1)
        self._spawn("wm", [wm], env=env)
        time.sleep(0.5)

        passfile = RUN_DIR / "vncpass"
        subprocess.run([x11vnc, "-storepasswd", cfg["vnc_pass"], str(passfile)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._spawn("x11vnc", [x11vnc, "-display", disp, "-rfbport", str(cfg["vnc_port"]),
                               "-rfbauth", str(passfile), "-localhost", "-forever",
                               "-shared", "-noxdamage"])
        self._spawn("novnc", [websockify, "--web", novnc_dir,
                              f"127.0.0.1:{cfg['novnc_port']}", f"127.0.0.1:{cfg['vnc_port']}"])

        self._spawn("chrome", [
            chrome,
            "--no-sandbox",
            f"--user-data-dir={PROFILE_DIR}",
            "--remote-debugging-address=127.0.0.1",
            f"--remote-debugging-port={cfg['debug_port']}",
            "--window-position=0,0",
            f"--window-size={w},{h}",
            "--no-first-run",
            "--no-default-browser-check",
            cfg["start_url"],
        ], env=env)
        time.sleep(2)
        return None

    def stop(self):
        for name in reversed(SERVICES):
            p = self.procs.get(name)
            if p and p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                except Exception:
                    p.terminate()
                try:
                    p.wait(timeout=5)
                except Exception:
                    try:
                        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                    except Exception:
                        pass
        self.procs.clear()


@st.cache_resource
def get_manager():
    return Manager()


def cdp(port, path, method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    with urllib.request.urlopen(req, timeout=5) as r:
        body = r.read().decode()
    try:
        return json.loads(body)
    except Exception:
        return body


# =====================================================================
# UI
# =====================================================================
st.title("🖥️ Remote Chrome (X11 + noVNC + Debug Port)")
if st.session_state.get("no_login_mode"):
    st.warning("Mode tanpa login aktif (APP_PASSWORD tidak diatur). "
               "Pastikan Streamlit hanya diakses lewat 127.0.0.1 / SSH tunnel.")
mgr = get_manager()

with st.sidebar:
    if st.button("🚪 Logout"):
        st.session_state["auth_ok"] = False
        st.rerun()
    st.header("Pengaturan")
    width = st.number_input("Lebar layar", 800, 3840, 1366, step=2)
    height = st.number_input("Tinggi layar", 600, 2160, 768, step=2)
    display = st.text_input("DISPLAY", ":99")
    novnc_port = st.number_input("Port noVNC", 1024, 65535, 6080)
    vnc_port = st.number_input("Port VNC (internal)", 1024, 65535, 5900)
    debug_port = st.number_input("Port Remote Debugging", 1024, 65535, 9222)
    vnc_pass = st.text_input(
        "Password VNC (maks 8 karakter dipakai)", mgr.default_vnc_pass, type="password"
    )
    start_url = st.text_input("URL awal", "https://www.google.com")
    chrome_bin = st.text_input("Path Chrome (kosong = auto)", "")
    st.divider()
    host = st.text_input(
        "Host untuk iframe noVNC", "localhost",
        help="Alamat yang dipakai BROWSER KAMU untuk menjangkau noVNC. "
             "Pakai 'localhost' bila lewat SSH tunnel, atau IP/domain server.",
    )
    autopass = st.checkbox("Auto-isi password VNC di URL", value=True,
                           help="Praktis; password terlihat di URL iframe. "
                                "Aman selama halaman ini sudah dilindungi login.")
    iframe_h = st.slider("Tinggi iframe", 400, 1400, 800, step=50)

cfg = dict(width=int(width), height=int(height), display=display,
           novnc_port=int(novnc_port), vnc_port=int(vnc_port),
           debug_port=int(debug_port), vnc_pass=vnc_pass[:8],
           start_url=start_url, chrome_bin=chrome_bin.strip())

b1, b2, b3, _ = st.columns([1, 1, 1, 5])
if b1.button("▶ Start", type="primary"):
    with st.spinner("Menjalankan layanan..."):
        err = mgr.start(cfg)
    if err:
        st.error(err)
    else:
        st.rerun()
if b2.button("■ Stop"):
    mgr.stop()
    st.rerun()
if b3.button("⟳ Refresh"):
    st.rerun()

cols = st.columns(len(SERVICES))
for c, n in zip(cols, SERVICES):
    c.metric(n, "🟢 jalan" if mgr.running(n) else "🔴 mati")

all_up = all(mgr.running(n) for n in SERVICES)

tab_view, tab_tabs, tab_logs = st.tabs(["Browser (noVNC)", "Tab Chrome (CDP)", "Log"])

with tab_view:
    if all_up:
        q = "autoconnect=true&resize=scale"
        if autopass:
            q += "&password=" + urllib.parse.quote(cfg["vnc_pass"])
        url = f"http://{host}:{cfg['novnc_port']}/vnc.html?{q}"
        shown = url.split("&password=")[0] + ("&password=***" if autopass else "")
        st.caption(f"noVNC: {shown}")
        components.iframe(url, height=iframe_h, scrolling=False)
        st.caption("Jika iframe kosong, pastikan port noVNC terjangkau dari browser kamu "
                   "(SSH tunnel jalan), atau buka link di tab baru.")
    else:
        st.info("Tekan **Start** untuk menjalankan Chrome dan noVNC.")

with tab_tabs:
    if not mgr.running("chrome"):
        st.info("Chrome belum berjalan.")
    else:
        dp = cfg["debug_port"]
        st.write(f"Endpoint CDP: `http://127.0.0.1:{dp}`  |  "
                 f"Playwright: `connect_over_cdp(\"http://127.0.0.1:{dp}\")`")
        c1, c2 = st.columns([5, 1])
        new_url = c1.text_input("Buka URL di tab baru", "https://", label_visibility="collapsed")
        if c2.button("Buka"):
            try:
                cdp(dp, "/json/new?" + urllib.parse.quote(new_url, safe=":/?&=#%"), method="PUT")
            except Exception as e:
                st.error(f"Gagal: {e}")
            else:
                st.rerun()
        try:
            tabs = [t for t in cdp(dp, "/json") if t.get("type") == "page"]
            for t in tabs:
                r1, r2, r3 = st.columns([6, 1, 1])
                r1.write(f"**{t.get('title', '')[:60]}**  \n`{t.get('url', '')[:100]}`")
                if r2.button("Fokus", key="f" + t["id"]):
                    cdp(dp, f"/json/activate/{t['id']}")
                    st.rerun()
                if r3.button("Tutup", key="c" + t["id"]):
                    cdp(dp, f"/json/close/{t['id']}")
                    st.rerun()
        except Exception as e:
            st.warning(f"Belum bisa baca daftar tab: {e}")

with tab_logs:
    for n in SERVICES:
        f = LOG_DIR / f"{n}.log"
        with st.expander(n):
            st.code(f.read_text()[-3000:] if f.exists() else "(kosong)")
