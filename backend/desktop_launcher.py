"""
ThreatLense - Native Windows Desktop Application.
Runs the autonomous endpoint protection engine, background threat sentinels,
and renders the dedicated ThreatLense desktop security console window (like McAfee / Windows Defender).
"""
import os
import sys
import time
import threading
import subprocess
import urllib.request
import uvicorn

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Handle PyInstaller temporary bundle path
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    os.chdir(sys._MEIPASS)

# Configure WebView2 profile directory to prevent E_ABORT / permission issues
APP_DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ThreatLense")
PROFILE_DIR = os.path.join(APP_DATA_DIR, "WebViewProfile")
os.makedirs(PROFILE_DIR, exist_ok=True)
os.environ["WEBVIEW2_USER_DATA_FOLDER"] = PROFILE_DIR

# Redirect stdout/stderr if running in windowed/noconsole mode
LOG_FILE = os.path.join(APP_DATA_DIR, "threatlense_runtime.log")
try:
    log_fp = open(LOG_FILE, 'a', encoding='utf-8', buffering=1)
    if sys.stdout is None:
        sys.stdout = log_fp
    if sys.stderr is None:
        sys.stderr = log_fp
except Exception:
    if sys.stdout is None:
        sys.stdout = open(os.devnull, 'w')
    if sys.stderr is None:
        sys.stderr = open(os.devnull, 'w')

def log_debug(msg):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

def global_excepthook(exc_type, exc_value, exc_tb):
    import traceback
    err = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log_debug(f"UNCAUGHT FATAL EXCEPTION:\n{err}")
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, f"ThreatLense Fatal Error:\n{err[:400]}", "ThreatLense Alert", 0x10)
    except Exception:
        pass

sys.excepthook = global_excepthook

def get_app_icon():
    """Locate ThreatLense shield icon for the native window frame."""
    candidates = []
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        candidates.append(os.path.join(sys._MEIPASS, "threatlense.ico"))
    candidates.extend([
        os.path.join(BASE_DIR, "threatlense.ico"),
        os.path.join(os.path.dirname(sys.executable), "threatlense.ico"),
        os.path.join(APP_DATA_DIR, "ThreatLense", "threatlense.ico"),
        os.path.join(APP_DATA_DIR, "threatlense.ico"),
    ])
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return None

def find_app_browser():
    """Find a native Chromium/Edge executable to host dedicated standalone window fallback."""
    candidates = [
        # Microsoft Edge (Built into 100% of Windows 10 & 11)
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
        # Google Chrome
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        # Brave Browser
        os.path.expandvars(r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"),
        os.path.expandvars(r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

def start_backend():
    """Runs FastAPI backend engine in a dedicated background daemon thread."""
    try:
        log_debug("Starting FastAPI backend engine on 127.0.0.1:8000...")
        from app.main import app
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=8000,
            log_level="warning",
            access_log=False
        )
    except Exception as e:
        import traceback
        log_debug(f"FastAPI backend exception: {e}\n{traceback.format_exc()}")

def wait_for_server(url="http://127.0.0.1:8000/api/health", timeout=15):
    """Wait until backend server is initialized and responding."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ThreatLense-Desktop"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    return False

def run_native_app_window(url="http://127.0.0.1:8000"):
    """
    Renders the dedicated native Windows desktop security suite window.
    NEVER opens a web browser tab or browser URL bar.
    Operates 100% like native Windows system security software (McAfee, Windows Defender).
    """
    icon_path = get_app_icon()

    # 1. Primary Engine: PyWebView Native Win32 / EdgeChromium Window
    try:
        log_debug(f"Attempting PyWebView native window on {url} (icon: {icon_path})...")
        import webview
        window = webview.create_window(
            title="ThreatLense - Autonomous AI Cybersecurity Defense System",
            url=url,
            width=1440,
            height=900,
            min_size=(1024, 680),
            background_color="#0a0f1d",
            resizable=True,
            text_select=True,
            confirm_close=False,
        )
        log_debug("PyWebView window created successfully, invoking webview.start()...")
        webview.start(
            gui="edgechromium",
            debug=False,
            private_mode=False,
            storage_path=PROFILE_DIR,
            icon=icon_path
        )
        log_debug("PyWebView window closed cleanly by user.")
        return
    except Exception as e:
        import traceback
        log_debug(f"PyWebView native window error: {e}\n{traceback.format_exc()}")

    # 2. Secondary Engine: Standalone Frameless Chromium App Mode (Edge / Chrome)
    browser_exe = find_app_browser()
    if browser_exe:
        try:
            app_profile = os.path.join(APP_DATA_DIR, "AppBrowserProfile")
            os.makedirs(app_profile, exist_ok=True)
            cmd = [
                browser_exe,
                f"--app={url}",
                "--window-size=1440,900",
                f"--user-data-dir={app_profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-translate",
                "--app-name=ThreatLense",
            ]
            proc = subprocess.Popen(cmd)
            time.sleep(2)
            lock_file = os.path.join(app_profile, "lockfile")
            if os.path.exists(lock_file):
                while os.path.exists(lock_file):
                    time.sleep(1)
            else:
                proc.wait()
            return
        except Exception as e:
            print(f"[-] Standalone app mode error: {e}", file=sys.stderr)

    # 3. Native system error dialog if neither native window engine initialized
    # Never open regular web browser tabs
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0,
            "ThreatLense could not initialize the desktop security window.\n"
            "Please ensure Microsoft Edge or WebView2 Runtime is installed on Windows.",
            "ThreatLense - System Defense Alert",
            0x10
        )
    except Exception:
        pass

def main():
    print("=" * 65)
    print("       THREATLENSE - NATIVE ENDPOINT SECURITY SYSTEM")
    print("=" * 65)
    print("[+] Starting Autonomous Threat Sentinels & Telemetry Engine...")
    print("[+] Initializing Native Desktop Security Console Window...")
    print("=" * 65)

    # 1. Start backend server in background thread
    server_thread = threading.Thread(target=start_backend, daemon=True)
    server_thread.start()

    # 2. Wait for backend to be ready
    wait_for_server()

    # 3. Launch Native Window (Zero browser chrome, McAfee-style app window)
    run_native_app_window("http://127.0.0.1:8000")

    # 4. Clean exit when window closes
    sys.exit(0)

if __name__ == "__main__":
    main()
