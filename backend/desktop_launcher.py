"""
ThreatLense - Native Windows Desktop Application.
Runs the autonomous endpoint protection engine, background threat sentinels,
and renders the dedicated ThreatLense desktop security console window (like McAfee / Windows Defender).
"""
import os
import sys
import time
import shutil
import socket
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

APP_DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ThreatLense")
os.makedirs(APP_DATA_DIR, exist_ok=True)
LOG_FILE = os.path.join(APP_DATA_DIR, "threatlense_runtime.log")

def log_debug(msg):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

# Redirect stdout/stderr if running in windowed/noconsole mode
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

def ensure_single_instance():
    """Guarantee only one instance runs. Bring existing window to front on double-click."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        mutex = kernel32.CreateMutexW(None, False, "ThreatLense_App_Single_Instance_v1")
        if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            log_debug("Instance already running. Activating existing window...")
            hwnd = user32.FindWindowW(None, "ThreatLense - Autonomous AI Cybersecurity Defense System")
            if hwnd:
                user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
            sys.exit(0)
        return mutex
    except Exception as e:
        log_debug(f"Single instance check notice: {e}")
        return None

def get_clean_webview_profile():
    """
    Generate an isolated, PID-unique profile folder.
    Guarantees 0x800700AA (resource in use) errors can NEVER occur.
    """
    base_wv = os.path.join(APP_DATA_DIR, "WebViewProfiles")
    os.makedirs(base_wv, exist_ok=True)

    # Clean up stale session directories from dead processes
    try:
        for item in os.listdir(base_wv):
            if item.startswith("Session_"):
                folder = os.path.join(base_wv, item)
                try:
                    shutil.rmtree(folder, ignore_errors=True)
                except Exception:
                    pass
    except Exception:
        pass

    session_profile = os.path.join(base_wv, f"Session_{os.getpid()}")
    os.makedirs(session_profile, exist_ok=True)
    os.environ["WEBVIEW2_USER_DATA_FOLDER"] = session_profile
    return session_profile

def find_free_port(preferred=8000):
    """Find an available port. Uses 8000 if open, or an ephemeral port if occupied."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', preferred))
            return preferred
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
    except Exception:
        return preferred

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
    """Find a native Chromium/Edge executable for standalone app window fallback."""
    candidates = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"),
        os.path.expandvars(r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

def start_backend(port):
    """Runs FastAPI backend engine in a dedicated background daemon thread."""
    try:
        log_debug(f"Starting FastAPI backend engine on 127.0.0.1:{port}...")
        from app.main import app
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False
        )
    except Exception as e:
        import traceback
        log_debug(f"FastAPI backend exception: {e}\n{traceback.format_exc()}")

def wait_for_server(port, timeout=20):
    """Wait until backend server is initialized and responding."""
    url = f"http://127.0.0.1:{port}/api/health"
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ThreatLense-Desktop"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    log_debug(f"Backend server is healthy and responding on port {port}.")
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    log_debug(f"Warning: Backend server did not respond within {timeout}s.")
    return False

def cleanup_session_processes(profile_dir):
    """Terminate lingering msedgewebview2 processes belonging to this session."""
    try:
        import psutil
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = (proc.info.get('name') or '').lower()
                if 'webview2' in name:
                    cmdline = " ".join(proc.info.get('cmdline') or []).lower()
                    if profile_dir.lower() in cmdline:
                        proc.kill()
            except Exception:
                pass
    except Exception:
        pass

def run_native_app_window(url, profile_dir):
    """
    Renders the dedicated native Windows desktop security suite window.
    NEVER opens a web browser tab or browser URL bar.
    Operates 100% like native Windows system security software (McAfee, Windows Defender).
    """
    icon_path = get_app_icon()

    # 1. Primary Engine: PyWebView Native Win32 / EdgeChromium Window
    try:
        log_debug(f"Opening PyWebView native window for {url} (profile: {profile_dir})...")
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
        webview.start(
            gui="edgechromium",
            debug=False,
            private_mode=False,
            storage_path=profile_dir,
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
            log_debug(f"Launching standalone app mode fallback with {browser_exe}...")
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
            log_debug(f"Standalone app mode error: {e}")

    # 3. Native system error dialog if neither native window engine initialized
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
    log_debug("=" * 65)
    log_debug("       THREATLENSE - NATIVE ENDPOINT SECURITY SYSTEM")
    log_debug("=" * 65)

    # 1. Single Instance Protection (Focus existing if already running)
    _mutex = ensure_single_instance()

    # 2. Configure clean, collision-free WebView2 profile
    profile_dir = get_clean_webview_profile()

    # 3. Select open port (8000 or next available)
    port = find_free_port(8000)
    log_debug(f"[+] Selected network port: {port}")

    # 4. Start backend server in daemon thread
    server_thread = threading.Thread(target=start_backend, args=(port,), daemon=True)
    server_thread.start()

    # 5. Wait for backend to be ready
    wait_for_server(port)

    # 6. Launch Native Security Console Window
    url = f"http://127.0.0.1:{port}"
    run_native_app_window(url, profile_dir)

    # 7. Cleanup session processes and clean exit
    cleanup_session_processes(profile_dir)
    sys.exit(0)

if __name__ == "__main__":
    main()
