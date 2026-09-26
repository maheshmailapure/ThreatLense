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

# Redirect stdout/stderr if running in windowed/noconsole mode
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

def find_app_browser():
    """Find a native Chromium/Edge executable to host the dedicated application frame."""
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
    from app.main import app
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="warning",
        access_log=False
    )

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
    Launches a dedicated native desktop window.
    No browser URL bar, no search bar, no tabs, no 'localhost' text visible.
    Behaves 100% like native Windows system security software (McAfee, Windows Defender).
    """
    # 1. Native Application Mode Window via Edge/Chrome (zero external DLL requirements)
    browser_exe = find_app_browser()
    if browser_exe:
        try:
            profile_dir = os.path.join(os.path.expanduser("~"), ".threatlense_app_profile")
            os.makedirs(profile_dir, exist_ok=True)
            cmd = [
                browser_exe,
                f"--app={url}",
                "--window-size=1400,900",
                f"--user-data-dir={profile_dir}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-translate",
                "--app-name=ThreatLense",
            ]
            proc = subprocess.Popen(cmd)
            proc.wait()
            return
        except Exception as e:
            print(f"[-] Native app window error: {e}")

    # 2. PyWebView Engine Fallback
    try:
        import webview
        window = webview.create_window(
            title="ThreatLense - Autonomous AI Cybersecurity Defense System",
            url=url,
            width=1400,
            height=900,
            min_size=(1024, 680),
            background_color="#eaf1ed",
            resizable=True,
        )
        webview.start()
        return
    except Exception as e:
        print(f"[-] PyWebView fallback error: {e}")

    # 3. Fail-safe browser fallback
    import webbrowser
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
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
