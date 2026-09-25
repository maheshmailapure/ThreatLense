"""
AI-IDS Shield - Desktop Standalone Launcher.
Starts the Intrusion Detection System backend, autonomous sensors,
serves the React UI, and opens the default web browser.
"""
import os
import sys
import time
import threading
import webbrowser
import uvicorn

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Handle PyInstaller temporary bundle path
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    os.chdir(sys._MEIPASS)

def open_browser():
    """Wait for server startup and open default browser."""
    time.sleep(2.0)
    webbrowser.open("http://127.0.0.1:8000")

def main():
    print("=" * 60)
    print("   AI-IDS CYBERSECURITY DEFENSE SHIELD - DESKTOP AGENT")
    print("=" * 60)
    print("[+] Initializing Real-Time Endpoint Sensors & Threat Engine...")
    print("[+] Serving Web Console on http://127.0.0.1:8000")
    print("[+] Launching user interface...")
    print("=" * 60)

    # Launch browser in a background daemon thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Import FastAPI application
    from app.main import app

    # Run Uvicorn server directly
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
        access_log=False
    )

if __name__ == "__main__":
    main()
