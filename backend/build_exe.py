"""
Build script to compile AI-IDS-Shield into a standalone Windows executable.
Bundles the FastAPI backend, background security sensors, and compiled React frontend.
"""
import os
import sys
import subprocess
import shutil

def build():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(backend_dir, ".."))
    frontend_dist = os.path.join(project_root, "frontend", "dist")

    if not os.path.exists(frontend_dist):
        print(f"[-] Error: Frontend dist directory not found at {frontend_dist}")
        print("[-] Please run 'npm.cmd run build' in frontend first.")
        sys.exit(1)

    print(f"[+] Found frontend distribution at {frontend_dist}")
    print("[+] Packaging AI-IDS Shield into standalone Windows executable...")

    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--onedir",
        "--name", "AI-IDS-Shield",
        f"--add-data={frontend_dist};frontend_dist",
        "--hidden-import=uvicorn.logging",
        "--hidden-import=uvicorn.loops",
        "--hidden-import=uvicorn.loops.auto",
        "--hidden-import=uvicorn.protocols",
        "--hidden-import=uvicorn.protocols.http",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.protocols.websockets",
        "--hidden-import=uvicorn.protocols.websockets.auto",
        "--hidden-import=uvicorn.lifespan",
        "--hidden-import=uvicorn.lifespan.on",
        "--hidden-import=engineio.async_drivers.asgi",
        "--hidden-import=sklearn",
        "--hidden-import=psutil",
        "--hidden-import=dotenv",
        "desktop_launcher.py"
    ]

    print("[+] Executing command:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=backend_dir)
    if res.returncode == 0:
        exe_path = os.path.join(backend_dir, "dist", "AI-IDS-Shield", "AI-IDS-Shield.exe")
        print(f"[+] Build succeeded! Executable generated at: {exe_path}")
    else:
        print(f"[-] PyInstaller failed with code {res.returncode}")
        sys.exit(res.returncode)

if __name__ == "__main__":
    build()
