"""
Build script to compile ThreatLense-Setup.exe - Single Standalone Installer.
Bundles the payload archive and the Tkinter Setup Wizard into a single .exe.
"""
import os
import sys
import shutil
import subprocess

def build():
    installer_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(installer_dir, ".."))
    payload_src = os.path.join(project_root, "backend", "dist", "ThreatLense-Windows.zip")
    payload_dst = os.path.join(installer_dir, "payload.zip")

    if not os.path.exists(payload_src):
        print(f"[-] Error: Payload archive not found at: {payload_src}")
        sys.exit(1)

    print(f"[+] Staging payload archive: {payload_src} -> {payload_dst}")
    shutil.copy2(payload_src, payload_dst)

    print("[+] Compiling ThreatLense-Setup.exe via PyInstaller...")
    ico_path = os.path.join(installer_dir, "threatlense.ico")
    logo_path = os.path.join(installer_dir, "threatlense_logo.png")

    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--noconsole",
        "--name", "ThreatLense-Setup",
        f"--icon={ico_path}",
        f"--add-data={ico_path};.",
        f"--add-data={logo_path};.",
        f"--add-data={payload_dst};.",
        "--hidden-import=PIL",
        "--hidden-import=PIL.Image",
        "--hidden-import=PIL.ImageTk",
        "installer_gui.py"
    ]

    print("[+] Executing:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=installer_dir)
    if res.returncode == 0:
        exe_path = os.path.join(installer_dir, "dist", "ThreatLense-Setup.exe")
        size_mb = os.path.getsize(exe_path) / (1024 * 1024)
        print("=" * 65)
        print(f"[SUCCESS] Standalone Installer generated at: {exe_path}")
        print(f"[+] Total Installer Size: {size_mb:.2f} MB")
        print("=" * 65)
    else:
        print(f"[-] PyInstaller failed with code: {res.returncode}")
        sys.exit(res.returncode)

if __name__ == "__main__":
    build()
