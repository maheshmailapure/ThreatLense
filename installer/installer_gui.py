"""
ThreatLense Setup Wizard - Professional Windows Installer.
Standard multi-page installation wizard with Terms & Conditions,
destination selection, desktop shortcuts, and real-time installation.
"""
import os
import sys
import time
import zipfile
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# EULA / Terms & Conditions Text
EULA_TEXT = """THREATLENSE™ AUTONOMOUS AI ENDPOINT DEFENSE & INTRUSION DETECTION
END USER LICENSE AGREEMENT & TERMS OF SERVICE

PLEASE READ CAREFULLY BEFORE INSTALLING THIS SOFTWARE.

1. ACCEPTANCE OF TERMS
By installing or using ThreatLense ("the Software"), you agree to be bound by the terms of this Agreement. If you do not agree to the terms, cancel this installation immediately.

2. REAL-TIME ENDPOINT DEFENSE & MONITORING
ThreatLense operates as a continuous defensive security sentinel on your Windows computer. The software is authorized to:
  (a) Inspect active host network connections, socket bindings, and listening ports in real time.
  (b) Monitor incoming downloaded files in your Downloads directory to intercept high-entropy payloads, malicious scripts, and trojans.
  (c) Enforce automated containment actions including Windows Firewall IP blocking (netsh advfirewall) and process termination when high-severity threats are verified.

3. ATRIA AI CLOUD INTELLIGENCE GATEWAY
ThreatLense utilizes the Atria AI Autonomous Neural Engine (Atria-Dawn-Preview) for deep forensic triage:
  (a) Token-Saver Sentinel: The AI engine sleeps during routine operating baseline (0 tokens consumed).
  (b) Autonomous Triage: AI scanning wakes automatically when suspicious ingress or downloads occur.
  (c) Telemetry: Only non-personally-identifiable forensic attributes (packet headers, connection states, file hashes, entropy) are evaluated.

4. USER PRIVACY & DATA PROTECTION
ThreatLense does not sell, harvest, or transfer your personal documents, browsing history, or private keystrokes. All local logs are stored securely on your host system.

5. SYSTEM COMPATIBILITY
ThreatLense is engineered for Windows 10, Windows 11, and compatible Windows Server architectures (64-bit).

6. DISCLAIMER OF WARRANTIES
The Software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability or fitness for a particular purpose.

Click "I accept the agreement" below if you understand and agree to these terms.
"""

def get_bundle_dir():
    """Get extraction dir if PyInstaller onefile, otherwise script dir."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

def get_default_install_dir():
    """Default install location in user's LocalAppData Programs folder (zero admin elevation required)."""
    local_app_data = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
    return os.path.join(local_app_data, 'Programs', 'ThreatLense')

class ThreatLenseInstaller(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ThreatLense Setup")
        self.geometry("620x460")
        self.minsize(580, 420)
        self.resizable(False, False)
        
        # Configure modern aesthetic styling
        self.configure(bg="#f1f5f9")
        self.install_dir = tk.StringVar(value=get_default_install_dir())
        self.create_desktop_shortcut = tk.BooleanVar(value=True)
        self.create_start_menu_shortcut = tk.BooleanVar(value=True)
        self.launch_after_install = tk.BooleanVar(value=True)
        self.license_accepted = tk.BooleanVar(value=False)
        self.current_step = 0
        self.is_installing = False

        self.setup_ui()
        self.show_page(0)

    def setup_ui(self):
        # Top Header Banner
        self.header_frame = tk.Frame(self, bg="#0f172a", height=70)
        self.header_frame.pack(side="top", fill="x")
        self.header_frame.pack_propagate(False)

        self.header_title = tk.Label(
            self.header_frame, 
            text="ThreatLense Setup", 
            font=("Segoe UI", 13, "bold"), 
            fg="#38bdf8", 
            bg="#0f172a", 
            anchor="w"
        )
        self.header_title.pack(side="top", fill="x", padx=20, pady=(12, 2))

        self.header_subtitle = tk.Label(
            self.header_frame, 
            text="Autonomous AI Intrusion Detection & Real-Time Endpoint Defense", 
            font=("Segoe UI", 9), 
            fg="#94a3b8", 
            anchor="w"
        )
        self.header_subtitle.pack(side="top", fill="x", padx=20)

        # Content Area Container
        self.content_frame = tk.Frame(self, bg="#f8fafc", padx=25, pady=18)
        self.content_frame.pack(side="top", fill="both", expand=True)

        # Bottom Navigation Bar
        self.nav_frame = tk.Frame(self, bg="#e2e8f0", height=54, padx=20)
        self.nav_frame.pack(side="bottom", fill="x")
        self.nav_frame.pack_propagate(False)

        self.btn_cancel = ttk.Button(self.nav_frame, text="Cancel", command=self.on_cancel)
        self.btn_cancel.pack(side="right", padx=(8, 0), pady=12)

        self.btn_next = ttk.Button(self.nav_frame, text="Next >", command=self.on_next)
        self.btn_next.pack(side="right", padx=(8, 0), pady=12)

        self.btn_back = ttk.Button(self.nav_frame, text="< Back", command=self.on_back)
        self.btn_back.pack(side="right", pady=12)

        # Build Wizard Pages
        self.pages = [
            self.create_welcome_page(),
            self.create_eula_page(),
            self.create_destination_page(),
            self.create_tasks_page(),
            self.create_install_page(),
            self.create_finish_page()
        ]

    # --- Page 0: Welcome ---
    def create_welcome_page(self):
        page = tk.Frame(self.content_frame, bg="#f8fafc")
        lbl_welcome = tk.Label(
            page, 
            text="Welcome to the ThreatLense Setup Wizard", 
            font=("Segoe UI", 13, "bold"), 
            fg="#0f172a", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_welcome.pack(fill="x", pady=(8, 12))

        desc_text = (
            "This wizard will install ThreatLense on your Windows computer.\n\n"
            "ThreatLense is an enterprise-grade Autonomous AI Endpoint Protection "
            "and Real-Time Network Intrusion Detection System powered by the Atria-Dawn-Preview "
            "deep reasoning neural engine.\n\n"
            "Highlights:\n"
            "  • Continuous behavioral socket monitoring (SMB, RDP, Port Scans, SYN Floods)\n"
            "  • Automatic AI triage on high-entropy & suspicious file downloads\n"
            "  • Autonomous firewall containment & process neutralization\n"
            "  • Zero-token baseline idle consumption\n\n"
            "Click Next to continue, or Cancel to exit Setup."
        )
        lbl_desc = tk.Label(
            page, 
            text=desc_text, 
            font=("Segoe UI", 9), 
            fg="#334155", 
            bg="#f8fafc", 
            justify="left", 
            anchor="nw"
        )
        lbl_desc.pack(fill="both", expand=True)
        return page

    # --- Page 1: Terms & Conditions ---
    def create_eula_page(self):
        page = tk.Frame(self.content_frame, bg="#f8fafc")
        lbl_title = tk.Label(
            page, 
            text="License Agreement & Terms of Service", 
            font=("Segoe UI", 11, "bold"), 
            fg="#0f172a", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_title.pack(fill="x", pady=(0, 6))

        lbl_instruct = tk.Label(
            page, 
            text="Please review the license terms before proceeding with installation:", 
            font=("Segoe UI", 9), 
            fg="#475569", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_instruct.pack(fill="x", pady=(0, 6))

        # Scrolled Text Box for EULA
        txt_frame = tk.Frame(page, bd=1, relief="solid")
        txt_frame.pack(fill="both", expand=True, pady=(0, 10))

        scrollbar = tk.Scrollbar(txt_frame)
        scrollbar.pack(side="right", fill="y")

        self.txt_eula = tk.Text(
            txt_frame, 
            wrap="word", 
            font=("Consolas", 8), 
            bg="#ffffff", 
            fg="#1e293b", 
            yscrollcommand=scrollbar.set,
            height=10
        )
        self.txt_eula.insert("1.0", EULA_TEXT)
        self.txt_eula.configure(state="disabled")
        self.txt_eula.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.txt_eula.yview)

        # Radio Buttons for Acceptance
        rb_frame = tk.Frame(page, bg="#f8fafc")
        rb_frame.pack(fill="x")

        def on_eula_choice():
            if self.license_accepted.get():
                self.btn_next.configure(state="normal")
            else:
                self.btn_next.configure(state="disabled")

        self.rb_accept = tk.Radiobutton(
            rb_frame, 
            text="I accept the agreement and terms of service", 
            variable=self.license_accepted, 
            value=True, 
            command=on_eula_choice,
            bg="#f8fafc", 
            font=("Segoe UI", 9, "bold"),
            fg="#0f172a"
        )
        self.rb_accept.pack(anchor="w", pady=(0, 2))

        self.rb_decline = tk.Radiobutton(
            rb_frame, 
            text="I do not accept the agreement", 
            variable=self.license_accepted, 
            value=False, 
            command=on_eula_choice,
            bg="#f8fafc", 
            font=("Segoe UI", 9),
            fg="#64748b"
        )
        self.rb_decline.pack(anchor="w")

        return page

    # --- Page 2: Select Destination ---
    def create_destination_page(self):
        page = tk.Frame(self.content_frame, bg="#f8fafc")
        lbl_title = tk.Label(
            page, 
            text="Select Destination Location", 
            font=("Segoe UI", 11, "bold"), 
            fg="#0f172a", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_title.pack(fill="x", pady=(0, 6))

        lbl_instruct = tk.Label(
            page, 
            text="Where should ThreatLense be installed on your computer?", 
            font=("Segoe UI", 9), 
            fg="#475569", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_instruct.pack(fill="x", pady=(0, 16))

        # Path Entry & Browse Button
        path_box = tk.Frame(page, bg="#f8fafc")
        path_box.pack(fill="x", pady=(0, 12))

        ent_path = ttk.Entry(path_box, textvariable=self.install_dir, font=("Segoe UI", 9))
        ent_path.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=4)

        def browse_folder():
            chosen = filedialog.askdirectory(initialdir=self.install_dir.get(), title="Select Install Folder")
            if chosen:
                self.install_dir.set(os.path.join(chosen, "ThreatLense"))

        btn_browse = ttk.Button(path_box, text="Browse...", command=browse_folder)
        btn_browse.pack(side="right")

        info_text = (
            "Standard install location places ThreatLense in your user profile,\n"
            "ensuring seamless execution without administrative privilege blocks.\n\n"
            "At least 150 MB of free disk space is required."
        )
        lbl_info = tk.Label(
            page, 
            text=info_text, 
            font=("Segoe UI", 9), 
            fg="#64748b", 
            bg="#f8fafc", 
            justify="left", 
            anchor="nw"
        )
        lbl_info.pack(fill="x", pady=(10, 0))

        return page

    # --- Page 3: Additional Tasks ---
    def create_tasks_page(self):
        page = tk.Frame(self.content_frame, bg="#f8fafc")
        lbl_title = tk.Label(
            page, 
            text="Select Additional Tasks", 
            font=("Segoe UI", 11, "bold"), 
            fg="#0f172a", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_title.pack(fill="x", pady=(0, 6))

        lbl_instruct = tk.Label(
            page, 
            text="Select additional shortcuts and options to configure during installation:", 
            font=("Segoe UI", 9), 
            fg="#475569", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_instruct.pack(fill="x", pady=(0, 18))

        cb_desktop = tk.Checkbutton(
            page, 
            text="Create a Desktop shortcut (Recommended)", 
            variable=self.create_desktop_shortcut,
            bg="#f8fafc", 
            font=("Segoe UI", 9, "bold"),
            fg="#0f172a"
        )
        cb_desktop.pack(anchor="w", pady=(0, 8))

        cb_start = tk.Checkbutton(
            page, 
            text="Create a Start Menu folder and shortcut", 
            variable=self.create_start_menu_shortcut,
            bg="#f8fafc", 
            font=("Segoe UI", 9),
            fg="#334155"
        )
        cb_start.pack(anchor="w", pady=(0, 8))

        return page

    # --- Page 4: Installing Progress ---
    def create_install_page(self):
        page = tk.Frame(self.content_frame, bg="#f8fafc")
        lbl_title = tk.Label(
            page, 
            text="Installing ThreatLense...", 
            font=("Segoe UI", 11, "bold"), 
            fg="#0f172a", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_title.pack(fill="x", pady=(0, 8))

        self.lbl_status = tk.Label(
            page, 
            text="Preparing installation components...", 
            font=("Segoe UI", 9), 
            fg="#475569", 
            bg="#f8fafc", 
            anchor="w"
        )
        self.lbl_status.pack(fill="x", pady=(0, 14))

        self.progress_bar = ttk.Progressbar(page, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", pady=(0, 8))

        self.lbl_file = tk.Label(
            page, 
            text="", 
            font=("Consolas", 8), 
            fg="#64748b", 
            bg="#f8fafc", 
            anchor="w"
        )
        self.lbl_file.pack(fill="x")

        return page

    # --- Page 5: Finish Page ---
    def create_finish_page(self):
        page = tk.Frame(self.content_frame, bg="#f8fafc")
        lbl_title = tk.Label(
            page, 
            text="Completing the ThreatLense Setup Wizard", 
            font=("Segoe UI", 13, "bold"), 
            fg="#0f172a", 
            bg="#f8fafc", 
            anchor="w"
        )
        lbl_title.pack(fill="x", pady=(8, 12))

        desc_text = (
            "ThreatLense has been successfully installed on your computer.\n\n"
            "The system is configured with real-time autonomous threat protection, "
            "automatic Downloads directory inspection, and Atria AI forensic triage.\n\n"
            "You can launch ThreatLense anytime from your Desktop or Start Menu."
        )
        lbl_desc = tk.Label(
            page, 
            text=desc_text, 
            font=("Segoe UI", 9), 
            fg="#334155", 
            bg="#f8fafc", 
            justify="left", 
            anchor="nw"
        )
        lbl_desc.pack(fill="both", expand=True, pady=(0, 14))

        cb_launch = tk.Checkbutton(
            page, 
            text="Launch ThreatLense now (Native Security Console)", 
            variable=self.launch_after_install,
            bg="#f8fafc", 
            font=("Segoe UI", 9, "bold"),
            fg="#0284c7"
        )
        cb_launch.pack(anchor="w")

        return page

    def show_page(self, index):
        for p in self.pages:
            p.pack_forget()
        self.current_step = index
        self.pages[index].pack(fill="both", expand=True)

        # Update button state and labels
        if index == 0:
            self.btn_back.configure(state="disabled")
            self.btn_next.configure(text="Next >", state="normal")
            self.header_title.configure(text="ThreatLense Setup - Welcome")
        elif index == 1:
            self.btn_back.configure(state="normal")
            self.btn_next.configure(text="Next >", state="normal" if self.license_accepted.get() else "disabled")
            self.header_title.configure(text="ThreatLense Setup - License Agreement")
        elif index == 2:
            self.btn_back.configure(state="normal")
            self.btn_next.configure(text="Next >", state="normal")
            self.header_title.configure(text="ThreatLense Setup - Destination Location")
        elif index == 3:
            self.btn_back.configure(state="normal")
            self.btn_next.configure(text="Install", state="normal")
            self.header_title.configure(text="ThreatLense Setup - Additional Tasks")
        elif index == 4:
            self.btn_back.configure(state="disabled")
            self.btn_next.configure(state="disabled")
            self.btn_cancel.configure(state="disabled")
            self.header_title.configure(text="ThreatLense Setup - Installing")
            self.start_installation()
        elif index == 5:
            self.btn_back.pack_forget()
            self.btn_cancel.pack_forget()
            self.btn_next.configure(text="Finish", state="normal")
            self.header_title.configure(text="ThreatLense Setup - Complete")

    def on_next(self):
        if self.current_step == 5:
            # Finish action
            if self.launch_after_install.get():
                target_exe = os.path.join(self.install_dir.get(), "ThreatLense.exe")
                if os.path.exists(target_exe):
                    try:
                        subprocess.Popen([target_exe], cwd=self.install_dir.get())
                    except Exception as e:
                        messagebox.showwarning("Launch Warning", f"Could not launch ThreatLense: {e}")
            self.destroy()
            sys.exit(0)
        else:
            self.show_page(self.current_step + 1)

    def on_back(self):
        if self.current_step > 0:
            self.show_page(self.current_step - 1)

    def on_cancel(self):
        if self.is_installing:
            return
        if messagebox.askyesno("Exit Setup", "Are you sure you want to cancel the installation of ThreatLense?"):
            self.destroy()
            sys.exit(0)

    def start_installation(self):
        self.is_installing = True
        t = threading.Thread(target=self._perform_installation, daemon=True)
        t.start()

    def _perform_installation(self):
        dest = self.install_dir.get()
        os.makedirs(dest, exist_ok=True)
        
        # Locate payload archive
        bundle_dir = get_bundle_dir()
        payload_zip = os.path.join(bundle_dir, "payload.zip")

        if not os.path.exists(payload_zip):
            # Development fallback
            dev_zip = os.path.abspath(os.path.join(bundle_dir, "..", "backend", "dist", "ThreatLense-Windows.zip"))
            if os.path.exists(dev_zip):
                payload_zip = dev_zip

        if not os.path.exists(payload_zip):
            self.lbl_status.config(text="Error: Could not locate installation payload archive.")
            messagebox.showerror("Installation Error", f"Installation payload not found at:\n{payload_zip}")
            self.btn_cancel.config(state="normal")
            return

        try:
            with zipfile.ZipFile(payload_zip, 'r') as zf:
                file_list = [f for f in zf.infolist() if not f.is_dir()]
                total_files = len(file_list)
                self.progress_bar['maximum'] = total_files

                for idx, item in enumerate(file_list):
                    # Unpack stripping root folder if needed
                    parts = item.filename.split('/')
                    if len(parts) > 1 and parts[0] == "ThreatLense":
                        rel_path = "/".join(parts[1:])
                    else:
                        rel_path = item.filename
                    
                    if not rel_path:
                        continue

                    target_file = os.path.join(dest, rel_path.replace('/', os.sep))
                    os.makedirs(os.path.dirname(target_file), exist_ok=True)

                    with zf.open(item) as src, open(target_file, 'wb') as dst:
                        dst.write(src.read())

                    # Update progress UI
                    if idx % 10 == 0 or idx == total_files - 1:
                        self.progress_bar['value'] = idx + 1
                        self.lbl_status.config(text=f"Extracting components ({idx + 1}/{total_files})...")
                        self.lbl_file.config(text=os.path.basename(target_file))
                        self.update_idletasks()

            # Create Desktop Shortcut
            target_exe = os.path.join(dest, "ThreatLense.exe")
            if self.create_desktop_shortcut.get():
                self.lbl_status.config(text="Creating Desktop shortcut...")
                self._create_shortcut(
                    target=target_exe, 
                    link_name="ThreatLense.lnk", 
                    folder=os.path.expanduser("~/Desktop"),
                    desc="ThreatLense - Autonomous AI Cybersecurity Defense System"
                )

            # Create Start Menu Shortcut
            if self.create_start_menu_shortcut.get():
                self.lbl_status.config(text="Creating Start Menu shortcut...")
                start_menu = os.path.join(
                    os.environ.get('APPDATA', os.path.expanduser('~\\AppData\\Roaming')),
                    "Microsoft", "Windows", "Start Menu", "Programs", "ThreatLense"
                )
                os.makedirs(start_menu, exist_ok=True)
                self._create_shortcut(
                    target=target_exe,
                    link_name="ThreatLense.lnk",
                    folder=start_menu,
                    desc="ThreatLense - Autonomous AI Cybersecurity Defense System"
                )

            # Create Uninstaller Script in the application folder
            self._create_uninstaller(dest)

            # Move to Complete page
            self.lbl_status.config(text="Installation completed successfully!")
            self.progress_bar['value'] = total_files
            time.sleep(0.5)
            self.after(100, lambda: self.show_page(5))

        except Exception as e:
            self.lbl_status.config(text=f"Installation failed: {str(e)}")
            messagebox.showerror("Error", f"Failed during installation:\n{e}")
            self.btn_cancel.config(state="normal")

    def _create_shortcut(self, target, link_name, folder, desc):
        """Creates a Windows .lnk shortcut using PowerShell and WScript.Shell."""
        try:
            link_path = os.path.join(folder, link_name)
            ps_script = f"""
            $ws = New-Object -ComObject WScript.Shell
            $s = $ws.CreateShortcut('{link_path}')
            $s.TargetPath = '{target}'
            $s.WorkingDirectory = '{os.path.dirname(target)}'
            $s.Description = '{desc}'
            $s.Save()
            """
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], creationflags=0x08000000)
        except Exception as ex:
            print("Shortcut error:", ex)

    def _create_uninstaller(self, dest):
        """Generates an uninstaller script in the application directory."""
        uninstaller_bat = os.path.join(dest, "Uninstall_ThreatLense.bat")
        content = f"""@echo off
title ThreatLense Uninstaller
echo ===============================================================================
echo                   THREATLENSE - APPLICATION REMOVAL
echo ===============================================================================
echo Are you sure you want to remove ThreatLense from your computer?
pause
echo [*] Terminating active processes...
taskkill /f /im ThreatLense.exe 2>nul
echo [*] Removing shortcuts...
del "%USERPROFILE%\\Desktop\\ThreatLense.lnk" 2>nul
rmdir /s /q "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\ThreatLense" 2>nul
echo [*] Removing application files...
cd /d "%TEMP%"
rmdir /s /q "{dest}" 2>nul
echo [SUCCESS] ThreatLense has been uninstalled.
pause
"""
        try:
            with open(uninstaller_bat, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception:
            pass

def main():
    app = ThreatLenseInstaller()
    app.mainloop()

if __name__ == "__main__":
    main()
