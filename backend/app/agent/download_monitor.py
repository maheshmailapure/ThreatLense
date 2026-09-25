import os
import time
import math
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.utils.logger import logger, log_event

DOWNLOAD_EXTENSIONS_IN_PROGRESS = {".crdownload", ".tmp", ".part", ".download", ".partial"}
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".js", ".wsf", ".jar", ".dll"}

class DownloadMonitor:
    """
    Monitors the Windows user Downloads and Temp directories in real-time.
    Detects in-progress browser downloads as they start, inspects file extensions,
    calculates Shannon entropy, and tracks quarantine vault actions.
    """
    def __init__(self, watch_dir: Optional[str] = None):
        if watch_dir and os.path.exists(watch_dir):
            self.watch_dir = watch_dir
        else:
            self.watch_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        
        self.quarantine_dir = os.path.join(os.path.expanduser("~"), ".ai_ids_quarantine")
        os.makedirs(self.watch_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

        self._known_files: Dict[str, float] = {}
        self._in_progress_downloads: Dict[str, Dict[str, Any]] = {}
        self._recent_inspections: List[Dict[str, Any]] = []

        # Index existing files on startup so existing downloads are never falsely flagged
        try:
            for entry in os.scandir(self.watch_dir):
                if entry.is_file():
                    self._known_files[entry.name] = entry.stat().st_mtime
        except Exception:
            pass

    def _calc_entropy(self, filepath: str) -> float:
        """Calculate Shannon entropy for a given file."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(65536) # Read up to 64KB
            if not data:
                return 0.0
            occ = {}
            for byte in data:
                occ[byte] = occ.get(byte, 0) + 1
            length = len(data)
            entropy = -sum((count / length) * math.log2(count / length) for count in occ.values())
            return round(entropy, 3)
        except Exception:
            return 0.0

    def _calc_sha256(self, filepath: str) -> str:
        """Compute SHA256 hash safely."""
        try:
            h = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "N/A"

    def scan(self) -> Dict[str, Any]:
        """Perform a real-time inspection of the watched downloads directory."""
        now = time.time()
        in_progress: List[Dict[str, Any]] = []
        recent_files: List[Dict[str, Any]] = []
        new_threats: List[Dict[str, Any]] = []

        try:
            entries = os.scandir(self.watch_dir)
            sorted_entries = sorted(entries, key=lambda e: e.stat().st_mtime, reverse=True)[:50]
        except Exception as err:
            logger.warn(f"Download monitor access error: {err}")
            sorted_entries = []

        for entry in sorted_entries:
            try:
                if not entry.is_file():
                    continue

                filepath = entry.path
                filename = entry.name
                stat = entry.stat()
                size_bytes = stat.st_size
                mtime = stat.st_mtime

                # Check if download is in-progress
                ext = os.path.splitext(filename)[1].lower()
                is_downloading = ext in DOWNLOAD_EXTENSIONS_IN_PROGRESS

                # Check for double extension evasion (e.g. invoice.pdf.exe)
                has_double_ext = False
                parts = filename.split('.')
                if len(parts) > 2 and f".{parts[-1].lower()}" in SUSPICIOUS_EXTENSIONS:
                    has_double_ext = True

                file_info = {
                    "filename": filename,
                    "filepath": filepath,
                    "size_bytes": size_bytes,
                    "size_kb": round(size_bytes / 1024, 2),
                    "extension": ext,
                    "modified_time": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "is_in_progress": is_downloading,
                    "has_double_extension": has_double_ext
                }

                if is_downloading:
                    in_progress.append(file_info)

                # Only inspect newly downloaded files (within last 180s and not previously inspected)
                is_previously_known = filename in self._known_files and abs(mtime - self._known_files[filename]) < 1.0
                if not is_previously_known and (now - mtime < 180):
                    self._known_files[filename] = mtime
                    entropy = self._calc_entropy(filepath)
                    file_info["entropy"] = entropy
                    
                    # Risk evaluation: double extension or script/executable with high entropy
                    is_suspicious = has_double_ext or (ext in SUSPICIOUS_EXTENSIONS and entropy > 7.3)
                    file_info["is_suspicious"] = is_suspicious
                    file_info["risk_level"] = "SUSPICIOUS" if is_suspicious else "LOW"

                    if is_suspicious:
                        file_info["sha256"] = self._calc_sha256(filepath)
                        new_threats.append(file_info)

                    recent_files.append(file_info)

            except Exception:
                continue

        # Quarantine count
        quarantined_count = 0
        try:
            quarantined_count = len([f for f in os.listdir(self.quarantine_dir) if os.path.isfile(os.path.join(self.quarantine_dir, f))])
        except Exception:
            pass

        return {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "watch_directory": self.watch_dir,
            "in_progress_downloads_count": len(in_progress),
            "in_progress_downloads": in_progress,
            "recent_downloads_count": len(recent_files),
            "recent_downloads": recent_files[:25],
            "quarantined_files_count": quarantined_count,
            "new_threats_detected": len(new_threats),
            "new_threats": new_threats
        }

    def quarantine_file(self, filepath: str) -> Dict[str, Any]:
        """Safely move a suspicious file into the isolated quarantine vault."""
        if not os.path.exists(filepath):
            return {"success": False, "error": "File does not exist."}
        try:
            filename = os.path.basename(filepath)
            dest = os.path.join(self.quarantine_dir, f"{int(time.time())}_{filename}.quarantine")
            shutil.move(filepath, dest)
            log_event("FILE_QUARANTINED", {"source": filepath, "vault_path": dest})
            return {"success": True, "quarantined_as": dest}
        except Exception as err:
            return {"success": False, "error": str(err)}
