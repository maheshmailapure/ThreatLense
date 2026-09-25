import os
import shutil
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.database.database import SessionLocal
from app.database.models import Alert
from app.services.malware_scanner_service import MalwareScannerService
from app.utils.logger import log_event, logger

SCANNED_FILES_CACHE: Dict[str, Dict[str, Any]] = {}
WATCHER_ENABLED = True
WHITELISTED_HASHES = set()
ALARMED_HASHES = set()
INITIAL_INDEXED = False
RECENT_INTERCEPTED_THREATS: List[Dict[str, Any]] = []
_WATCHER_THREAD: Optional[threading.Thread] = None
_WATCHER_RUNNING = False

def get_system_downloads_folder() -> Path:
    """Resolve the host system's real Downloads directory."""
    home = Path.home()
    downloads = home / "Downloads"
    if downloads.exists() and downloads.is_dir():
        return downloads
    # Windows fallback
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        win_downloads = Path(user_profile) / "Downloads"
        if win_downloads.exists():
            return win_downloads
    return home

def get_quarantine_vault_folder() -> Path:
    """Resolve or create the isolated quarantine vault folder."""
    home = Path.home()
    vault = home / ".ai_ids_quarantine"
    vault.mkdir(parents=True, exist_ok=True)
    return vault

def index_existing_downloads():
    """Index pre-existing files in Downloads folder so already-downloaded files never falsely alarm on boot."""
    global INITIAL_INDEXED
    if INITIAL_INDEXED:
        return
    downloads_dir = get_system_downloads_folder()
    if downloads_dir.exists():
        try:
            with os.scandir(downloads_dir) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        try:
                            stat = entry.stat()
                            effective_time = max(stat.st_mtime, getattr(stat, "st_ctime", stat.st_mtime))
                            SCANNED_FILES_CACHE[entry.path] = {
                                "filename": entry.name,
                                "file_path": entry.path,
                                "file_stat_size": stat.st_size,
                                "size_bytes": stat.st_size,
                                "effective_time": effective_time,
                                "is_preexisting": True,
                                "is_malicious": False,
                                "is_harmful": False,
                                "ai_status": "EXISTING_FILE_SAFE",
                                "threat_level": "LOW",
                                "verdict": "PRE-EXISTING FILE (Indexed Safe on Startup)",
                                "threat_name": "None",
                                "threat_indicators": [],
                                "alert_created": False,
                                "trigger_alarm": False,
                                "last_modified": datetime.fromtimestamp(effective_time).strftime("%Y-%m-%d %H:%M:%S")
                            }
                        except Exception:
                            continue
            INITIAL_INDEXED = True
            logger.info(f"Indexed {len(SCANNED_FILES_CACHE)} existing files in Downloads folder (safe baseline established).")
        except Exception as e:
            logger.warning(f"Error during baseline download indexing: {e}")

class DownloadWatcherService:
    @staticmethod
    def start_background_watcher():
        """Starts the persistent background watcher daemon thread if not already running."""
        global _WATCHER_THREAD, _WATCHER_RUNNING
        # Establish baseline index of existing downloads before starting loop
        index_existing_downloads()

        if _WATCHER_RUNNING and _WATCHER_THREAD and _WATCHER_THREAD.is_alive():
            return

        _WATCHER_RUNNING = True
        _WATCHER_THREAD = threading.Thread(target=DownloadWatcherService._watcher_loop, daemon=True, name="RealtimeDownloadWatcher")
        _WATCHER_THREAD.start()
        logger.info(f"Realtime Download Watcher Daemon started on {get_system_downloads_folder()}")

    @staticmethod
    def _watcher_loop():
        """Continuous background loop inspecting Downloads directory every 3 seconds."""
        global _WATCHER_RUNNING
        while _WATCHER_RUNNING:
            try:
                if WATCHER_ENABLED:
                    DownloadWatcherService.scan_system_downloads(db=None)
            except Exception as e:
                logger.error(f"Error in background download watcher loop: {str(e)}")
            time.sleep(3.0)

    @staticmethod
    def get_watcher_status() -> Dict[str, Any]:
        downloads_dir = get_system_downloads_folder()
        return {
            "watcher_enabled": WATCHER_ENABLED,
            "daemon_running": _WATCHER_RUNNING,
            "downloads_folder_path": str(downloads_dir),
            "quarantine_vault_path": str(get_quarantine_vault_folder()),
            "folder_exists": downloads_dir.exists(),
            "total_files_monitored": len(SCANNED_FILES_CACHE),
            "threats_intercepted": sum(1 for f in SCANNED_FILES_CACHE.values() if f.get("is_malicious")),
            "whitelisted_count": len(WHITELISTED_HASHES),
            "recent_threats_count": len(RECENT_INTERCEPTED_THREATS)
        }

    @staticmethod
    def scan_system_downloads(db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Actively inspects the real host system Downloads folder for new or modified files.
        If a malicious file is downloaded, it generates a CRITICAL alert and triggers the alarm.
        """
        downloads_dir = get_system_downloads_folder()
        if not downloads_dir.exists():
            return {
                "scanned_count": 0,
                "malicious_detected": 0,
                "files": [],
                "folder": str(downloads_dir)
            }

        index_existing_downloads()

        new_threats = []

        try:
            # Collect all regular files
            file_entries = []
            with os.scandir(downloads_dir) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        fname = entry.name
                        # Skip browser in-flight temporary download handles
                        if (fname.endswith(".crdownload") or 
                            fname.endswith(".part") or 
                            fname.endswith(".tmp") or 
                            fname.endswith(".quarantined_safe") or
                            fname.startswith("~$") or
                            fname == "desktop.ini"):
                            continue
                        try:
                            stat = entry.stat()
                            # Use max of mtime and ctime for accurate download time detection
                            effective_time = max(stat.st_mtime, getattr(stat, "st_ctime", stat.st_mtime))
                            file_entries.append((effective_time, stat.st_size, entry.path, fname))
                        except Exception:
                            continue

            # Sort descending by most recently created/modified
            file_entries.sort(key=lambda x: x[0], reverse=True)
            active_entries = file_entries[:60]

            # Inspect files
            for effective_time, size, file_path_str, filename in active_entries:
                cache_key = file_path_str

                # Check cache validity (match by size and modification time)
                if cache_key in SCANNED_FILES_CACHE:
                    cached = SCANNED_FILES_CACHE[cache_key]
                    if (cached.get("file_stat_size") == size or cached.get("size_bytes") == size) and cached.get("effective_time") == effective_time:
                        continue

                # Read and inspect content
                try:
                    content_bytes = b""
                    # Read up to 256KB for deep header & heuristic inspection
                    with open(file_path_str, "rb") as f:
                        content_bytes = f.read(256 * 1024)

                    analysis = MalwareScannerService.inspect_file_content(
                        filename=filename,
                        content_bytes=content_bytes,
                        source_url=f"file:///{file_path_str.replace('\\', '/')}",
                        db=db
                    )

                    # Check if hash is whitelisted by security policy
                    if analysis.get("md5_hash") in WHITELISTED_HASHES:
                        analysis["is_malicious"] = False
                        analysis["is_harmful"] = False
                        analysis["threat_level"] = "LOW"
                        analysis["policy_status"] = "ALLOWED BY ANALYST"
                        analysis["verdict"] = "ANALYST WHITELISTED (Allowed by Policy)"

                    analysis["file_path"] = file_path_str
                    analysis["file_stat_size"] = size
                    analysis["effective_time"] = effective_time
                    analysis["last_modified"] = datetime.fromtimestamp(effective_time).strftime("%Y-%m-%d %H:%M:%S")

                    SCANNED_FILES_CACHE[cache_key] = analysis

                    # Alarm ONLY if Atria AI confirmed genuine threat and hash has not been alerted previously
                    file_md5 = analysis.get("md5_hash")
                    if analysis.get("is_malicious") and analysis.get("is_harmful"):
                        if file_md5 not in ALARMED_HASHES:
                            ALARMED_HASHES.add(file_md5)
                            analysis["is_new_threat"] = True
                            new_threats.append(analysis)
                            if analysis not in RECENT_INTERCEPTED_THREATS:
                                RECENT_INTERCEPTED_THREATS.append(analysis)
                                log_event("REALTIME_DOWNLOAD_INTERCEPTED_ALERT", {
                                    "filename": filename,
                                    "threat": analysis.get("threat_name"),
                                    "size": size
                                })
                        else:
                            analysis["trigger_alarm"] = False
                    else:
                        analysis["trigger_alarm"] = False

                except Exception as ex:
                    logger.warning(f"Could not read download file {filename}: {str(ex)}")

        except Exception as e:
            logger.error(f"Error scanning downloads directory: {str(e)}")

        # Build chronological feed of scanned files
        all_files = sorted(
            list(SCANNED_FILES_CACHE.values()),
            key=lambda x: x.get("effective_time", 0),
            reverse=True
        )

        return {
            "downloads_folder": str(downloads_dir),
            "total_files_scanned": len(all_files),
            "malicious_detected_count": len([f for f in all_files if f.get("is_malicious")]),
            "new_threats": new_threats,
            "trigger_alarm": len(new_threats) > 0,
            "files": all_files[:60]
        }

    @staticmethod
    def apply_policy_decision(filename: str, action: str, md5_hash: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute Security Policy Decision:
        - action='block': Quarantines/neutralizes file by renaming/moving to vault.
        - action='allow': Overrides threat and whitelists hash.
        """
        downloads_dir = get_system_downloads_folder()
        vault_dir = get_quarantine_vault_folder()
        target_path = downloads_dir / filename

        if action.lower() == "block":
            quarantine_filename = f"{filename}.quarantined_safe"
            quarantine_path = vault_dir / quarantine_filename

            # If target exists on disk, move/rename it to quarantine vault
            if target_path.exists():
                try:
                    shutil.move(str(target_path), str(quarantine_path))
                except Exception as e:
                    logger.error(f"Could not move file to vault: {str(e)}")

            # Update cache state
            for key, val in list(SCANNED_FILES_CACHE.items()):
                if val.get("filename") == filename:
                    val["policy_status"] = "BLOCKED & QUARANTINED"
                    val["is_malicious"] = False
                    val["verdict"] = "NEUTRALIZED (Quarantined in Security Vault)"

            # Remove from recent threats list
            global RECENT_INTERCEPTED_THREATS
            RECENT_INTERCEPTED_THREATS = [t for t in RECENT_INTERCEPTED_THREATS if t.get("filename") != filename]

            log_event("POLICY_DECISION_BLOCK", {"filename": filename, "quarantine_path": str(quarantine_path)})

            return {
                "status": "SUCCESS",
                "policy_decision": "BLOCK",
                "filename": filename,
                "action_taken": f"File '{filename}' neutralized and moved to security vault: {str(quarantine_path)}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        elif action.lower() == "allow":
            if md5_hash:
                WHITELISTED_HASHES.add(md5_hash)
            
            for key, val in list(SCANNED_FILES_CACHE.items()):
                if val.get("filename") == filename or (md5_hash and val.get("md5_hash") == md5_hash):
                    val["policy_status"] = "ALLOWED BY ANALYST"
                    val["is_malicious"] = False
                    val["verdict"] = "ALLOWED (Whitelisted by Security Policy)"

            RECENT_INTERCEPTED_THREATS = [t for t in RECENT_INTERCEPTED_THREATS if t.get("filename") != filename]

            log_event("POLICY_DECISION_ALLOW", {"filename": filename, "md5": md5_hash})

            return {
                "status": "SUCCESS",
                "policy_decision": "ALLOW",
                "filename": filename,
                "action_taken": f"File '{filename}' approved by analyst. Whitelisted in security policy.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        else:
            raise ValueError(f"Unknown policy action: {action}. Must be 'allow' or 'block'.")

    @staticmethod
    def set_watcher_enabled(enabled: bool) -> bool:
        global WATCHER_ENABLED
        WATCHER_ENABLED = enabled
        return WATCHER_ENABLED

# Auto-start watcher daemon on module load
DownloadWatcherService.start_background_watcher()
