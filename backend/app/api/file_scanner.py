from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import User
from app.api.auth import get_current_user
from app.services.malware_scanner_service import MalwareScannerService
from app.services.download_watcher_service import DownloadWatcherService

router = APIRouter(prefix="/api/file-scanner", tags=["Malicious Download & File Scanner"])

class ToggleWatcherRequest(BaseModel):
    enabled: bool

class TextPayloadScanRequest(BaseModel):
    filename: str
    content: str
    source_url: Optional[str] = "http://unknown-source.net/download"

class PolicyDecisionRequest(BaseModel):
    filename: str
    action: str   # 'allow' or 'block'
    md5_hash: Optional[str] = None


@router.get("/watcher-status")
def get_download_watcher_status(
    current_user: User = Depends(get_current_user)
):
    """Get status of the live background system Downloads directory watcher."""
    return DownloadWatcherService.get_watcher_status()


@router.post("/toggle-watcher")
def toggle_download_watcher(
    request: ToggleWatcherRequest,
    current_user: User = Depends(get_current_user)
):
    """Enable or disable the automatic downloads folder watcher."""
    new_state = DownloadWatcherService.set_watcher_enabled(request.enabled)
    return {"watcher_enabled": new_state}


@router.post("/scan-downloads")
def scan_real_system_downloads(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Actively scans the real host system Downloads folder.
    Automatically detects new malicious file downloads, writes alerts to DB, and triggers sirens.
    """
    return DownloadWatcherService.scan_system_downloads(db=db)


@router.post("/policy-decision")
def execute_policy_decision(
    request: PolicyDecisionRequest,
    current_user: User = Depends(get_current_user)
):
    """Execute policy decision: Allow (whitelist) or Block (quarantine and isolate)."""
    try:
        return DownloadWatcherService.apply_policy_decision(
            filename=request.filename,
            action=request.action,
            md5_hash=request.md5_hash
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/scan-text")
def scan_text_payload(
    request: TextPayloadScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Inspect a custom file download payload string for malicious patterns and trigger alarm."""
    return MalwareScannerService.inspect_file_content(
        filename=request.filename,
        content_bytes=request.content.encode('utf-8'),
        source_url=request.source_url or "http://external-gateway.com/download",
        db=db
    )
