from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from app.database.models import User
from app.api.auth import get_current_user
from app.services.web_audit_service import WebAuditService

router = APIRouter(prefix="/api/web-auditor", tags=["Web & IP Security Auditor"])

class WebScanRequest(BaseModel):
    target: str

@router.post("/scan")
async def scan_website_or_ip(
    request: WebScanRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Perform a comprehensive security audit of a website URL or IP address.
    Evaluates SSL/TLS certificates, OWASP security headers, DNS latency, and AI posture ratings.
    """
    try:
        return await WebAuditService.analyze_target(request.target)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Website security audit failed: {str(e)}")
