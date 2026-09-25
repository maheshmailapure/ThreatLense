from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

class HashCheckRequest(BaseModel):
    sha256: str

class IPCheckRequest(BaseModel):
    ip: str

class ThreatIntelConfigRequest(BaseModel):
    abuseipdb_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    otx_key: Optional[str] = None

@router.get("/config")
def get_threat_intel_config():
    """Return active threat intelligence providers and key statuses."""
    return ThreatIntelligenceService.get_config()

@router.post("/config")
def update_threat_intel_config(req: ThreatIntelConfigRequest):
    """Update runtime API keys for AbuseIPDB, VirusTotal, and AlienVault OTX."""
    return ThreatIntelligenceService.update_config(
        abuseipdb_key=req.abuseipdb_key,
        virustotal_key=req.virustotal_key,
        otx_key=req.otx_key
    )

@router.post("/check-hash")
async def check_hash(req: HashCheckRequest):
    """Check a file SHA-256 hash against free threat intelligence databases."""
    return await ThreatIntelligenceService.check_file_hash(req.sha256)

@router.post("/check-ip")
async def check_ip(req: IPCheckRequest):
    """Check an external IP address reputation against free threat intelligence databases."""
    return await ThreatIntelligenceService.check_ip_reputation(req.ip)
