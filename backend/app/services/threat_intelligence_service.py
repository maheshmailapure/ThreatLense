import os
import time
import httpx
from typing import Dict, Any, Optional
from app.utils.logger import logger, log_event

# In-memory LRU-style cache for threat intelligence lookups (expires in 2 hours)
_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 7200

# Environment / Configurable API Keys
THREAT_INTEL_CONFIG = {
    "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "alienvault_otx_api_key": os.getenv("OTX_API_KEY", ""),
    "urlhaus_enabled": True
}

class ThreatIntelligenceService:
    """
    Threat Intelligence Verification Layer.
    Provides non-blocking auxiliary validation for external IP reputation,
    file SHA-256 hashes, and download URLs using free public APIs:
    - URLhaus (abuse.ch - Free Community API, Zero Key Required)
    - AbuseIPDB (Free Tier 1,000 req/day)
    - VirusTotal (Public API 500 req/day)
    - AlienVault OTX (Free Threat Intel Pulses)
    """

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Return provider status and active key configuration."""
        return {
            "urlhaus": {
                "name": "URLhaus (abuse.ch)",
                "status": "ACTIVE (Free Community API - No Key Required)",
                "enabled": THREAT_INTEL_CONFIG["urlhaus_enabled"],
                "requires_key": False
            },
            "abuseipdb": {
                "name": "AbuseIPDB",
                "status": "CONFIGURED" if THREAT_INTEL_CONFIG["abuseipdb_api_key"] else "READY (Optional API Key)",
                "enabled": bool(THREAT_INTEL_CONFIG["abuseipdb_api_key"]),
                "requires_key": True
            },
            "virustotal": {
                "name": "VirusTotal",
                "status": "CONFIGURED" if THREAT_INTEL_CONFIG["virustotal_api_key"] else "READY (Optional API Key)",
                "enabled": bool(THREAT_INTEL_CONFIG["virustotal_api_key"]),
                "requires_key": True
            },
            "alienvault_otx": {
                "name": "AlienVault OTX",
                "status": "CONFIGURED" if THREAT_INTEL_CONFIG["alienvault_otx_api_key"] else "READY (Optional API Key)",
                "enabled": bool(THREAT_INTEL_CONFIG["alienvault_otx_api_key"]),
                "requires_key": True
            }
        }

    @staticmethod
    def update_config(abuseipdb_key: Optional[str] = None, virustotal_key: Optional[str] = None, otx_key: Optional[str] = None) -> Dict[str, Any]:
        """Update runtime API keys."""
        if abuseipdb_key is not None:
            THREAT_INTEL_CONFIG["abuseipdb_api_key"] = abuseipdb_key.strip()
        if virustotal_key is not None:
            THREAT_INTEL_CONFIG["virustotal_api_key"] = virustotal_key.strip()
        if otx_key is not None:
            THREAT_INTEL_CONFIG["alienvault_otx_api_key"] = otx_key.strip()
        return ThreatIntelligenceService.get_config()

    @staticmethod
    async def check_file_hash(sha256: str) -> Dict[str, Any]:
        """
        Check SHA-256 hash against URLhaus payload database (free) and VirusTotal (if key present).
        """
        cache_key = f"hash:{sha256.lower()}"
        now = time.time()
        if cache_key in _INTEL_CACHE and (now - _INTEL_CACHE[cache_key]["timestamp"] < CACHE_TTL):
            return _INTEL_CACHE[cache_key]["data"]

        result = {
            "sha256": sha256,
            "is_malicious": False,
            "verdict": "CLEAN / UNKNOWN",
            "threat_score": 0,
            "sources": []
        }

        # 1. URLhaus Community API (Free, No Key Required)
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/payload/",
                    data={"sha256_hash": sha256}
                )
                if res.status_code == 200:
                    payload_data = res.json()
                    query_status = payload_data.get("query_status")
                    if query_status == "ok":
                        result["is_malicious"] = True
                        result["verdict"] = "MALWARE DETECTED"
                        result["threat_score"] = 95
                        result["sources"].append({
                            "provider": "URLhaus (abuse.ch)",
                            "file_type": payload_data.get("file_type"),
                            "signature": payload_data.get("signature", "Malware Payload"),
                            "first_seen": payload_data.get("firstseen"),
                            "url_count": payload_data.get("url_count", 1)
                        })
                    else:
                        result["sources"].append({
                            "provider": "URLhaus (abuse.ch)",
                            "status": "Not listed in active malware payload database"
                        })
        except Exception as err:
            logger.info(f"URLhaus lookup bypassed/timed out: {err}")

        # 2. VirusTotal (If API Key is configured)
        vt_key = THREAT_INTEL_CONFIG["virustotal_api_key"]
        if vt_key:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    res = await client.get(
                        f"https://www.virustotal.com/api/v3/files/{sha256}",
                        headers={"x-apikey": vt_key}
                    )
                    if res.status_code == 200:
                        vt_data = res.json().get("data", {}).get("attributes", {})
                        stats = vt_data.get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0)
                        if positives > 0:
                            result["is_malicious"] = True
                            result["verdict"] = f"MALICIOUS ({positives} vendors flagged)"
                            result["threat_score"] = min(positives * 10, 100)
                        result["sources"].append({
                            "provider": "VirusTotal",
                            "positives": positives,
                            "total": sum(stats.values()) if stats else 0
                        })
            except Exception as err:
                logger.info(f"VirusTotal lookup error: {err}")

        _INTEL_CACHE[cache_key] = {"timestamp": now, "data": result}
        return result

    @staticmethod
    async def check_ip_reputation(ip: str) -> Dict[str, Any]:
        """
        Check external IP reputation against AbuseIPDB and AlienVault OTX.
        """
        if ip in ["127.0.0.1", "0.0.0.0", "::1"] or ip.startswith(("192.168.", "10.", "172.16.")):
            return {
                "ip": ip,
                "is_malicious": False,
                "verdict": "INTERNAL_LAN / LOOPBACK",
                "abuse_confidence_score": 0,
                "sources": [{"provider": "Local Host Filter", "status": "Internal Private Traffic"}]
            }

        cache_key = f"ip:{ip}"
        now = time.time()
        if cache_key in _INTEL_CACHE and (now - _INTEL_CACHE[cache_key]["timestamp"] < CACHE_TTL):
            return _INTEL_CACHE[cache_key]["data"]

        result = {
            "ip": ip,
            "is_malicious": False,
            "verdict": "NEUTRAL / UNFLAGGED",
            "abuse_confidence_score": 0,
            "sources": []
        }

        # 1. AbuseIPDB (If API Key is configured)
        abuse_key = THREAT_INTEL_CONFIG["abuseipdb_api_key"]
        if abuse_key:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    res = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        headers={"Key": abuse_key, "Accept": "application/json"}
                    )
                    if res.status_code == 200:
                        data = res.json().get("data", {})
                        score = data.get("abuseConfidenceScore", 0)
                        result["abuse_confidence_score"] = score
                        if score > 20:
                            result["is_malicious"] = True
                            result["verdict"] = f"HIGH RISK (Abuse Score: {score}%)"
                        result["sources"].append({
                            "provider": "AbuseIPDB",
                            "abuse_score": score,
                            "total_reports": data.get("totalReports", 0),
                            "country": data.get("countryCode", "Unknown"),
                            "isp": data.get("isp", "Unknown")
                        })
            except Exception as err:
                logger.info(f"AbuseIPDB lookup error: {err}")

        # 2. URLhaus Host Check (Free Community API)
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": ip}
                )
                if res.status_code == 200:
                    host_data = res.json()
                    if host_data.get("query_status") == "ok":
                        result["is_malicious"] = True
                        result["verdict"] = "MALWARE HOSTING IP"
                        result["sources"].append({
                            "provider": "URLhaus (abuse.ch)",
                            "first_seen": host_data.get("firstseen"),
                            "url_count": host_data.get("url_count", 1)
                        })
        except Exception:
            pass

        _INTEL_CACHE[cache_key] = {"timestamp": now, "data": result}
        return result
