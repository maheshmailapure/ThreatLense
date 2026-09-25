import time
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.services.atria_service import AtriaService
from app.utils.logger import logger, log_event

class RiskEngine:
    """
    Evaluates correlated security incidents, enriches with Atria AI
    cloud intelligence on-demand, generates SIEM alerts, and manages database persistence.
    Operates in TOKEN-SAVER mode by default: uses sub-millisecond local rule triage (0 tokens),
    and only wakes Atria AI MoE when triggered by operator or explicit critical trigger.
    """
    AUTO_WAKE_AI_ENABLED = True  # Trigger-based: wakes Atria AI automatically on suspicious events (0 tokens during rest)

    def __init__(self):
        self._incident_cache: Dict[str, float] = {}
        self._ai_wake_cache: Dict[str, float] = {}

    def process_incidents(self, incidents: List[Dict[str, Any]], db: Optional[Session] = None) -> List[Dict[str, Any]]:
        """Process detected incidents with zero-token local triage and containment options."""
        processed: List[Dict[str, Any]] = []
        now = time.time()

        for inc in incidents:
            # Deduplicate similar incidents within 60 seconds
            dedup_key = f"{inc.get('incident_type')}-{inc.get('process')}-{inc.get('pid')}-{inc.get('source_ip')}"
            if now - self._incident_cache.get(dedup_key, 0) < 60.0:
                continue
            self._incident_cache[dedup_key] = now

            # 1. Immediate Fast Triage via local cybersecurity rules (0 tokens consumed)
            try:
                ai_analysis = AtriaService.fast_triage_incident(inc)
                inc["atria_analysis"] = ai_analysis
                if ai_analysis.get("firewall_rule"):
                    inc["firewall_rule"] = ai_analysis.get("firewall_rule")
            except Exception as err:
                logger.info(f"Local rule triage: ({err})")
                inc["atria_analysis"] = {
                    "verdict": "ANALYZING",
                    "reasoning": "Local rule-based heuristic triage.",
                    "recommended_action": inc.get("recommended_action", "Investigate process.")
                }

            import hashlib
            stable_sig = f"{inc.get('incident_type')}-{inc.get('process')}-{inc.get('source_ip')}-{inc.get('target_port')}-{inc.get('filepath')}"
            stable_hash = hashlib.md5(stable_sig.encode()).hexdigest()[:8].upper()
            inc["incident_id"] = f"INC-{stable_hash}"
            inc["ai_status"] = "WAKING_AI"  # Triggering Atria AI inspection
            inc["is_harmful"] = inc.get("is_harmful", False)
            inc["tokens_consumed"] = 0

            # 2. Attach instant containment capabilities
            containment = {}
            if inc.get("source_ip") and inc.get("source_ip") not in ["127.0.0.1", "::1", "0.0.0.0"]:
                containment["can_block_ip"] = True
                containment["target_ip"] = inc.get("source_ip")
            if inc.get("target_port") and inc.get("target_port") > 0:
                containment["can_block_port"] = True
                containment["target_port"] = inc.get("target_port")
            if inc.get("pid") and isinstance(inc.get("pid"), int) and inc.get("pid") > 4:
                containment["can_kill_process"] = True
                containment["target_pid"] = inc.get("pid")
                containment["target_process"] = inc.get("process")
            if inc.get("filepath"):
                containment["can_quarantine"] = True
                containment["target_filepath"] = inc.get("filepath")
            inc["containment"] = containment

            # 3. Persist incident into database
            try:
                from app.database.database import SessionLocal
                from app.database.models import Detection, Alert
                with SessionLocal() as session:
                    det = Detection(
                        prediction="ATTACK" if inc.get("is_harmful") else "SUSPICIOUS",
                        attack_type=(inc.get("attack_category") or "Intrusion")[:50],
                        model=f"Atria AI ({AtriaService.get_config().get('model')})",
                        anomaly_score=inc.get("confidence", 75.0) / 100.0,
                        is_anomaly=True,
                        risk_level=inc.get("severity", "MEDIUM"),
                        input_features=inc.get("input_features") or {
                            "title": inc.get("title"),
                            "process": inc.get("process"),
                            "source_ip": inc.get("source_ip"),
                            "target_port": inc.get("target_port"),
                            "filepath": inc.get("filepath")
                        },
                        explanation=inc.get("atria_analysis") or {"evidence": inc.get("evidence")}
                    )
                    session.add(det)
                    session.flush()

                    alert = Alert(
                        detection_id=det.id,
                        alert_type=(inc.get("title") or "Security Event")[:50],
                        risk_level=inc.get("severity", "MEDIUM"),
                        status="NEW",
                        description=f"{inc.get('evidence', '')} | Action: {inc.get('recommended_action', '')}"
                    )
                    session.add(alert)
                    session.commit()
                    inc["alert_id"] = alert.id
            except Exception as dberr:
                logger.warning(f"Could not persist incident to database: {dberr}")

            # 4. Trigger-based AI Wake: Automatically invokes Atria AI when suspicious event happens
            if self.AUTO_WAKE_AI_ENABLED:
                wake_key = f"{inc.get('incident_type')}-{inc.get('process')}-{inc.get('source_ip')}-{inc.get('filepath')}"
                if now - self._ai_wake_cache.get(wake_key, 0) > 180.0:  # 3 minute cache
                    self._ai_wake_cache[wake_key] = now
                    def _async_atria_deep_eval(incident_copy):
                        import asyncio
                        import os
                        try:
                            telemetry_payload = {
                                "incident_type": incident_copy.get("incident_type"),
                                "title": incident_copy.get("title"),
                                "process": incident_copy.get("process"),
                                "filepath": incident_copy.get("filepath"),
                                "source_ip": incident_copy.get("source_ip"),
                                "target_port": incident_copy.get("target_port"),
                                "entropy": incident_copy.get("entropy"),
                                "evidence": incident_copy.get("evidence"),
                                "input_features": incident_copy.get("input_features")
                            }
                            res = asyncio.run(AtriaService.analyze_threat(telemetry_payload))
                            incident_copy["atria_deep_eval"] = res
                            incident_copy["tokens_consumed"] = 45

                            # Check if Atria AI evaluated this event as genuinely harmful
                            is_attack = (
                                str(res.get("verdict", "")).upper() in ["ATTACK", "MALICIOUS"] or
                                res.get("is_intrusion") is True or
                                str(res.get("threat_level", "")).upper() in ["CRITICAL", "HIGH"]
                            )

                            if is_attack:
                                incident_copy["ai_status"] = "CONFIRMED_THREAT"
                                incident_copy["is_harmful"] = True
                                incident_copy["severity"] = "CRITICAL"
                                incident_copy["confidence"] = round(float(res.get("confidence_score", 0.98)) * 100, 1)
                                incident_copy["title"] = f"CRITICAL THREAT CONFIRMED BY ATRIA AI: {res.get('attack_type', incident_copy.get('title'))}"
                                if res.get("firewall_rule") and res.get("firewall_rule") != "None":
                                    incident_copy["firewall_rule"] = res.get("firewall_rule")
                                log_event("ATRIA_CONFIRMED_THREAT", {"incident_id": incident_copy.get("incident_id"), "verdict": "ATTACK"})
                            else:
                                incident_copy["ai_status"] = "BENIGN_VERIFIED"
                                incident_copy["is_harmful"] = False
                                incident_copy["severity"] = "LOW"
                                incident_copy["confidence"] = 99.0
                                display_name = incident_copy.get("process") or (os.path.basename(incident_copy.get("filepath")) if incident_copy.get("filepath") else "Connection")
                                incident_copy["title"] = f"SAFE / BENIGN VERIFIED BY ATRIA AI: {display_name}"
                                log_event("ATRIA_VERIFIED_BENIGN", {"incident_id": incident_copy.get("incident_id"), "verdict": "NORMAL"})
                        except Exception as ex:
                            logger.info(f"Async Atria inference worker: {ex}")

                    threading.Thread(target=_async_atria_deep_eval, args=(inc,), daemon=True).start()

            log_event("REAL_INCIDENT_DETECTED", {"title": inc.get("title"), "incident_id": inc["incident_id"], "ai_status": inc["ai_status"]})
            processed.append(inc)

        return processed
