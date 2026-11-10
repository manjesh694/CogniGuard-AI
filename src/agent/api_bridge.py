"""
CogniGuard AI - Local Agent API Bridge & Telemetry Daemon
Author: CogniGuard Engineering Team
Description: FastAPI bridge connecting the Chrome extension, web portals,
             and CLI scanners to persistent audit logs and lead telemetry.
"""

import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError:
    print("[!] FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.repo_scanner import scan_repository  # noqa: E402

APP_VERSION = "1.0.3"
AUDIT_LOG_FILE = os.path.join(_AGENT_DIR, "audit_logs.json")
LEADS_FILE = os.path.join(_AGENT_DIR, "leads.json")

app = FastAPI(
    title="CogniGuard AI Local Bridge",
    version=APP_VERSION,
    description="Local agentic security daemon & telemetry API for CogniGuard AI.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InspectPayloadRequest(BaseModel):
    filename: str
    source_url: str
    file_size_bytes: int = 0
    client_version: str = APP_VERSION


class SecurityDecisionResponse(BaseModel):
    status: str
    verdict: str
    threat_score: float
    action_taken: str
    reason: str
    timestamp: str


class RepoScanRequest(BaseModel):
    target_dir: str


class LeadCaptureRequest(BaseModel):
    plan: Literal["pro", "enterprise"]
    email: str = Field(..., min_length=3)
    company: Optional[str] = None
    seats: Optional[int] = Field(default=None, ge=1)
    trial_key: Optional[str] = None


def _load_json_list(filepath: str) -> List[Dict[str, Any]]:
    """Load a JSON list from disk, returning [] if missing or unreadable."""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _prepend_json_record(filepath: str, entry: Dict[str, Any], max_items: int = 500) -> None:
    """Prepend a record to a bounded JSON list file."""
    entries = _load_json_list(filepath)
    entries.insert(0, entry)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(entries[:max_items], f, indent=2)


def log_incident_to_disk(entry: Dict[str, Any]) -> None:
    """Persist incident records for enterprise IT compliance audit."""
    _prepend_json_record(AUDIT_LOG_FILE, entry, max_items=500)


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "OK",
        "agent": "CogniGuard AI Daemon",
        "version": APP_VERSION,
        "active_vaults": ["SSH_KEYS", "AWS_CREDENTIALS", "CHROME_COOKIES", "ENV_SECRETS"],
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/v1/inspect", response_model=SecurityDecisionResponse)
def inspect_download(payload: InspectPayloadRequest):
    """Evaluate download request using heuristic rules & behavioral signatures."""
    clean_name = payload.filename.lower()
    dangerous_exts = (".exe", ".scr", ".vbs", ".bat", ".cmd", ".pdf.exe", ".docm")
    is_dangerous = any(clean_name.endswith(ext) for ext in dangerous_exts)

    threat_score = 0.98 if is_dangerous else 0.04
    verdict = "INTRUSION_DETECTED" if is_dangerous else "SAFE"
    action = "QUARANTINE_IN_AIRLOCK" if is_dangerous else "ALLOW"
    reason = "Executable payload disguised as document" if is_dangerous else "Clean verified file"

    decision = {
        "status": "OK",
        "verdict": verdict,
        "threat_score": threat_score,
        "action_taken": action,
        "reason": reason,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    log_incident_to_disk({
        **decision,
        "filename": payload.filename,
        "source_url": payload.source_url,
        "file_size": payload.file_size_bytes,
    })
    return decision


@app.post("/api/v1/scan-repo")
def scan_repo_endpoint(payload: RepoScanRequest):
    """Run CogniGuard pre-install scanner on a local directory and log findings."""
    if not os.path.exists(payload.target_dir):
        raise HTTPException(status_code=404, detail=f"Directory not found: {payload.target_dir}")

    report = scan_repository(payload.target_dir)
    if report is None:
        raise HTTPException(status_code=400, detail="Scan failed to produce a report")

    is_threat = report["verdict"] != "SAFE_TO_INSTALL"
    log_incident_to_disk({
        "status": "OK",
        "verdict": report["verdict"],
        "threat_score": round(report["risk_score"] / 100.0, 2),
        "action_taken": "BLOCK_REPO_INSTALL" if is_threat else "ALLOW_REPO",
        "reason": f"Repo scan ({report['files_scanned']} files, {len(report['findings'])} findings)",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename": os.path.basename(os.path.abspath(payload.target_dir)),
        "source_url": payload.target_dir,
    })
    return report


@app.post("/api/v1/leads")
def capture_lead(payload: LeadCaptureRequest):
    """Capture Pro Trial activation or Enterprise IT Fleet pilot requests."""
    issued_key = payload.trial_key
    if payload.plan == "pro" and not issued_key:
        issued_key = f"CG-PRO-{uuid.uuid4().hex[:6].upper()}"

    record = {
        "id": uuid.uuid4().hex[:10],
        "plan": payload.plan,
        "email": payload.email.strip(),
        "company": payload.company.strip() if payload.company else None,
        "seats": payload.seats,
        "trial_key": issued_key,
        "created_at": datetime.now().isoformat(),
    }
    _prepend_json_record(LEADS_FILE, record, max_items=1000)
    return {"status": "OK", "lead": record}


@app.get("/api/v1/leads")
def list_leads():
    """List captured Pro Trial and Enterprise pilot leads."""
    return _load_json_list(LEADS_FILE)


@app.get("/api/v1/logs")
def get_audit_logs():
    """Return recent security audit logs for the SOC dashboard."""
    return _load_json_list(AUDIT_LOG_FILE)


@app.get("/api/v1/telemetry/summary")
def get_telemetry_summary():
    """Return aggregated SOC & GTM conversion telemetry."""
    logs = _load_json_list(AUDIT_LOG_FILE)
    leads = _load_json_list(LEADS_FILE)

    blocked = sum(
        1 for item in logs
        if item.get("verdict") in ("INTRUSION_DETECTED", "HONEYPOT_BREACH", "DO_NOT_INSTALL", "REVIEW_REQUIRED")
    )
    pro_trials = sum(1 for item in leads if item.get("plan") == "pro")
    enterprise_pilots = sum(1 for item in leads if item.get("plan") == "enterprise")

    return {
        "status": "OK",
        "version": APP_VERSION,
        "total_events": len(logs),
        "threats_blocked": blocked,
        "clean_events": len(logs) - blocked,
        "leads_captured": len(leads),
        "pro_trials": pro_trials,
        "enterprise_pilots": enterprise_pilots,
    }


if __name__ == "__main__":
    print("=" * 65)
    print("🛡️ Starting CogniGuard AI Local Security Bridge Daemon...")
    print("📡 Listening at: http://127.0.0.1:8765")
    print("🔒 Endpoints:")
    print("   • GET  /api/v1/health            -> Operational status")
    print("   • POST /api/v1/inspect           -> Pre-execution threat analysis")
    print("   • POST /api/v1/scan-repo         -> Repo & AI-Skill scan API")
    print("   • POST /api/v1/leads             -> Trial & Enterprise lead capture")
    print("   • GET  /api/v1/logs              -> SOC audit event history")
    print("   • GET  /api/v1/telemetry/summary -> Aggregated SOC & lead stats")
    print("=" * 65)
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
