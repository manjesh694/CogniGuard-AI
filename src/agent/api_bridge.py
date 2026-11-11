"""
CogniGuard AI - Local Agent API Bridge & Telemetry Daemon
Author: CogniGuard Engineering Team
Description: Hardened FastAPI bridge connecting the Chrome extension, web portals,
             and CLI scanners to atomic SQLite WAL storage and lead telemetry.
"""

import hmac
import os
import sys
from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query
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

from agent.heuristics import evaluate_filename_risk  # noqa: E402
from agent.repo_scanner import is_url_like, scan_repository  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402

APP_VERSION = "1.0.3"
DEFAULT_ALLOWED_ORIGINS = [
    "https://manjesh694.github.io",
    "http://127.0.0.1:8765",
    "http://localhost:8765",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://localhost:3000",
]


def get_allowed_origins() -> List[str]:
    """Return configured CORS origins from env or safe defaults."""
    extra = os.environ.get("COGNIGUARD_CORS_ORIGINS", "")
    parsed = [origin.strip() for origin in extra.split(",") if origin.strip()]
    return parsed if parsed else list(DEFAULT_ALLOWED_ORIGINS)


store = CogniGuardStore()

app = FastAPI(
    title="CogniGuard AI Local Bridge",
    version=APP_VERSION,
    description="Hardened agentic security daemon & telemetry API for CogniGuard AI.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


class InspectPayloadRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=512)
    source_url: str = Field(..., min_length=1, max_length=2048)
    file_size_bytes: int = Field(default=0, ge=0)
    client_version: str = APP_VERSION


class SecurityDecisionResponse(BaseModel):
    status: str
    verdict: str
    threat_score: float
    action_taken: str
    reason: str
    timestamp: str


class RepoScanRequest(BaseModel):
    target_dir: str = Field(..., min_length=1, max_length=1024)


class LeadCaptureRequest(BaseModel):
    plan: Literal["pro", "enterprise"]
    email: str = Field(..., min_length=3, max_length=254)
    company: Optional[str] = Field(default=None, max_length=200)
    seats: Optional[int] = Field(default=None, ge=1, le=100000)
    trial_key: Optional[str] = Field(default=None, max_length=64)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Enforce X-API-Key authentication when COGNIGUARD_API_KEY is configured."""
    expected = os.environ.get("COGNIGUARD_API_KEY", "").strip()
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def _validate_local_scan_path(target: str) -> str:
    """Validate local scan directory path and enforce optional scan root confinement."""
    if "\x00" in target:
        raise HTTPException(status_code=400, detail="Invalid path")
    resolved = os.path.abspath(target)
    allowed_root = os.environ.get("COGNIGUARD_ALLOWED_SCAN_ROOT", "").strip()
    if allowed_root:
        root_abs = os.path.abspath(allowed_root)
        if os.path.commonpath([resolved, root_abs]) != root_abs:
            raise HTTPException(status_code=403, detail="Scan target outside allowed root")
    if not os.path.exists(resolved):
        raise HTTPException(status_code=404, detail=f"Directory not found: {target}")
    return resolved


def log_incident_to_disk(entry: Dict[str, Any]) -> None:
    """Persist incident records to atomic SQLite WAL storage."""
    store.record_audit_event(entry)


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "OK",
        "agent": "CogniGuard AI Daemon",
        "version": APP_VERSION,
        "auth_enabled": bool(os.environ.get("COGNIGUARD_API_KEY", "").strip()),
        "active_vaults": ["SSH_KEYS", "AWS_CREDENTIALS", "CHROME_COOKIES", "ENV_SECRETS"],
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/v1/inspect", response_model=SecurityDecisionResponse)
def inspect_download(payload: InspectPayloadRequest):
    """Evaluate download request using shared heuristic rules."""
    assessment = evaluate_filename_risk(payload.filename)
    decision = {
        "status": "OK",
        **assessment,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    log_incident_to_disk({
        **decision,
        "filename": payload.filename,
        "source_url": payload.source_url,
        "file_size": payload.file_size_bytes,
    })
    return decision


@app.post("/api/v1/scan-repo", dependencies=[Depends(require_api_key)])
def scan_repo_endpoint(payload: RepoScanRequest):
    """Run CogniGuard pre-install scanner on a local directory or public GitHub URL."""
    target = payload.target_dir.strip()
    is_remote = is_url_like(target)
    scan_arg = target if is_remote else _validate_local_scan_path(target)

    try:
        report = scan_repository(scan_arg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if report is None:
        raise HTTPException(status_code=400, detail="Scan failed to produce a report")

    is_threat = report["verdict"] != "SAFE_TO_INSTALL"
    target_name = target if is_remote else os.path.basename(scan_arg)
    log_incident_to_disk({
        "status": "OK",
        "verdict": report["verdict"],
        "threat_score": round(report["risk_score"] / 100.0, 2),
        "action_taken": "BLOCK_REPO_INSTALL" if is_threat else "ALLOW_REPO",
        "reason": f"Repo scan ({report['files_scanned']} files, {len(report['findings'])} findings)",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename": target_name,
        "source_url": report["target"],
    })
    return report


@app.post("/api/v1/leads")
def capture_lead(payload: LeadCaptureRequest):
    """Capture Pro Trial activation or Enterprise IT Fleet pilot requests."""
    record = store.record_lead(
        plan=payload.plan,
        email=payload.email,
        company=payload.company,
        seats=payload.seats,
        trial_key=payload.trial_key,
    )
    return {"status": "OK", "lead": record}


@app.get("/api/v1/leads", dependencies=[Depends(require_api_key)])
def list_leads(
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    plan: Annotated[Optional[Literal["pro", "enterprise"]], Query()] = None,
):
    """List captured Pro Trial and Enterprise pilot leads."""
    return store.list_leads(limit=limit, offset=offset, plan=plan)


@app.get("/api/v1/logs", dependencies=[Depends(require_api_key)])
def get_audit_logs(
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    verdict: Annotated[Optional[str], Query()] = None,
):
    """Return recent security audit logs for the SOC dashboard."""
    return store.list_audit_logs(limit=limit, offset=offset, verdict=verdict)


@app.get("/api/v1/telemetry/summary")
def get_telemetry_summary():
    """Return aggregated SOC & GTM conversion telemetry."""
    return store.get_telemetry_summary(APP_VERSION)


if __name__ == "__main__":
    print("=" * 65)
    print("🛡️ Starting CogniGuard AI Local Security Bridge Daemon...")
    print("📡 Listening at: http://127.0.0.1:8765")
    print("🔒 Endpoints:")
    print("   • GET  /api/v1/health            -> Operational status")
    print("   • POST /api/v1/inspect           -> Pre-execution threat analysis")
    print("   • POST /api/v1/scan-repo         -> Repo & AI-Skill scan API")
    print("   • POST /api/v1/leads             -> Trial & Enterprise lead capture")
    print("   • GET  /api/v1/leads             -> Paginated lead list")
    print("   • GET  /api/v1/logs              -> Paginated SOC audit history")
    print("   • GET  /api/v1/telemetry/summary -> Aggregated SOC & lead stats")
    print("=" * 65)
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
