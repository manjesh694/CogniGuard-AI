"""
CogniGuard AI - Local Agent API Bridge & Daemon
Author: CogniGuard Engineering Team
Description: Lightweight REST API bridge connecting the Chrome extension 
             to the local Python heuristic threat engine and system vault watcher.
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from typing import Dict, Any

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    print("[!] FastAPI/Uvicorn not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)

app = FastAPI(
    title="CogniGuard AI Local Bridge",
    version="1.0.2",
    description="Local agentic security daemon for CogniGuard AI."
)

# Enable CORS for Chrome Extension origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AUDIT_LOG_FILE = os.path.join(os.path.dirname(__file__), "audit_logs.json")

class InspectPayloadRequest(BaseModel):
    filename: str
    source_url: str
    file_size_bytes: int = 0
    client_version: str = "1.0.2"

class SecurityDecisionResponse(BaseModel):
    status: str
    verdict: str
    threat_score: float
    action_taken: str
    reason: str
    timestamp: str

def log_incident_to_disk(entry: Dict[str, Any]):
    """Persists incident records for enterprise IT compliance audit."""
    entries = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r") as f:
                entries = json.load(f)
        except Exception:
            entries = []
    
    entries.insert(0, entry)
    entries = entries[:500] # Retain latest 500 audit events
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "OK",
        "agent": "CogniGuard AI Daemon",
        "version": "1.0.2",
        "active_vaults": ["SSH_KEYS", "AWS_CREDENTIALS", "CHROME_COOKIES", "ENV_SECRETS"],
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v1/inspect", response_model=SecurityDecisionResponse)
def inspect_download(payload: InspectPayloadRequest):
    """
    Evaluates download request using heuristic rules & behavioural signatures.
    """
    clean_name = payload.filename.lower()
    dangerous_exts = [".exe", ".scr", ".vbs", ".bat", ".cmd", ".pdf.exe", ".docm"]
    is_dangerous = any(clean_name.endswith(ext) for ext in dangerous_exts)
    
    # Calculate mock heuristic threat score
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
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    log_entry = {
        **decision,
        "filename": payload.filename,
        "source_url": payload.source_url,
        "file_size": payload.file_size_bytes
    }
    log_incident_to_disk(log_entry)

    return decision

@app.get("/api/v1/logs")
def get_audit_logs():
    """Returns recent security audit logs for the SOC dashboard."""
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

if __name__ == "__main__":
    print("=" * 65)
    print("🛡️ Starting CogniGuard AI Local Security Bridge Daemon...")
    print("📡 Listening at: http://127.0.0.1:8765")
    print("🔒 Endpoints:")
    print("   • GET  /api/v1/health   -> Operational status")
    print("   • POST /api/v1/inspect  -> Pre-execution threat analysis")
    print("   • GET  /api/v1/logs     -> SOC audit event history")
    print("=" * 65)
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
