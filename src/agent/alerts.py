"""
CogniGuard AI - Real-Time Webhook Alert Dispatcher
Author: CogniGuard Engineering Team
Description: Sends non-blocking threat notifications to Slack, Discord, or
             custom SIEM webhooks with SSRF-safe URL validation.
"""

import ipaddress
import os
import sys
import threading
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.storage import CogniGuardStore  # noqa: E402

WEBHOOK_SETTING_KEY = "alert_webhook_url"


def validate_webhook_url(raw_url: str) -> str:
    """Validate webhook URL, allowing HTTPS or explicit localhost for testing."""
    cleaned = (raw_url or "").strip()
    if not cleaned or any(ch.isspace() for ch in cleaned):
        raise ValueError("Webhook URL must be non-empty without whitespace.")

    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    if not host:
        raise ValueError("Webhook URL is missing a hostname.")

    is_localhost = host in {"localhost", "127.0.0.1", "::1"}
    if scheme == "http" and not is_localhost:
        raise ValueError("Insecure http:// webhooks are only allowed for localhost.")
    if scheme not in {"https", "http"}:
        raise ValueError("Webhook URL must use https:// (or http://localhost for local tests).")

    # Block link-local / cloud metadata IPs even on HTTPS
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_link_local or (ip_obj.is_private and not is_localhost):
            raise ValueError("Private or link-local IP addresses are not permitted for webhooks.")
    except ValueError as exc:
        if "not permitted" in str(exc):
            raise

    return cleaned


def mask_webhook_url(url: str) -> str:
    """Return a masked version of a webhook URL safe for API responses."""
    parsed = urlparse(url)
    path_tail = parsed.path[-6:] if len(parsed.path) > 6 else parsed.path
    return f"{parsed.scheme}://{parsed.netloc}/***{path_tail}"


def format_alert_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    """Build a payload compatible with Slack, Discord, and generic SIEM webhooks."""
    severity = str(event.get("severity") or "CRITICAL").upper()
    filename = event.get("filename") or event.get("target") or "unknown"
    reason = event.get("reason") or event.get("verdict") or "Security threat intercepted"
    action = event.get("action_taken") or "CONTAINED"
    score = event.get("threat_score", 0.98)
    ts = event.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = (
        f"🚨 [CogniGuard AI | {severity}] {filename} — {reason} "
        f"(Score: {score}, Action: {action}) @ {ts}"
    )
    return {
        "text": summary,
        "content": summary,
        "cogniguard_event": {
            "severity": severity,
            "filename": filename,
            "reason": reason,
            "threat_score": score,
            "action_taken": action,
            "source_url": event.get("source_url", ""),
            "timestamp": ts,
        },
    }


class WebhookDispatcher:
    """Dispatches threat notifications synchronously or on background threads."""

    def __init__(self, store: Optional[CogniGuardStore] = None, timeout: float = 4.0):
        self.store = store
        self.timeout = timeout

    def get_webhook_url(self) -> Optional[str]:
        env_url = os.environ.get("COGNIGUARD_WEBHOOK_URL", "").strip()
        if env_url:
            return env_url
        if self.store is not None:
            return self.store.get_setting(WEBHOOK_SETTING_KEY)
        return None

    def send_sync(self, event: Dict[str, Any], override_url: Optional[str] = None) -> Tuple[bool, Optional[int], Optional[str]]:
        target = override_url or self.get_webhook_url()
        if not target:
            return False, None, "No webhook URL configured"

        try:
            validated = validate_webhook_url(target)
            payload = format_alert_payload(event)
            resp = requests.post(validated, json=payload, timeout=self.timeout)
            ok = 200 <= resp.status_code < 300
            return ok, resp.status_code, None if ok else f"HTTP {resp.status_code}"
        except Exception as exc:
            return False, None, str(exc)

    def dispatch_async(self, event: Dict[str, Any]) -> bool:
        if not self.get_webhook_url():
            return False
        thread = threading.Thread(target=self.send_sync, args=(event,), daemon=True)
        thread.start()
        return True
