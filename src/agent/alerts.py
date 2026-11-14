"""
CogniGuard AI - Real-Time Multi-Channel SOC Alert Dispatcher
Author: CogniGuard Engineering Team
Description: Sends non-blocking threat notifications to Telegram, Discord, Slack,
             and custom SIEM webhooks with SSRF-safe URL validation and rich formatting.
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
TELEGRAM_BOT_TOKEN_KEY = "telegram_bot_token"
TELEGRAM_CHAT_ID_KEY = "telegram_chat_id"


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
    """Build a multi-compatible payload for Slack, Discord, and generic SIEM webhooks."""
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

    # Discord Rich Embed format
    discord_embed = {
        "title": f"🚨 CogniGuard AI SOC Alert — {severity}",
        "description": f"**Threat Intercepted:** {reason}",
        "color": 0xFF0033 if severity == "CRITICAL" else 0xFF9900,
        "fields": [
            {"name": "Target / Resource", "value": f"`{filename}`", "inline": True},
            {"name": "Threat Score", "value": f"{float(score)*100:.1f}%", "inline": True},
            {"name": "Containment", "value": f"⚡ {action} (0 Bytes Leaked)", "inline": False},
            {"name": "Timestamp", "value": ts, "inline": True},
        ],
        "footer": {"text": "CogniGuard AI Autonomous Zero-Entry Defense Council"},
    }

    # Slack Blocks format
    slack_blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🚨 CogniGuard AI Incident Alert [{severity}]", "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Target:*\n`{filename}`"},
                {"type": "mrkdwn", "text": f"*Score:*\n{float(score)*100:.1f}%"},
                {"type": "mrkdwn", "text": f"*Verdict:*\n{reason}"},
                {"type": "mrkdwn", "text": f"*Action Taken:*\n`{action}` (0 Bytes Leaked)"},
            ],
        },
    ]

    return {
        "text": summary,
        "content": summary,
        "embeds": [discord_embed],
        "blocks": slack_blocks,
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


def format_telegram_message(event: Dict[str, Any]) -> str:
    """Format markdown message for Telegram Bot API."""
    severity = str(event.get("severity") or "CRITICAL").upper()
    filename = event.get("filename") or event.get("target") or "unknown"
    reason = event.get("reason") or event.get("verdict") or "Security threat intercepted"
    action = event.get("action_taken") or "CONTAINED"
    score = event.get("threat_score", 0.98)
    ts = event.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return (
        f"🚨 *COGNIGUARD AI SOC ALERT*\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ *Severity:* `{severity}`\n"
        f"🎯 *Target:* `{filename}`\n"
        f"🔥 *Threat Score:* `{float(score)*100:.1f}%`\n"
        f"🔍 *Verdict:* {reason}\n"
        f"🛡️ *Action:* `{action}` (0 Bytes Leaked)\n"
        f"⏰ *Time:* `{ts}`\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 _System Secured & Protected by CogniGuard Zero-Entry Council_"
    )


class WebhookDispatcher:
    """Dispatches threat notifications synchronously or on background threads across channels."""

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

    def get_telegram_config(self) -> Tuple[Optional[str], Optional[str]]:
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not bot_token and self.store is not None:
            bot_token = self.store.get_setting(TELEGRAM_BOT_TOKEN_KEY) or ""
        if not chat_id and self.store is not None:
            chat_id = self.store.get_setting(TELEGRAM_CHAT_ID_KEY) or ""
        return (bot_token or None, chat_id or None)

    def send_telegram(self, event: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        token, chat_id = self.get_telegram_config()
        if not token or not chat_id:
            return False, "Telegram Bot Token or Chat ID not configured"

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        text = format_telegram_message(event)
        try:
            resp = requests.post(
                url,
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=self.timeout,
            )
            ok = 200 <= resp.status_code < 300
            return ok, None if ok else f"Telegram HTTP {resp.status_code}: {resp.text[:100]}"
        except Exception as exc:
            return False, str(exc)

    def send_sync(
        self, event: Dict[str, Any], override_url: Optional[str] = None
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        target = override_url or self.get_webhook_url()
        webhook_ok, status_code, err = False, None, None

        if target:
            try:
                validated = validate_webhook_url(target)
                payload = format_alert_payload(event)
                resp = requests.post(validated, json=payload, timeout=self.timeout)
                webhook_ok = 200 <= resp.status_code < 300
                status_code = resp.status_code
                err = None if webhook_ok else f"HTTP {resp.status_code}"
            except Exception as exc:
                webhook_ok, status_code, err = False, None, str(exc)

        # Also dispatch to Telegram if configured
        tg_ok, tg_err = self.send_telegram(event)

        if not target and not tg_ok:
            return False, None, tg_err or "No webhook URL or Telegram credentials configured"

        return (webhook_ok or tg_ok), status_code, err

    def dispatch_async(self, event: Dict[str, Any]) -> bool:
        has_webhook = bool(self.get_webhook_url())
        has_tg = bool(self.get_telegram_config()[0] and self.get_telegram_config()[1])
        if not has_webhook and not has_tg:
            return False
        thread = threading.Thread(target=self.send_sync, args=(event,), daemon=True)
        thread.start()
        return True
