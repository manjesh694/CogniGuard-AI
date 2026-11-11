"""
CogniGuard AI - Automated Threat Intelligence IOC Feed Sync
Author: CogniGuard Engineering Team
Description: Imports and normalizes SHA-256 threat intelligence feeds from
             built-in community baseline indicators, local JSON/CSV/STIX2
             bundles, or SSRF-guarded HTTPS threat feeds into SQLite.
"""

import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.storage import CogniGuardStore  # noqa: E402

SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
STIX_SHA256_RE = re.compile(r"SHA-256'\s*=\s*'([0-9a-fA-F]{64})'", re.IGNORECASE)
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}

BUILTIN_THREAT_FEED: List[Dict[str, str]] = [
    {
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "label": "EICAR_Standard_AV_Test_File",
        "severity": "CRITICAL",
    },
    {
        "sha256": "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
        "label": "Lumma_Infostealer_Sample_Hash",
        "severity": "CRITICAL",
    },
    {
        "sha256": "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
        "label": "RedLine_Dropper_Campaign_Hash",
        "severity": "HIGH",
    },
]


def validate_feed_url(raw_url: str) -> str:
    """Validate that a remote IOC feed URL uses public HTTPS without private-network SSRF targets."""
    cleaned = (raw_url or "").strip()
    if not cleaned or any(ch.isspace() for ch in cleaned):
        raise ValueError("Feed URL must be non-empty without whitespace.")

    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme != "https" or not host:
        raise ValueError("Remote threat feeds must use a valid public https:// URL.")
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        raise ValueError("Localhost and internal .local hosts are not permitted for threat feeds.")

    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_loopback or ip_obj.is_reserved:
            raise ValueError("Private or reserved IP addresses are not permitted for threat feeds.")
    except ValueError as exc:
        if "not permitted" in str(exc):
            raise

    return cleaned


def _normalize_entry(sha256: str, label: str, severity: str = "CRITICAL") -> Optional[Dict[str, str]]:
    clean_sha = (sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", clean_sha):
        return None
    clean_sev = (severity or "CRITICAL").strip().upper()
    if clean_sev not in VALID_SEVERITIES:
        clean_sev = "HIGH"
    clean_label = (label or "Synced_Threat_IOC").strip()[:200] or "Synced_Threat_IOC"
    return {"sha256": clean_sha, "label": clean_label, "severity": clean_sev}


def parse_ioc_entries(raw_payload: Any) -> List[Dict[str, str]]:
    """Parse JSON lists, MalwareBazaar/STIX2 bundles, or plain text SHA-256 feeds."""
    entries: List[Dict[str, str]] = []
    seen = set()

    def push(item: Optional[Dict[str, str]]) -> None:
        if item and item["sha256"] not in seen:
            seen.add(item["sha256"])
            entries.append(item)

    if isinstance(raw_payload, str):
        text = raw_payload.strip()
        if text.startswith(("{", "[")):
            try:
                return parse_ioc_entries(json.loads(text))
            except json.JSONDecodeError:
                pass
        for line in text.splitlines():
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue
            match = SHA256_RE.search(line_clean)
            if match:
                parts = [p.strip() for p in re.split(r"[,;\t|]+", line_clean) if p.strip()]
                label = next((p for p in parts if p.lower() != match.group(1).lower()), "Imported_Threat_Hash")
                push(_normalize_entry(match.group(1), label, "CRITICAL"))
        return entries

    if isinstance(raw_payload, dict):
        if isinstance(raw_payload.get("objects"), list):
            for obj in raw_payload["objects"]:
                if isinstance(obj, dict) and obj.get("type") == "indicator":
                    stix_match = STIX_SHA256_RE.search(str(obj.get("pattern") or ""))
                    if stix_match:
                        push(_normalize_entry(stix_match.group(1), str(obj.get("name") or "STIX2_Indicator"), "CRITICAL"))
        if isinstance(raw_payload.get("data"), list):
            raw_payload = raw_payload["data"]
        elif isinstance(raw_payload.get("iocs"), list):
            raw_payload = raw_payload["iocs"]
        elif "sha256" in raw_payload or "sha256_hash" in raw_payload:
            raw_payload = [raw_payload]
        else:
            raw_payload = []

    if isinstance(raw_payload, list):
        for item in raw_payload:
            if isinstance(item, str):
                push(_normalize_entry(item, "Imported_Threat_Hash", "CRITICAL"))
            elif isinstance(item, dict):
                sha = str(item.get("sha256") or item.get("sha256_hash") or "")
                label = str(item.get("label") or item.get("signature") or item.get("malware") or "Synced_Threat_IOC")
                sev = str(item.get("severity") or "CRITICAL")
                push(_normalize_entry(sha, label, sev))

    return entries


def apply_ioc_entries(entries: List[Dict[str, str]], store: CogniGuardStore, source_name: str) -> Dict[str, Any]:
    """Upsert normalized IOC entries into SQLite and return a sync summary."""
    imported = 0
    for item in entries:
        store.add_ioc(item["sha256"], item["label"], item["severity"])
        imported += 1
    return {
        "status": "OK",
        "source": source_name,
        "imported_count": imported,
        "total_iocs": len(store.list_iocs(limit=500)),
    }


def sync_builtin_feed(store: CogniGuardStore) -> Dict[str, Any]:
    """Load CogniGuard's curated built-in starter IOC feed into SQLite."""
    return apply_ioc_entries(BUILTIN_THREAT_FEED, store=store, source_name="builtin_community_feed")


def import_ioc_bundle(filepath: str, store: CogniGuardStore) -> Dict[str, Any]:
    """Import IOCs from a local JSON, STIX2, CSV, or newline SHA-256 bundle file."""
    abs_path = os.path.abspath(filepath)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"IOC bundle file not found: {filepath}")
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        entries = parse_ioc_entries(f.read())
    return apply_ioc_entries(entries, store=store, source_name=os.path.basename(abs_path))


def sync_remote_feed(feed_url: str, store: CogniGuardStore, timeout: int = 10) -> Dict[str, Any]:
    """Download and sync SHA-256 threat indicators from an SSRF-validated HTTPS feed."""
    safe_url = validate_feed_url(feed_url)
    resp = requests.get(safe_url, timeout=timeout)
    resp.raise_for_status()
    try:
        payload: Any = resp.json()
    except ValueError:
        payload = resp.text
    entries = parse_ioc_entries(payload)
    return apply_ioc_entries(entries, store=store, source_name=safe_url)
