"""
CogniGuard AI - SHA-256 Quarantine Vault Manager
Author: CogniGuard Engineering Team
Description: Isolates suspicious files into a non-executable .quarantine vault,
             records SHA-256 digests in SQLite, and supports safe restore or shred.
"""

import hashlib
import os
import re
import shutil
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.storage import CogniGuardStore  # noqa: E402

DEFAULT_VAULT_DIR = os.path.abspath(os.path.join(_AGENT_DIR, "..", "..", ".quarantine"))


def compute_sha256(filepath: str) -> str:
    """Compute hex SHA-256 digest of a file in 64 KB chunks."""
    digest = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineManager:
    """Manages isolation, restoration, and shredding of flagged payloads."""

    def __init__(
        self,
        vault_dir: Optional[str] = None,
        store: Optional[CogniGuardStore] = None,
    ):
        self.vault_dir = vault_dir or os.environ.get("COGNIGUARD_QUARANTINE_DIR") or DEFAULT_VAULT_DIR
        self.store = store or CogniGuardStore()
        os.makedirs(self.vault_dir, exist_ok=True)

    def quarantine_file(
        self,
        filepath: str,
        reason: str,
        threat_score: float = 0.96,
    ) -> Dict[str, Any]:
        """Hash and move a flagged file into the locked .quarantine vault."""
        abs_src = os.path.abspath(filepath)
        if not os.path.isfile(abs_src):
            raise FileNotFoundError(f"File not found: {filepath}")

        qid = uuid.uuid4().hex[:12]
        orig_name = os.path.basename(abs_src)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", orig_name)
        sha256 = compute_sha256(abs_src)
        size_bytes = os.path.getsize(abs_src)

        vault_path = os.path.join(self.vault_dir, f"{qid}__{safe_name}.quarantine")
        shutil.move(abs_src, vault_path)

        record = {
            "id": qid,
            "filename": orig_name,
            "original_path": abs_src,
            "vault_path": vault_path,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "threat_score": threat_score,
            "reason": reason,
            "status": "QUARANTINED",
            "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return self.store.record_quarantine_item(record)

    def restore_file(self, qid: str) -> Optional[Dict[str, Any]]:
        """Restore a quarantined file back to its original path."""
        item = self.store.get_quarantine_item(qid)
        if not item or item["status"] != "QUARANTINED":
            return None
        if not os.path.exists(item["vault_path"]):
            return None

        dest_dir = os.path.dirname(item["original_path"])
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
        shutil.move(item["vault_path"], item["original_path"])
        self.store.update_quarantine_status(qid, "RESTORED")
        item["status"] = "RESTORED"
        return item

    def shred_file(self, qid: str) -> bool:
        """Permanently remove a quarantined file from disk."""
        item = self.store.get_quarantine_item(qid)
        if not item:
            return False
        if os.path.exists(item["vault_path"]):
            os.remove(item["vault_path"])
        self.store.update_quarantine_status(qid, "SHREDDED")
        return True
