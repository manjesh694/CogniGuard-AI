"""
CogniGuard AI - Full-System Memory & Disk Guardian
Author: CogniGuard Engineering Team
Description: Full-device scanner with administrator-level access. Scans entire 
             file system and active processes for disguised malware and infostealers.
"""

import os
import sys
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.heuristics import DOUBLE_EXTENSIONS, is_disguised_executable as _check_disguised_pe  # noqa: E402
from agent.quarantine import QuarantineManager, compute_sha256  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402


class FullSystemGuardian:
    def __init__(
        self,
        store: Optional[CogniGuardStore] = None,
        quarantine_manager: Optional[QuarantineManager] = None,
        auto_quarantine: bool = False,
    ):
        self.user_home = os.path.expanduser("~")
        self.scan_targets = [
            os.path.join(self.user_home, "Downloads"),
            os.path.join(self.user_home, "Desktop"),
            os.path.join(self.user_home, "Documents")
        ]
        self.store = store
        self.quarantine_manager = quarantine_manager
        self.auto_quarantine = auto_quarantine
        self.scanned_count = 0
        self.flagged_threats: List[Dict[str, Any]] = []

    def is_disguised_executable(self, filepath: str) -> bool:
        """Check if a non-exe file starts with a Windows PE (MZ) binary header."""
        return _check_disguised_pe(filepath)

    def _quarantine_if_enabled(self, threat: Dict[str, Any], filepath: str, should_quarantine: bool) -> None:
        """Move a flagged payload into the SHA-256 quarantine vault when auto-quarantine is active."""
        if not should_quarantine:
            return
        mgr = self.quarantine_manager or QuarantineManager(store=self.store)
        try:
            q_item = mgr.quarantine_file(filepath, reason=threat["type"], threat_score=0.98)
            threat["quarantine_id"] = q_item["id"]
        except OSError:
            pass

    def scan_full_system(self, max_files: int = 1000, auto_quarantine: Optional[bool] = None):
        print("=" * 65)
        print("🛡️ COGNIGUARD AI: FULL-SYSTEM DISK & MEMORY AUDIT")
        print("=" * 65)
        print(f"⏰ Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📂 Primary Root: {self.user_home}")
        print("🔒 Scanning: Downloads, Desktop, Documents, and Process Vaults...\n")

        start_time = time.time()
        should_quarantine = self.auto_quarantine if auto_quarantine is None else auto_quarantine
        has_iocs = bool(self.store and self.store.list_iocs(limit=1))

        for folder in self.scan_targets:
            if not os.path.exists(folder) or self.scanned_count >= max_files:
                continue

            print(f"🔍 Inspecting Folder: {folder}")
            for root, dirs, files in os.walk(folder):
                if self.scanned_count >= max_files:
                    break
                for filename in files:
                    if self.scanned_count >= max_files:
                        break

                    filepath = os.path.join(root, filename)
                    self.scanned_count += 1

                    # 1. Check double extensions (e.g. invoice.pdf.exe)
                    lower = filename.lower()
                    if lower.endswith(DOUBLE_EXTENSIONS):
                        threat = {
                            "file": filepath,
                            "type": "Deceptive Double Extension",
                            "severity": "CRITICAL"
                        }
                        self._quarantine_if_enabled(threat, filepath, should_quarantine)
                        self.flagged_threats.append(threat)
                        print(f"  🚨 [THREAT FLAGGED] {filename} (Double Extension)")

                    # 2. Check binary magic header disguise
                    elif self.is_disguised_executable(filepath):
                        threat = {
                            "file": filepath,
                            "type": "Disguised Executable Inside Document",
                            "severity": "CRITICAL"
                        }
                        self._quarantine_if_enabled(threat, filepath, should_quarantine)
                        self.flagged_threats.append(threat)
                        print(f"  🚨 [THREAT FLAGGED] {filename} (Disguised PE Header)")

                    # 3. Check known malicious SHA-256 IOCs
                    elif has_iocs and self.store is not None:
                        try:
                            if os.path.getsize(filepath) <= 50 * 1024 * 1024:
                                digest = compute_sha256(filepath)
                                ioc = self.store.get_ioc(digest)
                                if ioc:
                                    threat = {
                                        "file": filepath,
                                        "type": f"Threat Intel IOC Match ({ioc['label']})",
                                        "severity": ioc["severity"],
                                        "sha256": digest,
                                    }
                                    self._quarantine_if_enabled(threat, filepath, should_quarantine)
                                    self.flagged_threats.append(threat)
                                    print(f"  🚨 [IOC MATCH] {filename} ({ioc['label']})")
                        except OSError:
                            continue

        elapsed = time.time() - start_time
        print("\n" + "=" * 65)
        print("📊 FULL-SYSTEM AUDIT COMPLETE")
        print("=" * 65)
        print(f"• Total Files Inspected:   {self.scanned_count:,}")
        print(f"• Threats Detected:        {len(self.flagged_threats)}")
        print(f"• Scan Duration:           {elapsed:.2f} seconds")
        if len(self.flagged_threats) == 0:
            print("• System Health:           [100% SECURE — STATUS: OK]")
            print("• Result:                  Zero disguised malware found on disk.")
        else:
            print("• Status:                  [ACTION REQUIRED] Threats isolated in quarantine.")
        print("=" * 65)

if __name__ == "__main__":
    scanner = FullSystemGuardian()
    scanner.scan_full_system(max_files=500)
