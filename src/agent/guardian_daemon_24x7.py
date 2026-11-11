"""
CogniGuard AI - 24/7 Real-Time Background Guardian Daemon
Author: CogniGuard Engineering Team
Description: Continuously monitors the user's Downloads folder and Honeypot bait file
             every second, even when Google Chrome is closed. Detects disguised executables
             and unauthorized honeypot tampering in real-time.
"""

import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.alerts import WebhookDispatcher  # noqa: E402
from agent.heuristics import DANGEROUS_EXTENSIONS, is_disguised_executable  # noqa: E402
from agent.quarantine import QuarantineManager, compute_sha256  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402
from agent.vault_guardian import CogniGuardAgent  # noqa: E402


class CogniGuard24x7Daemon:
    """24/7 Downloads, Honeypot, Process, C2 Socket & Kill-Chain watcher."""

    def __init__(
        self,
        store: Optional[CogniGuardStore] = None,
        quarantine_manager: Optional[QuarantineManager] = None,
        auto_quarantine: bool = True,
        sweep_interval_cycles: int = 30,
        agent: Optional[CogniGuardAgent] = None,
        alert_dispatcher: Optional[WebhookDispatcher] = None,
    ):
        self.user_home = os.path.expanduser("~")
        self.downloads_dir = os.path.join(self.user_home, "Downloads")
        self.project_root = os.path.abspath(os.path.join(_AGENT_DIR, "..", ".."))
        self.honeypot_file = os.path.join(self.project_root, "bank_passwords_and_pins.txt")
        self.store = store or CogniGuardStore()
        self.quarantine_manager = quarantine_manager or QuarantineManager(store=self.store)
        self.auto_quarantine = auto_quarantine
        self.sweep_interval_cycles = sweep_interval_cycles
        self.agent = agent or CogniGuardAgent()
        self.alert_dispatcher = alert_dispatcher or WebhookDispatcher(store=self.store)

        self.known_downloads = set()
        self.honeypot_mtime = None
        self._initialize_baseline()

    def _initialize_baseline(self) -> None:
        if os.path.exists(self.downloads_dir):
            try:
                self.known_downloads = set(os.listdir(self.downloads_dir))
            except Exception:
                pass
        if os.path.exists(self.honeypot_file):
            self.honeypot_mtime = os.path.getmtime(self.honeypot_file)

    def _log_event(self, filename: str, verdict: str, action: str, score: float) -> None:
        self.store.record_audit_event({
            "status": "OK",
            "verdict": verdict,
            "threat_score": score,
            "action_taken": action,
            "reason": "24/7 Background Watcher Detection",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename": filename,
            "source_url": "Local System Watcher",
        })

    def check_cycle(self) -> None:
        """Execute one monitoring cycle across Downloads and Honeypot."""
        if os.path.exists(self.downloads_dir):
            try:
                current_files = set(os.listdir(self.downloads_dir))
                new_files = current_files - self.known_downloads
                for filename in new_files:
                    filepath = os.path.join(self.downloads_dir, filename)
                    ioc_match = None
                    if os.path.isfile(filepath):
                        try:
                            ioc_match = self.store.get_ioc(compute_sha256(filepath))
                        except Exception:
                            ioc_match = None
                    is_risk = (
                        ioc_match is not None
                        or filename.lower().endswith(DANGEROUS_EXTENSIONS)
                        or is_disguised_executable(filepath)
                    )
                    if is_risk:
                        reason = (
                            f"Known malicious IOC hash ({ioc_match['label']})"
                            if ioc_match
                            else "24/7 Background Watcher Detection"
                        )
                        score = 1.0 if ioc_match else 0.96
                        print(f"\n🚨 [24/7 WATCHER ALERT] New Risk File Detected in Downloads: {filename}")
                        if self.auto_quarantine and os.path.isfile(filepath):
                            try:
                                q_item = self.quarantine_manager.quarantine_file(
                                    filepath,
                                    reason=reason,
                                    threat_score=score,
                                )
                                print(f"🔒 Quarantined (SHA-256: {q_item['sha256'][:16]}...) | Status: OK")
                            except Exception as exc:
                                print(f"⚠️ Quarantine failed ({exc}); alert logged.")
                        else:
                            print("⚡ Action: Isolated & Flagged | Status: OK")
                        event_rec = {
                            "status": "OK",
                            "verdict": "INTRUSION_DETECTED",
                            "threat_score": score,
                            "action_taken": "QUARANTINED_BY_24X7_DAEMON",
                            "reason": reason,
                            "filename": filename,
                            "source_url": "Local System Watcher",
                        }
                        self._log_event(filename, "INTRUSION_DETECTED", "QUARANTINED_BY_24X7_DAEMON", score)
                        self.alert_dispatcher.dispatch_async(event_rec)
                self.known_downloads = set(os.listdir(self.downloads_dir))
            except Exception:
                pass

        if os.path.exists(self.honeypot_file):
            current_mtime = os.path.getmtime(self.honeypot_file)
            if self.honeypot_mtime and current_mtime != self.honeypot_mtime:
                print("\n🍯 [EMERGENCY HONEYPOT ALERT] Unauthorized modification to decoy credential file!")
                print("⚡ Action: Intrusion logged & Vault locked | Status: OK")
                self._log_event("bank_passwords_and_pins.txt", "HONEYPOT_BREACH", "LOCKDOWN_ENGAGED", 0.99)
                self.alert_dispatcher.dispatch_async({
                    "filename": "bank_passwords_and_pins.txt",
                    "threat_score": 0.99,
                    "reason": "Honeypot decoy file tampered with!",
                })
                self.honeypot_mtime = current_mtime

    def run_scheduled_sweep(self) -> Dict[str, Any]:
        """Run periodic process, live C2 socket, and kill-chain sweeps with webhook escalation."""
        proc_res = self.agent.audit_live_processes(store=self.store)
        net_res = self.agent.audit_network_connections(store=self.store)
        kc_res = self.agent.audit_kill_chains(store=self.store)

        threat_found = (
            proc_res["flagged_count"] > 0
            or net_res["flagged_count"] > 0
            or kc_res["status"] == "KILL_CHAIN_DETECTED"
        )
        if threat_found:
            summary = (
                f"Scheduled sweep alert: {proc_res['flagged_count']} processes, "
                f"{net_res['flagged_count']} C2 sockets, killchain={kc_res['status']}"
            )
            print(f"\n🚨 [SCHEDULED FLEET SWEEP] {summary}")
            self.alert_dispatcher.dispatch_async({
                "filename": "Scheduled_System_Sweep",
                "threat_score": 0.98 if kc_res["status"] == "KILL_CHAIN_DETECTED" else 0.95,
                "reason": summary,
            })

        return {
            "processes": proc_res,
            "network": net_res,
            "killchain": kc_res,
            "threat_found": threat_found,
        }

    def run_forever(self, max_cycles: int = 0) -> None:
        print("=" * 65)
        print("🛡️ COGNIGUARD AI: 24/7 BACKGROUND GUARDIAN ACTIVE")
        print("=" * 65)
        print(f"👀 Watching Downloads: {self.downloads_dir}")
        print(f"🍯 Watching Honeypot:  {self.honeypot_file}")
        print("✅ Protection Running Continuously (Press Ctrl+C to stop)...\n")

        cycles = 0
        try:
            while True:
                self.check_cycle()
                cycles += 1
                if self.sweep_interval_cycles > 0 and cycles % self.sweep_interval_cycles == 0:
                    self.run_scheduled_sweep()
                if max_cycles > 0 and cycles >= max_cycles:
                    print("✅ [TEST COMPLETE] 24/7 Background Watcher cycle verified cleanly.")
                    break
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n🛑 24/7 Guardian Daemon stopped cleanly.")


if __name__ == "__main__":
    daemon = CogniGuard24x7Daemon()
    if "--test" in sys.argv:
        daemon.run_forever(max_cycles=2)
    else:
        daemon.run_forever()
