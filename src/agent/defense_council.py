"""
CogniGuard AI - Autonomous Multi-Agent Defense Council
Author: CogniGuard Engineering Team
Description: Coordinates specialized Static, Runtime, and Kill-Chain Planner agents
             through an observe -> correlate -> contain -> verify security loop.
"""

import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.quarantine import QuarantineManager  # noqa: E402
from agent.repo_scanner import scan_repository  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402
from agent.vault_guardian import CogniGuardAgent  # noqa: E402


class AutonomousDefenseCouncil:
    """Multi-agent security coordinator executing closed-loop threat triage and verification."""

    def __init__(
        self,
        store: Optional[CogniGuardStore] = None,
        quarantine_manager: Optional[QuarantineManager] = None,
        agent: Optional[CogniGuardAgent] = None,
    ):
        self.store = store or CogniGuardStore()
        self.quarantine_manager = quarantine_manager or QuarantineManager(store=self.store)
        self.agent = agent or CogniGuardAgent()

    def _run_static_agent(self, target_dir: Optional[str]) -> Dict[str, Any]:
        """Run code, secret, AST-taint, and multi-head attention inspection on a workspace."""
        if not target_dir:
            return {"executed": False, "verdict": "SKIPPED", "risk_score": 0, "findings": []}
        report = scan_repository(target_dir, quiet=True)
        if report is None:
            return {"executed": False, "verdict": "NOT_FOUND", "risk_score": 0, "findings": []}
        return {
            "executed": True,
            "verdict": report["verdict"],
            "risk_score": report["risk_score"],
            "findings": report["findings"],
        }

    def _run_runtime_agent(self, include_runtime: bool) -> Dict[str, Any]:
        """Inspect live processes, LOLBins, outbound C2 sockets, and memory injections when enabled."""
        if not include_runtime:
            return {
                "executed": False,
                "processes_flagged": [],
                "network_flagged": [],
                "injections_flagged": [],
            }
        proc_res = self.agent.audit_live_processes(store=self.store)
        net_res = self.agent.audit_network_connections(store=self.store)
        inj_res = self.agent.audit_memory_injections(store=self.store)
        return {
            "executed": True,
            "processes_inspected": proc_res["processes_inspected"],
            "processes_flagged": proc_res["flagged"],
            "connections_inspected": net_res["connections_inspected"],
            "network_flagged": net_res["flagged"],
            "injections_flagged": inj_res["flagged"],
        }

    def _execute_containment(
        self,
        target_dir: Optional[str],
        static_res: Dict[str, Any],
        runtime_res: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Execute bounded quarantine and process termination for verified critical findings."""
        actions: List[Dict[str, Any]] = []

        if target_dir and static_res.get("verdict") == "DO_NOT_INSTALL":
            seen_files = set()
            for finding in static_res.get("findings", []):
                rel = finding.get("file", "")
                if not rel or rel in seen_files:
                    continue
                seen_files.add(rel)
                candidate = os.path.abspath(os.path.join(target_dir, rel))
                if os.path.isfile(candidate):
                    try:
                        qrec = self.quarantine_manager.quarantine_file(
                            candidate,
                            reason=f"Defense Council Auto-Containment: {finding['threat']}",
                            threat_score=0.98,
                        )
                        actions.append({
                            "type": "QUARANTINED_FILE",
                            "target": rel,
                            "quarantine_id": qrec["id"],
                        })
                    except OSError:
                        pass

        flagged_procs = (
            list(runtime_res.get("processes_flagged", []))
            + list(runtime_res.get("network_flagged", []))
            + list(runtime_res.get("injections_flagged", []))
        )
        if flagged_procs:
            for item in self.agent.terminate_flagged_processes(flagged_procs):
                actions.append({"type": "PROCESS_TERMINATION", **item})

        return actions

    def investigate(
        self,
        target_dir: Optional[str] = None,
        window_seconds: int = 300,
        auto_remediate: bool = False,
        include_runtime: bool = True,
    ) -> Dict[str, Any]:
        """Run Static, Runtime, and Kill-Chain Planner agents with optional closed-loop verification."""
        reasoning_trace: List[Dict[str, str]] = []

        static_res = self._run_static_agent(target_dir)
        reasoning_trace.append({
            "agent": "StaticSupplyChainAgent",
            "summary": f"verdict={static_res['verdict']} risk_score={static_res['risk_score']} findings={len(static_res['findings'])}",
        })

        runtime_res = self._run_runtime_agent(include_runtime=include_runtime)
        reasoning_trace.append({
            "agent": "RuntimeTelemetryAgent",
            "summary": (
                f"processes_flagged={len(runtime_res['processes_flagged'])} "
                f"network_flagged={len(runtime_res['network_flagged'])}"
            ),
        })

        killchain_res = self.agent.audit_kill_chains(store=self.store, window_seconds=window_seconds)
        reasoning_trace.append({
            "agent": "KillChainPlannerAgent",
            "summary": (
                f"status={killchain_res['status']} severity={killchain_res['severity']} "
                f"stages={killchain_res['stages_detected']}"
            ),
        })

        has_threat = (
            static_res.get("verdict") in {"DO_NOT_INSTALL", "REVIEW_REQUIRED"}
            or bool(runtime_res["processes_flagged"])
            or bool(runtime_res["network_flagged"])
            or killchain_res["status"] == "KILL_CHAIN_DETECTED"
        )

        actions_taken: List[Dict[str, Any]] = []
        post_verification: Optional[Dict[str, Any]] = None
        final_verdict = "THREATS_DETECTED" if has_threat else "OK"

        if auto_remediate and has_threat:
            actions_taken = self._execute_containment(target_dir, static_res, runtime_res)
            post_static = self._run_static_agent(target_dir)
            post_verification = {
                "post_static_verdict": post_static["verdict"],
                "post_static_risk_score": post_static["risk_score"],
            }
            reasoning_trace.append({
                "agent": "VerificationLoop",
                "summary": (
                    f"actions={len(actions_taken)} post_static_verdict={post_static['verdict']} "
                    f"post_risk={post_static['risk_score']}"
                ),
            })
            if (
                post_static["verdict"] in {"SAFE_TO_INSTALL", "SKIPPED"}
                and not runtime_res["processes_flagged"]
                and not runtime_res["network_flagged"]
                and killchain_res["status"] != "KILL_CHAIN_DETECTED"
            ):
                final_verdict = "CONTAINED_AND_VERIFIED"

        return {
            "status": final_verdict,
            "timestamp": datetime.now().isoformat(),
            "static": static_res,
            "runtime": runtime_res,
            "killchain": killchain_res,
            "actions_taken": actions_taken,
            "post_verification": post_verification,
            "reasoning_trace": reasoning_trace,
        }
