"""
CogniGuard AI - GitHub Repo & AI Skill Pre-Install Scanner (CLI)
Author: CogniGuard Engineering Team
Description: Scans local repositories, public GitHub URLs, npm/pip packages,
             and AI Agent skills before installation to detect hidden backdoors,
             credential theft, malicious install hooks, and prompt injections.
Usage: python src/agent/repo_scanner.py <folder_path_or_github_url>
"""

import ast
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Executable code patterns (for .py, .js, .ts, .sh, .ps1, .bat)
CODE_SIGNATURES: List[Tuple[str, str, int]] = [
    (r"(open\(.*(\.ssh|id_rsa|aws/credentials|Network/Cookies))", "Unauthorized Credential / SSH File Read", 50),
    (r"(base64\s*-d|frombase64string|b64decode)", "Obfuscated Base64 Payload Execution", 35),
    (r"(curl\s+.*http|wget\s+.*http).*(\$|env|token|key)", "Suspicious Credential Exfiltration via Network", 45),
    (r"(eval\(|exec\(|os\.system\(|subprocess\.Popen)", "Dynamic Shell / Remote Code Execution", 20),
    (r"(cryptunprotectdata|Login Data)", "Browser Password Decryption Stealer", 50),
    (r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True", "Shell Injection Risk (subprocess shell=True)", 25),
    (r"(?:-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{16,}", "Obfuscated PowerShell EncodedCommand", 45),
    (
        r"(?:requests\.(?:post|put)|urllib\.request\.urlopen|fetch\().*(?:os\.environ|AWS_SECRET|id_rsa|token|cookie)",
        "Programmatic Environment / Secret Exfiltration",
        45,
    ),
]

# Prompt injection & pipe-to-shell patterns (for .md, .yaml, .yml, .txt)
PROMPT_INJECTION_SIGNATURES: List[Tuple[str, str, int]] = [
    (r"(ignore previous instructions|disregard system prompt|bypass safety)", "AI Skill Prompt Injection Attack", 50),
    (r"(exfiltrate|send secrets to http)", "Hidden Malicious AI Instruction", 50),
    (r"(?:curl|wget|powershell|irm)\s+https?://[^|\n]+\|\s*(?:sh|bash|iex)", "Pipe-to-Shell Remote Execution Instruction", 50),
]

# Malicious npm lifecycle hook patterns (for package.json)
MALICIOUS_NPM_HOOK_RE = re.compile(
    r'"(?:preinstall|install|postinstall|prepare)"\s*:\s*"[^"]*(?:curl|wget|powershell|bash\s+-c|sh\s+-c|node\s+-e|eval|base64)',
    re.IGNORECASE,
)
ANY_NPM_HOOK_RE = re.compile(r'"(?:preinstall|postinstall)"\s*:', re.IGNORECASE)

CODE_EXTENSIONS = (".py", ".js", ".ts", ".sh", ".ps1", ".bat")
DOC_EXTENSIONS = (".md", ".yaml", ".yml", ".txt")
GITHUB_REPO_PATH_RE = re.compile(r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")

# CogniGuard's own core modules (skip self-signatures when scanning self)
SELF_DEFENSE_FILES = {
    "repo_scanner.py", "reverse_engineer.py", "honeypot_trap.py",
    "vault_guardian.py", "simulator.py", "full_system_scanner.py",
    "api_bridge.py", "verify_all.py", "bank_passwords_and_pins.txt",
    "cli.py", "heuristics.py", "storage.py", "quarantine.py",
    "guardian_daemon_24x7.py", "alerts.py",
    "test_api_and_cli.py", "test_backend_modules.py",
}


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per character) for obfuscation detection."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _call_name(node: ast.AST) -> str:
    """Extract dotted name for simple AST call targets."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def _collect_docstring_ids(tree: ast.AST) -> Set[int]:
    """Return object ids of AST Constant nodes that are module/class/function docstrings."""
    doc_ids: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr):
                val = node.body[0].value
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    doc_ids.add(id(val))
    return doc_ids


def _ast_inspect_python(rel_path: str, content: str) -> List[Dict[str, Any]]:
    """Inspect Python AST for evasive imports, builtins lookups, and high-entropy blobs."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings: List[Dict[str, Any]] = []
    seen_threats: Set[str] = set()
    docstring_ids = _collect_docstring_ids(tree)

    def add_finding(threat: str, score: int) -> None:
        if threat not in seen_threats:
            seen_threats.add(threat)
            findings.append({"file": rel_path, "threat": threat, "score": score})

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name == "__import__":
                add_finding("Dynamic __import__() Code Loading", 40)
            elif name == "getattr" and node.args:
                target_arg = node.args[0]
                if isinstance(target_arg, ast.Name) and target_arg.id in {"__builtins__", "builtins"}:
                    add_finding("Obfuscated Builtins Lookup", 45)
            elif name in {"marshal.loads", "pickle.loads"}:
                add_finding("Unsafe Binary Deserialization (marshal/pickle)", 35)
            elif name in {"eval", "exec"} and node.args:
                inner_calls = {_call_name(sub.func) for sub in ast.walk(node.args[0]) if isinstance(sub, ast.Call)}
                if inner_calls & {"bytes.fromhex", "zlib.decompress", "marshal.loads", "compile", "base64.b64decode"}:
                    add_finding("AST-Detected Obfuscated Dynamic Execution", 50)
        elif (
            isinstance(node, ast.Constant)
            and id(node) not in docstring_ids
            and isinstance(node.value, str)
            and len(node.value) >= 64
            and not any(ch.isspace() for ch in node.value)
            and not node.value.startswith(("http://", "https://"))
            and _shannon_entropy(node.value) >= 4.7
        ):
            add_finding("High-Entropy Obfuscated Payload Blob", 30)

    return findings


def is_url_like(target: str) -> bool:
    """Return True if target looks like a remote repository URL."""
    lower = target.strip().lower()
    return "://" in lower or lower.startswith("git@")


def validate_github_url(raw_url: str) -> str:
    """Validate and normalize a public HTTPS GitHub repository URL.

    Rejects non-HTTPS schemes, non-GitHub hosts, query/fragment tricks, and
    git option-injection strings.
    """
    cleaned = raw_url.strip()
    if not cleaned or cleaned.startswith("-") or any(ch.isspace() for ch in cleaned):
        raise ValueError(f"Unsafe or malformed repository URL: {raw_url}")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Only public https://github.com/<owner>/<repo> URLs are supported.")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("GitHub URL must not contain credentials, query strings, or fragments.")

    match = GITHUB_REPO_PATH_RE.match(parsed.path)
    if not match:
        raise ValueError("URL path must match https://github.com/<owner>/<repo>.")

    owner, repo = match.group(1), match.group(2)
    if owner in {".", ".."} or repo in {".", ".."}:
        raise ValueError("Invalid owner or repository name.")

    return f"https://github.com/{owner}/{repo}.git"


def _evaluate_file_content(rel_path: str, filename: str, content: str) -> List[Dict[str, Any]]:
    """Run signature checks on a single file's text and return findings."""
    lower_file = filename.lower()
    file_findings: List[Dict[str, Any]] = []

    if lower_file == "package.json":
        if MALICIOUS_NPM_HOOK_RE.search(content):
            file_findings.append({
                "file": rel_path,
                "threat": "Malicious npm Lifecycle Install Hook",
                "score": 50,
            })
        elif ANY_NPM_HOOK_RE.search(content):
            file_findings.append({
                "file": rel_path,
                "threat": "npm Lifecycle Hook Present (Manual Review)",
                "score": 15,
            })
        return file_findings

    sigs = CODE_SIGNATURES if lower_file.endswith(CODE_EXTENSIONS) else PROMPT_INJECTION_SIGNATURES
    seen_threats: Set[str] = set()
    for pattern, description, score in sigs:
        if re.search(pattern, content, re.IGNORECASE) and description not in seen_threats:
            seen_threats.add(description)
            file_findings.append({"file": rel_path, "threat": description, "score": score})

    if lower_file.endswith(".py"):
        for ast_item in _ast_inspect_python(rel_path, content):
            if ast_item["threat"] not in seen_threats:
                seen_threats.add(ast_item["threat"])
                file_findings.append(ast_item)

    return file_findings


def _scan_local_directory(
    target_dir: str,
    display_target: Optional[str] = None,
    quiet: bool = False,
) -> Dict[str, Any]:
    """Scan all supported files inside an existing local directory."""
    shown_target = display_target or target_dir
    if not quiet:
        print("\n" + "=" * 60)
        print(f"$ cogniguard scan {shown_target}")
        print("=" * 60)

    start_time = time.time()
    files_scanned = 0
    total_risk_score = 0
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(target_dir):
        skip_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist"}
        if os.path.basename(os.path.abspath(target_dir)) != "mock_infected_skill":
            skip_dirs.add("mock_infected_skill")
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for file in files:
            lower_file = file.lower()
            is_supported = (
                lower_file.endswith(CODE_EXTENSIONS)
                or lower_file.endswith(DOC_EXTENSIONS)
                or lower_file == "package.json"
            )
            if not is_supported or file in SELF_DEFENSE_FILES:
                continue

            filepath = os.path.join(root, file)
            files_scanned += 1

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                rel_path = os.path.relpath(filepath, target_dir)
                for item in _evaluate_file_content(rel_path, file, content):
                    total_risk_score += item["score"]
                    findings.append(item)
            except Exception:
                pass

    final_score = min(100, total_risk_score)
    elapsed = time.time() - start_time

    if final_score >= 70:
        severity, verdict, color_icon = "CRITICAL", "DO_NOT_INSTALL", "🚨"
    elif final_score >= 30:
        severity, verdict, color_icon = "MEDIUM", "REVIEW_REQUIRED", "⚠️"
    else:
        severity, verdict, color_icon = "LOW", "SAFE_TO_INSTALL", "✅"

    if not quiet:
        print(f"Scanned {files_scanned:,} files in {elapsed:.2f}s\n")
        print("+" + "-" * 42 + "+")
        print(f"| Risk score   {final_score:>3} / 100                   |")
        print(f"| Severity     {severity:<27} |")
        print(f"| Verdict      {color_icon} {verdict:<24} |")
        print("+" + "-" * 42 + "+")

        if findings:
            print("\n🔍 Top Security Findings:")
            for item in findings[:5]:
                print(f"  • [{item['file']}] -> {item['threat']} (+{item['score']} risk)")
        else:
            print("\n🛡️ Clean repository: No hidden backdoors or credential stealers detected.")

        print("=" * 60 + "\n")

    return {
        "target": shown_target,
        "files_scanned": files_scanned,
        "risk_score": final_score,
        "severity": severity,
        "verdict": verdict,
        "findings": findings,
    }


def format_scan_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a scan_repository report into SARIF v2.1.0 for GitHub Code Scanning."""
    rules: List[Dict[str, Any]] = []
    seen_rules: Set[str] = set()
    results: List[Dict[str, Any]] = []

    for item in report.get("findings", []):
        threat = item["threat"]
        rule_id = re.sub(r"[^a-z0-9]+", "-", threat.lower()).strip("-") or "cogniguard-finding"
        level = "error" if item["score"] >= 35 else "warning"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": threat,
                "shortDescription": {"text": threat},
                "defaultConfiguration": {"level": level},
            })
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{threat} (+{item['score']} risk)"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(item["file"]).replace("\\", "/")},
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CogniGuard AI",
                    "version": "1.0.4",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def scan_repository(
    target: str,
    clone_timeout: int = 30,
    quiet: bool = False,
) -> Optional[Dict[str, Any]]:
    """Scan a local repository folder or a public HTTPS GitHub repository URL."""
    if is_url_like(target):
        normalized_url = validate_github_url(target)
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        with tempfile.TemporaryDirectory(prefix="cogniguard_repo_", ignore_cleanup_errors=True) as tmp_dir:
            clone_dir = os.path.join(tmp_dir, "repo")
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--", normalized_url, clone_dir],
                capture_output=True,
                text=True,
                timeout=clone_timeout,
                env=env,
            )
            if proc.returncode != 0:
                err_msg = (proc.stderr or proc.stdout or "git clone failed").strip()
                raise RuntimeError(f"Failed to clone {normalized_url}: {err_msg}")
            return _scan_local_directory(clone_dir, display_target=normalized_url, quiet=quiet)

    if not os.path.exists(target):
        if not quiet:
            print(f"[!] Directory not found: {target}")
        return None

    return _scan_local_directory(target, quiet=quiet)


if __name__ == "__main__":
    target_arg = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    try:
        scan_repository(target_arg)
    except (ValueError, RuntimeError) as exc:
        print(f"[!] {exc}")
        sys.exit(1)
