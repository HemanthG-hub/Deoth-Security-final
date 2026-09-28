"""Static checks for uploaded source; analyzers inspect text and never execute it."""

import ast
import importlib.util
import json
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path


def _finding(
    title: str,
    severity: str,
    cwe: str,
    owasp: str,
    line: int,
    evidence: str,
    explanation: str,
    recommendation: str,
    secure_fix: str,
    source: str = "DETERMINISTIC",
) -> dict:
    return {
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "owasp_category": owasp,
        "line": line,
        "evidence": evidence.strip()[:240],
        "explanation": explanation,
        "recommendation": recommendation,
        "secure_fix": secure_fix,
        "exploitability": "HIGH" if severity in {"CRITICAL", "HIGH"} else "MEDIUM",
        "source": source,
    }


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.findings: list[dict] = []

    def _add(self, node: ast.AST, **finding: str) -> None:
        line = getattr(node, "lineno", 1)
        evidence = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        self.findings.append(_finding(line=line, evidence=evidence, **finding))

    def visit_Call(self, node: ast.Call) -> None:
        name = ast.unparse(node.func).lower()
        if name in {"eval", "exec"}:
            self._add(
                node,
                title="Unsafe dynamic code execution",
                severity="CRITICAL",
                cwe="CWE-95",
                owasp="A03: Injection",
                explanation="Dynamic code execution can turn untrusted input into arbitrary Python execution.",
                recommendation="Replace dynamic evaluation with a strict parser and allow-listed operations.",
                secure_fix="value = json.loads(untrusted_text)",
            )
        elif name in {"os.system", "commands.getoutput", "commands.getstatusoutput"} or (
            name.startswith("subprocess.")
            and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
        ):
            self._add(
                node,
                title="Command injection surface",
                severity="CRITICAL",
                cwe="CWE-78",
                owasp="A03: Injection",
                explanation="A shell command is invoked without a visible argument boundary, creating command-injection risk.",
                recommendation="Pass an argument list with shell disabled and validate each argument against an allow-list.",
                secure_fix="subprocess.run([\"tool\", validated_arg], shell=False, check=True)",
            )
        elif name.endswith((".execute", ".executemany", ".query")) and node.args:
            query = node.args[0]
            if isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(query, ast.Call) and ast.unparse(query.func).endswith(".format")
            ):
                self._add(
                    node,
                    title="SQL injection",
                    severity="CRITICAL",
                    cwe="CWE-89",
                    owasp="A03: Injection",
                    explanation="SQL text is dynamically assembled rather than separating query structure from values.",
                    recommendation="Use parameterized queries and pass external values separately.",
                    secure_fix="cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
                )
        elif name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"} or name.endswith((".md5", ".sha1")):
            self._add(
                node,
                title="Weak cryptography",
                severity="MEDIUM",
                cwe="CWE-327",
                owasp="A02: Cryptographic Failures",
                explanation="MD5 and SHA-1 are unsuitable for security-sensitive hashing.",
                recommendation="Use Argon2id for passwords or a modern hash selected for the security purpose.",
                secure_fix="password_hash = argon2.PasswordHasher().hash(password)",
            )
        elif name == "yaml.load" and not any(
            keyword.arg == "Loader" and "safe" in ast.unparse(keyword.value).lower()
            for keyword in node.keywords
        ):
            self._add(
                node,
                title="Unsafe deserialization",
                severity="HIGH",
                cwe="CWE-502",
                owasp="A08: Software and Data Integrity Failures",
                explanation="yaml.load without a safe loader can construct arbitrary Python objects from untrusted input.",
                recommendation="Use safe_load and validate the decoded data against an explicit schema.",
                secure_fix="payload = yaml.safe_load(untrusted_text)",
            )
        self.generic_visit(node)


def _run_json_tool(command: list[str], timeout: int = 20) -> dict | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if result.stdout:
            return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def analyze_python_ast(code: str) -> list[dict]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return []
    visitor = PythonSecurityVisitor(code.splitlines())
    visitor.visit(tree)
    return visitor.findings


def _analyze_with_bandit(path: Path, lines: list[str]) -> list[dict]:
    if not importlib.util.find_spec("bandit") and not shutil.which("bandit"):
        return []
    command = [sys.executable, "-m", "bandit", "-q", "-f", "json", str(path)]
    output = _run_json_tool(command)
    findings = []
    for item in (output or {}).get("results", []):
        line = int(item.get("line_number", 1))
        severity = str(item.get("issue_severity", "MEDIUM")).upper()
        severity = severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
        cwe_id = item.get("issue_cwe", {}).get("id")
        cwe = f"CWE-{cwe_id}" if cwe_id else "CWE-693"
        findings.append(
            _finding(
                title=str(item.get("test_name") or "Bandit security finding"),
                severity=severity,
                cwe=cwe,
                owasp="A06: Vulnerable and Outdated Components" if cwe == "CWE-829" else "A05: Security Misconfiguration",
                line=line,
                evidence=lines[line - 1] if 0 < line <= len(lines) else str(item.get("code", "")),
                explanation=str(item.get("issue_text", "Static analyzer reported a security concern.")),
                recommendation="Review the flagged operation and apply a least-privilege, validated alternative.",
                secure_fix="Review the Bandit rule and replace the flagged operation with its safe alternative.",
                source="DETERMINISTIC",
            )
        )
    return findings


def _analyze_with_semgrep(path: Path, lines: list[str]) -> list[dict]:
    executable = shutil.which("semgrep")
    if not executable:
        script_name = "semgrep.exe" if sys.platform == "win32" else "semgrep"
        script_paths = [Path(sysconfig.get_path("scripts")) / script_name]
        if sys.platform == "win32":
            script_paths.append(Path(sysconfig.get_path("scripts", scheme="nt_user")) / script_name)
        executable = next((str(path) for path in script_paths if path.is_file()), None)
    if not executable:
        return []
    output = _run_json_tool([executable, "scan", "--config", "auto", "--json", "--quiet", str(path)])
    findings = []
    for item in (output or {}).get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        line = int(item.get("start", {}).get("line", 1))
        severity = str(extra.get("severity", "WARNING")).upper()
        severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(severity, "MEDIUM")
        cwe_value = metadata.get("cwe", "CWE-693")
        cwe = str(cwe_value[0] if isinstance(cwe_value, list) else cwe_value)
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        findings.append(
            _finding(
                title=str(item.get("check_id", "Semgrep security finding")).split(".")[-1].replace("-", " "),
                severity=severity,
                cwe=cwe,
                owasp=str(metadata.get("owasp", "A05: Security Misconfiguration")),
                line=line,
                evidence=lines[line - 1] if 0 < line <= len(lines) else str(extra.get("lines", "")),
                explanation=str(extra.get("message", "Semgrep reported a security concern.")),
                recommendation=str(metadata.get("fix", "Review the matched code and use a safe, validated alternative.")),
                secure_fix=str(extra.get("fix", "Apply the remediation recommended by the Semgrep rule.")),
                source="DETERMINISTIC",
            )
        )
    return findings


def analyze_with_optional_tools(code: str, language: str) -> list[dict]:
    """Run available analyzers against a temporary text file; no uploaded code is executed."""
    findings = analyze_python_ast(code) if language == "Python" else []
    lines = code.splitlines()
    suffix = {"Python": ".py", "JavaScript": ".js", "TypeScript": ".ts", "SQL": ".sql"}.get(language, ".txt")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, encoding="utf-8", delete=False) as source_file:
            source_file.write(code)
            temporary_path = Path(source_file.name)
        if language == "Python":
            findings.extend(_analyze_with_bandit(temporary_path, lines))
        findings.extend(_analyze_with_semgrep(temporary_path, lines))
    finally:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
    return findings
