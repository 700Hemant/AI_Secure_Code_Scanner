# backend/app/scanner.py

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any


# ============================================================
# CONFIG
# ============================================================

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "coverage",
}

SKIP_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".php",
    ".c",
    ".cpp",
    ".cs",
    ".go",
    ".rb",
    ".sql",
    ".html",
}

SEVERITY_DEDUCTION = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 2,
}


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def get_context(lines: list[str], line_no: int, radius: int = 3) -> str:
    start = max(0, line_no - radius - 1)
    end = min(len(lines), line_no + radius)

    output = []

    for index in range(start, end):
        marker = ">>> " if index == line_no - 1 else "    "
        output.append(f"{marker}{index + 1}: {lines[index]}")

    return "\n".join(output)


def is_comment_line(line: str) -> bool:
    stripped = line.strip()

    return (
        stripped.startswith("#")
        or stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
        or stripped.startswith("--")
    )


def is_scanner_source(path: Path, text: str) -> bool:
    """
    Prevent the scanner from reporting its own detection rules.
    """

    if path.name.lower() in {
        "scanner.py",
        "security_scanner.py",
        "sast_scanner.py",
    }:
        markers = [
            "SEVERITY_DEDUCTION",
            "scan_project",
            "def finding(",
            "def scan_file(",
            "CWE-78",
            "CWE-79",
            "CWE-89",
        ]

        matches = sum(marker in text for marker in markers)

        if matches >= 3:
            return True

    return False


def looks_like_test_or_example(path: Path, text: str = "") -> bool:
    path_text = str(path).lower()

    indicators = [
        "test_",
        "_test.",
        "/tests/",
        "\\tests\\",
        "/test/",
        "\\test\\",
        "/examples/",
        "\\examples\\",
        "/demo/",
        "\\demo\\",
        "/sample/",
        "\\sample\\",
        "example",
        "dummy",
        "mock",
    ]

    if any(item in path_text for item in indicators):
        return True

    return False


def is_obviously_safe_literal(value: str) -> bool:
    value = value.strip()

    safe_values = {
        "test",
        "testing",
        "demo",
        "example",
        "dummy",
        "changeme",
        "password",
        "secret",
        "your_api_key",
        "your-key-here",
        "replace_me",
        "replace-this",
        "xxx",
        "123456",
    }

    return value.lower() in safe_values


def extract_assignment_value(line: str) -> str | None:
    match = re.search(
        r"^\s*(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$",
        line,
    )

    if match:
        return match.group(2).strip()

    return None


# ============================================================
# CONFIDENCE
# ============================================================

def confidence_score(
    severity: str,
    *,
    source_controlled: bool = False,
    dangerous_sink: bool = False,
    sanitizer_present: bool = False,
    direct_flow: bool = False,
) -> tuple[str, int]:

    score = 45

    if source_controlled:
        score += 15

    if dangerous_sink:
        score += 20

    if direct_flow:
        score += 15

    if sanitizer_present:
        score -= 35

    score = max(5, min(100, score))

    # A direct, rule-based HIGH-severity detection is treated as
    # high-confidence even when it does not have a runtime sink.
    # This is important for hard-coded credentials: the scanner has
    # directly matched the credential assignment itself.
    if severity.upper() == "HIGH" and direct_flow and not sanitizer_present:
        confidence = "High"
    elif score >= 80:
        confidence = "High"
    elif score >= 55:
        confidence = "Medium"
    else:
        confidence = "Low"

    return confidence, score


# ============================================================
# FINDING
# ============================================================

def finding(
    *,
    file: str,
    line: int,
    title: str,
    category: str,
    severity: str,
    cwe: str,
    description: str,
    evidence: str,
    context: str,
    fix: str,
    confidence: str = "Medium",
    confidence_score_value: int = 60,
    data_flow: list[str] | None = None,
) -> dict[str, Any]:

    result = {
        "file": file,
        "line": line,
        "title": title,
        "category": category,
        "severity": severity,
        "cwe": cwe,
        "confidence": confidence,
        "confidence_score": confidence_score_value,
        "description": description,
        "evidence": evidence,
        "context": context,
        "fix": fix,
    }

    if data_flow:
        result["data_flow"] = data_flow

    return result


# ============================================================
# PYTHON DATA-FLOW ANALYZER
# ============================================================

SOURCE_PATTERNS = [
    "input(",
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.values",
    "request.query_params",
    "request.GET",
    "request.POST",
    "sys.argv",
    "os.environ",
]

SQL_SINKS = [
    "execute(",
    "executemany(",
    "executescript(",
]

COMMAND_SINKS = [
    "os.system(",
    "subprocess.call(",
    "subprocess.run(",
    "subprocess.Popen(",
    "subprocess.check_output(",
    "subprocess.check_call(",
]

XSS_SINKS = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write(",
]

SANITIZERS = [
    "escape(",
    "html.escape(",
    "bleach.clean(",
    "DOMPurify.sanitize(",
    "sanitize(",
]


def get_python_name(node: ast.AST) -> str | None:

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parts = []

        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return ".".join(reversed(parts))

    return None


def expression_contains_source(node: ast.AST) -> bool:

    for child in ast.walk(node):

        if isinstance(child, ast.Call):

            function_name = get_python_name(child.func)

            if function_name:
                text = function_name.lower()

                if any(
                    source.lower() in text
                    for source in SOURCE_PATTERNS
                ):
                    return True

        if isinstance(child, ast.Attribute):

            text = get_python_name(child)

            if text:
                if any(
                    source.lower() in text.lower()
                    for source in SOURCE_PATTERNS
                ):
                    return True

    return False


def expression_contains_sanitizer(node: ast.AST) -> bool:

    for child in ast.walk(node):

        if isinstance(child, ast.Call):

            name = get_python_name(child.func)

            if name:
                if any(
                    sanitizer.lower() in name.lower()
                    for sanitizer in SANITIZERS
                ):
                    return True

    return False


def get_variable_names(node: ast.AST) -> set[str]:

    names = set()

    for child in ast.walk(node):

        if isinstance(child, ast.Name):
            names.add(child.id)

    return names


def build_python_data_flow(
    tree: ast.AST,
    lines: list[str],
) -> list[dict[str, Any]]:

    tainted: dict[str, dict[str, Any]] = {}

    findings: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # PASS 1
    # Find user-controlled variables
    # --------------------------------------------------------

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            if expression_contains_source(node.value):

                variables = []

                for target in node.targets:

                    if isinstance(target, ast.Name):
                        variables.append(target.id)

                        tainted[target.id] = {
                            "line": node.lineno,
                            "source": lines[node.lineno - 1].strip(),
                        }

            else:

                names = get_variable_names(node.value)

                tainted_names = [
                    name
                    for name in names
                    if name in tainted
                ]

                if tainted_names:

                    for target in node.targets:

                        if isinstance(target, ast.Name):

                            tainted[target.id] = {
                                "line": node.lineno,
                                "source": (
                                    tainted[
                                        tainted_names[0]
                                    ]["source"]
                                ),
                            }

        elif isinstance(node, ast.AnnAssign):

            if expression_contains_source(node.value):

                if isinstance(node.target, ast.Name):

                    tainted[node.target.id] = {
                        "line": node.lineno,
                        "source": lines[node.lineno - 1].strip(),
                    }

    # --------------------------------------------------------
    # PASS 2
    # SQL injection
    # --------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        function_name = get_python_name(node.func)

        if not function_name:
            continue

        if not any(
            function_name.endswith(sink[:-1])
            for sink in SQL_SINKS
        ):
            continue

        if not node.args:
            continue

        query_node = node.args[0]

        variable_names = get_variable_names(query_node)

        source_variables = [
            name
            for name in variable_names
            if name in tainted
        ]

        direct_source = expression_contains_source(query_node)

        dynamic_query = isinstance(
            query_node,
            (ast.JoinedStr, ast.BinOp),
        )

        if source_variables or direct_source or dynamic_query:

            source_line = (
                tainted[source_variables[0]]["line"]
                if source_variables
                else node.lineno
            )

            flow = []

            if source_variables:

                variable = source_variables[0]

                flow.append(
                    f"User input at line {source_line}"
                )

                flow.append(
                    f"{variable} flows into SQL query"
                )

            flow.append(
                f"SQL execution sink at line {node.lineno}"
            )

            confidence, score = confidence_score(
                "HIGH",
                source_controlled=bool(
                    source_variables or direct_source
                ),
                dangerous_sink=True,
                direct_flow=True,
            )

            findings.append(
                finding(
                    file="",
                    line=node.lineno,
                    title="Potential SQL Injection",
                    category="SQL Injection",
                    severity="HIGH",
                    cwe="CWE-89",
                    confidence=confidence,
                    confidence_score_value=score,
                    description=(
                        "User-controlled data appears to flow "
                        "into a SQL execution function without "
                        "clear parameterization."
                    ),
                    evidence=lines[node.lineno - 1].strip(),
                    context=get_context(
                        lines,
                        node.lineno,
                    ),
                    fix=(
                        "Use parameterized queries / prepared "
                        "statements instead of string concatenation "
                        "or interpolation."
                    ),
                    data_flow=flow,
                )
            )

    # --------------------------------------------------------
    # PASS 3
    # Command injection
    # --------------------------------------------------------

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        function_name = get_python_name(node.func)

        if not function_name:
            continue

        matching_sink = next(
            (
                sink
                for sink in COMMAND_SINKS
                if function_name.endswith(sink[:-1])
            ),
            None,
        )

        if not matching_sink:
            continue

        if not node.args:
            continue

        command_node = node.args[0]

        variable_names = get_variable_names(command_node)

        source_variables = [
            name
            for name in variable_names
            if name in tainted
        ]

        direct_source = expression_contains_source(command_node)

        if source_variables or direct_source:

            flow = []

            if source_variables:

                variable = source_variables[0]

                flow.append(
                    f"User input at line "
                    f"{tainted[variable]['line']}"
                )

                flow.append(
                    f"{variable} flows into command"
                )

            flow.append(
                f"Command execution sink at line {node.lineno}"
            )

            confidence, score = confidence_score(
                "CRITICAL",
                source_controlled=True,
                dangerous_sink=True,
                direct_flow=True,
            )

            findings.append(
                finding(
                    file="",
                    line=node.lineno,
                    title="Potential Command Injection",
                    category="Command Injection",
                    severity="CRITICAL",
                    cwe="CWE-78",
                    confidence=confidence,
                    confidence_score_value=score,
                    description=(
                        "User-controlled data appears to reach "
                        "an operating-system command execution sink."
                    ),
                    evidence=lines[node.lineno - 1].strip(),
                    context=get_context(
                        lines,
                        node.lineno,
                    ),
                    fix=(
                        "Avoid shell execution where possible. "
                        "Use a fixed command with a safe argument "
                        "list and validate user input."
                    ),
                    data_flow=flow,
                )
            )

    return findings


# ============================================================
# REGEX / GENERAL ANALYZER
# ============================================================

def scan_file(path: Path) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    try:
        text = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return findings

    if not text.strip():
        return findings

    if is_scanner_source(path, text):
        return findings

    lines = text.splitlines()

    if path.suffix.lower() == ".py":

        try:

            tree = ast.parse(text)

            flow_findings = build_python_data_flow(
                tree,
                lines,
            )

            for item in flow_findings:
                item["file"] = str(path)

            findings.extend(flow_findings)

        except SyntaxError:
            pass

    # ========================================================
    # HARD-CODED SECRETS
    # ========================================================

    secret_pattern = re.compile(
        r"""
        \b(
            api[_-]?key|
            secret[_-]?key|
            access[_-]?token|
            auth[_-]?token|
            password
        )
        \s*[:=]\s*
        ["']([^"']{8,})["']
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    for line_no, line in enumerate(lines, 1):

        if is_comment_line(line):
            continue

        match = secret_pattern.search(line)

        if not match:
            continue

        value = match.group(2)

        if is_obviously_safe_literal(value):
            continue

        confidence, score = confidence_score(
            "HIGH",
            dangerous_sink=False,
            direct_flow=True,
        )

        findings.append(
            finding(
                file=str(path),
                line=line_no,
                title="Potential Hard-Coded Secret",
                category="Secrets Management",
                severity="HIGH",
                cwe="CWE-798",
                confidence=confidence,
                confidence_score_value=score,
                description=(
                    "A credential-like value appears to be "
                    "hard-coded in source code."
                ),
                evidence=line.strip(),
                context=get_context(
                    lines,
                    line_no,
                ),
                fix=(
                    "Move secrets to environment variables "
                    "or a secure secrets manager and rotate "
                    "any exposed credential."
                ),
            )
        )

    # ========================================================
    # EVAL / EXEC
    # ========================================================

    for line_no, line in enumerate(lines, 1):

        line_lower = line.lower()

        if is_comment_line(line):
            continue

        if re.search(r"\b(eval|exec)\s*\(", line):

            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="Dynamic Code Execution",
                    category="Code Injection",
                    severity="HIGH",
                    cwe="CWE-95",
                    confidence="High",
                    confidence_score_value=90,
                    description=(
                        "Dynamic code execution can execute "
                        "attacker-controlled code."
                    ),
                    evidence=line.strip(),
                    context=get_context(
                        lines,
                        line_no,
                    ),
                    fix=(
                        "Avoid eval/exec. Use explicit parsing "
                        "and safe APIs instead."
                    ),
                )
            )

    # ========================================================
    # SHELL EXECUTION
    # ========================================================

    for line_no, line in enumerate(lines, 1):

        line_lower = line.lower()

        if is_comment_line(line):
            continue

        if "shell=true" in line_lower:

            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="Shell Execution Enabled",
                    category="Command Injection",
                    severity="HIGH",
                    cwe="CWE-78",
                    confidence="High",
                    confidence_score_value=88,
                    description=(
                        "shell=True increases the risk of command "
                        "injection when command arguments are not "
                        "strictly controlled."
                    ),
                    evidence=line.strip(),
                    context=get_context(
                        lines,
                        line_no,
                    ),
                    fix=(
                        "Avoid shell=True. Pass commands as an "
                        "argument list and validate arguments."
                    ),
                )
            )

    # ========================================================
    # XSS
    # ========================================================

    for line_no, line in enumerate(lines, 1):

        if is_comment_line(line):
            continue

        line_lower = line.lower()

        xss_sink = any(
            sink.lower() in line_lower
            for sink in XSS_SINKS
        )

        if not xss_sink:
            continue

        # Strong indicators that attacker-controlled data may be involved.
        source_indicator = any(
            term in line_lower
            for term in [
                "input",
                "request",
                "query",
                "params",
                "location",
                "document.cookie",
                "window.name",
                "user",
                "url",
                "hash",
                "form",
                "searchparams",
                "${",
            ]
        )

        # Also inspect nearby lines for a source-to-sink flow. This catches
        # cases such as `userInput = params.get(...)` followed by an
        # innerHTML assignment on the next line.
        if not source_indicator:
            nearby_start = max(0, line_no - 4)
            nearby_end = min(len(lines), line_no + 2)
            nearby_text = " ".join(
                lines[nearby_start:nearby_end]
            ).lower()
            source_indicator = any(
                term in nearby_text
                for term in [
                    "params.get",
                    "urlsearchparams",
                    "location.search",
                    "location.hash",
                    "request.args",
                    "request.form",
                    "document.cookie",
                    "window.name",
                    "userinput",
                    "user_input",
                ]
            )

        sanitizer_present = any(
            sanitizer.lower() in line_lower
            for sanitizer in SANITIZERS
        )

        if sanitizer_present:
            continue

        if source_indicator:
            severity = "HIGH"
            confidence = "High"
            score = 88
            description = (
                "Potential attacker-controlled data appears to reach "
                "an HTML/DOM sink without an obvious sanitization step."
            )
        else:
            # Generic innerHTML/outerHTML usage alone is not enough to
            # claim a high-confidence vulnerability.
            severity = "LOW"
            confidence = "Low"
            score = 40
            description = (
                "An HTML/DOM sink was detected, but the scanner did not "
                "find clear evidence that attacker-controlled input reaches "
                "the sink."
            )

        findings.append(
            finding(
                file=str(path),
                line=line_no,
                title="Potential Cross-Site Scripting (XSS)",
                category="Cross-Site Scripting",
                severity=severity,
                cwe="CWE-79",
                confidence=confidence,
                confidence_score_value=score,
                description=description,
                evidence=line.strip(),
                context=get_context(lines, line_no),
                fix=(
                    "Prefer textContent/createElement for untrusted data. "
                    "If HTML is required, sanitize untrusted content with "
                    "a trusted sanitizer such as DOMPurify."
                ),
            )
        )

    # ========================================================
    # SSRF - SERVER-SIDE REQUEST FORGERY
    # ========================================================

    ssrf_sink = re.compile(
        r"\b(?:requests\.(?:get|post|put|patch|delete|request)|"
        r"urllib\.request\.urlopen|httpx\.(?:get|post|put|patch|delete|request)|"
        r"aiohttp\.(?:request|get|post))\s*\(",
        re.IGNORECASE,
    )

    ssrf_source = re.compile(
        r"(?:request\.(?:args|form|json|values|query_params)|"
        r"req\.(?:query|body)|params\.get\(|searchParams\.get\(|"
        r"input\s*\(|os\.environ)",
        re.IGNORECASE,
    )

    for line_no, line in enumerate(lines, 1):
        if is_comment_line(line):
            continue

        if not ssrf_sink.search(line):
            continue

        nearby = "\n".join(
            lines[max(0, line_no - 4):min(len(lines), line_no + 2)]
        )
        direct_flow = bool(ssrf_source.search(line) or ssrf_source.search(nearby))

        if not direct_flow:
            continue

        findings.append(
            finding(
                file=str(path),
                line=line_no,
                title="Potential Server-Side Request Forgery (SSRF)",
                category="SSRF",
                severity="HIGH",
                cwe="CWE-918",
                confidence="High",
                confidence_score_value=88,
                description=(
                    "A potentially user-controlled URL appears to reach a "
                    "server-side HTTP request function. An attacker may abuse "
                    "this to access internal services or restricted resources."
                ),
                evidence=line.strip(),
                context=get_context(lines, line_no),
                fix=(
                    "Do not fetch arbitrary user-supplied URLs. Use an allowlist "
                    "of permitted hosts/schemes, validate redirects, and block "
                    "loopback/private/link-local destinations."
                ),
            )
        )

    # ========================================================
    # PATH TRAVERSAL
    # ========================================================

    traversal_source = re.compile(
        r"(?:request\.(?:args|form|json|values|query_params)|"
        r"params\.get\(|searchParams\.get\(|input\s*\(|os\.environ)",
        re.IGNORECASE,
    )

    traversal_sink = re.compile(
        r"\b(?:open|read_text|write_text|send_file|send_from_directory|"
        r"File|FileInputStream|FileOutputStream)\s*\(",
        re.IGNORECASE,
    )

    for line_no, line in enumerate(lines, 1):
        if is_comment_line(line):
            continue

        suspicious_literal = "../" in line or "..\\" in line
        sink = traversal_sink.search(line)

        if not sink:
            continue

        nearby = "\n".join(
            lines[max(0, line_no - 4):min(len(lines), line_no + 2)]
        )
        source_flow = bool(traversal_source.search(line) or traversal_source.search(nearby))

        if not (suspicious_literal or source_flow):
            continue

        severity = "HIGH" if source_flow else "MEDIUM"
        confidence = "High" if source_flow else "Medium"
        score = 90 if source_flow else 72

        findings.append(
            finding(
                file=str(path),
                line=line_no,
                title="Potential Path Traversal",
                category="Path Traversal",
                severity=severity,
                cwe="CWE-22",
                confidence=confidence,
                confidence_score_value=score,
                description=(
                    "A file-system operation may use attacker-controlled "
                    "path data or an unsafe relative path."
                ),
                evidence=line.strip(),
                context=get_context(lines, line_no),
                fix=(
                    "Resolve paths against a fixed trusted base directory, "
                    "normalize/canonicalize the result, and reject paths that "
                    "escape the allowed directory."
                ),
            )
        )

    # ========================================================
    # INSECURE CORS
    # ========================================================

    cors_patterns = [
        re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*[\"']?\*[\"']?", re.IGNORECASE),
        re.compile(r"(?:cors|CORS).*\borigins?\s*=\s*[\"']?\*[\"']?", re.IGNORECASE),
        re.compile(r"(?:allow_origins|allowed_origins)\s*=\s*\[[^\]]*[\"']\*[\"']", re.IGNORECASE),
    ]

    for line_no, line in enumerate(lines, 1):
        if is_comment_line(line):
            continue

        if any(pattern.search(line) for pattern in cors_patterns):
            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="Overly Permissive CORS Policy",
                    category="Security Misconfiguration",
                    severity="MEDIUM",
                    cwe="CWE-942",
                    confidence="High",
                    confidence_score_value=90,
                    description=(
                        "CORS is configured to allow requests from any origin. "
                        "This can expose authenticated APIs to unintended web origins."
                    ),
                    evidence=line.strip(),
                    context=get_context(lines, line_no),
                    fix=(
                        "Replace wildcard origins with an explicit allowlist of "
                        "trusted origins. Avoid allowing credentials with wildcard origins."
                    ),
                )
            )

    # ========================================================
    # CSRF - COOKIE/SESSION-AWARE HEURISTIC CHECK
    # ========================================================

    csrf_route = re.compile(
        r"(?:@(?:app|router)\.route\([^\n]*methods\s*=\s*\[[^\]]*['\"](?:POST|PUT|PATCH|DELETE)['\"]|"
        r"@(?:app|router)\.(?:post|put|patch|delete)\s*\()",
        re.IGNORECASE,
    )

    csrf_protection = re.compile(
        r"(?:csrf_protect|csrf_token|csrf_token_field|validate_csrf|CSRFProtect|csrf\.protect|xsrf|same_site|samesite)",
        re.IGNORECASE,
    )

    cookie_session_auth = re.compile(
        r"(?:request\.cookies|response\.set_cookie|set_cookie\(|session\b|session\[|cookie\b|cookies\b|"
        r"login_required|current_user|flask_login|fastapi_login|oauth2|bearer|authorization)",
        re.IGNORECASE,
    )

    file_auth_context = "\n".join(lines)
    has_cookie_session_auth = bool(cookie_session_auth.search(file_auth_context))

    for line_no, line in enumerate(lines, 1):
        if is_comment_line(line):
            continue

        if not csrf_route.search(line):
            continue

        nearby = "\n".join(
            lines[max(0, line_no - 8):min(len(lines), line_no + 16)]
        )

        if csrf_protection.search(nearby):
            continue

        if not has_cookie_session_auth and not cookie_session_auth.search(nearby):
            continue

        findings.append(
            finding(
                file=str(path),
                line=line_no,
                title="Potential Missing CSRF Protection",
                category="Cross-Site Request Forgery",
                severity="MEDIUM",
                cwe="CWE-352",
                confidence="Medium",
                confidence_score_value=68,
                description=(
                    "A state-changing web route appears to rely on browser-managed "
                    "cookie/session credentials without an obvious CSRF protection "
                    "mechanism nearby. This is a heuristic finding."
                ),
                evidence=line.strip(),
                context=get_context(lines, line_no, radius=5),
                fix=(
                    "For cookie-authenticated browser requests, use framework-supported "
                    "CSRF tokens and validate them on state-changing requests. Also use "
                    "SameSite cookies where appropriate."
                ),
            )
        )

    # ========================================================
    # WEAK CRYPTOGRAPHY
    # ========================================================

    for line_no, line in enumerate(lines, 1):

        line_lower = line.lower()

        if is_comment_line(line):
            continue

        if re.search(
            r"\b(hashlib\.)?(md5|sha1)\s*\(",
            line_lower,
        ):

            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="Weak Cryptographic Algorithm",
                    category="Cryptography",
                    severity="MEDIUM",
                    cwe="CWE-327",
                    confidence="High",
                    confidence_score_value=92,
                    description=(
                        "MD5/SHA-1 should not be used for "
                        "security-sensitive hashing."
                    ),
                    evidence=line.strip(),
                    context=get_context(
                        lines,
                        line_no,
                    ),
                    fix=(
                        "Use SHA-256/SHA-3 for integrity use cases. "
                        "For passwords, use Argon2, bcrypt, or scrypt."
                    ),
                )
            )

    # ========================================================
    # TLS VERIFICATION
    # ========================================================

    for line_no, line in enumerate(lines, 1):

        if is_comment_line(lines[line_no - 1]):
            continue

        if re.search(
            r"\bverify\s*=\s*False\b",
            lines[line_no - 1],
            re.IGNORECASE,
        ):

            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="TLS Certificate Verification Disabled",
                    category="Transport Security",
                    severity="HIGH",
                    cwe="CWE-295",
                    confidence="High",
                    confidence_score_value=95,
                    description=(
                        "TLS certificate verification is disabled, "
                        "which can enable man-in-the-middle attacks."
                    ),
                    evidence=lines[line_no - 1].strip(),
                    context=get_context(
                        lines,
                        line_no,
                    ),
                    fix=(
                        "Keep TLS certificate verification enabled "
                        "and use a trusted certificate chain."
                    ),
                )
            )

    # ========================================================
    # INSECURE HTTP
    # ========================================================

    http_pattern = re.compile(
        r"[\"'](http://[^\"']+)[\"']",
        re.IGNORECASE,
    )

    local_http_host = re.compile(
        r"^http://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/|$)",
        re.IGNORECASE,
    )

    for line_no, line in enumerate(lines, 1):
        if is_comment_line(lines[line_no - 1]):
            continue

        for match in http_pattern.finditer(lines[line_no - 1]):
            url = match.group(1).strip()

            if local_http_host.match(url):
                continue

            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="Insecure HTTP Connection",
                    category="Transport Security",
                    severity="MEDIUM",
                    cwe="CWE-319",
                    confidence="Medium",
                    confidence_score_value=70,
                    description=(
                        "An unencrypted HTTP URL was detected outside the "
                        "recognized local development endpoints."
                    ),
                    evidence=lines[line_no - 1].strip(),
                    context=get_context(lines, line_no),
                    fix=(
                        "Use HTTPS for production and external network communication."
                    ),
                )
            )

    # ========================================================
    # DEBUG MODE
    # ========================================================

    for line_no, line in enumerate(lines, 1):

        if is_comment_line(line):
            continue

        if re.search(
            r"\bdebug\s*=\s*True\b",
            line,
            re.IGNORECASE,
        ):

            findings.append(
                finding(
                    file=str(path),
                    line=line_no,
                    title="Debug Mode Enabled",
                    category="Security Misconfiguration",
                    severity="MEDIUM",
                    cwe="CWE-489",
                    confidence="High",
                    confidence_score_value=90,
                    description=(
                        "Debug mode may expose sensitive information "
                        "or debugging interfaces."
                    ),
                    evidence=line.strip(),
                    context=get_context(
                        lines,
                        line_no,
                    ),
                    fix=(
                        "Disable debug mode in production."
                    ),
                )
            )

    return findings


# ============================================================
# SMART FINDING DEDUPLICATION
# ============================================================

def deduplicate_findings(
    findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Same file + same line + same CWE ko duplicate report
    hone se rokta hai.
    Agar same location par multiple detections milen,
    higher severity aur phir higher confidence wali finding rakhi jati hai.
    """

    unique: dict[tuple[str, int, str], dict[str, Any]] = {}

    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    confidence_rank = {
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    for item in findings:
        file_name = normalize_text(item.get("file"))
        cwe = normalize_text(item.get("cwe")) or "N/A"

        try:
            line_no = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line_no = 0

        key = (
            file_name.lower(),
            line_no,
            cwe.upper(),
        )

        existing = unique.get(key)

        if existing is None:
            unique[key] = item
            continue

        old_severity = severity_rank.get(
            normalize_text(existing.get("severity")).upper(),
            0,
        )
        new_severity = severity_rank.get(
            normalize_text(item.get("severity")).upper(),
            0,
        )

        old_confidence = confidence_rank.get(
            normalize_text(existing.get("confidence")),
            0,
        )
        new_confidence = confidence_rank.get(
            normalize_text(item.get("confidence")),
            0,
        )

        if new_severity > old_severity:
            unique[key] = item
        elif (
            new_severity == old_severity
            and new_confidence > old_confidence
        ):
            unique[key] = item

    return list(unique.values())


# ============================================================
# PROJECT SCANNER
# ============================================================

def scan_project(project_path: str | Path) -> dict[str, Any]:

    root = Path(project_path)

    all_findings: list[dict[str, Any]] = []

    files_scanned = 0
    lines_scanned = 0

    if not root.exists():

        return {
            "score": 100,
            "counts": {},
            "findings": [],
            "summary": "Project path does not exist.",
            "files_scanned": 0,
            "lines_scanned": 0,
            "confidence_counts": {},
            "category_counts": {},
            "cwe_counts": {},
        }

    if root.is_file():

        files = [root]

    else:

        files = []

        for path in root.rglob("*"):

            if not path.is_file():
                continue

            if path.name in SKIP_FILES:
                continue

            if path.suffix.lower() not in EXTS:
                continue

            relative_parts = path.relative_to(root).parts

            if any(
                part.lower() in SKIP_DIRS
                for part in relative_parts
            ):
                continue

            files.append(path)

    for path in files:

        try:

            text = path.read_text(
                encoding="utf-8",
                errors="ignore",
            )

        except Exception:
            continue

        if not text.strip():
            continue

        files_scanned += 1
        lines_scanned += len(text.splitlines())

        file_findings = scan_file(path)

        all_findings.extend(file_findings)

    # ========================================================
    # SMART DEDUPLICATION
    # ========================================================

    all_findings = deduplicate_findings(all_findings)

    # ========================================================
    # COUNTS
    # ========================================================

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    confidence_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    category_counts: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}

    for item in all_findings:

        severity = item.get(
            "severity",
            "LOW",
        ).upper()

        if severity in counts:
            counts[severity] += 1

        confidence = item.get(
            "confidence",
            "Medium",
        )

        confidence_counts[confidence] = (
            confidence_counts.get(confidence, 0) + 1
        )

        category = item.get(
            "category",
            "Other",
        )

        category_counts[category] = (
            category_counts.get(category, 0) + 1
        )

        cwe = item.get(
            "cwe",
            "N/A",
        )

        cwe_counts[cwe] = (
            cwe_counts.get(cwe, 0) + 1
        )

    # ========================================================
    # SCORE
    # ========================================================

    if not all_findings:

        score = 100

    else:

        deduction = 0

        for severity, count in counts.items():

            deduction += (
                SEVERITY_DEDUCTION[severity]
                * count
            )

        score = max(
            5,
            100 - deduction,
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    if not all_findings:

        summary = (
            "No security findings were detected "
            "by the current ruleset."
        )

    else:

        summary = (
            f"Detected {len(all_findings)} security finding(s): "
            f"{counts['CRITICAL']} critical, "
            f"{counts['HIGH']} high, "
            f"{counts['MEDIUM']} medium and "
            f"{counts['LOW']} low."
        )

    return {
        "score": score,
        "counts": counts,
        "findings": all_findings,
        "summary": summary,
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "confidence_counts": confidence_counts,
        "category_counts": category_counts,
        "cwe_counts": cwe_counts,
    }   