import re
import os
from typing import Dict, Tuple, List

# ==================== SQL INJECTION PATTERNS ====================
SQLI_PATTERNS = [
    r"\b(select|union|insert|update|delete|drop)\b",
    r"--",
    r"/\*.*\*/",
    r"\bor\b\s+\d+\s*=",
    r"'.*or.*'.*'.*=.*'",  # NEW: Détecte 1' OR '1'='1
    r"\bsleep\s*\(",  # NEW: Time-based blind SLEEP(5)
    r"\bbenchmark\s*\(",  # NEW: Time-based blind BENCHMARK
    r"\bwaitfor\b.*\bdelay\b",  # NEW: MSSQL WAITFOR DELAY
    r"\bexec\b|\bexecute\b",  # NEW: EXEC/EXECUTE commands
]

# ==================== XSS PATTERNS ====================
XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:\s*",
    r"<img\s+src=",
    r"<svg[^>]*onload",  # NEW: <svg/onload=alert(1)>
    r"<iframe[^>]*src",  # NEW: <iframe src=...>
    r"<object[^>]*data",  # NEW: <object data=...>
    r"<embed[^>]*src",  # NEW: <embed src=...>
    r"on\w+\s*=",  # NEW: All event handlers (onclick, onerror, etc.)
]

# ==================== COMMAND INJECTION PATTERNS ====================
CMDI_PATTERNS = [
    r"[;|&]\s*(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)",
    r"`.*`",  # Backticks: `whoami`
    r"\$\(.*\)",  # Command substitution: $(whoami)
    r"%0a|%0d",  # Newline injection
]

# ==================== PATH TRAVERSAL / LFI PATTERNS ====================
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\/",  # ../ or ..\
    r"%2e%2e%2f|%2e%2e/|%2e%2e%5c",  # Encoded ../
    r"\.\.%2f|\.\.%5c",  # Partially encoded
    r"\.\.\.\./+|\.\.\.\.\\+",  # Double slash evasion: ....//
    r"/etc/passwd|/etc/shadow|/etc/hosts",  # Unix sensitive files
    r"c:\\windows\\|c:/windows/",  # Windows paths
]

# ==================== SSRF PATTERNS ====================
SSRF_PATTERNS = [
    r"169\.254\.169\.254",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"(url|target|redirect|proxy|host|src|href).*?(localhost|127\.0\.0\.1)",  # Loopback in parameters
    r"file:///",  # File protocol
    r"(gopher|dict|ftp)://",  # Alternative protocols
]

# ==================== XXE PATTERNS ====================
XXE_PATTERNS = [
    r"<!ENTITY",  # XML Entity declaration
    r"<!DOCTYPE.*\[",  # DOCTYPE with DTD
    r"SYSTEM\s+[\"']file://",  # External entity: file://
]

# ==================== BRUTE FORCE PATTERNS ====================
BRUTE_PATTERNS = [
    r"(login|password).*(\d{6,})",
]

# Combine and compile
_default_compiled = []
for p in SQLI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'sqli'))
for p in XSS_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xss'))
for p in CMDI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'cmdi'))
for p in PATH_TRAVERSAL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'path-traversal'))
for p in SSRF_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ssrf'))
for p in XXE_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xxe'))
for p in BRUTE_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'brute'))

# Allow an environment-specified additional rules file (one regex per line prefixed by kind: e.g. sqli:regex)
COMPILED_RULES = list(_default_compiled)
_rules_file = os.environ.get('BEEWAF_RULES_FILE')
if _rules_file and os.path.exists(_rules_file):
    try:
        with open(_rules_file, 'r') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                if ':' in ln:
                    kind, rx = ln.split(':', 1)
                    try:
                        COMPILED_RULES.append((re.compile(rx, re.IGNORECASE), kind.strip()))
                    except re.error:
                        continue
    except Exception:
        pass

# Simple allowlist (paths that should never be blocked)
ALLOW_PATHS = os.environ.get('BEEWAF_ALLOW_PATHS', '/health,/metrics').split(',')
ALLOW_PATHS = [p.strip() for p in ALLOW_PATHS if p.strip()]


def _headers_to_text(headers: Dict[str, str]) -> str:
    # Exclude Host header to avoid false positives with 127.0.0.1:port
    return ' '.join(f"{k}:{v}" for k, v in headers.items() if k.lower() != 'host')


def check_regex_rules(path: str, body: str, headers: Dict[str, str]) -> Tuple[bool, str]:
    """Return (blocked:bool, reason:str_or_None).

    Checks request path+body+headers against compiled regex rules.
    Respects `ALLOW_PATHS`.
    """
    if path in ALLOW_PATHS:
        return False, None

    target = ' '.join([path or '', body or '', _headers_to_text(headers or {})])
    for pat, kind in COMPILED_RULES:
        if pat.search(target):
            return True, f"regex-{kind}"
    return False, None


def list_rules() -> List[Tuple[str, str]]:
    """Return list of (pattern, kind) for debugging/monitoring."""
    return [(p.pattern, k) for p, k in COMPILED_RULES]

