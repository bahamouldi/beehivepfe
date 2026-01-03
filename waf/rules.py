import re
import os
from typing import Dict, Tuple, List

# Default patterns for common attacks
SQLI_PATTERNS = [
    r"\b(select|union|insert|update|delete|drop)\b",
    r"--",
    r"/\*.*\*/",
    r"\bor\b\s+\d+\s*=",
]
XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:\s*",
    r"<img\s+src=",
]
BRUTE_PATTERNS = [
    r"(login|password).*(\d{6,})",
]

# Combine and compile
_default_compiled = []
for p in SQLI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'sqli'))
for p in XSS_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'xss'))
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
    return ' '.join(f"{k}:{v}" for k, v in headers.items())


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

