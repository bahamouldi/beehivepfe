import re
import os
from typing import Dict, Tuple, List

# ==================== SQL INJECTION PATTERNS ====================
SQLI_PATTERNS = [
    r"\b(select|union|insert|update|delete|drop)\b",
    r"--",
    r"/\*.*\*/",
    r"\bor\b\s+\d+\s*=",
    r"'.*or.*'.*'.*=.*'",  # Détecte 1' OR '1'='1
    r"\bsleep\s*\(",  # Time-based blind SLEEP(5)
    r"\bbenchmark\s*\(",  # Time-based blind BENCHMARK
    r"\bwaitfor\b.*\bdelay\b",  # MSSQL WAITFOR DELAY
    r"\bexec\b|\bexecute\b",  # EXEC/EXECUTE commands
    r"\|\|",  # SQL concatenation operator ||
    r"0x[0-9a-f]{6,}",  # Hex encoding (0x73656c656374)
    r"\bascii\s*\(",  # ASCII-based blind SQLi
    r"\bsubstring\s*\(",  # SUBSTRING extraction
    r"[\u1d00-\u1d7f]{4,}",  # Unicode small caps block (ᴜɴɪᴏɴ)
    r"[\ua71f-\ua7ff]",  # Unicode Latin Extended-D
    # Additional SQL patterns
    r"#",  # MySQL comment
    r"\binto\s+outfile\b",  # INTO OUTFILE
    r"\binto\s+dumpfile\b",  # INTO DUMPFILE
    r"\bload_file\s*\(",  # LOAD_FILE()
    r"\binformation_schema\b",  # information_schema
    r"\bsysobjects\b",  # SQL Server sysobjects
    r"\bsyscolumns\b",  # SQL Server syscolumns
    r"\bpg_tables\b",  # PostgreSQL pg_tables
    r"\bpg_catalog\b",  # PostgreSQL pg_catalog
    r"\bxp_cmdshell\b",  # SQL Server xp_cmdshell
    r"\bxp_regread\b",  # SQL Server xp_regread
]

# ==================== XSS PATTERNS ====================
XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"javascript:\s*",
    r"<img\s+src=",
    r"<svg[^>]*onload",  # <svg/onload=alert(1)>
    r"<iframe[^>]*src",  # <iframe src=...>
    r"<object[^>]*data",  # <object data=...>
    r"<embed[^>]*src",  # <embed src=...>
    r"on\w+\s*=",  # All event handlers (onclick, onerror, etc.)
    r"\[\]\[",  # JSFuck obfuscation patterns
    r"\(\!\[\]\+\[\]\)",  # JSFuck patterns (![]+[])
    r"\\x[0-9a-f]{2}",  # Hex escape sequences
    r"data:text/html",  # Data URI XSS
    r"data:image/svg\+xml",  # SVG data URI
    r"location\.(hash|href|search)",  # DOM manipulation
    r"document\.(cookie|domain|referrer)",  # Document manipulation
    r"expression\s*\(",  # CSS expression injection
    r"vbscript:",  # VBScript protocol
    r"mhtml:",  # MHTML protocol
    # Additional XSS patterns
    r"\beval\s*\(",  # eval()
    r"\.innerHTML\s*=",  # innerHTML assignment
    r"\.outerHTML\s*=",  # outerHTML assignment
    r"\.write\s*\(",  # document.write()
    r"\.writeln\s*\(",  # document.writeln()
    r"fromCharCode",  # String.fromCharCode()
    r"atob\s*\(",  # atob() base64 decode
    r"btoa\s*\(",  # btoa() base64 encode
]

# ==================== COMMAND INJECTION PATTERNS ====================
CMDI_PATTERNS = [
    r"[;|&]\s*(whoami|id|ls|cat|wget|curl|nc|bash|sh|cmd|uname|pwd)",
    r"`.*`",  # Backticks: `whoami`
    r"\$\(.*\)",  # Command substitution: $(whoami)
    r"%0a|%0d",  # Newline injection
    r"\|\s*(grep|awk|sed|sort|uniq|head|tail|cut)",  # Pipe with Unix commands
    r"\$IFS",  # FIXED: IFS variable manipulation
    r"\$\d+",  # FIXED: Positional parameters ($1, $9)
    r"\$PATH|\$HOME|\$USER",  # FIXED: Environment variables
    r"\\[a-z]",  # FIXED: Backslash escaping (c\at)
    r"\{[a-z]+,[^}]+\}",  # FIXED: Brace expansion {cat,/etc/passwd}
    # Shell interpreters and dangerous commands
    r"/bin/(ba)?sh\b",  # /bin/sh, /bin/bash
    r"/usr/bin/(ba)?sh\b",  # /usr/bin/sh, /usr/bin/bash
    r"\bpython[23]?\s+-c",  # python -c, python2 -c, python3 -c
    r"\bperl\s+-e",  # perl -e
    r"\bruby\s+-e",  # ruby -e
    r"\bphp\s+-r",  # php -r
    r"\bnc\s+-[elp]",  # nc -e, nc -l, nc -p (netcat reverse shell)
    r"\bncat\s",  # ncat
    r"\bwget\s+https?://",  # wget http://
    r"\bcurl\s+https?://",  # curl http://
    r"\bfetch\s+https?://",  # fetch http:// (BSD)
    # Additional command patterns
    r"\bping\b.*-[cn]",  # ping -c / ping -n
    r"\bnslookup\b",  # nslookup command
    r"\bdig\b",  # dig command
    r"\btraceroute\b",  # traceroute
    r"\bnetcat\b",  # netcat
    r"\btelnet\b",  # telnet
    r"\bftp\b\s",  # ftp command
    r"\bssh\b\s",  # ssh command
    r"\bchmod\b",  # chmod
    r"\bchown\b",  # chown
    r"\brm\b\s+-[rf]",  # rm -rf
    r"\bmkdir\b",  # mkdir
    r"\btouch\b",  # touch
    r"\bkill\b\s+-\d",  # kill -9
]

# ==================== PATH TRAVERSAL / LFI PATTERNS ====================
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\/",  # ../ or ..\
    r"%2e%2e%2f|%2e%2e/|%2e%2e%5c",  # Encoded ../
    r"\.\.%2f|\.\.%5c",  # Partially encoded
    r"\.\.\.\./+|\.\.\.\.\\+",  # Double slash evasion: ....//
    r"/etc/passwd|/etc/shadow|/etc/hosts",  # Unix sensitive files
    r"c:\\windows\\|c:/windows/",  # Windows paths
    r"\\\\\\\\[0-9.]+",  # FIXED: UNC paths (\\127.0.0.1)
    r"\\\\[a-z0-9.-]+\\c\$",  # FIXED: Windows admin shares (\\host\c$)
    # NEW: UTF-8 overlong encoding bypass prevention
    r"%c0%ae|%c0%af",  # UTF-8 overlong encoding for . and /
    r"%c1%1c|%c1%9c",  # UTF-8 overlong encoding variants
    r"%e0%80%ae",  # 3-byte overlong encoding for .
    r"%f0%80%80%ae",  # 4-byte overlong encoding for .
    r"%252e|%252f",  # Double URL encoding
    r"\.\.;/",  # Tomcat path traversal bypass
    r"/\.\./",  # Normalized traversal
]
# ==================== SSRF PATTERNS ====================
SSRF_PATTERNS = [
    r"169\.254\.169\.254",  # AWS metadata
    r"metadata\.google\.internal",  # GCP metadata
    r"(url|target|redirect|proxy|host|src|href).*?(localhost|127\.0\.0\.1)",  # Loopback in parameters
    r"file:///",  # File protocol
    r"(gopher|dict|ftp)://",  # Alternative protocols
    # Private network ranges (RFC 1918)
    r"://10\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # 10.0.0.0/8
    r"://192\.168\.\d{1,3}\.\d{1,3}",  # 192.168.0.0/16
    r"://172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",  # 172.16.0.0/12
    # Loopback and special addresses
    r"://localhost(?![a-zA-Z0-9])",  # Direct localhost access (negative lookahead)
    r"://127\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Entire 127.0.0.0/8 range
    r"://0\.0\.0\.0(?![0-9])",  # 0.0.0.0 wildcard (negative lookahead)
    r"://\[::1\]",  # IPv6 loopback
    r"://\[0:0:0:0:0:0:0:1\]",  # IPv6 loopback full
    r"://\[::ffff:127\.0\.0\.1\]",  # IPv6 mapped IPv4
    r"://2130706433\b",  # Decimal IP for 127.0.0.1
    r"://0177\.0+\.0+\.0*1\b",  # Octal IP variations
    r"://017700000001\b",  # Octal IP compact
    r"://0x7f\.0x0\.0x0\.0x1\b",  # Hex IP dotted
    r"://0x7f000001\b",  # Hex IP compact
    r"ldap://",  # LDAP protocol SSRF
    r"ldaps://",  # LDAPS protocol
    r"tftp://",  # TFTP protocol
    r"netdoc://",  # netdoc protocol
    r"jar:http",  # JAR URL scheme
    r"\.(burpcollaborator|oastify|interact\.sh|dnslog)\.com",  # DNS rebinding/OAST
    r"@localhost\b",  # URL with @ before localhost
    r"@127\.0\.0\.1\b",  # URL with @ before IP
    r"\blocaltest\.me\b",  # localhost alternative domains
    r"\bvcap\.me\b",  # localhost alternative
    r"\blvh\.me\b",  # localhost alternative
    r"\bnip\.io\b",  # wildcard DNS
    r"\bxip\.io\b",  # wildcard DNS
    r"\bsslip\.io\b",  # wildcard DNS
]

# ==================== XXE PATTERNS ====================
XXE_PATTERNS = [
    r"<!ENTITY",  # XML Entity declaration
    r"<!DOCTYPE\s+\w",  # DOCTYPE declaration (any DOCTYPE with name)
    r"SYSTEM\s+[\"']file://",  # External entity: file://
    r"PUBLIC\s+[\"']",  # PUBLIC external entity
]

# ==================== LDAP INJECTION PATTERNS ====================
LDAP_PATTERNS = [
    r"\(\|\(",  # (|( LDAP OR injection
    r"\)\(\|",  # )(| LDAP injection
    r"\*\)\(",  # *)( LDAP wildcard injection
    r"\(&\(",  # (&( LDAP AND injection
    r"\)\(uid=",  # )(uid= filter injection
    r"\)\(cn=",  # )(cn= filter injection
    r"\)\(password",  # )(password filter injection
    r"objectClass\s*=",  # objectClass query
    r"\)\(objectClass",  # )(objectClass=*) injection
    r"\(objectClass=\*\)",  # Full objectClass pattern
    r"\|\(cn=",  # |cn= OR injection
    r"\|\(uid=",  # |uid= OR injection
    r"\bunionall\b",  # LDAP union
    r"\bnull\)\(",  # Null termination
]

# ==================== NOSQL INJECTION PATTERNS ====================
NOSQL_PATTERNS = [
    r"\{\s*\$\w+\s*:",  # {$ne:, {$gt:, etc.
    r"\[\s*\$\w+\s*\]",  # [$ne], [$regex], etc.
    r"\{\s*['\"]?\$where['\"]?\s*:",  # $where queries
    r"sleep\s*\(\s*\d+\s*\)",  # sleep(5000)
    r"\$ne\b|\$gt\b|\$lt\b|\$gte\b|\$lte\b",  # FIXED: NoSQL operators
    r":\s*\{\s*\"\$ne\"\s*:\s*null\s*\}",  # FIXED: {"$ne": null} pattern
    # NEW: Additional NoSQL patterns
    r"\$regex\b",  # $regex operator
    r"\$options\b",  # $options (used with $regex)
    r"\$exists\b",  # $exists operator
    r"\$type\b",  # $type operator
    r"\$or\s*:\s*\[",  # $or array
    r"\$and\s*:\s*\[",  # $and array
    r"\$not\s*:",  # $not operator
    r"\$nin\b",  # $nin (not in)
    r"\$in\s*:\s*\[",  # $in array
    r"\$elemMatch\b",  # $elemMatch
    r"\$comment\b",  # $comment (info leak)
    r"\{\s*\"\$regex\"\s*:",  # JSON format $regex
]

# ==================== LOG4SHELL/JNDI INJECTION PATTERNS ====================
JNDI_PATTERNS = [
    r"\$\{jndi:",  # ${jndi:ldap://
    r"\$\{jndi:ldap://",
    r"\$\{jndi:rmi://",
    r"\$\{jndi:dns://",
    # NEW: JNDI obfuscation bypass patterns
    r"\$\{.*j.*n.*d.*i.*:",  # Any chars between j-n-d-i
    r"j\]?n\[?d\]?i",  # Bracket obfuscation: j]n[d]i
    r"\$\{\$\{.*\}.*ndi",  # Nested lookup: ${${lower:j}ndi
    r"\$\{lower:j\}",  # ${lower:j} Log4j lookup
    r"\$\{upper:j\}",  # ${upper:J} Log4j lookup
    r"\$\{lower:n\}",  # ${lower:n}
    r"\$\{env:.*\}.*ndi",  # Environment variable lookup
    r"\$\{base64:.*\}",  # Base64 lookup
    r"\$\{date:.*\}",  # Date lookup
    r"\$\{ctx:.*\}",  # Context lookup
    r"\$\{java:.*\}",  # Java lookup
    r"\$\{bundle:.*\}",  # Bundle lookup  
    r"\$\{main:.*\}",  # Main arguments lookup
    r"\$\{sys:.*\}",  # System property lookup
    r"\$\{\:\-j\}",  # Default value obfuscation
    r"j\$\{.*\}ndi",  # Injection in middle
    r"jn\$\{.*\}di",  # Injection in middle variant
]

# ==================== PHP FILTER/WRAPPER PATTERNS ====================
PHP_FILTER_PATTERNS = [
    r"php://filter",
    r"php://input",
    r"php://output",
    r"data://text/plain",
    r"expect://",
    r"phar://",
]

# ==================== SERVER-SIDE TEMPLATE INJECTION (SSTI) PATTERNS ====================
SSTI_PATTERNS = [
    r"\{\{.*\*.*\}\}",  # {{7*7}}
    r"\$\{.*\*.*\}",  # ${7*7}
    r"\{\%.*\%\}",  # {%...%}
    r"<\%.*\%>",  # <%...%>
    r"\{\{.*config.*\}\}",  # {{config}}
    r"\{\{.*self.*\}\}",  # {{self}}
    r"#\{.*\}",  # Ruby #{...} interpolation
    r"\{\{.*\}\}",  # Generic Jinja2/Twig {{...}}
    r"\$\{[^}]+\}",  # Generic ${...} expressions
]

# ==================== JSP CODE INJECTION PATTERNS ====================
JSP_PATTERNS = [
    r"<\%\s*eval\s*\(",  # <% eval(
    r"<\%=.*request\.getParameter",  # <%= request.getParameter
    r"<jsp:include",
    r"<jsp:forward",
]

# ==================== ADVANCED LFI PATTERNS ====================
ADVANCED_LFI_PATTERNS = [
    r"/proc/self/",
    r"/proc/\d+/",
    r"/var/log/",
    r"/var/mail/",
    r"\.\./\.\./proc/",
]

# ==================== PYTHON CODE INJECTION PATTERNS ====================
PYTHON_INJECTION_PATTERNS = [
    r"__import__\s*\(",  # __import__('os')
    r"\bexec\s*\(",  # exec(code)
    r"\beval\s*\(",  # eval(code)
    r"\bcompile\s*\(",  # compile(code)
    r"os\.system",  # os.system('cmd')
    r"subprocess\.",  # subprocess.call, subprocess.Popen
    r"commands\.",  # commands.getoutput
    r"__init__\.__globals__",  # FIXED: Python introspection
    r"__class__\.__bases__",  # FIXED: Class introspection
    r"\{[a-z_]+\.__[a-z_]+__",  # FIXED: Format string with dunder methods
]

# ==================== JAVA/JAR PROTOCOL PATTERNS ====================
JAR_PROTOCOL_PATTERNS = [
    r"jar:http://",  # JAR URL remote class loading
    r"jar:https://",
    r"jar:ftp://",
    r"jar:file://",
]

# ==================== GRAPHQL INJECTION PATTERNS ====================
GRAPHQL_PATTERNS = [
    r"__schema\s*\{",  # GraphQL introspection
    r"__type\s*\(",  # Type introspection
    r"__typename",  # Type name introspection
    r"query\s+IntrospectionQuery",  # Full introspection
]

# ==================== DESERIALIZATION PATTERNS ====================
DESERIALIZATION_PATTERNS = [
    r"!!python/object",  # YAML Python object deserialization
    r"O:\d+:",  # PHP serialized object: O:8:"stdClass"
    r"a:\d+:",  # PHP serialized array: a:2:{...}
    r"rO0AB",  # Java serialized (base64 encoded)
    r"\xac\xed\x00\x05",  # Java serialization magic bytes
]

# ==================== PROTOTYPE POLLUTION PATTERNS ====================
PROTOTYPE_POLLUTION_PATTERNS = [
    r"__proto__",  # JavaScript prototype pollution
    r"constructor\s*\[\s*['\"]?prototype",  # constructor["prototype"] or constructor[prototype]
    r"\[\s*['\"]__proto__['\"]?\s*\]",  # ["__proto__"] or [__proto__]
    r"prototype\s*\[\s*['\"]?\w+['\"]?\s*\]",  # prototype["x"] or prototype[x]
    r"Object\.assign\s*\(",  # Object.assign pollution
    r"\$\.extend\s*\(",  # jQuery extend pollution
    r"_\.merge\s*\(",  # Lodash merge pollution
    r"_\.defaultsDeep\s*\(",  # Lodash defaultsDeep
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
for p in LDAP_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ldap'))
for p in NOSQL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'nosql'))
for p in JNDI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jndi'))
for p in PHP_FILTER_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'php-filter'))
for p in SSTI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'ssti'))
for p in JSP_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jsp'))
for p in ADVANCED_LFI_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'lfi'))
for p in PYTHON_INJECTION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'python-injection'))
for p in JAR_PROTOCOL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'jar-protocol'))
for p in GRAPHQL_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'graphql'))
for p in DESERIALIZATION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'deserialization'))
for p in PROTOTYPE_POLLUTION_PATTERNS:
    _default_compiled.append((re.compile(p, re.IGNORECASE), 'prototype-pollution'))
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
    import urllib.parse
    
    if path in ALLOW_PATHS:
        return False, None

    # Decode URL encoding to detect obfuscated attacks
    decoded_path = urllib.parse.unquote(path or '') if path else ''
    decoded_body = urllib.parse.unquote(body or '') if body else ''
    
    # Check both original and decoded versions
    target = ' '.join([path or '', body or '', _headers_to_text(headers or {})])
    decoded_target = ' '.join([decoded_path, decoded_body, _headers_to_text(headers or {})])
    
    for pat, kind in COMPILED_RULES:
        if pat.search(target) or pat.search(decoded_target):
            return True, f"regex-{kind}"
    return False, None


def list_rules() -> List[Tuple[str, str]]:
    """Return list of (pattern, kind) for debugging/monitoring."""
    return [(p.pattern, k) for p, k in COMPILED_RULES]

