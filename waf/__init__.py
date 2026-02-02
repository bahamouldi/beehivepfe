# BeeWAF - Web Application Firewall Module
# This package provides WAF functionality including:
# - rules: Regex-based attack pattern detection
# - anomaly: ML-based anomaly detection (IsolationForest)
# - ratelimit: Rate limiting for brute force protection
# - clamav_scanner: ClamAV integration for malware scanning

from . import rules
from . import anomaly
from . import ratelimit
from . import clamav_scanner

__all__ = ['rules', 'anomaly', 'ratelimit', 'clamav_scanner']
__version__ = '1.0.0'
