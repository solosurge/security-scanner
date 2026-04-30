"""
Security Scanner Package

An automated security scanner for web applications.
Checks for common security issues including missing HTTP headers,
SSL/TLS certificate problems, and information disclosure.
"""

__version__ = "1.0.0"

from scanner.base_checker import BaseChecker, CheckResult, SeverityLevel
from scanner.core import SecurityScanner
from scanner.threat_intel import ThreatIntelChecker

__all__ = [
    "SecurityScanner",
    "BaseChecker",
    "CheckResult",
    "SeverityLevel",
    "ThreatIntelChecker",
    "__version__"
]
