"""
Base checker module for security scanners.

This module provides the abstract base class and data structures
that all security checkers must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SeverityLevel(Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    """
    Standardized result from any security check.

    Attributes:
        checker_name: Name of the checker that produced this result
        status: Overall status - "PASS", "FAIL", "WARNING", or "ERROR"
        severity: Highest severity level found in this check
        findings: List of individual findings/issues discovered
        timestamp: ISO format timestamp when check was performed
        duration_ms: Time taken to perform the check in milliseconds
        error: Error message if status is "ERROR", None otherwise
    """

    checker_name: str
    status: str
    severity: SeverityLevel
    findings: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_ms: float = 0.0
    error: str | None = None

    def __post_init__(self):
        """Validate the status field."""
        valid_statuses = {"PASS", "FAIL", "WARNING", "ERROR"}
        if self.status not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}, got {self.status}")


class BaseChecker(ABC):
    """
    Abstract base class for all security checkers.

    All security checkers must inherit from this class and implement
    the check() method and name property.

    Attributes:
        target: The target URL or host to check
        timeout: Timeout in seconds for network operations
    """

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize the base checker.

        Args:
            target: Target URL or host to scan
            timeout: Network operation timeout in seconds (default: 10)
        """
        self.target = target
        self.timeout = timeout
        self._start_time: float = 0.0

    @abstractmethod
    def check(self) -> CheckResult:
        """
        Perform the security check and return results.

        This method must be implemented by all subclasses.

        Returns:
            CheckResult: The results of the security check

        Raises:
            NotImplementedError: If the subclass doesn't implement this method
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the checker name for identification.

        Returns:
            str: Human-readable name of this checker
        """
        pass

    def _start_timer(self) -> None:
        """Start timing the check operation."""
        import time
        self._start_time = time.time()

    def _get_duration_ms(self) -> float:
        """
        Get the duration since timer was started.

        Returns:
            float: Duration in milliseconds
        """
        import time
        return (time.time() - self._start_time) * 1000

    def _create_finding(
        self,
        issue: str,
        severity: SeverityLevel,
        description: str,
        recommendation: str = ""
    ) -> dict[str, Any]:
        """
        Create a standardized finding dictionary.

        Args:
            issue: Short description of the issue
            severity: Severity level of this finding
            description: Detailed description of the issue
            recommendation: Recommended remediation (optional)

        Returns:
            dict: Standardized finding dictionary
        """
        finding = {
            "issue": issue,
            "severity": severity.value,
            "description": description
        }

        if recommendation:
            finding["recommendation"] = recommendation

        return finding
