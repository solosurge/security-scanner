"""
Report Generator Module

Generates security scan reports in various formats including
colorized tables and JSON output.
"""

import json
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate
from scanner.base_checker import CheckResult, SeverityLevel


# Initialize colorama for cross-platform colored output
init(autoreset=True)


class ReportGenerator:
    """
    Generates reports from security scan results.

    Supports multiple output formats including colorized tables
    and JSON for programmatic consumption.
    """

    @staticmethod
    def to_table(results: list[CheckResult], colorize: bool = True) -> str:
        """
        Generate a tabulated report with optional color coding.

        Args:
            results: List of check results
            colorize: Whether to apply color coding (default: True)

        Returns:
            str: Formatted table as string
        """
        if not results:
            return "No scan results available."

        # Prepare table data
        table_data = []

        for result in results:
            # Colorize status and severity if enabled
            if colorize:
                status = ReportGenerator._colorize_status(result.status)
                severity = ReportGenerator._colorize_severity(result.severity)
            else:
                status = result.status
                severity = result.severity.value

            # Count findings or show error
            if result.error:
                findings_count = f"Error: {result.error}"
            else:
                findings_count = len(result.findings)

            table_data.append([
                result.checker_name,
                status,
                severity,
                findings_count,
                f"{result.duration_ms:.0f}ms"
            ])

        # Create table with headers
        headers = ["Checker", "Status", "Severity", "Findings", "Duration"]
        table = tabulate(table_data, headers=headers, tablefmt="grid")

        return table

    @staticmethod
    def to_detailed_table(results: list[CheckResult], colorize: bool = True) -> str:
        """
        Generate a detailed report showing all findings.

        Args:
            results: List of check results
            colorize: Whether to apply color coding (default: True)

        Returns:
            str: Detailed formatted report
        """
        if not results:
            return "No scan results available."

        output = []

        for result in results:
            # Header for each checker
            if colorize:
                status_colored = ReportGenerator._colorize_status(result.status)
                severity_colored = ReportGenerator._colorize_severity(result.severity)
                header = f"\n{'=' * 80}\n{Fore.CYAN}{Style.BRIGHT}{result.checker_name}{Style.RESET_ALL}\n"
                header += f"Status: {status_colored} | Severity: {severity_colored} | Duration: {result.duration_ms:.0f}ms\n"
                header += f"{'=' * 80}"
            else:
                header = f"\n{'=' * 80}\n{result.checker_name}\n"
                header += f"Status: {result.status} | Severity: {result.severity.value} | Duration: {result.duration_ms:.0f}ms\n"
                header += f"{'=' * 80}"

            output.append(header)

            # Show error if present
            if result.error:
                output.append(f"\n{Fore.RED}Error: {result.error}{Style.RESET_ALL}" if colorize else f"\nError: {result.error}")
                continue

            # Show findings
            if not result.findings:
                output.append(f"\n{Fore.GREEN}✓ No issues found{Style.RESET_ALL}" if colorize else "\n✓ No issues found")
            else:
                for i, finding in enumerate(result.findings, 1):
                    issue = finding.get('issue', 'Unknown issue')
                    severity = finding.get('severity', 'UNKNOWN')
                    description = finding.get('description', '')
                    recommendation = finding.get('recommendation', '')

                    if colorize:
                        severity_colored = ReportGenerator._colorize_severity_string(severity)
                        output.append(f"\n{Fore.YELLOW}Finding #{i}:{Style.RESET_ALL}")
                        output.append(f"  Issue: {issue}")
                        output.append(f"  Severity: {severity_colored}")
                    else:
                        output.append(f"\nFinding #{i}:")
                        output.append(f"  Issue: {issue}")
                        output.append(f"  Severity: {severity}")

                    if description:
                        output.append(f"  Description: {description}")
                    if recommendation:
                        output.append(f"  Recommendation: {recommendation}")

        return "\n".join(output)

    @staticmethod
    def to_json(results: list[CheckResult], indent: int = 2) -> str:
        """
        Generate JSON report from results.

        Args:
            results: List of check results
            indent: JSON indentation level (default: 2)

        Returns:
            str: JSON formatted string
        """
        # Convert results to dictionaries
        results_data = []

        for result in results:
            result_dict = {
                'checker_name': result.checker_name,
                'status': result.status,
                'severity': result.severity.value,
                'findings': result.findings,
                'timestamp': result.timestamp,
                'duration_ms': result.duration_ms,
                'error': result.error
            }
            results_data.append(result_dict)

        # Create full report structure
        report = {
            'scan_time': datetime.utcnow().isoformat(),
            'total_checks': len(results),
            'results': results_data
        }

        return json.dumps(report, indent=indent)

    @staticmethod
    def get_summary(results: list[CheckResult]) -> dict[str, int]:
        """
        Get summary statistics from results.

        Args:
            results: List of check results

        Returns:
            dict: Summary statistics including counts by severity
        """
        summary = {
            'total_checks': len(results),
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'errors': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total_findings': 0
        }

        for result in results:
            # Count by status
            if result.status == 'PASS':
                summary['passed'] += 1
            elif result.status == 'FAIL':
                summary['failed'] += 1
            elif result.status == 'WARNING':
                summary['warnings'] += 1
            elif result.status == 'ERROR':
                summary['errors'] += 1

            # Count findings
            summary['total_findings'] += len(result.findings)

            # Count by severity
            for finding in result.findings:
                severity = finding.get('severity', '').lower()
                if severity in summary:
                    summary[severity] += 1

        return summary

    @staticmethod
    def format_summary(summary: dict[str, int], colorize: bool = True) -> str:
        """
        Format summary statistics as a readable string.

        Args:
            summary: Summary dictionary from get_summary()
            colorize: Whether to apply color coding (default: True)

        Returns:
            str: Formatted summary string
        """
        lines = []

        if colorize:
            lines.append(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}SCAN SUMMARY{Style.RESET_ALL}")
            lines.append(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 60}{Style.RESET_ALL}\n")
        else:
            lines.append(f"\n{'=' * 60}")
            lines.append("SCAN SUMMARY")
            lines.append(f"{'=' * 60}\n")

        # Status counts
        lines.append(f"Total Checks: {summary['total_checks']}")
        lines.append(f"  Passed: {Fore.GREEN}{summary['passed']}{Style.RESET_ALL}" if colorize else f"  Passed: {summary['passed']}")
        lines.append(f"  Failed: {Fore.RED}{summary['failed']}{Style.RESET_ALL}" if colorize else f"  Failed: {summary['failed']}")
        lines.append(f"  Warnings: {Fore.YELLOW}{summary['warnings']}{Style.RESET_ALL}" if colorize else f"  Warnings: {summary['warnings']}")
        lines.append(f"  Errors: {Fore.RED}{summary['errors']}{Style.RESET_ALL}" if colorize else f"  Errors: {summary['errors']}")

        # Findings by severity
        lines.append(f"\nTotal Findings: {summary['total_findings']}")
        if summary['critical'] > 0:
            lines.append(f"  Critical: {Fore.RED}{Style.BRIGHT}{summary['critical']}{Style.RESET_ALL}" if colorize else f"  Critical: {summary['critical']}")
        if summary['high'] > 0:
            lines.append(f"  High: {Fore.RED}{summary['high']}{Style.RESET_ALL}" if colorize else f"  High: {summary['high']}")
        if summary['medium'] > 0:
            lines.append(f"  Medium: {Fore.YELLOW}{summary['medium']}{Style.RESET_ALL}" if colorize else f"  Medium: {summary['medium']}")
        if summary['low'] > 0:
            lines.append(f"  Low: {Fore.BLUE}{summary['low']}{Style.RESET_ALL}" if colorize else f"  Low: {summary['low']}")
        if summary['info'] > 0:
            lines.append(f"  Info: {Fore.GREEN}{summary['info']}{Style.RESET_ALL}" if colorize else f"  Info: {summary['info']}")

        return "\n".join(lines)

    @staticmethod
    def _colorize_status(status: str) -> str:
        """Apply color to status string."""
        if status == 'PASS':
            return f"{Fore.GREEN}{Style.BRIGHT}{status}{Style.RESET_ALL}"
        elif status == 'FAIL':
            return f"{Fore.RED}{Style.BRIGHT}{status}{Style.RESET_ALL}"
        elif status == 'WARNING':
            return f"{Fore.YELLOW}{Style.BRIGHT}{status}{Style.RESET_ALL}"
        elif status == 'ERROR':
            return f"{Fore.RED}{status}{Style.RESET_ALL}"
        return status

    @staticmethod
    def _colorize_severity(severity: SeverityLevel) -> str:
        """Apply color to SeverityLevel enum."""
        return ReportGenerator._colorize_severity_string(severity.value)

    @staticmethod
    def _colorize_severity_string(severity: str) -> str:
        """Apply color to severity string."""
        if severity in ['CRITICAL', 'HIGH']:
            return f"{Fore.RED}{Style.BRIGHT}{severity}{Style.RESET_ALL}"
        elif severity == 'MEDIUM':
            return f"{Fore.YELLOW}{Style.BRIGHT}{severity}{Style.RESET_ALL}"
        elif severity == 'LOW':
            return f"{Fore.BLUE}{severity}{Style.RESET_ALL}"
        elif severity == 'INFO':
            return f"{Fore.GREEN}{severity}{Style.RESET_ALL}"
        return severity

    @staticmethod
    def save_json_report(results: list[CheckResult], filepath: str) -> None:
        """
        Save JSON report to file.

        Args:
            results: List of check results
            filepath: Path where to save the report
        """
        json_content = ReportGenerator.to_json(results)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(json_content)
