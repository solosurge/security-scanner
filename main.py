"""
Automated Security Scanner - Main Entry Point

A command-line tool for automated security scanning of web applications.
Checks for common security issues including HTTP headers, SSL/TLS certificates,
and information disclosure.
"""

import argparse
import sys
from datetime import datetime
from colorama import Fore, Style, init
from scanner import SecurityScanner
from scanner.headers import SecurityHeadersChecker
from scanner.ssl_checker import SSLChecker
from scanner.server_info import ServerInfoChecker
from scanner.threat_intel import ThreatIntelChecker
from scanner.reporter import ReportGenerator


# Initialize colorama
init(autoreset=True)


def print_banner():
    """Display ASCII banner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           AUTOMATED SECURITY SCANNER v1.0                     ║
║           Web Application Security Assessment Tool            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Automated Security Scanner for Web Applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py https://example.com
  python main.py https://example.com --timeout 15
  python main.py https://example.com --output json --save reports/scan.json
  python main.py https://example.com --checkers headers ssl
  python main.py https://example.com --checkers threat-intel --detailed
  python main.py https://example.com --detailed
        '''
    )

    parser.add_argument(
        'target',
        help='Target URL to scan (e.g., https://example.com)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )

    parser.add_argument(
        '--output',
        choices=['table', 'json', 'detailed'],
        default='table',
        help='Output format: table, json, or detailed (default: table)'
    )

    parser.add_argument(
        '--save',
        metavar='FILEPATH',
        help='Save report to file (JSON format if output is json, otherwise text)'
    )

    parser.add_argument(
        '--checkers',
        nargs='+',
        choices=['headers', 'ssl', 'server-info', 'threat-intel', 'all'],
        default=['all'],
        help='Specific checkers to run (default: all)'
    )

    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed findings for each check'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    return parser.parse_args()


def register_checkers(scanner: SecurityScanner, checker_names: list[str], verbose: bool = False):
    """
    Register specified checkers with the scanner.

    Args:
        scanner: SecurityScanner instance
        checker_names: List of checker names to register
        verbose: Whether to print verbose output
    """
    checker_map = {
        'headers': SecurityHeadersChecker,
        'ssl': SSLChecker,
        'server-info': ServerInfoChecker,
        'threat-intel': ThreatIntelChecker
    }

    if 'all' in checker_names:
        scanner.register_all_checkers()
        if verbose:
            print(f"{Fore.BLUE}[INFO] Registered all checkers{Style.RESET_ALL}")
    else:
        for checker_name in checker_names:
            if checker_name in checker_map:
                scanner.register_checker(checker_map[checker_name])
                if verbose:
                    print(f"{Fore.BLUE}[INFO] Registered {checker_name} checker{Style.RESET_ALL}")


def main():
    """Main execution function."""
    args = parse_arguments()

    # Print banner
    if not args.no_color:
        print_banner()

    # Create scanner instance
    try:
        if args.verbose:
            print(f"{Fore.BLUE}[INFO] Initializing security scanner...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[INFO] Target: {args.target}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[INFO] Timeout: {args.timeout}s{Style.RESET_ALL}\n")

        scanner = SecurityScanner(target=args.target, timeout=args.timeout)

    except ValueError as e:
        print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    # Register checkers
    register_checkers(scanner, args.checkers, args.verbose)

    if len(scanner.checkers) == 0:
        print(f"{Fore.RED}[ERROR] No checkers registered{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    # Run security checks
    print(f"{Fore.CYAN}{Style.BRIGHT}Starting security scan...{Style.RESET_ALL}\n")

    if args.verbose:
        print(f"{Fore.BLUE}[INFO] Running {len(scanner.checkers)} security checks...{Style.RESET_ALL}\n")

    try:
        results = scanner.run_all_checks()

        if args.verbose:
            print(f"\n{Fore.BLUE}[INFO] Scan completed. Generating report...{Style.RESET_ALL}\n")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Scan failed: {str(e)}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    # Generate and display report
    colorize = not args.no_color

    if args.output == 'json':
        report = ReportGenerator.to_json(results)
        print(report)

    elif args.output == 'detailed' or args.detailed:
        report = ReportGenerator.to_detailed_table(results, colorize=colorize)
        print(report)

        # Also show summary
        summary = ReportGenerator.get_summary(results)
        summary_text = ReportGenerator.format_summary(summary, colorize=colorize)
        print(summary_text)

    else:  # table format
        report = ReportGenerator.to_table(results, colorize=colorize)
        print(report)

        # Show summary
        summary = ReportGenerator.get_summary(results)
        summary_text = ReportGenerator.format_summary(summary, colorize=colorize)
        print(summary_text)

    # Save report if requested
    if args.save:
        try:
            if args.output == 'json':
                ReportGenerator.save_json_report(results, args.save)
            else:
                # Save detailed text report
                with open(args.save, 'w', encoding='utf-8') as f:
                    f.write(f"Security Scan Report\n")
                    f.write(f"Target: {args.target}\n")
                    f.write(f"Scan Time: {datetime.utcnow().isoformat()}\n")
                    f.write(f"{'=' * 80}\n\n")
                    f.write(ReportGenerator.to_detailed_table(results, colorize=False))
                    f.write("\n\n")
                    summary = ReportGenerator.get_summary(results)
                    f.write(ReportGenerator.format_summary(summary, colorize=False))

            print(f"\n{Fore.GREEN}[SUCCESS] Report saved to: {args.save}{Style.RESET_ALL}")

        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Failed to save report: {str(e)}{Style.RESET_ALL}", file=sys.stderr)

    # Exit with appropriate code
    if scanner.has_critical_findings():
        print(f"\n{Fore.RED}{Style.BRIGHT}[WARNING] Critical or high severity findings detected!{Style.RESET_ALL}")
        sys.exit(1)
    else:
        print(f"\n{Fore.GREEN}Scan completed successfully.{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}[FATAL] Unexpected error: {str(e)}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
