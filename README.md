# Automated Security Scanner v1.0

![Python](https://img.shields.io/badge/python-3.12-blue)
![Tests](https://img.shields.io/badge/tests-5%20passed-brightgreen)

A command-line web application security assessment tool that audits HTTP security headers, validates SSL/TLS certificates, detects server information disclosure, and enriches results with live threat intelligence from VirusTotal and AbuseIPDB. Built around a modular checker architecture that makes adding new security checks a matter of dropping in a single file.

## Features

- Security Headers — audits the presence and configuration of HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- SSL/TLS Certificate — validates certificate validity, expiry warnings, trust chain, self-signed detection, and protocol version
- Server Information Disclosure — detects headers and responses that leak server software or version details
- Threat Intelligence — queries VirusTotal and AbuseIPDB to surface known-malicious domains and high-risk IP addresses
- Multiple output formats: colored terminal table, detailed findings view, and JSON
- Save reports to disk for later review
- Run all checkers at once or target specific ones

## Installation

```bash
git clone https://github.com/your-username/security-scanner.git
cd security-scanner

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Open .env and add your API keys
```

### API Keys

Two free-tier API keys unlock the Threat Intelligence checker:

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| VirusTotal | 500 requests/day | https://www.virustotal.com |
| AbuseIPDB | 1,000 requests/day | https://www.abuseipdb.com |

Add them to your `.env` file (see `.env.example` for the template):

```
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

The scanner runs without API keys — the Threat Intelligence checker will return `ERROR` with a clear message, and all other checkers continue normally.

## Usage

```bash
# Scan all checkers with detailed output
python main.py https://example.com --detailed

# Run only threat intelligence check
python main.py https://example.com --checkers threat-intel --detailed

# Run specific checkers
python main.py https://example.com --checkers headers ssl --detailed

# Save report as JSON
python main.py https://example.com --output json --save reports/scan.json

# Run unit tests
python -m pytest tests/ -v
```

**Available checkers:** `headers`, `ssl`, `server-info`, `threat-intel`, `all` (default)

**Full options:**

```
positional arguments:
  target                Target URL to scan (e.g., https://example.com)

optional arguments:
  --timeout SECONDS     Request timeout in seconds (default: 10)
  --output FORMAT       Output format: table, json, or detailed (default: table)
  --checkers [...]      Specific checkers to run (default: all)
  --detailed            Show detailed findings for each check
  --save FILEPATH       Save report to file
  --verbose             Enable verbose output
  --no-color            Disable colored output
```

## Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║           AUTOMATED SECURITY SCANNER v1.0                     ║
║           Web Application Security Assessment Tool            ║
╚═══════════════════════════════════════════════════════════════╝

Starting security scan...

================================================================================
Security Headers
Status: FAIL | Severity: HIGH | Duration: 565ms
================================================================================
Finding #1:
  Issue: Missing Strict-Transport-Security header
  Severity: HIGH
  Description: Prevents protocol downgrade attacks and cookie hijacking
  Recommendation: Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Finding #2:
  Issue: Missing Content-Security-Policy header
  Severity: HIGH
  Description: Prevents XSS, clickjacking, and other code injection attacks

================================================================================
Threat Intelligence
Status: PASS | Severity: INFO | Duration: 1419ms
================================================================================
Finding #1:
  Issue: Domain reputation clean
  Severity: INFO
  Description: VirusTotal reports no malicious or suspicious activity for 'example.com'.

Finding #2:
  Issue: IP address reputation clean
  Severity: INFO
  Description: AbuseIPDB reports no significant abuse activity. IP: 172.66.147.243 | Country: US | ISP: Cloudflare, Inc. | Usage: Content Delivery Network | Total Reports: 0

============================================================
SCAN SUMMARY
============================================================
Total Checks: 4 | Passed: 2 | Failed: 1 | Warnings: 1
Total Findings: 11 | High: 2 | Medium: 2 | Low: 4 | Info: 3
[WARNING] Critical or high severity findings detected!
```

## Project Structure

```
Security_Scanner/
├── main.py                  # CLI entry point (argparse, colorama)
├── requirements.txt
├── .env.example             # API key template — safe to commit
├── scanner/
│   ├── __init__.py          # Package exports
│   ├── base_checker.py      # BaseChecker ABC, CheckResult, SeverityLevel
│   ├── core.py              # SecurityScanner orchestrator
│   ├── headers.py           # HTTP security headers checker
│   ├── ssl_checker.py       # SSL/TLS certificate checker
│   ├── server_info.py       # Server information disclosure checker
│   ├── threat_intel.py      # VirusTotal + AbuseIPDB threat intelligence checker
│   └── reporter.py          # Output formatting (table, JSON, summary)
└── tests/
    ├── __init__.py
    └── test_threat_intel.py # Unit tests with mocked API calls
```

## Running Tests

```bash
python -m pytest tests/ -v
```

Tests mock all external API calls and DNS resolution, so they run offline without any API keys.

## Architecture

Every checker inherits from `BaseChecker`, an abstract base class that enforces a consistent `check() -> CheckResult` interface and provides shared utilities for timing, finding creation, and error handling. `SecurityScanner` acts as the orchestrator — it registers checker classes, instantiates them with the target URL and timeout, runs them in sequence, and aggregates results. Adding a new check means creating one file with a class that implements `check()` and `name`, then registering it in `core.py` and `main.py`. The `CheckResult` dataclass normalizes output across all checkers, which lets the reporter generate consistent tables, JSON, and summaries regardless of which checks ran.

## Tech Stack

- Python 3.12
- [requests](https://docs.python-requests.org/) — HTTP client
- [colorama](https://github.com/tartley/colorama) — colored terminal output
- [tabulate](https://github.com/astanin/python-tabulate) — formatted tables
- [python-dotenv](https://github.com/theskumar/python-dotenv) — environment variable management
- [cryptography](https://cryptography.io/) — SSL certificate parsing
- unittest / pytest — testing with mocked API calls

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning systems you do not own or have explicit permission to test.
