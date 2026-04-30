"""
Utility functions for the security scanner.

This module provides common utilities used across different checkers.
"""

import re
from datetime import datetime
from urllib.parse import urlparse, urlunparse


def validate_url(url: str) -> bool:
    """
    Validate URL format.

    Args:
        url: URL string to validate

    Returns:
        bool: True if URL is valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False

    try:
        result = urlparse(url)
        # Must have scheme and netloc (hostname)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize URL by adding https:// scheme if missing.

    Args:
        url: URL string to normalize

    Returns:
        str: Normalized URL with scheme

    Examples:
        >>> normalize_url("example.com")
        "https://example.com"
        >>> normalize_url("http://example.com")
        "http://example.com"
    """
    if not url:
        return url

    # Remove whitespace
    url = url.strip()

    # If no scheme, add https://
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    return url


def parse_target(target: str) -> tuple[str, int]:
    """
    Extract hostname and port from target URL.

    Args:
        target: Target URL string

    Returns:
        tuple: (hostname, port) where port defaults to 443 for https, 80 for http

    Examples:
        >>> parse_target("https://example.com")
        ("example.com", 443)
        >>> parse_target("http://example.com:8080")
        ("example.com", 8080)
    """
    parsed = urlparse(target)

    hostname = parsed.hostname or parsed.netloc
    port = parsed.port

    # Determine default port based on scheme
    if port is None:
        if parsed.scheme == 'https':
            port = 443
        elif parsed.scheme == 'http':
            port = 80
        else:
            port = 443  # Default to HTTPS port

    return hostname, port


def format_timestamp() -> str:
    """
    Return current timestamp in ISO 8601 format.

    Returns:
        str: ISO format timestamp (UTC)

    Example:
        >>> format_timestamp()
        "2024-01-15T10:30:45.123456"
    """
    return datetime.utcnow().isoformat()


def extract_domain(url: str) -> str:
    """
    Extract domain from URL.

    Args:
        url: URL string

    Returns:
        str: Domain name without protocol or path

    Example:
        >>> extract_domain("https://www.example.com/path")
        "www.example.com"
    """
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]


def is_https(url: str) -> bool:
    """
    Check if URL uses HTTPS protocol.

    Args:
        url: URL string to check

    Returns:
        bool: True if URL uses HTTPS, False otherwise
    """
    return urlparse(url).scheme == 'https'


def sanitize_url_for_display(url: str, max_length: int = 60) -> str:
    """
    Sanitize and truncate URL for display purposes.

    Args:
        url: URL to sanitize
        max_length: Maximum length for display (default: 60)

    Returns:
        str: Sanitized URL, truncated if necessary
    """
    if len(url) <= max_length:
        return url

    # Truncate from the middle to preserve protocol and domain
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if len(base) >= max_length:
        return base[:max_length - 3] + "..."

    remaining = max_length - len(base) - 3
    path_part = parsed.path[:remaining] if parsed.path else ""

    return f"{base}{path_part}..."
