"""Security functions for AT Protocol OAuth."""

import logging
import re
import ipaddress
import urllib.parse
from typing import Set

from .exceptions import SecurityError

logger = logging.getLogger(__name__)

# Known AT Protocol domains
KNOWN_AT_PROTOCOL_DOMAINS: Set[str] = {
    # Official Bluesky domains
    "bsky.social",
    "bsky.app",
    "bsky.network",
    # PLC directory
    "plc.directory",
    # Common PDS providers
    "blueskyweb.xyz",
    "staging.bsky.dev",
    # Common third-party PDS providers
    "pds.public.url",
    "atproto.com",
    # Add more known domains as needed
}


def _validate_https_protocol(parsed_url: urllib.parse.ParseResult, url: str) -> None:
    """Validate that the URL uses HTTPS protocol."""
    if parsed_url.scheme != "https":
        error_msg = f"SSRF protection: Rejected non-HTTPS URL: {url}"
        logger.warning(error_msg)
        raise SecurityError(error_msg)


def _extract_hostname(netloc: str) -> str:
    """Extract hostname from netloc, handling IPv6 brackets."""
    if netloc.startswith("[") and "]" in netloc:
        # IPv6 address like [::1] or [::1]:8080
        bracket_end = netloc.find("]")
        return netloc[1:bracket_end]  # Extract IP without brackets
    else:
        # IPv4 address or hostname, split on : to remove port
        return netloc.split(":")[0]


def _validate_ip_address(hostname: str, url: str) -> bool:
    """
    Validate IP addresses and reject private/reserved ones.
    
    Returns:
        True if hostname is an IP address (and validation passed)
        False if hostname is not an IP address
    """
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
            error_msg = f"SSRF protection: Rejected URL with private/reserved IP: {url}"
            logger.warning(error_msg)
            raise SecurityError(error_msg)
        # Reject all IP addresses for security (only allow known domains)
        error_msg = f"SSRF protection: Rejected public IP address: {url}"
        logger.warning(error_msg)
        raise SecurityError(error_msg)
    except ValueError:
        # Not an IP address
        return False


def _validate_internal_hostnames(hostname: str, url: str) -> None:
    """Validate against internal hostnames."""
    if (
        hostname == "localhost"
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        error_msg = f"SSRF protection: Rejected internal hostname: {url}"
        logger.warning(error_msg)
        raise SecurityError(error_msg)


def _validate_numeric_ip_hostname(hostname: str, url: str) -> None:
    """Validate numeric IP hostnames to catch unusual formats."""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
                error_msg = f"SSRF protection: Rejected numeric IP hostname: {url}"
                logger.warning(error_msg)
                raise SecurityError(error_msg)
        except ValueError as e:
            error_msg = f"SSRF protection: Rejected unusual numeric hostname: {url}"
            logger.warning(error_msg)
            raise SecurityError(error_msg) from e


def _check_domain_whitelist(hostname: str) -> bool:
    """Check if hostname is in the AT Protocol domain whitelist."""
    domain_parts = hostname.split(".")
    for i in range(len(domain_parts) - 1):
        potential_domain = ".".join(domain_parts[i:])
        if potential_domain in KNOWN_AT_PROTOCOL_DOMAINS:
            return True
    return False


def is_safe_url(url: str) -> bool:
    """
    Validate if a URL is safe to make a request to.

    Implements SSRF protections by:
    - Ensuring HTTPS protocol
    - Checking for private IP ranges or localhost
    - Validating against known AT Protocol domains

    Args:
        url: The URL to validate

    Returns:
        True if the URL is considered safe

    Raises:
        SecurityError: If the URL fails security checks
    """
    if not url:
        raise SecurityError("URL cannot be empty")

    try:
        parsed = urllib.parse.urlparse(url)
        
        # Validate HTTPS protocol
        _validate_https_protocol(parsed, url)
        
        # Extract hostname from netloc
        hostname = _extract_hostname(parsed.netloc)
        
        # Check if it's an IP address and validate it
        if _validate_ip_address(hostname, url):
            return True  # This won't be reached due to SecurityError in _validate_ip_address
        
        # For IPv6 bracket notation that failed IP parsing, use the full netloc
        if parsed.netloc.startswith("["):
            hostname = parsed.netloc
        
        # Validate against internal hostnames
        _validate_internal_hostnames(hostname, url)
        
        # Check for numeric IP patterns
        _validate_numeric_ip_hostname(hostname, url)
        
        # Check domain whitelist
        if _check_domain_whitelist(hostname):
            return True
        
        # Domain not in whitelist
        logger.warning(
            "SSRF protection: URL hostname not in AT Protocol whitelist: %s", hostname
        )
        return False
        
    except SecurityError:
        # Re-raise security errors
        raise
    except Exception as e:
        error_msg = f"SSRF protection: URL validation error: {e}"
        logger.error(error_msg)
        raise SecurityError(error_msg) from e
