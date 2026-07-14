"""Security functions for AT Protocol OAuth."""

import logging
from typing import Set
from urllib.parse import urlparse

import httpx
import validators

from .exceptions import SecurityError

logger = logging.getLogger(__name__)


def create_hardened_client(timeout_seconds: int = 30) -> httpx.Client:
    """Create a hardened HTTP client with security settings and timeouts.

    Args:
        timeout_seconds: Request timeout in seconds

    Returns:
        Configured httpx.Client instance
    """
    return httpx.Client(
        timeout=httpx.Timeout(
            connect=10.0,  # Time to establish connection
            read=timeout_seconds,  # Time to read response
            write=10.0,  # Time to send request
            pool=5.0,  # Time to get connection from pool
        ),
        limits=httpx.Limits(
            max_keepalive_connections=5, max_connections=10, keepalive_expiry=30.0
        ),
        follow_redirects=False,  # Don't follow redirects automatically for security
        verify=True,  # Verify SSL certificates
        http2=True,  # Enable HTTP/2 for better performance
    )


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


def _is_internal_hostname(hostname: str) -> bool:
    """Return True if the hostname refers to an internal/reserved name."""
    return (
        hostname == "localhost"
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".arpa")
    )


def _is_known_domain(hostname: str) -> bool:
    """Return True if hostname is (a subdomain of) a known AT Protocol domain."""
    domain_parts = hostname.split(".")
    for i in range(len(domain_parts) - 1):
        potential_domain = ".".join(domain_parts[i:])
        if potential_domain in KNOWN_AT_PROTOCOL_DOMAINS:
            return True
    return False


def validate_scheme(scheme: str) -> bool:
    """Only https is an acceptable URL scheme."""
    return scheme == "https"


def valid_url(url: str) -> None:
    """
    Validate that a URL is safe to make a request to.

    Implements SSRF protections by ensuring the URL:
    - Is well-formed, uses HTTPS, and has no port or IP-literal host
    - Does not point at an internal/reserved hostname
    - Does not embed credentials

    Hosts outside KNOWN_AT_PROTOCOL_DOMAINS are allowed (AT Protocol is
    federated, so handles and PDS servers live on arbitrary domains) but
    are logged at WARNING level.

    Args:
        url: The URL to validate

    Raises:
        SecurityError: If the URL fails any security check
    """
    if not validators.url(
        url,
        skip_ipv6_addr=True,
        skip_ipv4_addr=True,
        may_have_port=False,
        validate_scheme=validate_scheme,
    ):
        error_msg = (
            "SSRF protection: rejected URL (must be well-formed https "
            f"with no port or IP-literal host): {url}"
        )
        logger.warning(error_msg)
        raise SecurityError(error_msg)

    url_parts = urlparse(url)
    hostname = url_parts.hostname

    if not hostname or _is_internal_hostname(hostname):
        error_msg = f"SSRF protection: rejected internal hostname: {url}"
        logger.warning(error_msg)
        raise SecurityError(error_msg)

    if url_parts.username or url_parts.password:
        error_msg = f"SSRF protection: rejected URL with embedded credentials: {url}"
        logger.warning(error_msg)
        raise SecurityError(error_msg)

    if not _is_known_domain(hostname):
        logger.warning("URL host is not a known AT Protocol domain: %s", hostname)
