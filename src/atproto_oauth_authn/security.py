"""Security functions for AT Protocol OAuth."""

import logging
import re
import ipaddress
from typing import Set

import validators
from validators.utils import validator
from urllib.parse import urlparse

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

@validator
def _is_internal_hostname(hostname: str) -> bool:
    """Validate against internal hostnames."""
    if (
        hostname == "localhost"
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".arpa")
    ):
        error_msg = f"SSRF protection: Rejected internal hostname: {url}"
        logger.warning(error_msg)
        return False
    return True

@validator
def _check_domain_whitelist(hostname: str) -> bool:
    """Check if hostname is in the AT Protocol domain whitelist."""
    domain_parts = hostname.split(".")
    for i in range(len(domain_parts) - 1):
        potential_domain = ".".join(domain_parts[i:])
        if potential_domain in KNOWN_AT_PROTOCOL_DOMAINS:
            return True
    return False

@validator
def _check_url_creds(url_parts) -> bool:
    if parts.username is not None:
        return False
    if parts.password is not None:
        return False
    return True

# Used in the validator ti check the
def validate_scheme(scheme: str) -> bool:
    if scheme == "https":
        return True
    return False

def valid_url(url: str):
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

    url_parts = urlparse(url)

    try:  
        validators.url(
            value=url,
            skip_ipv6_addr=True,
            skip_ipv4_addr=True,
            may_have_port=False,
            validate_scheme=validate_scheme
        )

        # Validate against internal hostnames
        _is_internal_hostname(parts.hostname)

        # Check domain whitelist
        _check_domain_whitelist(parts.hostname)

        # Check for username and password
        _check_url_creds(parts.hostname)

    except ValidationError as e:
        logger.error(f"URL validation error {e}")
        raise ValidationError
    
    return

 

