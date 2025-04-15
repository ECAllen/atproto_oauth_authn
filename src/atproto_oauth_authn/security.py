"""Security functions for AT Protocol OAuth."""

import logging
import re
import ipaddress
import urllib.parse
from typing import Set

logger = logging.getLogger(__name__)

# Known AT Protocol domains
KNOWN_AT_PROTOCOL_DOMAINS: Set[str] = {
    # Official Bluesky domains
    'bsky.social', 'bsky.app', 'bsky.network',
    # PLC directory
    'plc.directory',
    # Common PDS providers
    'blueskyweb.xyz', 'staging.bsky.dev',
    # Common third-party PDS providers
    'pds.public.url', 'atproto.com',
    # Add more known domains as needed
}

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
        True if the URL is considered safe, False otherwise
    """
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Ensure HTTPS protocol
        if parsed.scheme != 'https':
            logger.warning(f"SSRF protection: Rejected non-HTTPS URL: {url}")
            return False
            
        # Check for private IP ranges or localhost
        hostname = parsed.netloc.split(':')[0]
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
                logger.warning(f"SSRF protection: Rejected URL with private/reserved IP: {url}")
                return False
        except ValueError:
            # Not an IP address, continue with hostname checks
            pass
            
        # Reject localhost and common internal hostnames
        if hostname == 'localhost' or hostname.endswith('.local') or hostname.endswith('.internal'):
            logger.warning(f"SSRF protection: Rejected internal hostname: {url}")
            return False
            
        # Check for numeric IP in hostname to catch IP literals like 0177.0.0.1
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
                    logger.warning(f"SSRF protection: Rejected numeric IP hostname: {url}")
                    return False
            except ValueError:
                logger.warning(f"SSRF protection: Rejected unusual numeric hostname: {url}")
                return False
        
        # Whitelist of known AT Protocol domains
        domain_parts = hostname.split('.')
        for i in range(len(domain_parts) - 1):
            potential_domain = '.'.join(domain_parts[i:])
            if potential_domain in KNOWN_AT_PROTOCOL_DOMAINS:
                return True
                
        # For domains not in the whitelist, log a warning but still allow if other checks passed
        logger.warning(f"SSRF protection: URL hostname not in AT Protocol whitelist: {hostname}")
        
        return True
    except Exception as e:
        logger.error(f"SSRF protection: URL validation error: {e}")
        return False
