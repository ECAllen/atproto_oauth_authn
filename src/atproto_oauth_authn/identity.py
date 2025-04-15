"""Identity resolution functions for AT Protocol."""

import logging
import re
import json
from typing import Optional

import httpx

from .security import is_safe_url

logger = logging.getLogger(__name__)

# Constants
HANDLE_REGEX = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
DID_RE = r"^did:[a-z]+:[a-zA-Z0-9.%-]+$"

def resolve_identity(username: str) -> Optional[str]:
    """
    Resolve a username (handle or DID) to a DID.
    
    Args:
        username: A string that could be a handle or DID
        
    Returns:
        The DID if resolution is successful, None otherwise
    """
    if re.match(HANDLE_REGEX, username):
        # Handle the case where username is a handle
        logger.debug(f"Username is a handle: {username}")

        # Extract domain and TLD from the handle
        parts = username.split(".")
        if len(parts) >= 2:
            domain_tld = ".".join(parts[1:])
            logger.info(f"Extracted domain and TLD: {domain_tld}")
        else:
            logger.warning(f"Could not extract domain from handle: {username}")
            return None

        url = f"https://{domain_tld}/xrpc/com.atproto.identity.resolveHandle?handle={username}"

        # Check URL for SSRF vulnerabilities
        if not is_safe_url(url):
            logger.error(f"SSRF protection: Blocked request to potentially unsafe URL: {url}")
            return None

        # Make HTTP request to resolve handle to DID
        try:
            response = httpx.get(url)
            response.raise_for_status()  # Raise exception for 4XX/5XX responses

            # Parse the JSON response
            data = response.json()

            # Extract the DID from the response
            did = data.get("did")
            if did:
                logger.debug(f"Resolved handle {username} to DID: {did}")
                return did
            else:
                logger.info(
                    f"Failed to resolve handle: {username} No DID found in response"
                )
                return None
        except httpx.HTTPStatusError as e:
            logger.info(f"HTTP error occurred while resolving handle: {e}")
            return None
        except httpx.RequestError as e:
            logger.info(f"Request error occurred while resolving handle: {e}")
            return None
        except json.JSONDecodeError:
            logger.info("Failed to parse JSON response from handle resolution")
            return None
    elif re.match(DID_RE, username):
        # If the username is already a DID, return it directly
        logger.info(f"Username is already a DID: {username}")
        return username
    else:
        logger.warning(f"Username '{username}' is neither a valid handle nor a DID")
        return None
