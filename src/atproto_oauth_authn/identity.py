"""Identity resolution functions for AT Protocol."""

import logging
import re
import json

import httpx

from .security import is_safe_url
from .exceptions import IdentityResolutionError, SecurityError

logger = logging.getLogger(__name__)

# Constants
HANDLE_REGEX = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
DID_RE = r"^did:[a-z]+:[a-zA-Z0-9.%-]+$"


def resolve_identity(username: str) -> str:
    """
    Resolve a username (handle or DID) to a DID.

    Args:
        username: A string that could be a handle or DID

    Returns:
        The DID if resolution is successful

    Raises:
        IdentityResolutionError: If the username cannot be resolved to a DID
        SecurityError: If there's a security issue with the URL
    """
    if not username:
        raise IdentityResolutionError("Username cannot be empty")

    if re.match(HANDLE_REGEX, username):
        # Handle the case where username is a handle
        logger.debug(f"Username is a handle: {username}")

        # Extract domain and TLD from the handle
        parts = username.split(".")
        if len(parts) >= 2:
            domain_tld = ".".join(parts[1:])
            logger.info(f"Extracted domain and TLD: {domain_tld}")
        else:
            error_msg = f"Could not extract domain from handle: {username}"
            logger.warning(error_msg)
            raise IdentityResolutionError(error_msg)

        url = f"https://{domain_tld}/xrpc/com.atproto.identity.resolveHandle?handle={username}"

        # Check URL for SSRF vulnerabilities
        try:
            is_safe_url(url)
        except SecurityError:
            logger.error(f"Security check failed for URL: {url}")
            raise

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
                error_msg = (
                    f"Failed to resolve handle: {username}. No DID found in response"
                )
                logger.info(error_msg)
                raise IdentityResolutionError(error_msg)
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP error occurred while resolving handle: {e}"
            logger.info(error_msg)
            raise IdentityResolutionError(error_msg)
        except httpx.RequestError as e:
            error_msg = f"Request error occurred while resolving handle: {e}"
            logger.info(error_msg)
            raise IdentityResolutionError(error_msg)
        except json.JSONDecodeError:
            error_msg = "Failed to parse JSON response from handle resolution"
            logger.info(error_msg)
            raise IdentityResolutionError(error_msg)
    elif re.match(DID_RE, username):
        # If the username is already a DID, return it directly
        logger.info(f"Username is already a DID: {username}")
        return username
    else:
        error_msg = f"Username '{username}' is neither a valid handle nor a DID"
        logger.warning(error_msg)
        raise IdentityResolutionError(error_msg)
