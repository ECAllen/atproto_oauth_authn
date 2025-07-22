"""Metadata retrieval functions for AT Protocol."""

import logging
import json
from typing import List, Dict, Any, Tuple

import httpx

from .security import is_safe_url
from .exceptions import MetadataError, SecurityError

logger = logging.getLogger(__name__)


def get_pds_metadata(pds_url: str) -> Dict[str, Any]:
    """
    Retrieve the OAuth protected resource metadata from the PDS server.

    Args:
        pds_url: The URL of the PDS server

    Returns:
        The metadata as a dictionary

    Raises:
        MetadataError: If the metadata cannot be retrieved or parsed
        SecurityError: If there's a security issue with the URL
    """
    if not pds_url:
        error_msg = "Cannot get PDS metadata: PDS URL is None"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    metadata_url = f"{pds_url.rstrip('/')}/.well-known/oauth-protected-resource"
    logger.info("Fetching PDS metadata from: %s", metadata_url)

    # Check URL for SSRF vulnerabilities
    try:
        is_safe_url(metadata_url)
    except SecurityError:
        logger.error("Security check failed for URL: %s", metadata_url)
        raise

    try:
        response = httpx.get(metadata_url)
        response.raise_for_status()

        metadata = response.json()
        logger.info("Successfully retrieved PDS metadata")
        return metadata
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error occurred while retrieving PDS metadata: {e}"
        logger.error(error_msg)
        raise MetadataError(error_msg) from e
    except httpx.RequestError as e:
        error_msg = f"Request error occurred while retrieving PDS metadata: {e}"
        logger.error(error_msg)
        raise MetadataError(error_msg) from e
    except json.JSONDecodeError:
        error_msg = "Failed to parse JSON response from PDS metadata retrieval"
        logger.error(error_msg)
        raise MetadataError(error_msg) from e


def extract_auth_server(metadata: Dict[str, Any]) -> List[str]:
    """
    Extract the authorization server URL from the PDS metadata.

    Args:
        metadata: The PDS metadata dictionary

    Returns:
        The list of authorization server URLs

    Raises:
        MetadataError: If no authorization servers can be found
    """
    if not metadata:
        error_msg = "Cannot extract authorization server: Metadata is None"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    auth_servers = metadata.get("authorization_servers")
    if not auth_servers or not isinstance(auth_servers, list) or len(auth_servers) == 0:
        error_msg = "No authorization servers found in metadata"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    # Return the list of authorization servers
    logger.info("Found authorization servers: %s", auth_servers)
    return auth_servers


def _fetch_single_auth_server_metadata(auth_server: str) -> Tuple[Dict[str, Any], str, str, str]:
    """Fetch metadata from a single auth server."""
    metadata_url = (
        f"{auth_server.rstrip('/')}/.well-known/oauth-authorization-server"
    )
    logger.info("Trying to fetch auth server metadata from: %s", metadata_url)

    # Check URL for SSRF vulnerabilities
    is_safe_url(metadata_url)  # Raises SecurityError if unsafe

    response = httpx.get(metadata_url)
    response.raise_for_status()

    metadata = response.json()
    logger.info(
        "Successfully retrieved auth server metadata from %s", auth_server
    )

    return _extract_endpoints_from_metadata(metadata, auth_server)


def _extract_endpoints_from_metadata(
    metadata: Dict[str, Any], auth_server: str
) -> Tuple[Dict[str, Any], str, str, str]:
    """Extract and validate endpoints from metadata."""
    auth_endpoint = metadata.get("authorization_endpoint")
    token_endpoint = metadata.get("token_endpoint")
    par_endpoint = metadata.get("pushed_authorization_request_endpoint")

    if not auth_endpoint or not token_endpoint:
        error_msg = (
            "Missing required endpoints in auth server metadata "
            f"from {auth_server}"
        )
        raise MetadataError(error_msg)

    logger.info("Found authorization endpoint: %s", auth_endpoint)
    logger.info("Found token endpoint: %s", token_endpoint)
    if par_endpoint:
        logger.info("Found PAR endpoint: %s", par_endpoint)
    else:
        logger.warning("PAR endpoint not found in auth server metadata")

    return metadata, auth_endpoint, token_endpoint, par_endpoint


def get_auth_server_metadata(
    auth_servers: List[str],
) -> Tuple[Dict[str, Any], str, str, str]:
    """
    Retrieve the OAuth authorization server metadata from the first available server.

    Args:
        auth_servers: List of authorization server URLs

    Returns:
        A tuple containing (metadata, auth_endpoint, token_endpoint, par_endpoint)

    Raises:
        MetadataError: If metadata cannot be retrieved from any server
        SecurityError: If there's a security issue with the URL
    """
    if not auth_servers or not isinstance(auth_servers, list):
        error_msg = (
            "Cannot get auth server metadata: "
            "No authorization servers provided"
        )
        logger.error(error_msg)
        raise MetadataError(error_msg)

    errors = []

    for auth_server in auth_servers:
        try:
            return _fetch_single_auth_server_metadata(auth_server)
        except SecurityError as e:
            error_msg = f"Security error for {auth_server}: {str(e)}"
            logger.error("Security check failed for auth server: %s", auth_server)
            errors.append(error_msg)
            continue
        except httpx.HTTPStatusError as e:
            error_msg = (
                "HTTP error occurred while retrieving auth server metadata "
                f"from {auth_server}: {e}"
            )
            logger.warning(error_msg)
            errors.append(error_msg)
            continue
        except httpx.RequestError as e:
            error_msg = (
                "Request error occurred while retrieving auth server metadata "
                f"from {auth_server}: {e}"
            )
            logger.warning(error_msg)
            errors.append(error_msg)
            continue
        except json.JSONDecodeError:
            error_msg = (
                "Failed to parse JSON response from auth server metadata "
                f"retrieval from {auth_server}"
            )
            logger.warning(error_msg)
            errors.append(error_msg)
            continue
        except MetadataError as e:
            logger.warning("Metadata validation failed for %s: %s", auth_server, e)
            errors.append(str(e))
            continue

    error_msg = (
        "Failed to retrieve metadata from any authorization server: "
        f"{'; '.join(errors)}"
    )
    logger.error(error_msg)
    raise MetadataError(error_msg)
