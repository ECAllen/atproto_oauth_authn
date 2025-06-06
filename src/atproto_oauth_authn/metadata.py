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
    logger.info(f"Fetching PDS metadata from: {metadata_url}")

    # Check URL for SSRF vulnerabilities
    try:
        is_safe_url(metadata_url)
    except SecurityError:
        logger.error(f"Security check failed for URL: {metadata_url}")
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
        raise MetadataError(error_msg)
    except httpx.RequestError as e:
        error_msg = f"Request error occurred while retrieving PDS metadata: {e}"
        logger.error(error_msg)
        raise MetadataError(error_msg)
    except json.JSONDecodeError:
        error_msg = "Failed to parse JSON response from PDS metadata retrieval"
        logger.error(error_msg)
        raise MetadataError(error_msg)


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
    logger.info(f"Found authorization servers: {auth_servers}")
    return auth_servers


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
        error_msg = "Cannot get auth server metadata: No authorization servers provided"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    errors = []

    for auth_server in auth_servers:
        metadata_url = (
            f"{auth_server.rstrip('/')}/.well-known/oauth-authorization-server"
        )
        logger.info(f"Trying to fetch auth server metadata from: {metadata_url}")

        # Check URL for SSRF vulnerabilities
        try:
            is_safe_url(metadata_url)
        except SecurityError as e:
            logger.error(f"Security check failed for URL: {metadata_url}")
            errors.append(f"Security error for {auth_server}: {str(e)}")
            continue

        try:
            response = httpx.get(metadata_url)
            response.raise_for_status()

            metadata = response.json()
            logger.info(
                f"Successfully retrieved auth server metadata from {auth_server}"
            )

            # Extract endpoints from metadata
            auth_endpoint = metadata.get("authorization_endpoint")
            token_endpoint = metadata.get("token_endpoint")
            par_endpoint = metadata.get("pushed_authorization_request_endpoint")

            if auth_endpoint and token_endpoint:
                logger.info(f"Found authorization endpoint: {auth_endpoint}")
                logger.info(f"Found token endpoint: {token_endpoint}")
                if par_endpoint:
                    logger.info(f"Found PAR endpoint: {par_endpoint}")
                else:
                    logger.warning("PAR endpoint not found in auth server metadata")
                    par_endpoint = None

                return metadata, auth_endpoint, token_endpoint, par_endpoint
            else:
                error_msg = f"Missing required endpoints in auth server metadata from {auth_server}"
                logger.warning(error_msg)
                errors.append(error_msg)
                continue

        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP error occurred while retrieving auth server metadata from {auth_server}: {e}"
            logger.warning(error_msg)
            errors.append(error_msg)
            continue
        except httpx.RequestError as e:
            error_msg = f"Request error occurred while retrieving auth server metadata from {auth_server}: {e}"
            logger.warning(error_msg)
            errors.append(error_msg)
            continue
        except json.JSONDecodeError:
            error_msg = f"Failed to parse JSON response from auth server metadata retrieval from {auth_server}"
            logger.warning(error_msg)
            errors.append(error_msg)
            continue

    error_msg = f"Failed to retrieve metadata from any authorization server: {'; '.join(errors)}"
    logger.error(error_msg)
    raise MetadataError(error_msg)
