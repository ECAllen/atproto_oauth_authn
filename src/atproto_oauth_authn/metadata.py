"""Metadata retrieval functions for AT Protocol."""

import logging
import json
from typing import Optional, List, Dict, Any, Tuple

import httpx

from .security import is_safe_url

logger = logging.getLogger(__name__)

def get_pds_metadata(pds_url: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve the OAuth protected resource metadata from the PDS server.
    
    Args:
        pds_url: The URL of the PDS server
        
    Returns:
        The metadata as a dictionary if successful, None otherwise
    """
    if not pds_url:
        logger.error("Cannot get PDS metadata: PDS URL is None")
        return None
        
    metadata_url = f"{pds_url.rstrip('/')}/.well-known/oauth-protected-resource"
    logger.info(f"Fetching PDS metadata from: {metadata_url}")
    
    # Check URL for SSRF vulnerabilities
    if not is_safe_url(metadata_url):
        logger.error(f"SSRF protection: Blocked request to potentially unsafe URL: {metadata_url}")
        return None

    try:
        response = httpx.get(metadata_url)
        response.raise_for_status()
        
        metadata = response.json()
        logger.info(f"Successfully retrieved PDS metadata")
        return metadata
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error occurred while retrieving PDS metadata: {e}")
        return None
    except httpx.RequestError as e:
        logger.error(f"Request error occurred while retrieving PDS metadata: {e}")
        return None
    except json.JSONDecodeError:
        logger.error("Failed to parse JSON response from PDS metadata retrieval")
        return None

def extract_auth_server(metadata: Dict[str, Any]) -> Optional[List[str]]:
    """
    Extract the authorization server URL from the PDS metadata.
    
    Args:
        metadata: The PDS metadata dictionary
        
    Returns:
        The authorization server URL if found, None otherwise
    """
    if not metadata:
        logger.error("Cannot extract authorization server: Metadata is None")
        return None
        
    auth_servers = metadata.get("authorization_servers")
    if not auth_servers or not isinstance(auth_servers, list) or len(auth_servers) == 0:
        logger.error("No authorization servers found in metadata")
        return None
        
    # Return the list of authorization servers
    logger.info(f"Found authorization servers: {auth_servers}")
    return auth_servers

def get_auth_server_metadata(
    auth_servers: List[str]
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str], Optional[str]]:
    """
    Retrieve the OAuth authorization server metadata from the first available server.
    
    Args:
        auth_servers: List of authorization server URLs
        
    Returns:
        A tuple containing (metadata, auth_endpoint, token_endpoint, par_endpoint)
        All values will be None if no server is available
    """
    if not auth_servers or not isinstance(auth_servers, list):
        logger.error("Cannot get auth server metadata: No authorization servers provided")
        return None, None, None, None
    
    for auth_server in auth_servers:
        metadata_url = (
            f"{auth_server.rstrip('/')}/.well-known/oauth-authorization-server"
        )
        logger.info(f"Trying to fetch auth server metadata from: {metadata_url}")

        # Check URL for SSRF vulnerabilities
        if not is_safe_url(metadata_url):
            logger.error(f"SSRF protection: Blocked request to potentially unsafe URL: {metadata_url}")
            continue

        try:
            response = httpx.get(metadata_url)
            response.raise_for_status()
            
            metadata = response.json()
            logger.info(f"Successfully retrieved auth server metadata from {auth_server}")
            
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
                
                return metadata, auth_endpoint, token_endpoint, par_endpoint
            else:
                logger.warning(f"Missing required endpoints in auth server metadata from {auth_server}")
                continue
                
        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error occurred while retrieving auth server metadata from {auth_server}: {e}")
            continue
        except httpx.RequestError as e:
            logger.warning(f"Request error occurred while retrieving auth server metadata from {auth_server}: {e}")
            continue
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON response from auth server metadata retrieval from {auth_server}")
            continue
    
    logger.error("Failed to retrieve metadata from any authorization server")
    return None, None, None, None
