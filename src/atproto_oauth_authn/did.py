"""DID document handling for AT Protocol."""

import logging
import json
from typing import Optional, Tuple, Dict, Any

import httpx

from .security import is_safe_url

logger = logging.getLogger(__name__)

def get_did_document(did: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Retrieve the DID document for a given DID.
    
    Args:
        did: The DID to retrieve the document for
        
    Returns:
        The DID document as a dictionary if successful, None otherwise
    """
    url = f"https://plc.directory/{did}"
    
    # Check URL for SSRF vulnerabilities
    if not is_safe_url(url):
        logger.error(f"SSRF protection: Blocked request to potentially unsafe URL: {url}")
        return None, None

    try:
        # Make HTTP request to retrieve the DID document
        response = httpx.get(url)
        response.raise_for_status()
        
        # Parse the JSON response
        did_document = response.json()
        logger.info(f"Retrieved DID document for {did}")
        
        # Extract the PDS URL from the DID document
        if 'service' in did_document and len(did_document['service']) > 0:
            pds_url = did_document['service'][0].get('serviceEndpoint')
            if pds_url:
                logger.info(f"User's PDS URL: {pds_url}")
                return did_document, pds_url
        
        logger.warning(f"Could not find PDS URL in DID document for {did}")
        return did_document, None
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.warning(f"DID not found: {did}")
            return None, None
        elif e.response.status_code == 410:
            logger.warning(f"DID not available (tombstone) 🪦: {did}")
            return None, None
        else:
            logger.error(f"HTTP error occurred while retrieving DID document: {e}")
            return None, None
    except httpx.RequestError as e:
        logger.error(f"Request error occurred while retrieving DID document: {e}")
        return None, None
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON response from DID document retrieval")
        return None, None
