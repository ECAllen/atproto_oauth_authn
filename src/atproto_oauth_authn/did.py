"""DID document handling for AT Protocol."""

import logging
import json
from typing import Tuple, Dict, Any

import httpx

from .security import is_safe_url
from .exceptions import DidDocumentError, SecurityError

logger = logging.getLogger(__name__)


# AI! this should be split into two functions, one to retrieve the DID document and another to extradt the PDS URL
def get_did_document(did: str) -> Tuple[Dict[str, Any], str]:
    """
    Retrieve the DID document for a given DID.

    Args:
        did: The DID to retrieve the document for

    Returns:
        A tuple containing the DID document as a dictionary and the PDS URL

    Raises:
        DidDocumentError: If the DID document cannot be retrieved or parsed
        SecurityError: If there's a security issue with the URL
    """
    if not did:
        raise DidDocumentError("DID cannot be empty")

    url = f"https://plc.directory/{did}"

    # Check URL for SSRF vulnerabilities
    try:
        is_safe_url(url)
    except SecurityError:
        logger.error(f"Security check failed for URL: {url}")
        raise

    try:
        # Make HTTP request to retrieve the DID document
        response = httpx.get(url)
        response.raise_for_status()

        # Parse the JSON response
        did_document = response.json()
        logger.info(f"Retrieved DID document for {did}")

        # Extract the PDS URL from the DID document
        if "service" in did_document and len(did_document["service"]) > 0:
            pds_url = did_document["service"][0].get("serviceEndpoint")
            if pds_url:
                logger.info(f"User's PDS URL: {pds_url}")
                return did_document, pds_url

        error_msg = f"Could not find PDS URL in DID document for {did}"
        logger.warning(error_msg)
        raise DidDocumentError(error_msg)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            error_msg = f"DID not found: {did}"
            logger.warning(error_msg)
            raise DidDocumentError(error_msg)
        elif e.response.status_code == 410:
            error_msg = f"DID not available (tombstone) 🪦: {did}"
            logger.warning(error_msg)
            raise DidDocumentError(error_msg)
        else:
            error_msg = f"HTTP error occurred while retrieving DID document: {e}"
            logger.error(error_msg)
            raise DidDocumentError(error_msg)
    except httpx.RequestError as e:
        error_msg = f"Request error occurred while retrieving DID document: {e}"
        logger.error(error_msg)
        raise DidDocumentError(error_msg)
    except json.JSONDecodeError:
        error_msg = f"Failed to parse JSON response from DID document retrieval"
        logger.error(error_msg)
        raise DidDocumentError(error_msg)
