"""DID document handling for AT Protocol."""

import logging
import json
from typing import Tuple, Dict, Any

import httpx

from .security import is_safe_url
from .exceptions import DidDocumentError, SecurityError

logger = logging.getLogger(__name__)


def retrieve_did_document(did: str) -> Dict[str, Any]:
    """
    Retrieve the DID document for a given DID.

    Args:
        did: The DID to retrieve the document for

    Returns:
        The DID document as a dictionary

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
        return did_document
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


def extract_pds_url(did_document: Dict[str, Any]) -> str:
    """
    Extract the PDS URL from a DID document.

    Args:
        did_document: The DID document dictionary

    Returns:
        The PDS URL as a string

    Raises:
        DidDocumentError: If the PDS URL cannot be found in the document
    """
    if not did_document:
        raise DidDocumentError("DID document cannot be empty")

    # Extract the PDS URL from the DID document
    if "service" in did_document and len(did_document["service"]) > 0:
        pds_url = did_document["service"][0].get("serviceEndpoint")
        if pds_url:
            logger.info(f"Extracted PDS URL: {pds_url}")
            return pds_url

    error_msg = "Could not find PDS URL in DID document"
    logger.warning(error_msg)
    raise DidDocumentError(error_msg)


def get_did_document(did: str) -> Tuple[Dict[str, Any], str]:
    """
    Retrieve the DID document for a given DID and extract the PDS URL.

    Args:
        did: The DID to retrieve the document for

    Returns:
        A tuple containing the DID document as a dictionary and the PDS URL

    Raises:
        DidDocumentError: If the DID document cannot be retrieved or parsed
        SecurityError: If there's a security issue with the URL
    """
    did_document = retrieve_did_document(did)
    pds_url = extract_pds_url(did_document)
    return did_document, pds_url
