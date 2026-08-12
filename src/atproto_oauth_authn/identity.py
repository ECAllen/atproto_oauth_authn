"""Identity resolution functions for AT Protocol."""

import logging
import re

import dns.exception
import dns.resolver
import httpx

from .security import valid_url
from .exceptions import IdentityResolutionError, SecurityError

logger = logging.getLogger(__name__)

# Constants
HANDLE_REGEX = (
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]"
    r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
DID_RE = r"^did:[a-z]+:[a-zA-Z0-9.%-]+$"

DNS_TXT_PREFIX = "did="


def _resolve_via_dns_txt(handle: str) -> str | None:
    """Resolve a handle via the `_atproto.<handle>` DNS TXT method.

    Returns the DID, or None if the record is absent or unparsable (not an
    error condition — the caller falls back to the HTTPS well-known method).
    """
    qname = f"_atproto.{handle}"
    try:
        answers = dns.resolver.resolve(qname, "TXT", lifetime=5.0)
    except dns.exception.DNSException as e:
        logger.debug("DNS TXT resolution for %s found nothing: %s", qname, e)
        return None

    for rdata in answers:
        txt_value = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if txt_value.startswith(DNS_TXT_PREFIX):
            did = txt_value[len(DNS_TXT_PREFIX):]
            if re.match(DID_RE, did):
                return did
            logger.debug("DNS TXT record for %s had a malformed DID: %r", qname, did)

    return None


def _resolve_via_well_known(handle: str) -> str | None:
    """Resolve a handle via the `https://<handle>/.well-known/atproto-did` method.

    Returns the DID, or None if the endpoint doesn't resolve one (not an
    error condition — the caller treats this as resolution failure only
    after both methods have been tried).

    Raises:
        SecurityError: If the constructed URL fails SSRF validation.
    """
    url = f"https://{handle}/.well-known/atproto-did"

    try:
        valid_url(url)
    except SecurityError:
        logger.error("Security check failed for URL: %s", url)
        raise

    try:
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
    except httpx.HTTPError as e:
        logger.debug("Well-known resolution for %s failed: %s", handle, e)
        return None

    did = response.text.strip()
    if re.match(DID_RE, did):
        return did

    logger.debug("Well-known response for %s was not a valid DID: %r", handle, did)
    return None


def resolve_identity(username: str) -> str:
    """
    Resolve a username (handle or DID) to a DID.

    Handles are resolved per the AT Protocol handle resolution spec
    (https://atproto.com/specs/handle): a DNS TXT record at
    `_atproto.<handle>` is tried first, falling back to the HTTPS
    `https://<handle>/.well-known/atproto-did` method.

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
        logger.debug("Username is a handle: %s", username)

        did = _resolve_via_dns_txt(username)
        if did:
            logger.debug("Resolved handle %s to DID via DNS TXT: %s", username, did)
            return did

        did = _resolve_via_well_known(username)
        if did:
            logger.debug("Resolved handle %s to DID via well-known: %s", username, did)
            return did

        error_msg = f"Failed to resolve handle: {username}. No DID found via DNS TXT or well-known"
        logger.info(error_msg)
        raise IdentityResolutionError(error_msg)

    if re.match(DID_RE, username):
        # If the username is already a DID, return it directly
        logger.info("Username is already a DID: %s", username)
        return username

    error_msg = f"Username '{username}' is neither a valid handle nor a DID"
    logger.warning(error_msg)
    raise IdentityResolutionError(error_msg)
