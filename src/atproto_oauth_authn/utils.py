"""Utility functions for AT Protocol OAuth."""

import logging
import urllib.parse

from .exceptions import InvalidParameterError

logger = logging.getLogger(__name__)


def build_auth_url(auth_endpoint: str, client_id: str, request_uri: str) -> str:
    """
    Build an authorization URL with proper URI encoding.

    Args:
        auth_endpoint: The authorization endpoint URL
        client_id: The client ID
        request_uri: The request URI from the PAR response

    Returns:
        The properly encoded authorization URL

    Raises:
        InvalidParameterError: If any required parameter is missing
    """
    if not auth_endpoint:
        error_msg = "Cannot build authorization URL: auth_endpoint is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    if not client_id:
        error_msg = "Cannot build authorization URL: client_id is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    if not request_uri:
        error_msg = "Cannot build authorization URL: request_uri is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    client_id_enc = urllib.parse.quote(client_id, safe="")
    request_uri_enc = urllib.parse.quote(request_uri)
    auth_url = (
        f"{auth_endpoint}?client_id={client_id_enc}&request_uri={request_uri_enc}"
    )
    logger.info("Built authorization URL with encoded parameters")
    return auth_url
