"""OAuth functionality for AT Protocol."""

import logging
import secrets
import base64
import hashlib
import json
from typing import Tuple

import httpx

from .security import is_safe_url
from .exceptions import OauthFlowError, SecurityError, InvalidParameterError

logger = logging.getLogger(__name__)


def generate_oauth_state() -> str:
    """
    Generate a secure random state value for OAuth requests.

    The state value is a random string that is:
    - Unpredictable and unique for each authorization request
    - At least 32 bytes (converted to a hex string)
    - Used as a CSRF protection mechanism

    Returns:
        A secure random string to use as the state parameter
    """
    # Generate 32 bytes of random data and convert to hex
    # This will result in a 64-character hex string
    state = secrets.token_hex(32)
    logger.info("Generated OAuth state parameter (%d characters)", len(state))
    return state


def generate_code_verifier(length: int = 128) -> str:
    """
    Generate a code_verifier for PKCE (Proof Key for Code Exchange) in OAuth.

    The code_verifier is:
    - A cryptographically random string between 43 and 128 characters
    - Contains only unreserved URL characters: A-Z, a-z, 0-9, hyphen (-),
      period (.), underscore (_), and tilde (~)

    Args:
        length: Length of the code verifier (default: 128)
               Must be between 43 and 128 characters

    Returns:
        A secure random string to use as the code_verifier parameter

    Raises:
        InvalidParameterError: If the length is not between 43 and 128
    """
    if length < 43 or length > 128:
        error_msg = "Code verifier length must be between 43 and 128 characters"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    # Generate random bytes and convert to base64
    # Generate random bytes (3/4 of the desired length to account for base64 expansion)
    random_bytes = secrets.token_bytes(length * 3 // 4)

    # Convert to base64 and remove padding
    code_verifier = base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")

    # Trim to desired length
    code_verifier = code_verifier[:length]

    logger.info("Generated code_verifier (%d characters)", len(code_verifier))
    return code_verifier


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a code_challenge from a code_verifier for PKCE in OAuth.

    The code_challenge is:
    - The SHA-256 hash of the code_verifier
    - Base64URL-encoded

    Args:
        code_verifier: The code_verifier string

    Returns:
        The code_challenge string
    """
    # Apply SHA-256 hash to the code_verifier
    code_verifier_bytes = code_verifier.encode("ascii")
    hash_bytes = hashlib.sha256(code_verifier_bytes).digest()

    # Base64URL-encode the hash
    code_challenge = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    logger.info("Generated code_challenge (%d characters)", len(code_challenge))
    return code_challenge


def send_par_request(
    par_endpoint: str,
    code_challenge: str,
    state: str,
    login_hint: str = None,
    client_id: str = None,
    redirect_uri: str = None,
    scope: str = "atproto transition:generic",
) -> Tuple[str, int]:
    """
    Send a Pushed Authorization Request (PAR) to the authorization server.

    Args:
        par_endpoint: The PAR endpoint URL from the authorization server metadata
        code_challenge: The PKCE code challenge generated from the code verifier
        state: The OAuth state parameter for CSRF protection
        login_hint: Optional handle or DID to pre-fill the login form
        client_id: The OAuth client ID (URL to client metadata)
        redirect_uri: The callback URL where the authorization code will be sent
        scope: The requested OAuth scopes

    Returns:
        A tuple containing (request_uri, expires_in)

    Raises:
        OauthFlowError: If the PAR request fails
        SecurityError: If there's a security issue with the URL
        InvalidParameterError: If required parameters are missing
    """
    if not par_endpoint:
        error_msg = "Cannot send PAR request: PAR endpoint is None"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    if not code_challenge:
        error_msg = "Cannot send PAR request: code_challenge is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    if not state:
        error_msg = "Cannot send PAR request: state is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    if not client_id:
        error_msg = "Cannot send PAR request: client_id is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    if not redirect_uri:
        error_msg = "Cannot send PAR request: redirect_uri is required"
        logger.error(error_msg)
        raise InvalidParameterError(error_msg)

    # Prepare the request parameters
    params = {
        "response_type": "code",
        "code_challenge_method": "S256",
        "scope": scope,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "state": state,
    }

    # Add login_hint if provided
    if login_hint:
        params["login_hint"] = login_hint

    logger.info("Sending PAR request to: %s", par_endpoint)
    logger.debug("PAR request parameters: %s", params)

    # Check URL for SSRF vulnerabilities
    try:
        is_safe_url(par_endpoint)
    except SecurityError:
        logger.error("Security check failed for URL: %s", par_endpoint)
        raise

    try:
        # Send the POST request with form-encoded body
        response = httpx.post(
            par_endpoint,
            data=params,
        )
        response.raise_for_status()

        # Parse the JSON response
        data = response.json()
        logger.info("PAR request successful")

        # Extract the request_uri and expires_in values
        request_uri = data.get("request_uri")
        expires_in = data.get("expires_in")

        if request_uri:
            logger.info("Received request_uri: %s", request_uri)
            logger.info("Request URI expires in: %s seconds", expires_in)
            return request_uri, expires_in
        else:
            error_msg = "No request_uri found in PAR response"
            logger.error(error_msg)
            raise OauthFlowError(error_msg)

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error occurred during PAR request: {e}"
        logger.error(error_msg)
        try:
            # Try to extract error details from response
            error_data = e.response.json()
            logger.error("Error details: %s", error_data)
            error_msg = f"{error_msg} - {error_data}"
        except json.JSONDecodeError:
            logger.error("Could not parse error response as JSON")
        except Exception as ex:
            logger.error("Error extracting details from error response: %s", ex)
        raise OauthFlowError(error_msg)
    except httpx.RequestError as e:
        error_msg = f"Request error occurred during PAR request: {e}"
        logger.error(error_msg)
        raise OauthFlowError(error_msg)
    except json.JSONDecodeError:
        error_msg = "Failed to parse JSON response from PAR request"
        logger.error(error_msg)
        raise OauthFlowError(error_msg)
