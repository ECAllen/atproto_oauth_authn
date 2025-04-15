"""OAuth functionality for AT Protocol."""

import logging
import secrets
import base64
import hashlib
import json
from typing import Optional, Tuple

import httpx

from .security import is_safe_url

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
    logger.info(f"Generated OAuth state parameter ({len(state)} characters)")
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
    """
    if length < 43 or length > 128:
        raise ValueError("Code verifier length must be between 43 and 128 characters")

    # Generate random bytes and convert to base64
    # Generate random bytes (3/4 of the desired length to account for base64 expansion)
    random_bytes = secrets.token_bytes(length * 3 // 4)

    # Convert to base64 and remove padding
    code_verifier = base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")

    # Trim to desired length
    code_verifier = code_verifier[:length]

    logger.info(f"Generated code_verifier ({len(code_verifier)} characters)")
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

    logger.info(f"Generated code_challenge ({len(code_challenge)} characters)")
    return code_challenge

def send_par_request(
    par_endpoint: str,
    code_challenge: str,
    state: str,
    login_hint: Optional[str] = None,
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    scope: str = "atproto transition:generic",
) -> Tuple[Optional[str], Optional[int]]:
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
        A tuple containing (request_uri, expires_in) if successful, (None, None) otherwise
    """
    if not par_endpoint:
        logger.error("Cannot send PAR request: PAR endpoint is None")
        return None, None
    
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
    
    logger.info(f"Sending PAR request to: {par_endpoint}")
    logger.debug(f"PAR request parameters: {params}")
    
    # Check URL for SSRF vulnerabilities
    if not is_safe_url(par_endpoint):
        logger.error(f"SSRF protection: Blocked request to potentially unsafe URL: {par_endpoint}")
        return None, None

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
            logger.info(f"Received request_uri: {request_uri}")
            logger.info(f"Request URI expires in: {expires_in} seconds")
            return request_uri, expires_in
        else:
            logger.error("No request_uri found in PAR response")
            return None, None
            
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error occurred during PAR request: {e}")
        try:
            # Try to extract error details from response
            error_data = e.response.json()
            logger.error(f"Error details: {error_data}")
        except json.JSONDecodeError:
            logger.error("Could not parse error response as JSON")
        except Exception as ex:
            logger.error(f"Error extracting details from error response: {ex}")
        return None, None
    except httpx.RequestError as e:
        logger.error(f"Request error occurred during PAR request: {e}")
        return None, None
    except json.JSONDecodeError:
        logger.error("Failed to parse JSON response from PAR request")
        return None, None
