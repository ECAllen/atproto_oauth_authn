"""AT Protocol OAuth authentication utilities.

This module provides functions for performing OAuth authentication flows
with AT Protocol services like Bluesky.
"""

import logging
import urllib.parse
import time
import json
from typing import Tuple, Any, List, Dict
from dataclasses import dataclass, asdict
from .security import valid_url
from .identity import resolve_identity
from .did import retrieve_did_document, extract_pds_url
from .oauth import (
    generate_oauth_state,
    generate_code_challenge,
    authserver_dpop_jwt,
    client_assertion_jwt,
    send_par_request,
    PARRequestContext,
    get_pds_metadata, 
    extract_auth_server, 
    get_pds_auth_server_metadata,
    build_client_config,
)
from validators import ValidationError
from .exceptions import InvalidParameterError
from joserfc import jwt
from joserfc.jwk import ECKey
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     handlers=[
#         logging.StreamHandler(),  # Output to console
#         logging.FileHandler("app.log"),  # Output to file
#     ],
# )

logger = logging.getLogger(__name__)


def resolve_user_did(username: str) -> str:
    """Resolve username to DID and extract PDS URL.

    Args:
        username: The AT Protocol username/handle to resolve

    Returns:
        The PDS URL for the user

    Raises:
        Various exceptions from the atproto_oauth_authn module if any step fails
    """
    # Resolve the users DID
    try:
        user_did = resolve_identity(username)
    except Exception as e:
        logging.error("Failed to resolve username %s to a DID: %s", username, e)
        raise

    logging.info("Resolved username %s to DID: %s", username, user_did)

    # Retrieve the user DID document
    try:
        did_document = retrieve_did_document(user_did)
    except Exception as e:
        logging.error("Failed to retrieve DID document for %s: %s", user_did, e)
        raise

    # Get the URL of the PDS server from the DID doc
    try:
        pds_url = extract_pds_url(did_document)
    except Exception as e:
        logging.error("Failed to extract PDS URL from DID document: %s", e)
        raise

    return pds_url, user_did

#TODO re-org to atproto specific file 
def get_pds_auth_servers(pds_url: str) -> List:
    try:
        valid_url(pds_url)
    except Exception as e:
        logging.error("The PDS URL failed vaildation {e}")
        raise ValidationError

    # Get the PDS server metadata from the well-known endpoint
    try:
        pds_metadata = get_pds_metadata(pds_url)
    except Exception as e:
        logging.error("Failed to retrieve PDS metadata: %s", e)
        raise 

    # From the metadata extract the authorization server
    try:
        auth_servers = extract_auth_server(pds_metadata)
    except Exception as e:
        logging.error("Failed to extract authorization server from metadata: %s", e)
        raise   

    return auth_servers


# def get_pds_auth_server_metadata(pds_auth_server_urls: List) -> Dict:
# 
#     logging.debug("Authorization server URL: %s", pds_auth_server_urls)
# 
#     # Get the metadata of the authorization server
# 
#     auth_metadata = get_auth_server_metadata(auth_servers)
# 
#     logging.debug("Auth server metadata retrieved successfully")
#     logging.debug("Auth Server Endpoints:")
#     logging.debug("  Authorization: %s", auth_endpoint)
#     logging.debug("  Token: %s", token_endpoint)
#     logging.debug("  PAR: %s", par_endpoint or "Not available")
#     logging.debug("  metadata: %s", auth_metadata or "Not available")
# 
#     return auth_metadata


# def generate_oauth_params() -> Tuple[str, str, str]:
#     """Generate OAuth state, code verifier, and code challenge.

#     Returns:
#         Tuple of (oauth_state, code_verifier, code_challenge)

#     Raises:
#         Various exceptions from the atproto_oauth_authn module if generation fails
#     """
#     # Generate a state parameter for OAuth request
#     try:
#         oauth_state = generate_oauth_state()
#     except Exception as e:
#         logging.error("Failed to generate the oauth request: %s", e)
#         raise

#     logging.debug("Generated OAuth state: %s... (truncated)", oauth_state[:10])

#     # Generate a code_verifier for PKCE
#     try:
        
#     except Exception as e:
#         logging.error("Failed to generate code verifier: %s", e)
#         raise

#     logging.debug("Generated code_verifier: %s... (truncated)", code_verifier[:10])

#     # Generate a code_challenge from the code_verifier
#     try:
#         code_challenge = generate_code_challenge(code_verifier)
#     except Exception as e:
#         logging.error("Failed to generate code challenge: %s", e)
#         raise

#     logging.debug("Generated code_challenge: %s... (truncated)", code_challenge[:10])

#     return oauth_state, code_verifier, code_challenge


# def build_client_config(app_url: str) -> Tuple[str, str]:
#     """Build client_id and redirect_uri from app_url.
# 
#     Args:
#         app_url: The base URL of the application
# 
#     Returns:
#         Tuple of (client_id, redirect_uri)
#     """
#     client_id = f"https://{app_url}/oauth/client-metadata.json"
#     redirect_uri = f"http://{app_url}/oauth/callback"
# 
#     # Special case for development/testing with localhost
#     if app_url in ["localhost", "127.0.0.1"]:
#         client_id = "http://localhost/oauth/client-metadata.json"
#         redirect_uri = "http://127.0.01/oauth/callback"
# 
#     return client_id, redirect_uri


def get_authn_url(username: str, app_url: str,  dpop_private_jwk: ECKey| None = None, client_secret_jwk: ECKey | None = None) -> Tuple[str,str,str,Any,dict]:
    """Generate an OAuth authorization URL for AT Protocol authentication.

    This function orchestrates the complete OAuth flow setup by calling
    specialized helper functions for each step of the process.

    Args:
        username: The AT Protocol username/handle to authenticate
        app_url: The base URL of the application (used for client_id and redirect_uri)

    Returns:
        The authorization URL that the user should be redirected to

    Raises:
        Various exceptions from the atproto_oauth_authn module if any step fails
    """
    # Resolve user and discover servers
    pds_url, user_did = resolve_user_did(username)
    
    auth_servers = get_pds_auth_servers(pds_url)
    auth_endpoint = auth_servers[0]

    # auth_endpoint = auth_server_metadata["authorization_endpoint"]
    auth_server_metadata = get_pds_auth_server_metadata(auth_servers)
    # auth_endpoint = auth_server_metadata["authorization_servers"][0]
    par_endpoint = auth_server_metadata["pushed_authorization_request_endpoint"]
    
    # Generate OAuth parameters
    code_verifier = generate_token(48)
    state = generate_token()
    code_challenge = create_s256_code_challenge(code_verifier)

    # Build client configuration
    client_id, redirect_uri = build_client_config(app_url)

    # Generate the client assertion
    client_assertion = client_assertion_jwt(
        client_id, auth_endpoint, client_secret_jwk
    )

    dpop_proof = authserver_dpop_jwt(
        method="POST", 
        url=par_endpoint,
        dpop_private_jwk=dpop_private_jwk
    )

    # Perform PAR request
    par_context = PARRequestContext(
        response_type="code",
        code_challenge=code_challenge,
        code_challenge_method="S256",
        state=state,
        login_hint=username,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope="atproto transition:generic",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion=client_assertion,
        par_endpoint=par_endpoint,
        app_url=app_url,
        dpop_proof=dpop_proof,
        dpop_private_jwk=dpop_private_jwk
        )

    dpop_nonce, response = send_par_request(
        context=par_context,
        )

    return code_verifier, state, dpop_nonce, response.json(), auth_server_metadata, user_did, pds_url, client_id
