
"""AT Protocol OAuth authentication utilities.

This module provides functions for performing OAuth authentication flows
with AT Protocol services like Bluesky.
"""
import logging
import urllib.parse
from typing import Tuple, List, Dict, Any
import atproto_oauth_authn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # Output to console
        logging.FileHandler("app.log"),  # Output to file
    ],
)
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
        user_did = atproto_oauth_authn.resolve_identity(username)
    except Exception as e:
        logging.error("Failed to resolve username %s to a DID: %s", username, e)
        raise

    logging.info("Resolved username %s to DID: %s", username, user_did)

    # Retrieve the user DID document
    try:
        did_document = atproto_oauth_authn.retrieve_did_document(user_did)
    except Exception as e:
        logging.error("Failed to retrieve DID document for %s: %s", user_did, e)
        raise

    # Get the URL of the PDS server from the DID doc
    try:
        pds_url = atproto_oauth_authn.extract_pds_url(did_document)
    except Exception as e:
        logging.error("Failed to extract PDS URL from DID document: %s", e)
        raise

    return pds_url


def discover_auth_server(pds_url: str) -> Tuple[str, str, str]:
    """Discover authorization server from PDS metadata.
    
    Args:
        pds_url: The PDS server URL
        
    Returns:
        Tuple of (auth_endpoint, token_endpoint, par_endpoint)
        
    Raises:
        Various exceptions from the atproto_oauth_authn module if any step fails
    """
    # Get the PDS server metadata from the well-known endpoint
    try:
        pds_metadata = atproto_oauth_authn.get_pds_metadata(pds_url)
    except Exception as e:
        logging.error("Failed to retrieve PDS metadata: %s", e)
        raise

    # From the metadata extract the authorization server
    try:
        auth_servers = atproto_oauth_authn.extract_auth_server(pds_metadata)
    except Exception as e:
        logging.error("Failed to extract authorization server from metadata: %s", e)
        raise

    logging.debug("Authorization server URL: %s", auth_servers[0])

    # Get the metadata of the authorization server
    try:
        auth_metadata, auth_endpoint, token_endpoint, par_endpoint = (
            atproto_oauth_authn.get_auth_server_metadata(auth_servers)
        )
    except Exception as e:
        logging.error("Failed to retrieve auth server metadata: %s", e)
        raise

    logging.debug("Auth server metadata retrieved successfully")
    logging.debug("Auth Server Endpoints:")
    logging.debug("  Authorization: %s", auth_endpoint)
    logging.debug("  Token: %s", token_endpoint)
    logging.debug("  PAR: %s", par_endpoint or 'Not available')
    logging.debug("  metadata: %s", auth_metadata or 'Not available')

    return auth_endpoint, token_endpoint, par_endpoint


def generate_oauth_params() -> Tuple[str, str, str]:
    """Generate OAuth state, code verifier, and code challenge.
    
    Returns:
        Tuple of (oauth_state, code_verifier, code_challenge)
        
    Raises:
        Various exceptions from the atproto_oauth_authn module if generation fails
    """
    # Generate a state parameter for OAuth request
    try:
        oauth_state = atproto_oauth_authn.generate_oauth_state()
    except Exception as e:
        logging.error("Failed to generate the oauth request: %s", e)
        raise

    logging.debug("Generated OAuth state: %s... (truncated)", oauth_state[:10])

    # Generate a code_verifier for PKCE
    try:
        code_verifier = atproto_oauth_authn.generate_code_verifier(48)
    except Exception as e:
        logging.error("Failed to generate code verifier: %s", e)
        raise

    logging.debug("Generated code_verifier: %s... (truncated)", code_verifier[:10])

    # Generate a code_challenge from the code_verifier
    try:
        code_challenge = atproto_oauth_authn.generate_code_challenge(code_verifier)
    except Exception as e:
        logging.error("Failed to generate code challenge: %s", e)
        raise

    logging.debug("Generated code_challenge: %s... (truncated)", code_challenge[:10])

    return oauth_state, code_verifier, code_challenge


def build_client_config(app_url: str) -> Tuple[str, str]:
    """Build client_id and redirect_uri from app_url.
    
    Args:
        app_url: The base URL of the application
        
    Returns:
        Tuple of (client_id, redirect_uri)
    """
    client_id = f"https://{app_url}/oauth/client-metadata.json"
    redirect_uri = f"https://{app_url}/oauth/callback"

    # Special case for development/testing with localhost
    if app_url in ['localhost','127.0.0.1']:
        client_id = 'http://localhost/oauth/client-metadata.json'
        redirect_uri = 'http://127.0.01/oauth/callback'

    return client_id, redirect_uri


def perform_par_request(par_endpoint: str, code_challenge: str, oauth_state: str, 
                       username: str, client_id: str, redirect_uri: str, app_url: str) -> Tuple[str, int]:
    """Send PAR request and return request_uri and expires_in.
    
    Args:
        par_endpoint: The PAR endpoint URL
        code_challenge: The PKCE code challenge
        oauth_state: The OAuth state parameter
        username: The username for login hint
        client_id: The OAuth client ID
        redirect_uri: The OAuth redirect URI
        app_url: The app URL for logging
        
    Returns:
        Tuple of (request_uri, expires_in)
        
    Raises:
        Various exceptions from the atproto_oauth_authn module if PAR request fails
    """
    logging.info("""app URL: %s
        PAR request parameters: 
        par_endpoint=%s,
        code_challenge=%s,
        state=%s,
        login_hint=%s,
        client_id=%s,
        redirect_uri=%s""", 
        app_url, par_endpoint, code_challenge, oauth_state, username, client_id, redirect_uri)

    # Use the username as login_hint if available
    try:
        request_uri, expires_in = atproto_oauth_authn.send_par_request(
            par_endpoint=par_endpoint,
            code_challenge=code_challenge,
            state=oauth_state,
            login_hint=username,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )
    except Exception as e:
        logging.error("Failed to send PAR request: %s", e)
        raise

    logging.debug("PAR request successful!")
    logging.debug("Request URI: %s", request_uri)
    logging.debug("Expires in: %s seconds", expires_in)

    return request_uri, expires_in


def get_authn_url(username: str, app_url: str) -> str:
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
    pds_url = resolve_user_did(username)
    auth_endpoint, token_endpoint, par_endpoint = discover_auth_server(pds_url)
    
    # Generate OAuth parameters
    oauth_state, code_verifier, code_challenge = generate_oauth_params()
    
    # Build client configuration
    client_id, redirect_uri = build_client_config(app_url)
    
    # Perform PAR request
    request_uri, expires_in = perform_par_request(
        par_endpoint, code_challenge, oauth_state,
        username, client_id, redirect_uri, app_url
    )
    
    # Build final auth URL
    qparam = urllib.parse.urlencode(
        {"client_id": client_id, "request_uri": request_uri}
    )
    auth_url = f"{auth_endpoint}?{qparam}"
    assert atproto_oauth_authn.security.is_safe_url(auth_url)

    logging.debug("\nAuthorization URL:")
    logging.debug("%s?client_id=%s&request_uri=%s", auth_endpoint, client_id, request_uri)
    logging.debug(auth_url)

    return auth_url
