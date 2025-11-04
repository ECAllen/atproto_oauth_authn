"""AT Protocol OAuth authentication utilities.

This module provides functions for performing OAuth authentication flows
with AT Protocol services like Bluesky.
"""

import logging
from typing import Tuple, Any, List

from validators import ValidationError
from joserfc.jwk import ECKey
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from .security import valid_url
from .identity import resolve_identity
from .did import retrieve_did_document, extract_pds_url
from .oauth import (
    authserver_dpop_jwt,
    client_assertion_jwt,
    send_par_request,
    PARRequestContext,
    get_pds_metadata,
    extract_auth_server,
    get_pds_auth_server_metadata,
    build_client_config,
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
        user_did = resolve_identity(username)
    except Exception as e:
        logger.error("Failed to resolve username %s to a DID: %s", username, e)
        raise

    logger.info("Resolved username %s to DID: %s", username, user_did)

    # Retrieve the user DID document
    try:
        did_document = retrieve_did_document(user_did)
    except Exception as e:
        logger.error("Failed to retrieve DID document for %s: %s", user_did, e)
        raise

    # Get the URL of the PDS server from the DID doc
    try:
        pds_url = extract_pds_url(did_document)
    except Exception as e:
        logger.error("Failed to extract PDS URL from DID document: %s", e)
        raise

    return pds_url, user_did


# TODO re-org to atproto specific file
def get_pds_auth_servers(pds_url: str) -> List:
    try:
        valid_url(pds_url)
    except Exception as e:
        logger.error(f"The PDS URL failed vaildation {e}")
        raise ValidationError from e

    # Get the PDS server metadata from the well-known endpoint
    try:
        pds_metadata = get_pds_metadata(pds_url)
    except Exception as e:
        logger.error("Failed to retrieve PDS metadata: %s", e)
        raise

    # From the metadata extract the authorization server
    try:
        auth_servers = extract_auth_server(pds_metadata)
    except Exception as e:
        logger.error("Failed to extract authorization server from metadata: %s", e)
        raise

    return auth_servers


def get_authn_url(
    username: str,
    app_url: str,
    dpop_private_jwk: ECKey | None = None,
    client_secret_jwk: ECKey | None = None,
) -> Tuple[str, str, str, Any, dict]:
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

    auth_server_metadata = get_pds_auth_server_metadata(auth_servers)
    par_endpoint = auth_server_metadata["pushed_authorization_request_endpoint"]
    revocation_endpoint = auth_server_metadata["revocation_endpoint"]

    # Generate OAuth parameters
    code_verifier = generate_token(48)
    state = generate_token()
    code_challenge = create_s256_code_challenge(code_verifier)

    client_id, redirect_uri = build_client_config(app_url)

    client_assertion = client_assertion_jwt(client_id, auth_endpoint, client_secret_jwk)
    logging.info(
        "Generated client assertion JWT for client_assertion: %s", client_assertion
    )

    dpop_proof = authserver_dpop_jwt(
        method="POST", url=par_endpoint, dpop_private_jwk=dpop_private_jwk
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
        dpop_private_jwk=dpop_private_jwk,
    )

    dpop_nonce, response = send_par_request(
        context=par_context,
    )

    return (
        code_verifier,
        state,
        dpop_nonce,
        response.json(),
        auth_server_metadata,
        user_did,
        pds_url,
        client_id,
        revocation_endpoint,
    )
