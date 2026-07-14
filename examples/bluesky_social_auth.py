"""
Bluesky Social OAuth Authentication Example

This example demonstrates how to use the atproto-oauth-authn library to initiate
an OAuth authentication flow for Bluesky Social (or other AT Protocol services).

The script:
1. Loads environment variables for USERNAME and APP_URL
2. Generates an OAuth authentication URL using the atproto_oauth_authn library
3. Opens the authentication URL in the user's default web browser

Required environment variables:
- USERNAME: The Bluesky handle or DID to authenticate (e.g., "user.bsky.social")
- APP_URL: Your application's URL for OAuth callbacks
- CLIENT_SECRET_JWK: The client's secret signing key (see generate_jwk.py)

Usage:
    python examples/bluesky_social_auth.py

The script will log detailed information about the OAuth flow process and
automatically open your browser to complete the authentication.
"""

import json
import logging
import os
import sys
import time
import urllib.parse
import webbrowser

from dotenv import load_dotenv
from joserfc.jwk import ECKey

import atproto_oauth_authn


# Set up logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # Output to console
        logging.FileHandler("app.log"),  # Output to file
    ],
)
logger = logging.getLogger(__name__)


def main() -> bool:  # pylint: disable=too-many-locals
    """
    Main function to initiate Bluesky OAuth authentication flow.

    Loads environment variables, validates required parameters, and opens
    the OAuth authentication URL in the user's default web browser.

    Returns:
        bool: True if the OAuth flow was successfully initiated, False if
              required environment variables are missing or other errors occur.

    Environment Variables Required:
        USERNAME: Bluesky handle or DID to authenticate
        APP_URL: Application URL for OAuth callbacks
        CLIENT_SECRET_JWK: The client's secret signing key
    """
    load_dotenv()

    # This is a "confidential" OAuth client, meaning it has access
    # to a persistent secret signing key.
    env_key = os.getenv("CLIENT_SECRET_JWK")
    if env_key is None:
        logger.error(
            "CLIENT_SECRET_JWK not set, please generate with generate_jwk.py "
            "and add into .env"
        )
        sys.exit(1)

    client_secret_jwk = ECKey.import_key(json.loads(env_key))

    username = os.getenv("USERNAME")
    if not username:
        logger.error("Missing USERNAME environment variable")
        print("Error: Missing USERNAME environment variable")
        return False

    app_url = os.getenv("APP_URL")
    if not app_url:
        logger.error("Missing APP_URL environment variable")
        print("Error: Missing APP_URL environment variable")
        return False

    logger.info("Starting OAuth flow for username: %s", username)

    # Generate DPoP private signing key for early binding during the PAR request.
    now = int(time.time())
    parameters = {"kid": f"dpop-par-request-{now}"}
    dpop_private_jwk = ECKey.generate_key("P-256", parameters=parameters)

    # A real application would persist code_verifier, state, dpop_nonce,
    # user_did, pds_url, and revocation_endpoint in the user's session for
    # the callback and token request steps.
    (
        _code_verifier,
        _state,
        _dpop_nonce,
        response,
        auth_server_metadata,
        _user_did,
        _pds_url,
        client_id,
        _revocation_endpoint,
    ) = atproto_oauth_authn.get_authn_url(
        username,
        app_url,
        client_secret_jwk=client_secret_jwk,
        dpop_private_jwk=dpop_private_jwk,
    )

    request_uri = response["request_uri"]
    auth_endpoint = auth_server_metadata["authorization_endpoint"]

    # Build final auth URL
    qparam = urllib.parse.urlencode(
        {"client_id": client_id, "request_uri": request_uri}
    )
    authn_url = f"{auth_endpoint}?{qparam}"

    # Raises SecurityError if the URL fails SSRF checks
    atproto_oauth_authn.valid_url(authn_url)

    # Open the browser with the authorization URL
    webbrowser.open(authn_url)

    return True


if __name__ == "__main__":
    main()
