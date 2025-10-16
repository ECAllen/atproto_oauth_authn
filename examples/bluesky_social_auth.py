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

Usage:
    python examples/bluesky_social_auth.py

The script will log detailed information about the OAuth flow process and
automatically open your browser to complete the authentication.
"""

import logging
import time
import os
import sys
import webbrowser
import json
from dotenv import load_dotenv
import atproto_oauth_authn
from joserfc.jwk import ECKey
import urllib.parse


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


def main() -> bool:
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
    """
    load_dotenv()

    # This is a "confidential" OAuth client, meaning it has access 
    # to a persistent secret signing key. parse that key as a global.
    env_key = os.getenv("CLIENT_SECRET_JWK")
    if env_key is None:
        logging.error("CLIENT_SECRET_JWK not set, please generate with the generate_jwk.py and add into .env")
        sys.exit(1)

    jwk_key = json.loads(env_key)
    CLIENT_SECRET_JWK = ECKey.import_key(jwk_key)

    # Create the public key dict
    public_key = CLIENT_SECRET_JWK.as_dict(private=False)

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

    logging.info("Starting OAuth flow for username: %s", username)

    # Generate DPoP private signing key for early binding during the PAR request.
    now = int(time.time())
    parameters = {"kid": f"dpop-par-request-{now}"}
    dpop_private_jwk  = ECKey.generate_key(
        'P-256', parameters=parameters)

    scope = "atproto transition:generic"

    code_verifier, state, dpop_nonce, response, auth_server_metadata, user_did, pds_url, client_id = atproto_oauth_authn.get_authn_url(username, app_url, client_secret_jwk=CLIENT_SECRET_JWK, dpop_private_jwk=dpop_private_jwk)

    request_uri = response['request_uri']
    auth_endpoint = auth_server_metadata["authorization_endpoint"]

    # Build final auth URL
    qparam = urllib.parse.urlencode(
        {"client_id": client_id, "request_uri": request_uri}
    )
    authn_url = f"{auth_endpoint}?{qparam}"

    assert atproto_oauth_authn.security.is_safe_url(authn_url)

    # Open the browser with the authorization URL
    webbrowser.open(authn_url)

    return True


if __name__ == "__main__":
    main()
