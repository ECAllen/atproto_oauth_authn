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
import os
import webbrowser
from dotenv import load_dotenv
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

    authn_url = atproto_oauth_authn.authn.get_authn_url(
        username=username, app_url=app_url
    )
    # Open the browser with the authorization URL
    webbrowser.open(authn_url)

    return True


if __name__ == "__main__":
    main()
