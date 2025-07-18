"""
# AI! please make a docstring
"""
from dotenv import load_dotenv
import logging
import os
import sys
import webbrowser
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

    logging.info(f"Starting OAuth flow for username: {username}")

    authn_url = atproto_oauth_authn.authn.get_authn_url(
        username=username, app_url=app_url
    )
    # Open the browser with the authorization URL
    webbrowser.open(authn_url)

    return True


if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)
