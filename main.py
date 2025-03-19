from authlib.jose import JsonWebKey
from dotenv import load_dotenv
import os
import json
import re
import httpx
import logging

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # Output to console
        logging.FileHandler("app.log"),  # Output to file
    ],
)
logger = logging.getLogger(__name__)
# AI! please replace print with logging.info
load_dotenv()

# jclient_secret_jwk_str = os.getenv("CLIENT_SECRET_JWK") or exit(
#     "Missing CLIENT_SECRET_JWK"
# )
#
# CLIENT_SECRET_JWK = JsonWebKey.import_key(client_secret_jwk_str)
# CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
# assert "d" not in CLIENT_PUB_JWK


DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z]$"
)

HANDLE_REGEX = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]"
    r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

DID_RE = re.compile(
    r"^did:"  # Required prefix
    r"[a-z]+:"  # method-name (lowercase only)
    r"[a-zA-Z0-9._%-]{1,2048}"  # method-specific-id with length limit
    r"(?<!:)$"  # Cannot end with colon
)


def resolve_identity(username: str):
    """
    Resolve a username (handle or DID) to a DID.

    Args:
        username: A string that could be a handle or DID

    Returns:
        The DID if resolution is successful, None otherwise
    """
    if re.match(HANDLE_REGEX, username):
        # Handle the case where username is a handle
        logging.debug(f"Username is a handle: {username}")
        url = f"https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle={username}"

        # Make HTTP request to resolve handle to DID
        try:
            response = httpx.get(url)
            response.raise_for_status()  # Raise exception for 4XX/5XX responses

            # Parse the JSON response
            data = response.json()

            # Extract the DID from the response
            did = data.get("did")
            if did:
                logging.debug(f"Resolved handle {username} to DID: {did}")
                return did
            else:
                logging.info(
                    f"Failed to resolve handle: {username} No DID found in response"
                )
                return None
        except httpx.HTTPStatusError as e:
            logging.info(f"HTTP error occurred while resolving handle: {e}")
            return None
        except httpx.RequestError as e:
            logging.info(f"Request error occurred while resolving handle: {e}")
            return None
        except json.JSONDecodeError:
            logging.info("Failed to parse JSON response from handle resolution")
            return None

    elif re.match(DID_RE, username):
        # Handle the case where username is already a DID
        print(f"Username is a DID: {username}")
        return username

    return None


# 1) get users handle

# Login can start with a handle, DID, or auth server URL. We are calling
# whatever the user supplied the "username".
username = "spacetimedonuts.bsky.social"
# username = "statb.statmeet.com"

# 2) retrieve the users DID
user_did = resolve_identity(username)
if user_did:
    print(f"Resolved username {username} to DID: {user_did}")
else:
    print(f"Failed to resolve username {username} to a DID")

#     pds_url = pds_endpoint(did_doc)
#     print(f"account PDS: {pds_url}")
#     authserver_url = resolve_pds_authserver(pds_url)
# elif username.startswith("https://") and is_safe_url(username):
#     # When starting with an auth server, we don't know about the account yet.
#     did, handle, pds_url = None, None, None
#     login_hint = None
#     # Check if this is a Resource Server (PDS) URL; otherwise assume it is authorization server
#     initial_url = username
#     try:
#         authserver_url = resolve_pds_authserver(initial_url)
#     except Exception:
#         authserver_url = initial_url
# else:
#     flash("Not a valid handle, DID, or auth server URL")
#     return render_template("login.html"), 400
