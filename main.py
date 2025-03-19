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

        # Extract domain and TLD from the handle
        parts = username.split(".")
        if len(parts) >= 2:
            domain_tld = ".".join(parts[1:])
            logging.info(f"Extracted domain and TLD: {domain_tld}")
        else:
            logging.warning(f"Could not extract domain from handle: {username}")
            return None

        url = f"https://{domain_tld}/xrpc/com.atproto.identity.resolveHandle?handle={username}"

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
    return None


def get_did_document(did):
    """
    Retrieve the DID document for a given DID.

    Args:
        did: The DID to retrieve the document for

    Returns:
        The DID document as a dictionary if successful, None otherwise
    """
    url = f"https://plc.directory/{did}"

    try:
        # Make HTTP request to retrieve the DID document
        response = httpx.get(url)
        response.raise_for_status()

        # Parse the JSON response
        did_document = response.json()
        logging.info(f"Retrieved DID document for {did}")

        # Extract the PDS URL from the DID document
        if "service" in did_document and len(did_document["service"]) > 0:
            pds_url = did_document["service"][0].get("serviceEndpoint")
            if pds_url:
                logging.info(f"User's PDS URL: {pds_url}")
                return did_document, pds_url

        logging.warning(f"Could not find PDS URL in DID document for {did}")
        return did_document, None
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logging.warning(f"DID not found: {did}")
            return None, None
        elif e.response.status_code == 410:
            logging.warning(f"DID not available (tombstone) 🪦: {did}")
            return None, None
        else:
            logging.error(f"HTTP error occurred while retrieving DID document: {e}")
            return None, None
    except httpx.RequestError as e:
        logging.error(f"Request error occurred while retrieving DID document: {e}")
        return None, None
    except json.JSONDecodeError:
        logging.error("Failed to parse JSON response from DID document retrieval")
        return None, None


# 1) get users handle

# Login can start with a handle, DID, or auth server URL. We are calling
# whatever the user supplied the "username".
username = "spacetimedonuts.bsky.social"

# 2) retrieve the users DID
user_did = resolve_identity(username)
if user_did:
    logging.info(f"Resolved username {username} to DID: {user_did}")
else:
    logging.info(f"Failed to resolve username {username} to a DID")


# 3) retrieve the user DID document
# If we have a user DID, retrieve the DID document
if user_did:
    did_document, pds_url = get_did_document(user_did)
    if did_document:
        logging.info(f"Successfully retrieved DID document for {user_did}")
    else:
        logging.error(f"Failed to retrieve DID document for {user_did}")
    print(did_document)

# 4) get the URL of the PDS server from the DID doc

print(pds_url)

# 5) get the PDS server metadata, example:  <https://velvetfoot.us-east.host.bsky.network/.well-known/oauth-protected-resource>.
# AI! please GET the metadata from the PDS server using the pds_url and /.well-known/oauth-protected-resource
