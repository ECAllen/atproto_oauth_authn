from authlib.jose import JsonWebKey
from dotenv import load_dotenv
import os
import json
import re
import httpx

load_dotenv()

client_secret_jwk_str = os.getenv("CLIENT_SECRET_JWK") or exit(
    "Missing CLIENT_SECRET_JWK"
)

CLIENT_SECRET_JWK = JsonWebKey.import_key(client_secret_jwk_str)
CLIENT_PUB_JWK = json.loads(CLIENT_SECRET_JWK.as_json(is_private=False))
assert "d" not in CLIENT_PUB_JWK


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

# 1) get users handle

# Login can start with a handle, DID, or auth server URL. We are calling
# whatever the user supplied the "username".
username = "blah"


# 2) retrieve the users DID

if re.match(HANDLE_REGEX, username):
    # Handle the case where username is a handle
    print(f"Username is a handle: {username}")
    # AI! pleae use httpx to amake a request to the url and then get the did from the josn response
    url = (
        f"https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle={username}"
    )

elif re.match(DID_RE, username):
    # Handle the case where username is already a DID
    print(f"Username is a DID: {username}")

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
