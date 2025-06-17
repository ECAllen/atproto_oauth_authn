import logging
import urllib.parse
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


def get_authn_url(username: str, app_url: str) -> str:
    # 2) retrieve the users DID
    try:
        user_did = atproto_oauth_authn.resolve_identity(username)
    except Exception as e:
        logging.error(f"Failed to resolve username {username} to a DID: {e}")
        raise

    logging.info(f"Resolved username {username} to DID: {user_did}")

    # 3) retrieve the user DID document
    try:
        did_document = atproto_oauth_authn.retrieve_did_document(user_did)
    except Exception as e:
        logging.error(f"Failed to retrieve DID document for {user_did}: {e}")
        raise

    # 4) get the URL of the PDS server from the DID doc
    try:
        pds_url = atproto_oauth_authn.extract_pds_url(did_document)
    except Exception as e:
        logging.error(f"Failed to extract PDS URL from DID document: {e}")
        raise

    # 5) get the PDS server metadata from the well-known endpoint
    try:
        pds_metadata = atproto_oauth_authn.get_pds_metadata(pds_url)
    except Exception as e:
        logging.error(f"Failed to retrieve PDS metadata: {e}")
        raise

    # 6) from the metadata extract the authorization server
    try:
        auth_servers = atproto_oauth_authn.extract_auth_server(pds_metadata)
    except Exception as e:
        logging.error(f"Failed to extract authorization server from metadata: {e}")
        raise

    logging.debug(f"Authorization server URL: {auth_servers[0]}")

    # 7) get the metadata of the authorization server
    try:
        auth_metadata, auth_endpoint, token_endpoint, par_endpoint = (
            atproto_oauth_authn.get_auth_server_metadata(auth_servers)
        )
    except Exception as e:
        logging.error(f"Failed to retrieve auth server metadata: {e}")
        raise

    logging.debug("Auth server metadata retrieved successfully")
    logging.debug("Auth Server Endpoints:")
    logging.debug(f"  Authorization: {auth_endpoint}")
    logging.debug(f"  Token: {token_endpoint}")
    logging.debug(f"  PAR: {par_endpoint or 'Not available'}")
    logging.debug(f"  metadata: {auth_metadata or 'Not available'}")

    # Generate a state parameter for OAuth request
    try:
        oauth_state = atproto_oauth_authn.generate_oauth_state()
    except Exception as e:
        logging.error(f"Failed to generate the oauth request: {e}")
        raise

    logging.debug(f"Generated OAuth state: {oauth_state[:10]}... (truncated)")

    # Generate a code_verifier for PKCE
    # TODO very param for code_verifier length
    try:
        code_verifier = atproto_oauth_authn.generate_code_verifier(48)
    except Exception as e:
        logging.error(f"Failed to generate code verifier: {e}")
        raise

    logging.debug(f"Generated code_verifier: {code_verifier[:10]}... (truncated)")

    # Generate a code_challenge from the code_verifier
    try:
        code_challenge = atproto_oauth_authn.generate_code_challenge(code_verifier)
    except Exception as e:
        logging.error(f"Failed to generate code challenge: {e}")
        raise

    logging.debug(f"Generated code_challenge: {code_challenge[:10]}... (truncated)")

    client_id = f"https://{app_url}/oauth/client-metadata.json"
    redirect_uri = f"https://{app_url}/oauth/callback"

    # Special case for development/testing with localhost
    if app_url == 'localhost' or app_url == '127.0.0.1':
        client_id = 'http://localhost/'
        redirect_uri = 'http://127.0.01/oauth/callback'

    logging.info(f"""PAR request parameters: 
        par_endpoint={par_endpoint}, 
        code_challenge={code_challenge},
        state={oauth_state},
        login_hint={username},
        client_id={client_id},
        redirect_uri={redirect_uri}""")

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
        logging.error(f"Failed to send PAR request: {e}")
        raise

    logging.debug("PAR request successful!")
    logging.debug(f"Request URI: {request_uri}")
    logging.debug(f"Expires in: {expires_in} seconds")

    qparam = urllib.parse.urlencode(
        {"client_id": client_id, "request_uri": request_uri}
    )
    auth_url = f"{auth_endpoint}?{qparam}"
    assert atproto_oauth_authn.security.is_safe_url(auth_url)

    logging.debug("\nAuthorization URL:")
    logging.debug(f"{auth_endpoint}?client_id={client_id}&request_uri={request_uri}")
    logging.debug(auth_url)

    return auth_url


# DOMAIN_RE = re.compile(
#     r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z]$"
# )
#
# HANDLE_REGEX = re.compile(
#     r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
#     r"+[a-zA-Z]"
#     r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
# )
#
# DID_RE = re.compile(
#     r"^did:"  # Required prefix
#     r"[a-z]+:"  # method-name (lowercase only)
#     r"[a-zA-Z0-9._%-]{1,2048}"  # method-specific-id with length limit
#     r"(?<!:)$"  # Cannot end with colon
# )
#
#
# def resolve_identity(username: str) -> str | None:
#     """
#     Resolve a username (handle or DID) to a DID.
#
#     Args:
#         username: A string that could be a handle or DID
#
#     Returns:
#         The DID if resolution is successful, None otherwise
#     """
#     if re.match(HANDLE_REGEX, username):
#         # Handle the case where username is a handle
#         logging.debug(f"Username is a handle: {username}")
#
#         # Extract domain and TLD from the handle
#         parts = username.split(".")
#         if len(parts) >= 2:
#             domain_tld = ".".join(parts[1:])
#             logging.info(f"Extracted domain and TLD: {domain_tld}")
#         else:
#             logging.warning(f"Could not extract domain from handle: {username}")
#             return None
#
#         url = f"https://{domain_tld}/xrpc/com.atproto.identity.resolveHandle?handle={username}"
#
#         # Check URL for SSRF vulnerabilities
#         if not is_safe_url(url):
#             logging.error(
#                 f"SSRF protection: Blocked request to potentially unsafe URL: {url}"
#             )
#             return None
#
#         # Make HTTP request to resolve handle to DID
#         try:
#             response = httpx.get(url)
#             response.raise_for_status()  # Raise exception for 4XX/5XX responses
#
#             # Parse the JSON response
#             data = response.json()
#
#             # Extract the DID from the response
#             did = data.get("did")
#             if did:
#                 logging.debug(f"Resolved handle {username} to DID: {did}")
#                 return did
#             else:
#                 logging.info(
#                     f"Failed to resolve handle: {username} No DID found in response"
#                 )
#                 return None
#         except httpx.HTTPStatusError as e:
#             logging.info(f"HTTP error occurred while resolving handle: {e}")
#             return None
#         except httpx.RequestError as e:
#             logging.info(f"Request error occurred while resolving handle: {e}")
#             return None
#         except json.JSONDecodeError:
#             logging.info("Failed to parse JSON response from handle resolution")
#             return None
#     elif re.match(DID_RE, username):
#         # If the username is already a DID, return it directly
#         logging.info(f"Username is already a DID: {username}")
#         return username
#     else:
#         logging.warning(f"Username '{username}' is neither a valid handle nor a DID")
#         return None
#
#
# def get_did_document(did: str) -> tuple[dict | None, str | None]:
#     """
#     Retrieve the DID document for a given DID.
#
#     Args:
#         did: The DID to retrieve the document for
#
#     Returns:
#         The DID document as a dictionary if successful, None otherwise
#     """
#     url = f"https://plc.directory/{did}"
#
#     # Check URL for SSRF vulnerabilities
#     if not is_safe_url(url):
#         logging.error(
#             f"SSRF protection: Blocked request to potentially unsafe URL: {url}"
#         )
#         return None, None
#
#     try:
#         # Make HTTP request to retrieve the DID document
#         response = httpx.get(url)
#         response.raise_for_status()
#
#         # Parse the JSON response
#         did_document = response.json()
#         logging.info(f"Retrieved DID document for {did}")
#
#         # Extract the PDS URL from the DID document
#         if "service" in did_document and len(did_document["service"]) > 0:
#             pds_url = did_document["service"][0].get("serviceEndpoint")
#             if pds_url:
#                 logging.info(f"User's PDS URL: {pds_url}")
#                 return did_document, pds_url
#
#         logging.warning(f"Could not find PDS URL in DID document for {did}")
#         return did_document, None
#     except httpx.HTTPStatusError as e:
#         if e.response.status_code == 404:
#             logging.warning(f"DID not found: {did}")
#             return None, None
#         elif e.response.status_code == 410:
#             logging.warning(f"DID not available (tombstone) 🪦: {did}")
#             return None, None
#         else:
#             logging.error(f"HTTP error occurred while retrieving DID document: {e}")
#             return None, None
#     except httpx.RequestError as e:
#         logging.error(f"Request error occurred while retrieving DID document: {e}")
#         return None, None
#     except json.JSONDecodeError:
#         logging.error("Failed to parse JSON response from DID document retrieval")
#         return None, None
#
#
# def get_pds_metadata(pds_url: str) -> dict | None:
#     """
#     Retrieve the OAuth protected resource metadata from the PDS server.
#
#     Args:
#         pds_url: The URL of the PDS server
#
#     Returns:
#         The metadata as a dictionary if successful, None otherwise
#     """
#     if not pds_url:
#         logging.error("Cannot get PDS metadata: PDS URL is None")
#         return None
#
#     metadata_url = f"{pds_url.rstrip('/')}/.well-known/oauth-protected-resource"
#     logging.info(f"Fetching PDS metadata from: {metadata_url}")
#
#     # Check URL for SSRF vulnerabilities
#     if not is_safe_url(metadata_url):
#         logging.error(
#             f"SSRF protection: Blocked request to potentially unsafe URL: {metadata_url}"
#         )
#         return None
#
#     try:
#         response = httpx.get(metadata_url)
#         response.raise_for_status()
#
#         metadata = response.json()
#         logging.info(f"Successfully retrieved PDS metadata")
#         return metadata
#     except httpx.HTTPStatusError as e:
#         logging.error(f"HTTP error occurred while retrieving PDS metadata: {e}")
#         return None
#     except httpx.RequestError as e:
#         logging.error(f"Request error occurred while retrieving PDS metadata: {e}")
#         return None
#     except json.JSONDecodeError:
#         logging.error("Failed to parse JSON response from PDS metadata retrieval")
#         return None
#
#
# def is_safe_url(url: str) -> bool:
#     """
#     Validate if a URL is safe to make a request to.
#
#     Implements SSRF protections by:
#     - Ensuring HTTPS protocol
#     - Checking for private IP ranges or localhost
#     - Validating against known AT Protocol domains
#
#     Args:
#         url: The URL to validate
#
#     Returns:
#         True if the URL is considered safe, False otherwise
#     """
#     try:
#         parsed = urllib.parse.urlparse(url)
#
#         # Ensure HTTPS protocol
#         if parsed.scheme != "https":
#             logging.warning(f"SSRF protection: Rejected non-HTTPS URL: {url}")
#             return False
#
#         # Check for private IP ranges or localhost
#         hostname = parsed.netloc.split(":")[0]
#         try:
#             ip = ipaddress.ip_address(hostname)
#             if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified:
#                 logging.warning(
#                     f"SSRF protection: Rejected URL with private/reserved IP: {url}"
#                 )
#                 return False
#         except ValueError:
#             # Not an IP address, continue with hostname checks
#             pass
#
#         # Reject localhost and common internal hostnames
#         if (
#             hostname == "localhost"
#             or hostname.endswith(".local")
#             or hostname.endswith(".internal")
#         ):
#             logging.warning(f"SSRF protection: Rejected internal hostname: {url}")
#             return False
#
#         # Check for numeric IP in hostname to catch IP literals like 0177.0.0.1
#         if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
#             try:
#                 ip = ipaddress.ip_address(hostname)
#                 if (
#                     ip.is_private
#                     or ip.is_loopback
#                     or ip.is_reserved
#                     or ip.is_unspecified
#                 ):
#                     logging.warning(
#                         f"SSRF protection: Rejected numeric IP hostname: {url}"
#                     )
#                     return False
#             except ValueError:
#                 logging.warning(
#                     f"SSRF protection: Rejected unusual numeric hostname: {url}"
#                 )
#                 return False
#
#         # Whitelist of known AT Protocol domains
#         known_at_protocol_domains = {
#             # Official Bluesky domains
#             "bsky.social",
#             "bsky.app",
#             "bsky.network",
#             # PLC directory
#             "plc.directory",
#             # Common PDS providers
#             "blueskyweb.xyz",
#             "staging.bsky.dev",
#             # Common third-party PDS providers
#             "pds.public.url",
#             "atproto.com",
#             # Add more known domains as needed
#         }
#
#         # Check if the hostname is a subdomain of a known AT Protocol domain
#         domain_parts = hostname.split(".")
#         for i in range(len(domain_parts) - 1):
#             potential_domain = ".".join(domain_parts[i:])
#             if potential_domain in known_at_protocol_domains:
#                 return True
#
#         # For domains not in the whitelist, log a warning but still allow if other checks passed
#         logging.warning(
#             f"SSRF protection: URL hostname not in AT Protocol whitelist: {hostname}"
#         )
#
#         return True
#     except Exception as e:
#         logging.error(f"SSRF protection: URL validation error: {e}")
#         return False
#
#
# def extract_auth_server(metadata: dict) -> list[str] | None:
#     """
#     Extract the authorization server URL from the PDS metadata.
#
#     Args:
#         metadata: The PDS metadata dictionary
#
#     Returns:
#         The authorization server URL if found, None otherwise
#     """
#     if not metadata:
#         logging.error("Cannot extract authorization server: Metadata is None")
#         return None
#
#     auth_servers = metadata.get("authorization_servers")
#     if not auth_servers or not isinstance(auth_servers, list) or len(auth_servers) == 0:
#         logging.error("No authorization servers found in metadata")
#         return None
#
#     # Use the first authorization server in the list
#     return auth_servers
#
#
# def get_auth_server_metadata(
#     auth_servers: list[str],
# ) -> tuple[dict | None, str | None, str | None, str | None]:
#     """
#     Retrieve the OAuth authorization server metadata from the first available server.
#
#     Args:
#         auth_servers: List of authorization server URLs
#
#     Returns:
#         A tuple containing (metadata, auth_endpoint, token_endpoint, par_endpoint)
#         All values will be None if no server is available
#     """
#     if not auth_servers or not isinstance(auth_servers, list):
#         logging.error(
#             "Cannot get auth server metadata: No authorization servers provided"
#         )
#         return None, None, None, None
#
#     for auth_server in auth_servers:
#         metadata_url = (
#             f"{auth_server.rstrip('/')}/.well-known/oauth-authorization-server"
#         )
#         logging.info(f"Trying to fetch auth server metadata from: {metadata_url}")
#
#         # Check URL for SSRF vulnerabilities
#         if not is_safe_url(metadata_url):
#             logging.error(
#                 f"SSRF protection: Blocked request to potentially unsafe URL: {metadata_url}"
#             )
#             continue
#
#         try:
#             response = httpx.get(metadata_url)
#             response.raise_for_status()
#
#             metadata = response.json()
#             logging.info(
#                 f"Successfully retrieved auth server metadata from {auth_server}"
#             )
#
#             # Extract endpoints from metadata
#             auth_endpoint = metadata.get("authorization_endpoint")
#             token_endpoint = metadata.get("token_endpoint")
#             par_endpoint = metadata.get("pushed_authorization_request_endpoint")
#
#             if auth_endpoint and token_endpoint:
#                 logging.info(f"Found authorization endpoint: {auth_endpoint}")
#                 logging.info(f"Found token endpoint: {token_endpoint}")
#                 if par_endpoint:
#                     logging.info(f"Found PAR endpoint: {par_endpoint}")
#                 else:
#                     logging.warning("PAR endpoint not found in auth server metadata")
#
#                 return metadata, auth_endpoint, token_endpoint, par_endpoint
#             else:
#                 logging.warning(
#                     f"Missing required endpoints in auth server metadata from {auth_server}"
#                 )
#                 continue
#
#         except httpx.HTTPStatusError as e:
#             logging.warning(
#                 f"HTTP error occurred while retrieving auth server metadata from {auth_server}: {e}"
#             )
#             continue
#         except httpx.RequestError as e:
#             logging.warning(
#                 f"Request error occurred while retrieving auth server metadata from {auth_server}: {e}"
#             )
#             continue
#         except json.JSONDecodeError:
#             logging.warning(
#                 f"Failed to parse JSON response from auth server metadata retrieval from {auth_server}"
#             )
#             continue
#
#     logging.error("Failed to retrieve metadata from any authorization server")
#     return None, None, None, None
#
#
# def generate_oauth_state() -> str:
#     """
#     Generate a secure random state value for OAuth requests.
#
#     The state value is a random string that is:
#     - Unpredictable and unique for each authorization request
#     - At least 32 bytes (converted to a hex string)
#     - Used as a CSRF protection mechanism
#
#     Returns:
#         A secure random string to use as the state parameter
#     """
#
#     # Generate 32 bytes of random data and convert to hex
#     # This will result in a 64-character hex string
#     state = secrets.token_hex(32)
#     logging.info(f"Generated OAuth state parameter ({len(state)} characters)")
#     return state
#
#
# def generate_code_verifier(length: int = 128) -> str:
#     """
#     Generate a code_verifier for PKCE (Proof Key for Code Exchange) in OAuth.
#
#     The code_verifier is:
#     - A cryptographically random string between 43 and 128 characters
#     - Contains only unreserved URL characters: A-Z, a-z, 0-9, hyphen (-),
#       period (.), underscore (_), and tilde (~)
#
#     Args:
#         length: Length of the code verifier (default: 128)
#                Must be between 43 and 128 characters
#
#     Returns:
#         A secure random string to use as the code_verifier parameter
#     """
#     if length < 43 or length > 128:
#         raise ValueError("Code verifier length must be between 43 and 128 characters")
#
#     # Generate random bytes and convert to base64
#     # Generate random bytes (3/4 of the desired length to account for base64 expansion)
#     random_bytes = secrets.token_bytes(length * 3 // 4)
#
#     # Convert to base64 and remove padding
#     code_verifier = base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")
#
#     # Trim to desired length
#     code_verifier = code_verifier[:length]
#
#     logging.info(f"Generated code_verifier ({len(code_verifier)} characters)")
#     return code_verifier
#
#
# def generate_code_challenge(code_verifier: str) -> str:
#     """
#     Generate a code_challenge from a code_verifier for PKCE in OAuth.
#
#     The code_challenge is:
#     - The SHA-256 hash of the code_verifier
#     - Base64URL-encoded
#
#     Args:
#         code_verifier: The code_verifier string
#
#     Returns:
#         The code_challenge string
#     """
#     import hashlib
#
#     # Apply SHA-256 hash to the code_verifier
#     code_verifier_bytes = code_verifier.encode("ascii")
#     hash_bytes = hashlib.sha256(code_verifier_bytes).digest()
#
#     # Base64URL-encode the hash
#     code_challenge = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")
#
#     logging.info(f"Generated code_challenge ({len(code_challenge)} characters)")
#     return code_challenge
#
#
# def send_par_request(
#     par_endpoint: str,
#     code_challenge: str,
#     state: str,
#     login_hint: str | None = None,
#     client_id: str | None = None,
#     redirect_uri: str | None = None,
#     scope: str = "atproto transition:generic",
# ) -> tuple[str | None, int | None]:
#     """
#     Send a Pushed Authorization Request (PAR) to the authorization server.
#
#     Args:
#         par_endpoint: The PAR endpoint URL from the authorization server metadata
#         code_challenge: The PKCE code challenge generated from the code verifier
#         state: The OAuth state parameter for CSRF protection
#         login_hint: Optional handle or DID to pre-fill the login form
#         client_id: The OAuth client ID (URL to client metadata)
#         redirect_uri: The callback URL where the authorization code will be sent
#         scope: The requested OAuth scopes
#
#     Returns:
#         A tuple containing (request_uri, expires_in) if successful, (None, None) otherwise
#     """
#     if not par_endpoint:
#         logging.error("Cannot send PAR request: PAR endpoint is None")
#         return None, None
#
#     # Prepare the request parameters
#     params = {
#         "response_type": "code",
#         "code_challenge_method": "S256",
#         "scope": scope,
#         "client_id": client_id,
#         "redirect_uri": redirect_uri,
#         "code_challenge": code_challenge,
#         "state": state,
#     }
#
#     # Add login_hint if provided
#     if login_hint:
#         params["login_hint"] = login_hint
#
#     logging.info(f"Sending PAR request to: {par_endpoint}")
#     logging.debug(f"PAR request parameters: {params}")
#
#     # Check URL for SSRF vulnerabilities
#     if not is_safe_url(par_endpoint):
#         logging.error(
#             f"SSRF protection: Blocked request to potentially unsafe URL: {par_endpoint}"
#         )
#         return None, None
#
#     try:
#         # Send the POST request with form-encoded body
#         response = httpx.post(
#             par_endpoint,
#             data=params,
#         )
#         response.raise_for_status()
#
#         # Parse the JSON response
#         data = response.json()
#         logging.info("PAR request successful")
#
#         # Extract the request_uri and expires_in values
#         request_uri = data.get("request_uri")
#         expires_in = data.get("expires_in")
#
#         if request_uri:
#             logging.info(f"Received request_uri: {request_uri}")
#             logging.info(f"Request URI expires in: {expires_in} seconds")
#             return request_uri, expires_in
#         else:
#             logging.error("No request_uri found in PAR response")
#             return None, None
#
#     except httpx.HTTPStatusError as e:
#         logging.error(f"HTTP error occurred during PAR request: {e}")
#         try:
#             # Try to extract error details from response
#             error_data = e.response.json()
#             logging.error(f"Error details: {error_data}")
#         except json.JSONDecodeError:
#             logging.error("Could not parse error response as JSON")
#         except Exception as ex:
#             logging.error(f"Error extracting details from error response: {ex}")
#         return None, None
#     except httpx.RequestError as e:
#         logging.error(f"Request error occurred during PAR request: {e}")
#         return None, None
#     except json.JSONDecodeError:
#         logging.error("Failed to parse JSON response from PAR request")
#         return None, None
