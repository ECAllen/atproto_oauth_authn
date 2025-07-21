
# AI! please add docstring
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
    if app_url in ['localhost','127.0.0.1']:
        client_id = 'http://localhost/oauth/client-metadata.json'
        redirect_uri = 'http://127.0.01/oauth/callback'

    logging.info(f"""app URL: {app_url}
        PAR request parameters: 
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
