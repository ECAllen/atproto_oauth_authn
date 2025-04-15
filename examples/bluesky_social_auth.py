from dotenv import load_dotenv
import logging
import os
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


# Main execution flow
def main() -> bool:
    load_dotenv()
    """Main execution flow for the OAuth authentication process."""
    # 1) get users handle
    # Login can start with a handle, DID, or auth server URL
    username = os.getenv("USERNAME") or exit("Missing USERNAME")
    app_url = os.getenv("APP_URL") or exit("Missing APP_URL")
    logging.info(f"Starting OAuth flow for username: {username}")

    # 2) retrieve the users DID
    user_did = atproto_oauth_authn.resolve_identity(username)
    if not user_did:
        logging.error(f"Failed to resolve username {username} to a DID")
        return False

    logging.info(f"Resolved username {username} to DID: {user_did}")

    # 3) retrieve the user DID document
    # 4) get the URL of the PDS server from the DID doc
    # AI! please fix all imports from atproto_oauth_authn
    did_document, pds_url = get_did_document(user_did)
    if not did_document or not pds_url:
        logging.error(f"Failed to retrieve DID document or PDS URL for {user_did}")
        return False

    logging.info(f"Successfully retrieved DID document for {user_did}")

    # 5) get the PDS server metadata from the well-known endpoint
    pds_metadata = get_pds_metadata(pds_url)
    if not pds_metadata:
        logging.error("Failed to retrieve PDS metadata")
        return False

    logging.info("PDS metadata retrieved successfully")

    # 6) from the metadata extract the authorization server
    auth_servers = extract_auth_server(pds_metadata)
    if not auth_servers:
        logging.error("Failed to extract authorization server from metadata")
        return False

    logging.info(f"Authorization server URL: {auth_servers[0]}")

    # 7) get the metadata of the authorization server
    auth_metadata, auth_endpoint, token_endpoint, par_endpoint = (
        get_auth_server_metadata(auth_servers)
    )

    if not auth_metadata:
        logging.error("Failed to retrieve auth server metadata from any server")
        return False

    logging.info("Auth server metadata retrieved successfully")
    print("Auth Server Endpoints:")
    print(f"  Authorization: {auth_endpoint}")
    print(f"  Token: {token_endpoint}")
    print(f"  PAR: {par_endpoint or 'Not available'}")

    # Generate a state parameter for OAuth request
    oauth_state = generate_oauth_state()
    print(f"Generated OAuth state: {oauth_state[:10]}... (truncated)")

    # Generate a code_verifier for PKCE
    # TODO very param for code_verifier length
    code_verifier = generate_code_verifier(48)
    print(f"Generated code_verifier: {code_verifier[:10]}... (truncated)")

    # Generate a code_challenge from the code_verifier
    code_challenge = generate_code_challenge(code_verifier)
    print(f"Generated code_challenge: {code_challenge[:10]}... (truncated)")

    # In a real application, you would store these values
    # to use them when exchanging the authorization code for tokens

    # Send the PAR request if we have a PAR endpoint
    if par_endpoint:
        client_id = f"https://{app_url}/oauth/client-metadata.json"
        redirect_uri = f"https://{app_url}/oauth/callback"
        # Use the username as login_hint if available
        request_uri, expires_in = send_par_request(
            par_endpoint=par_endpoint,
            code_challenge=code_challenge,
            state=oauth_state,
            login_hint=username,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )

        if request_uri:
            print("PAR request successful!")
            print(f"Request URI: {request_uri}")
            print(f"Expires in: {expires_in} seconds")

            import urllib.parse  # noqa: E402

            # auth_url = authserver_meta["authorization_endpoint"]
            # assert is_safe_url(auth_url)
            qparam = urllib.parse.urlencode(
                {"client_id": client_id, "request_uri": request_uri}
            )
            auth_url = f"{auth_endpoint}?{qparam}"

            # Construct the authorization URL

            # client_id_enc = urllib.parse.quote(client_id, safe="")
            # request_uri_enc = urllib.parse.quote(request_uri, safe="")
            # auth_url = f"{auth_endpoint}?client_id={client_id_enc}&request_uri={request_uri_enc}"
            #
            print("\nAuthorization URL:")
            print(f"{auth_endpoint}?client_id={client_id}&request_uri={request_uri}")
            print(auth_url)
            import webbrowser

            webbrowser.open(auth_url)
            return True
        else:
            print("PAR request failed. Check the logs for details.")
            return False
    else:
        logging.warning("No PAR endpoint available, cannot proceed with OAuth flow")
        return False


if __name__ == "__main__":
    main()
