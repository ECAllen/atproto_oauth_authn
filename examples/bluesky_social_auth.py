from dotenv import load_dotenv
import logging
import os
import sys
import webbrowser
import urllib.parse
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

# Main execution flow
# def main() -> bool:
#     """Main execution flow for the OAuth authentication process."""
#     try:
#         load_dotenv()
#
#         # 1) get users handle
#         # Login can start with a handle, DID, or auth server URL
#         username = os.getenv("USERNAME")
#         if not username:
#             logger.error("Missing USERNAME environment variable")
#             print("Error: Missing USERNAME environment variable")
#             return False
#
#         app_url = os.getenv("APP_URL")
#         if not app_url:
#             logger.error("Missing APP_URL environment variable")
#             print("Error: Missing APP_URL environment variable")
#             return False
#
#         logging.info(f"Starting OAuth flow for username: {username}")
#
#         # 2) retrieve the users DID
#         try:
#             user_did = atproto_oauth_authn.resolve_identity(username)
#             logging.info(f"Resolved username {username} to DID: {user_did}")
#         except IdentityResolutionError as e:
#             logging.error(f"Failed to resolve username {username} to a DID: {e}")
#             print(f"Error: Failed to resolve username: {e}")
#             return False
#
#         # 3) retrieve the user DID document
#         # 4) get the URL of the PDS server from the DID doc
#         try:
#             did_document, pds_url = atproto_oauth_authn.get_did_document(user_did)
#             logging.info(f"Successfully retrieved DID document for {user_did}")
#         except DidDocumentError as e:
#             logging.error(f"Failed to retrieve DID document for {user_did}: {e}")
#             print(f"Error: Failed to retrieve DID document: {e}")
#             return False
#
#         # 5) get the PDS server metadata from the well-known endpoint
#         try:
#             pds_metadata = atproto_oauth_authn.get_pds_metadata(pds_url)
#             logging.info("PDS metadata retrieved successfully")
#         except MetadataError as e:
#             logging.error(f"Failed to retrieve PDS metadata: {e}")
#             print(f"Error: Failed to retrieve PDS metadata: {e}")
#             return False
#
#         # 6) from the metadata extract the authorization server
#         try:
#             auth_servers = atproto_oauth_authn.extract_auth_server(pds_metadata)
#             logging.info(f"Authorization server URL: {auth_servers[0]}")
#         except MetadataError as e:
#             logging.error(f"Failed to extract authorization server from metadata: {e}")
#             print(f"Error: Failed to extract authorization server: {e}")
#             return False
#
#         # 7) get the metadata of the authorization server
#         try:
#             auth_metadata, auth_endpoint, token_endpoint, par_endpoint = (
#                 atproto_oauth_authn.get_auth_server_metadata(auth_servers)
#             )
#             logging.info("Auth server metadata retrieved successfully")
#             print("Auth Server Endpoints:")
#             print(f"  Authorization: {auth_endpoint}")
#             print(f"  Token: {token_endpoint}")
#             print(f"  PAR: {par_endpoint or 'Not available'}")
#         except MetadataError as e:
#             logging.error(f"Failed to retrieve auth server metadata: {e}")
#             print(f"Error: Failed to retrieve auth server metadata: {e}")
#             return False
#
#         # Generate a state parameter for OAuth request
#         oauth_state = atproto_oauth_authn.generate_oauth_state()
#         print(f"Generated OAuth state: {oauth_state[:10]}... (truncated)")
#
#         # Generate a code_verifier for PKCE
#         try:
#             code_verifier = atproto_oauth_authn.generate_code_verifier(48)
#             print(f"Generated code_verifier: {code_verifier[:10]}... (truncated)")
#         except InvalidParameterError as e:
#             logging.error(f"Failed to generate code verifier: {e}")
#             print(f"Error: Failed to generate code verifier: {e}")
#             return False
#
#         # Generate a code_challenge from the code_verifier
#         code_challenge = atproto_oauth_authn.generate_code_challenge(code_verifier)
#         print(f"Generated code_challenge: {code_challenge[:10]}... (truncated)")
#
#         # In a real application, you would store these values
#         # to use them when exchanging the authorization code for tokens
#
#         # Send the PAR request if we have a PAR endpoint
#         if par_endpoint:
#             client_id = f"https://{app_url}/oauth/client-metadata.json"
#             redirect_uri = f"https://{app_url}/oauth/callback"
#
#             try:
#                 # Use the username as login_hint if available
#                 request_uri, expires_in = atproto_oauth_authn.send_par_request(
#                     par_endpoint=par_endpoint,
#                     code_challenge=code_challenge,
#                     state=oauth_state,
#                     login_hint=username,
#                     client_id=client_id,
#                     redirect_uri=redirect_uri,
#                 )
#
#                 print("PAR request successful!")
#                 print(f"Request URI: {request_uri}")
#                 print(f"Expires in: {expires_in} seconds")
#
#                 # Build the authorization URL
#                 try:
#                     auth_url = atproto_oauth_authn.build_auth_url(
#                         auth_endpoint=auth_endpoint,
#                         client_id=client_id,
#                         request_uri=request_uri
#                     )
#
#                     print("\nAuthorization URL:")
#                     print(auth_url)
#
#                     return True
#                 except InvalidParameterError as e:
#                     logging.error(f"Failed to build authorization URL: {e}")
#                     print(f"Error: Failed to build authorization URL: {e}")
#                     return False
#
#             except (OauthFlowError, SecurityError, InvalidParameterError) as e:
#                 logging.error(f"PAR request failed: {e}")
#                 print(f"Error: PAR request failed: {e}")
#                 return False
#         else:
#             logging.warning("No PAR endpoint available, cannot proceed with OAuth flow")
#             print("Error: No PAR endpoint available, cannot proceed with OAuth flow")
#             return False
#
#     except AtprotoOauthError as e:
#         logging.error(f"OAuth flow error: {e}")
#         print(f"Error: {e}")
#         return False
#     except Exception as e:
#         logging.exception(f"Unexpected error: {e}")
#         print(f"Unexpected error: {e}")
#         return False
#
