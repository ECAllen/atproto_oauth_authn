"""OAuth functionality for AT Protocol."""

import logging
import secrets
import base64
import hashlib
import json
import time
from typing import List, Tuple, Dict, Any
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import urllib
from validators import ValidationError

from .security import valid_url, create_hardened_client
from .exceptions import (
    MetadataError,
    OauthFlowError,
    SecurityError,
    InvalidParameterError,
    TokenRequestError,
)

from joserfc.jwk import ECKey
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt

logger = logging.getLogger(__name__)


@dataclass
class PARRequestContext:
    """Context for performing a PAR request with all necessary parameters."""

    par_endpoint: str
    response_type: str
    code_challenge: str
    code_challenge_method: str
    state: str
    client_id: str
    redirect_uri: str
    scope: str
    client_assertion_type: str | None = None
    client_assertion: str | None = None
    login_hint: str | None = None
    app_url: str | None = None
    dpop_proof: str | None = None
    dpop_private_jwk: ECKey | None = None

    def __post_init__(self):
        """Validate required parameters after initialization."""
        if not self.response_type:
            raise InvalidParameterError("response_type is required")
        if not self.code_challenge:
            raise InvalidParameterError("code_challenge is required")
        if not self.client_id:
            raise InvalidParameterError("client_id is required")
        if not self.redirect_uri:
            raise InvalidParameterError("redirect_uri is required")
        if not self.scope:
            raise InvalidParameterError("scope is required")

    def par_request_body(self):
        return {
            "response_type": self.response_type,
            "code_challenge": self.code_challenge,
            "code_challenge_method": self.code_challenge_method,
            "client_id": self.client_id,
            "state": self.state,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "client_assertion_type": self.client_assertion_type,
            "client_assertion": self.client_assertion,
        }


def build_client_config(app_url: str) -> Tuple[str, str]:
    """Build client_id and redirect_uri from app_url.

    Args:
        app_url: The base URL of the application

    Returns:
        Tuple of (client_id, redirect_uri)
    """
    client_id = f"https://{app_url}/oauth/client-metadata.json"
    redirect_uri = f"https://{app_url}/oauth/callback"

    # Special case for development/testing with localhost
    if app_url in ["localhost", "127.0.0.1"]:
        client_id = "http://localhost/oauth/client-metadata.json"
        redirect_uri = "http://127.0.01/oauth/callback"

    return client_id, redirect_uri


def get_pds_metadata(pds_url: str) -> Dict[str, Any]:
    """
    Retrieve the OAuth protected resource metadata from the PDS server.

    Args:
        pds_url: The URL of the PDS server

    Returns:
        The metadata as a dictionary

    Raises:
        MetadataError: If the metadata cannot be retrieved or parsed
        SecurityError: If there's a security issue with the URL
    """
    if not pds_url:
        error_msg = "Cannot get PDS metadata: PDS URL is None"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    metadata_url = f"{pds_url.rstrip('/')}/.well-known/oauth-protected-resource"
    logger.info("Fetching PDS metadata from: %s", metadata_url)

    # Check URL for SSRF vulnerabilities
    try:
        valid_url(metadata_url)
    except SecurityError:
        logger.error("Security check failed for URL: %s", metadata_url)
        raise

    response = httpx.get(metadata_url)
    response.raise_for_status()
    metadata = response.json()
    logger.info("Successfully retrieved PDS metadata")

    return metadata


def extract_auth_server(metadata: Dict[str, Any]) -> List[str]:
    """
    Extract the authorization server URL from the PDS metadata.

    Args:
        metadata: The PDS metadata dictionary

    Returns:
        The list of authorization server URLs

    Raises:
        MetadataError: If no authorization servers can be found
    """
    if not metadata:
        error_msg = "Cannot extract authorization server: Metadata is None"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    # Look for authorization_servers field first (standard OAuth metadata)
    auth_servers = metadata.get("authorization_servers")
    if auth_servers and isinstance(auth_servers, list) and len(auth_servers) > 0:
        logger.info("Found authorization servers: %s", auth_servers)
        return auth_servers

    # Fall back to extracting from auth.oauth2 structure (AT Protocol specific)
    auth_config = metadata.get("auth", {}).get("oauth2", {})
    if auth_config:
        auth_endpoint = auth_config.get("authorization_endpoint")
        if auth_endpoint:
            # Extract the base URL from the authorization endpoint

            parsed = urlparse(auth_endpoint)
            auth_server = f"{parsed.scheme}://{parsed.netloc}"
            logger.info(
                "Extracted authorization server from auth config: %s", auth_server
            )
            return [auth_server]

    error_msg = "No authorization servers found in metadata"
    logger.error(error_msg)
    raise MetadataError(error_msg)


def get_pds_auth_server_metadata(
    auth_servers: List[str],
) -> dict:
    """
    Retrieve the OAuth authorization server metadata from the first available server.

    Args:
        auth_servers: List of authorization server URLs

    Returns:
        A tuple containing (metadata, auth_endpoint, token_endpoint, par_endpoint)

    Raises:
        MetadataError: If metadata cannot be retrieved from any server
        SecurityError: If there's a security issue with the URL
    """
    if not auth_servers or not isinstance(auth_servers, list):
        error_msg = "Cannot get auth server metadata: No authorization servers provided"
        logger.error(error_msg)
        raise MetadataError(error_msg)

    for auth_server in auth_servers:
        metadata_url = (
            f"{auth_server.rstrip('/')}/.well-known/oauth-authorization-server"
        )
        logger.info("Trying to fetch auth server metadata from: %s", metadata_url)

        # Check URL for SSRF vulnerabilities
        try:
            valid_url(metadata_url)  # Raises SecurityError if unsafe
        except Exception as e:
            logger.error(f"PDS Auth server metadata URL validation failed: {e}")
            raise ValidationError

        response = httpx.get(metadata_url)
        response.raise_for_status()

        metadata = response.json()
        logger.info("Successfully retrieved auth server metadata from %s", auth_server)
        return metadata


def initial_token_request(
    authn_metadata: dict,
    code: str,
    app_url: str,
    client_secret_jwk: ECKey,
) -> Tuple[dict, str]:
    authserver_url = authn_metadata["iss"]

    # TODO is this necessary?
    # Re-fetch server metadata
    authserver_meta = get_pds_auth_server_metadata([authserver_url])

    client_id, redirect_uri = build_client_config(app_url)

    client_assertion = client_assertion_jwt(
        client_id, authserver_url, client_secret_jwk
    )

    data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": authn_metadata["code_verifier"],
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
    }

    logger.debug(f"Data: {data}")

    # Create DPoP header JWT, using the existing DPoP signing key for this account/session
    token_endpoint = authserver_meta["token_endpoint"]
    try:
        valid_url(token_endpoint)
        logger.info("✅ Token endpoint valid.")
    except ValidationError as e:
        logger.error(f"Token endpoint {token_endpoint} validation error {e}")
        raise TokenRequestError

    dpop_private_jwk = ECKey.import_key(json.loads(authn_metadata["dpop_private_jwk"]))

    dpop_nonce = authn_metadata["dpop_nonce"]

    dpop_proof = authserver_dpop_jwt(
        method="POST",
        url=token_endpoint,
        dpop_private_jwk=dpop_private_jwk,
        nonce=dpop_nonce,
    )

    client = create_hardened_client()
    response = client.post(token_endpoint, headers={"DPoP": dpop_proof}, data=data)

    logger.debug(f"Response: {response.json()}")

    if response.status_code == 400 and response.json()["error"] == "use_dpop_nonce":
        dpop_nonce = response.headers["DPoP-Nonce"]

        dpop_proof = authserver_dpop_jwt(
            method="POST",
            url=token_endpoint,
            nonce=dpop_nonce,
            dpop_private_jwk=dpop_private_jwk,
        )

        try:
            with httpx.Client(
                timeout=10.0, follow_redirects=False, verify=True, trust_env=False
            ) as client:
                response = client.post(
                    token_endpoint, headers={"DPoP": dpop_proof}, data=data
                )
        except httpx.HTTPStatusError as e:
            logger.error(
                f"HTTP error occurred: {e.response.status_code} - {e.response.text}"
            )
            raise TokenRequestError

    response.raise_for_status()

    # TODO proper exception handling
    token = response.json()

    return token, dpop_nonce


# A resource server may signal the need for a [new] DPoP nonce via one of two methods
# 1. WWW-Authenticate header with paramater error="use_dpop_nonce"
#    (see https://datatracker.ietf.org/doc/html/rfc9449#RSNonce)
# 2. JSON response body with field error="use_dpop_nonce"
# The latter is only supposed to be returned by an
# Authorization Server (see https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid), but we support it anyway.
def use_dpop_nonce_response(resp: httpx.Response):
    if resp.status_code not in [400, 401]:
        return False

    www_authenticate = resp.headers.get("WWW-Authenticate")
    if www_authenticate:
        scheme, _, params = www_authenticate.partition(" ")
        items = urllib.request.parse_http_list(params)
        opts = urllib.request.parse_keqv_list(items)
        if scheme.lower() == "dpop" and opts.get("error") == "use_dpop_nonce":
            return True

    json_body = resp.json()
    if isinstance(json_body, dict) and json_body.get("error") == "use_dpop_nonce":
        return True

    return False


def authserver_dpop_jwt(
    method: str, url: str, dpop_private_jwk: ECKey, nonce: str | None = None
) -> str:
    dpop_pub_jwk = dpop_private_jwk.as_dict(private=False)

    # This should ONLY contain: kty, crv, x, y (no 'd' parameter)
    if "d" in dpop_pub_jwk:
        logger.error("❌ ERROR: Private key 'd' parameter found in public JWK!")
    else:
        logger.info("✅ Good: No private key material in JWK")

    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": dpop_pub_jwk}

    body = {
        "jti": generate_token(),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
        "exp": int(time.time()) + 30,
    }

    if nonce:
        body["nonce"] = nonce

    dpop_proof = jwt.encode(
        header,
        body,
        dpop_private_jwk,
    )

    if isinstance(dpop_proof, bytes):
        dpop_proof = dpop_proof.decode("utf-8")

    # decoded = jwt.decode(dpop_proof, dpop_private_jwk)

    return dpop_proof


def pds_dpop_jwt(
    method: str,
    url: str,
    dpop_private_jwk: ECKey,
    access_token: str,
    nonce: str | None = None,
) -> str:
    dpop_pub_jwk = dpop_private_jwk.as_dict(private=False)

    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": dpop_pub_jwk}

    body = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 10,
        "jti": generate_token(),
        "htm": method,
        "htu": url,
        "ath": create_s256_code_challenge(access_token),
    }

    if nonce:
        body["nonce"] = nonce

    dpop_proof = jwt.encode(
        header,
        body,
        dpop_private_jwk,
    )

    if isinstance(dpop_proof, bytes):
        dpop_proof = dpop_proof.decode("utf-8")

    return dpop_proof


def client_assertion_jwt(
    client_id: str, auth_endpoint: str, client_secret_jwk: ECKey
) -> str:
    header = {"alg": "ES256", "kid": client_secret_jwk["kid"]}
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": auth_endpoint,
        "jti": generate_token(),
        "iat": int(time.time()),
    }
    client_assertion = jwt.encode(header, claims, client_secret_jwk)

    return client_assertion


def generate_oauth_state() -> str:
    """
    Generate a secure random state value for OAuth requests.

    The state value is a random string that is:
    - Unpredictable and unique for each authorization request
    - At least 32 bytes (converted to a hex string)
    - Used as a CSRF protection mechanism

    Returns:
        A secure random string to use as the state parameter
    """
    # Generate 32 bytes of random data and convert to hex
    # This will result in a 64-character hex string
    state = secrets.token_hex(32)
    logger.info("Generated OAuth state parameter (%d characters)", len(state))
    return state


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a code_challenge from a code_verifier for PKCE in OAuth.

    The code_challenge is:
    - The SHA-256 hash of the code_verifier
    - Base64URL-encoded

    Args:
        code_verifier: The code_verifier string

    Returns:
        The code_challenge string
    """
    # Apply SHA-256 hash to the code_verifier
    code_verifier_bytes = code_verifier.encode("ascii")
    hash_bytes = hashlib.sha256(code_verifier_bytes).digest()

    # Base64URL-encode the hash
    code_challenge = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    logger.info("Generated code_challenge (%d characters)", len(code_challenge))
    return code_challenge


def send_par_request(
    context: PARRequestContext,
) -> Tuple[str, Any]:
    """
    Send a Pushed Authorization Request (PAR) to the authorization server.

    Args:
        context: PARRequestContext containing all necessary parameters
        scope: The requested OAuth scopes

    Returns:
        A tuple containing (request_uri, expires_in)

    Raises:
        OauthFlowError: If the PAR request fails
        SecurityError: If there's a security issue with the URL
        InvalidParameterError: If required parameters are missing (via context validation)
    """

    logger.debug("PAR request parameters: %s", context)

    # Check URL for SSRF vulnerabilities
    try:
        valid_url(context.par_endpoint)
    except SecurityError:
        logger.error("Security check failed for URL: %s", context.par_endpoint)
        raise OauthFlowError()

    logger.debug(f"PAR request body: {context.par_request_body()}")

    # First PAR request
    logger.info("Sending PAR request to: %s", context.par_endpoint)
    response = httpx.post(
        context.par_endpoint,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": context.dpop_proof,
        },
        data=context.par_request_body(),
    )

    if response.status_code == 400 and response.json()["error"] == "use_dpop_nonce":
        dpop_authserver_nonce = response.headers["DPoP-Nonce"]
        # TODO try needed?s
        dpop_proof = authserver_dpop_jwt(
            method="POST",
            url=context.par_endpoint,
            nonce=dpop_authserver_nonce,
            dpop_private_jwk=context.dpop_private_jwk,
        )

        logger.info("Retrying with new auth server DPoP nonce")
        response_dpop = httpx.post(
            context.par_endpoint,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": dpop_proof,
            },
            data=context.par_request_body(),
        )
        if "error" in response_dpop.json():
            logger.error("Error retrying with new DPoP")
            logger.error(response_dpop.json())
        response_dpop.raise_for_status()
    else:
        logger.error("Error sending PAR request")
        logger.error(response.json())
        response.raise_for_status()

    # Parse the JSON response
    data = response_dpop.json()
    logger.info("PAR request successful")
    # TODO make this debug later
    logger.info(f"{data}")

    return dpop_authserver_nonce, response_dpop
