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

    try:
        response = httpx.get(metadata_url)
        response.raise_for_status()
        metadata = response.json()
    except httpx.HTTPError as e:
        error_msg = f"Failed to retrieve PDS metadata from {metadata_url}: {e}"
        logger.error(error_msg)
        raise MetadataError(error_msg) from e
    except ValueError as e:
        error_msg = f"PDS metadata from {metadata_url} is not valid JSON"
        logger.error(error_msg)
        raise MetadataError(error_msg) from e

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

    Servers are tried in order; a server that fails is skipped and the next
    one is tried.

    Args:
        auth_servers: List of authorization server URLs

    Returns:
        The auth server metadata as a dictionary

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
        except SecurityError:
            logger.error("Security check failed for URL: %s", metadata_url)
            raise

        try:
            response = httpx.get(metadata_url)
            response.raise_for_status()
            metadata = response.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.warning(
                "Failed to retrieve auth server metadata from %s: %s", auth_server, e
            )
            continue

        logger.info("Successfully retrieved auth server metadata from %s", auth_server)
        return metadata

    error_msg = (
        f"Failed to retrieve metadata from any authorization server: {auth_servers}"
    )
    logger.error(error_msg)
    raise MetadataError(error_msg)


def auth_server_post(
    authserver_url: str,
    client_id: str,
    client_secret_jwk: ECKey,
    dpop_private_jwk: ECKey,
    dpop_authserver_nonce: str,
    post_url: str,
    post_data: dict,
) -> Tuple[str, httpx.Response]:
    client_assertion = client_assertion_jwt(
        client_id, authserver_url, client_secret_jwk
    )

    post_data |= {
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
    }

    if not isinstance(dpop_private_jwk, ECKey):
        dpop_private_jwk = ECKey.import_key(json.loads(dpop_private_jwk))

    # Create DPoP header JWT
    dpop_proof = authserver_dpop_jwt(
        method="POST",
        url=post_url,
        nonce=dpop_authserver_nonce,
        dpop_private_jwk=dpop_private_jwk,
    )

    # SSRF mitigations; raises SecurityError if unsafe
    valid_url(post_url)

    client = create_hardened_client()
    try:
        response = client.post(post_url, data=post_data, headers={"DPoP": dpop_proof})
    except httpx.RequestError as e:
        error_msg = f"POST to auth server {post_url} failed: {e}"
        logger.error(error_msg)
        raise OauthFlowError(error_msg) from e

    dpop_authserver_nonce = response.headers.get("DPoP-Nonce", dpop_authserver_nonce)

    # Handle DPoP missing/invalid nonce error by retrying with server-provided nonce
    if dpop_nonce_retry(response):
        server_nonce = response.headers.get("DPoP-Nonce")
        if not server_nonce:
            error_msg = (
                "Auth server demanded a DPoP nonce but sent no DPoP-Nonce header"
            )
            logger.error(error_msg)
            raise OauthFlowError(error_msg)

        dpop_authserver_nonce = server_nonce
        logging.debug(
            f"retrying with new auth server DPoP nonce: {dpop_authserver_nonce}"
        )
        dpop_proof = authserver_dpop_jwt(
            method="POST",
            url=post_url,
            nonce=dpop_authserver_nonce,
            dpop_private_jwk=dpop_private_jwk,
        )
        try:
            response = client.post(
                post_url, data=post_data, headers={"DPoP": dpop_proof}
            )
        except httpx.RequestError as e:
            error_msg = f"POST to auth server {post_url} failed: {e}"
            logger.error(error_msg)
            raise OauthFlowError(error_msg) from e

        dpop_authserver_nonce = response.headers.get(
            "DPoP-Nonce", dpop_authserver_nonce
        )

    return dpop_authserver_nonce, response


# Prepares and sends a pushed auth request (PAR) via HTTP POST to the Authorization Server.


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
    except SecurityError as e:
        logger.error(f"Token endpoint {token_endpoint} validation error {e}")
        raise TokenRequestError(
            f"Token endpoint failed security validation: {token_endpoint}"
        ) from e

    dpop_private_jwk = ECKey.import_key(json.loads(authn_metadata["dpop_private_jwk"]))

    dpop_nonce = authn_metadata["dpop_nonce"]

    dpop_proof = authserver_dpop_jwt(
        method="POST",
        url=token_endpoint,
        dpop_private_jwk=dpop_private_jwk,
        nonce=dpop_nonce,
    )

    client = create_hardened_client()
    try:
        response = client.post(token_endpoint, headers={"DPoP": dpop_proof}, data=data)
    except httpx.RequestError as e:
        error_msg = f"Token request to {token_endpoint} failed: {e}"
        logger.error(error_msg)
        raise TokenRequestError(error_msg) from e

    logger.debug("Token response status: %s", response.status_code)

    # Handle DPoP missing/invalid nonce error by retrying with server-provided nonce
    if (
        response.status_code in (400, 401)
        and _response_error_code(response) == "use_dpop_nonce"
    ):
        dpop_nonce = response.headers.get("DPoP-Nonce")
        if not dpop_nonce:
            error_msg = (
                "Auth server demanded a DPoP nonce but sent no DPoP-Nonce header"
            )
            logger.error(error_msg)
            raise TokenRequestError(error_msg)

        dpop_proof = authserver_dpop_jwt(
            method="POST",
            url=token_endpoint,
            nonce=dpop_nonce,
            dpop_private_jwk=dpop_private_jwk,
        )

        try:
            response = client.post(
                token_endpoint, headers={"DPoP": dpop_proof}, data=data
            )
        except httpx.RequestError as e:
            error_msg = f"Token request to {token_endpoint} failed: {e}"
            logger.error(error_msg)
            raise TokenRequestError(error_msg) from e

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        error_msg = (
            f"Token request failed: {e.response.status_code} - {e.response.text}"
        )
        logger.error(error_msg)
        raise TokenRequestError(error_msg) from e

    try:
        token = response.json()
    except ValueError as e:
        error_msg = "Token endpoint returned a non-JSON response"
        logger.error(error_msg)
        raise TokenRequestError(error_msg) from e

    # Prefer the freshest nonce the server provided for future requests
    dpop_nonce = response.headers.get("DPoP-Nonce", dpop_nonce)

    return token, dpop_nonce


def _response_error_code(response: httpx.Response) -> str | None:
    """Return the OAuth error code from a JSON error body, or None."""
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        return body.get("error")
    return None


# A resource server may signal the need for a [new] DPoP nonce via one of two methods
# 1. WWW-Authenticate header with paramater error="use_dpop_nonce"
#    (see https://datatracker.ietf.org/doc/html/rfc9449#RSNonce)
# 2. JSON response body with field error="use_dpop_nonce"
# The latter is only supposed to be returned by an
# Authorization Server (see https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid), but we support it anyway.
def dpop_nonce_retry(resp: httpx.Response):
    if resp.status_code not in [400, 401]:
        return False

    www_authenticate = resp.headers.get("WWW-Authenticate")
    if www_authenticate:
        scheme, _, params = www_authenticate.partition(" ")
        items = urllib.request.parse_http_list(params)
        opts = urllib.request.parse_keqv_list(items)
        if scheme.lower() == "dpop" and opts.get("error") == "use_dpop_nonce":
            return True

    if _response_error_code(resp) == "use_dpop_nonce":
        return True

    return False


def authserver_dpop_jwt(
    method: str, url: str, dpop_private_jwk: ECKey, nonce: str | None = None
) -> str:
    dpop_pub_jwk = dpop_private_jwk.as_dict(private=False)

    # This should ONLY contain: kty, crv, x, y (no 'd' parameter)
    if "d" in dpop_pub_jwk:
        error_msg = "Private key 'd' parameter found in public JWK"
        logger.error("❌ ERROR: %s!", error_msg)
        raise SecurityError(error_msg)

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
    except SecurityError as e:
        logger.error("Security check failed for URL: %s", context.par_endpoint)
        raise OauthFlowError(
            f"PAR endpoint failed security validation: {context.par_endpoint}"
        ) from e

    logger.debug(f"PAR request body: {context.par_request_body()}")

    # First PAR request
    logger.info("Sending PAR request to: %s", context.par_endpoint)
    try:
        response = httpx.post(
            context.par_endpoint,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "DPoP": context.dpop_proof,
            },
            data=context.par_request_body(),
        )
    except httpx.RequestError as e:
        error_msg = f"PAR request to {context.par_endpoint} failed: {e}"
        logger.error(error_msg)
        raise OauthFlowError(error_msg) from e

    dpop_authserver_nonce = response.headers.get("DPoP-Nonce")

    # Handle DPoP missing/invalid nonce error by retrying with server-provided nonce
    if (
        response.status_code in (400, 401)
        and _response_error_code(response) == "use_dpop_nonce"
    ):
        if not dpop_authserver_nonce:
            error_msg = (
                "Auth server demanded a DPoP nonce but sent no DPoP-Nonce header"
            )
            logger.error(error_msg)
            raise OauthFlowError(error_msg)

        dpop_proof = authserver_dpop_jwt(
            method="POST",
            url=context.par_endpoint,
            nonce=dpop_authserver_nonce,
            dpop_private_jwk=context.dpop_private_jwk,
        )

        logger.info("Retrying with new auth server DPoP nonce")
        try:
            response = httpx.post(
                context.par_endpoint,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "DPoP": dpop_proof,
                },
                data=context.par_request_body(),
            )
        except httpx.RequestError as e:
            error_msg = f"PAR request to {context.par_endpoint} failed: {e}"
            logger.error(error_msg)
            raise OauthFlowError(error_msg) from e

        dpop_authserver_nonce = response.headers.get(
            "DPoP-Nonce", dpop_authserver_nonce
        )

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        error_msg = f"PAR request failed: {e.response.status_code} - {e.response.text}"
        logger.error(error_msg)
        raise OauthFlowError(error_msg) from e

    logger.info("PAR request successful")

    return dpop_authserver_nonce, response
