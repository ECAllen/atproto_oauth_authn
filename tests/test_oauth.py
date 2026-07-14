"""Tests for OAuth functionality."""

# Pytest fixtures work by shadowing the fixture name in test signatures
# pylint: disable=redefined-outer-name

import json
import re
from unittest.mock import patch, Mock

import httpx
import pytest
from joserfc.jwk import ECKey

from atproto_oauth_authn.oauth import (
    generate_oauth_state,
    generate_code_challenge,
    send_par_request,
    initial_token_request,
    build_client_config,
    auth_server_post,
    authserver_dpop_jwt,
    dpop_nonce_retry,
    PARRequestContext,
)
from atproto_oauth_authn.exceptions import (
    InvalidParameterError,
    OauthFlowError,
    SecurityError,
    TokenRequestError,
)


def make_par_context(**overrides):
    """Build a valid PARRequestContext, with optional field overrides."""
    params = {
        "par_endpoint": "https://auth.example.com/par",
        "response_type": "code",
        "code_challenge": "challenge123",
        "code_challenge_method": "S256",
        "state": "state123",
        "client_id": "client123",
        "redirect_uri": "https://app.example.com/callback",
        "scope": "atproto transition:generic",
    }
    params.update(overrides)
    return PARRequestContext(**params)


def make_response(status_code=200, json_data=None, headers=None, text=""):
    """Build a mock httpx response. json_data=None simulates a non-JSON body."""
    response = Mock()
    response.status_code = status_code
    response.headers = headers or {}
    response.text = text
    if json_data is None:
        response.json.side_effect = ValueError("no JSON body")
    else:
        response.json.return_value = json_data
    if status_code >= 400:
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP Error: {status_code}", request=Mock(), response=response
        )
    else:
        response.raise_for_status.return_value = None
    return response


@pytest.fixture
def token_request_metadata():
    """Authn metadata as stored after a completed PAR round-trip."""
    key = ECKey.generate_key("P-256")
    return {
        "iss": "https://auth.example.com",
        "code_verifier": "verifier123",
        "dpop_private_jwk": json.dumps(key.as_dict(private=True)),
        "dpop_nonce": "stored-nonce",
    }


def test_generate_oauth_state():
    """Test generating OAuth state."""
    state = generate_oauth_state()
    assert isinstance(state, str)
    assert len(state) == 64  # 32 bytes as hex

    # Generate another to ensure they're different
    state2 = generate_oauth_state()
    assert state != state2


def test_generate_code_challenge():
    """Test generating code challenge from verifier."""
    verifier = "test_verifier"
    challenge = generate_code_challenge(verifier)

    assert isinstance(challenge, str)
    assert re.match(r"^[A-Za-z0-9_-]+$", challenge)  # URL-safe base64
    assert challenge != verifier  # Should be transformed
    assert challenge == generate_code_challenge(verifier)  # Deterministic


def test_build_client_config():
    """Test building client_id and redirect_uri from an app URL."""
    client_id, redirect_uri = build_client_config("myapp.example.com")
    assert client_id == "https://myapp.example.com/oauth/client-metadata.json"
    assert redirect_uri == "https://myapp.example.com/oauth/callback"


def test_par_request_context_valid():
    """Test that a fully populated context validates."""
    context = make_par_context()
    assert context.client_id == "client123"


@pytest.mark.parametrize(
    "field",
    ["response_type", "code_challenge", "client_id", "redirect_uri", "scope"],
)
def test_par_request_context_missing_required(field):
    """Test that missing required fields raise InvalidParameterError."""
    with pytest.raises(InvalidParameterError):
        make_par_context(**{field: ""})


def test_par_request_body():
    """Test PAR request body construction."""
    context = make_par_context(
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion="assertion123",
    )

    assert context.par_request_body() == {
        "response_type": "code",
        "code_challenge": "challenge123",
        "code_challenge_method": "S256",
        "client_id": "client123",
        "state": "state123",
        "redirect_uri": "https://app.example.com/callback",
        "scope": "atproto transition:generic",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": "assertion123",
    }


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_success_without_retry(mock_post):
    """A first-try success returns the response and the server's nonce."""
    success = make_response(
        201,
        {"request_uri": "urn:ietf:params:oauth:request_uri:example", "expires_in": 60},
        headers={"DPoP-Nonce": "server-nonce"},
    )
    mock_post.return_value = success

    nonce, response = send_par_request(make_par_context(dpop_proof="dpop-proof-1"))

    assert nonce == "server-nonce"
    assert response is success
    mock_post.assert_called_once()


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_success_without_nonce_header(mock_post):
    """A success with no DPoP-Nonce header returns None for the nonce."""
    success = make_response(201, {"request_uri": "urn:example", "expires_in": 60})
    mock_post.return_value = success

    nonce, response = send_par_request(make_par_context(dpop_proof="dpop-proof-1"))

    assert nonce is None
    assert response is success


@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt")
@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_dpop_nonce_retry(mock_post, mock_dpop_jwt):
    """Test the DPoP nonce flow: server demands a nonce, request is retried with it."""
    mock_dpop_jwt.return_value = "dpop-proof-2"

    nonce_demand = make_response(
        400, {"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "server-nonce"}
    )
    success = make_response(
        201,
        {"request_uri": "urn:ietf:params:oauth:request_uri:example", "expires_in": 60},
    )
    mock_post.side_effect = [nonce_demand, success]

    nonce, response = send_par_request(make_par_context(dpop_proof="dpop-proof-1"))

    assert nonce == "server-nonce"
    assert response is success
    assert mock_post.call_count == 2
    # The retry must use the freshly minted DPoP proof
    retry_headers = mock_post.call_args.kwargs["headers"]
    assert retry_headers["DPoP"] == "dpop-proof-2"


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_nonce_demand_without_header(mock_post):
    """A use_dpop_nonce error without a DPoP-Nonce header raises OauthFlowError."""
    mock_post.return_value = make_response(400, {"error": "use_dpop_nonce"})

    with pytest.raises(OauthFlowError):
        send_par_request(make_par_context(dpop_proof="dpop-proof-1"))


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_error_response(mock_post):
    """A non-nonce OAuth error is wrapped in OauthFlowError."""
    mock_post.return_value = make_response(
        400, {"error": "invalid_request"}, text='{"error": "invalid_request"}'
    )

    with pytest.raises(OauthFlowError):
        send_par_request(make_par_context(dpop_proof="dpop-proof-1"))


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_non_json_error_response(mock_post):
    """A non-JSON error body raises OauthFlowError, not JSONDecodeError."""
    mock_post.return_value = make_response(502, None, text="Bad Gateway")

    with pytest.raises(OauthFlowError):
        send_par_request(make_par_context(dpop_proof="dpop-proof-1"))


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_par_request_network_error(mock_post):
    """A network failure is wrapped in OauthFlowError."""
    mock_post.side_effect = httpx.ConnectError("connection refused")

    with pytest.raises(OauthFlowError):
        send_par_request(make_par_context(dpop_proof="dpop-proof-1"))


def call_auth_server_post(client_post_results, incoming_nonce="incoming-nonce"):
    """Invoke auth_server_post with mocked JWTs and a mocked HTTP client."""
    with (
        patch(
            "atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion"
        ),
        patch(
            "atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof"
        ),
        patch("atproto_oauth_authn.oauth.create_hardened_client") as mock_factory,
    ):
        client = Mock()
        client.post.side_effect = client_post_results
        mock_factory.return_value = client
        result = auth_server_post(
            authserver_url="https://auth.example.com",
            client_id="client123",
            client_secret_jwk=None,
            dpop_private_jwk=ECKey.generate_key("P-256"),
            dpop_authserver_nonce=incoming_nonce,
            post_url="https://auth.example.com/revoke",
            post_data={"token": "tok"},
        )
        return result, client


def test_auth_server_post_success():
    """A success updates the nonce from the response header."""
    success = make_response(200, {"ok": True}, headers={"DPoP-Nonce": "fresh-nonce"})

    (nonce, response), client = call_auth_server_post([success])

    assert nonce == "fresh-nonce"
    assert response is success
    client.post.assert_called_once()


def test_auth_server_post_success_without_nonce_header():
    """A response with no DPoP-Nonce header keeps the incoming nonce (was a KeyError)."""
    success = make_response(200, {"ok": True})

    (nonce, response), _ = call_auth_server_post([success])

    assert nonce == "incoming-nonce"
    assert response is success


def test_auth_server_post_dpop_nonce_retry():
    """A use_dpop_nonce demand triggers one retry with the server's nonce."""
    nonce_demand = make_response(
        400, {"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "server-nonce"}
    )
    success = make_response(200, {"ok": True})

    (nonce, response), client = call_auth_server_post([nonce_demand, success])

    assert nonce == "server-nonce"
    assert response is success
    assert client.post.call_count == 2


def test_auth_server_post_nonce_demand_without_header():
    """A use_dpop_nonce error without a DPoP-Nonce header raises OauthFlowError."""
    nonce_demand = make_response(400, {"error": "use_dpop_nonce"})

    with pytest.raises(OauthFlowError):
        call_auth_server_post([nonce_demand])


def test_auth_server_post_network_error():
    """A network failure is wrapped in OauthFlowError."""
    with pytest.raises(OauthFlowError):
        call_auth_server_post([httpx.ConnectError("connection refused")])


def test_dpop_nonce_retry_json_body():
    """A 400 with a use_dpop_nonce JSON body signals a retry."""
    assert dpop_nonce_retry(make_response(400, {"error": "use_dpop_nonce"})) is True


def test_dpop_nonce_retry_www_authenticate_header():
    """A 401 with a DPoP WWW-Authenticate challenge signals a retry."""
    response = make_response(
        401, None, headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}
    )
    assert dpop_nonce_retry(response) is True


def test_dpop_nonce_retry_other_error():
    """A different OAuth error does not signal a retry."""
    assert dpop_nonce_retry(make_response(400, {"error": "invalid_request"})) is False


def test_dpop_nonce_retry_success_status():
    """A success response does not signal a retry."""
    assert dpop_nonce_retry(make_response(200, {"ok": True})) is False


def test_dpop_nonce_retry_non_json_body():
    """A non-JSON error body does not crash and does not signal a retry."""
    assert dpop_nonce_retry(make_response(400, None, text="oops")) is False


def test_authserver_dpop_jwt_produces_jwt():
    """A real key produces a three-part JWT string."""
    key = ECKey.generate_key("P-256")
    proof = authserver_dpop_jwt(
        method="POST",
        url="https://auth.example.com/par",
        dpop_private_jwk=key,
        nonce="nonce-1",
    )
    assert isinstance(proof, str)
    assert proof.count(".") == 2


def test_authserver_dpop_jwt_rejects_private_key_leak():
    """A key whose public JWK leaks the private 'd' parameter raises SecurityError."""
    leaky_key = Mock()
    leaky_key.as_dict.return_value = {
        "kty": "EC",
        "crv": "P-256",
        "x": "x",
        "y": "y",
        "d": "private-material",
    }

    with pytest.raises(SecurityError):
        authserver_dpop_jwt(
            method="POST",
            url="https://auth.example.com/par",
            dpop_private_jwk=leaky_key,
        )


@patch("atproto_oauth_authn.oauth.create_hardened_client")
@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion")
@patch("atproto_oauth_authn.oauth.get_pds_auth_server_metadata")
def test_initial_token_request_success(
    mock_meta, _mock_assertion, _mock_dpop, mock_client_factory, token_request_metadata
):
    """A first-try token response is returned with the stored nonce."""
    mock_meta.return_value = {"token_endpoint": "https://auth.example.com/token"}
    client = Mock()
    client.post.return_value = make_response(200, {"access_token": "token123"})
    mock_client_factory.return_value = client

    token, nonce = initial_token_request(
        token_request_metadata, "code123", "app.example.com", client_secret_jwk=None
    )

    assert token == {"access_token": "token123"}
    assert nonce == "stored-nonce"
    client.post.assert_called_once()


@patch("atproto_oauth_authn.oauth.create_hardened_client")
@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion")
@patch("atproto_oauth_authn.oauth.get_pds_auth_server_metadata")
def test_initial_token_request_dpop_nonce_retry(
    mock_meta, _mock_assertion, _mock_dpop, mock_client_factory, token_request_metadata
):
    """A use_dpop_nonce demand triggers one retry using the server's nonce."""
    mock_meta.return_value = {"token_endpoint": "https://auth.example.com/token"}
    nonce_demand = make_response(
        400, {"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "fresh-nonce"}
    )
    success = make_response(200, {"access_token": "token123"})
    client = Mock()
    client.post.side_effect = [nonce_demand, success]
    mock_client_factory.return_value = client

    token, nonce = initial_token_request(
        token_request_metadata, "code123", "app.example.com", client_secret_jwk=None
    )

    assert token == {"access_token": "token123"}
    assert nonce == "fresh-nonce"
    assert client.post.call_count == 2


@patch("atproto_oauth_authn.oauth.create_hardened_client")
@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion")
@patch("atproto_oauth_authn.oauth.get_pds_auth_server_metadata")
def test_initial_token_request_nonce_demand_without_header(
    mock_meta, _mock_assertion, _mock_dpop, mock_client_factory, token_request_metadata
):
    """A use_dpop_nonce error without a DPoP-Nonce header raises TokenRequestError."""
    mock_meta.return_value = {"token_endpoint": "https://auth.example.com/token"}
    client = Mock()
    client.post.return_value = make_response(400, {"error": "use_dpop_nonce"})
    mock_client_factory.return_value = client

    with pytest.raises(TokenRequestError):
        initial_token_request(
            token_request_metadata, "code123", "app.example.com", client_secret_jwk=None
        )


@patch("atproto_oauth_authn.oauth.create_hardened_client")
@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion")
@patch("atproto_oauth_authn.oauth.get_pds_auth_server_metadata")
def test_initial_token_request_http_error(
    mock_meta, _mock_assertion, _mock_dpop, mock_client_factory, token_request_metadata
):
    """A token endpoint error response is wrapped in TokenRequestError."""
    mock_meta.return_value = {"token_endpoint": "https://auth.example.com/token"}
    client = Mock()
    client.post.return_value = make_response(
        401, {"error": "invalid_grant"}, text='{"error": "invalid_grant"}'
    )
    mock_client_factory.return_value = client

    with pytest.raises(TokenRequestError):
        initial_token_request(
            token_request_metadata, "code123", "app.example.com", client_secret_jwk=None
        )


@patch("atproto_oauth_authn.oauth.create_hardened_client")
@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion")
@patch("atproto_oauth_authn.oauth.get_pds_auth_server_metadata")
def test_initial_token_request_network_error(
    mock_meta, _mock_assertion, _mock_dpop, mock_client_factory, token_request_metadata
):
    """A network failure is wrapped in TokenRequestError."""
    mock_meta.return_value = {"token_endpoint": "https://auth.example.com/token"}
    client = Mock()
    client.post.side_effect = httpx.ConnectError("connection refused")
    mock_client_factory.return_value = client

    with pytest.raises(TokenRequestError):
        initial_token_request(
            token_request_metadata, "code123", "app.example.com", client_secret_jwk=None
        )


@patch("atproto_oauth_authn.oauth.create_hardened_client")
@patch("atproto_oauth_authn.oauth.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.oauth.client_assertion_jwt", return_value="assertion")
@patch("atproto_oauth_authn.oauth.get_pds_auth_server_metadata")
def test_initial_token_request_non_json_token_response(
    mock_meta, _mock_assertion, _mock_dpop, mock_client_factory, token_request_metadata
):
    """A non-JSON 200 body raises TokenRequestError, not a JSON error."""
    mock_meta.return_value = {"token_endpoint": "https://auth.example.com/token"}
    client = Mock()
    client.post.return_value = make_response(200, None, text="<html>ok</html>")
    mock_client_factory.return_value = client

    with pytest.raises(TokenRequestError):
        initial_token_request(
            token_request_metadata, "code123", "app.example.com", client_secret_jwk=None
        )
