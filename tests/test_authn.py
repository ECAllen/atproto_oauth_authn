"""Tests for the high-level OAuth orchestration functions in authn.py.

resolve_user_did, get_pds_auth_servers, and get_authn_url are the entry
points downstream consumers (e.g. the Cards app) call directly, but had no
dedicated coverage — every step they orchestrate (identity resolution, DID
document retrieval, PDS metadata discovery, PAR request) is mocked here so
the *orchestration* (call order, error propagation, exact return shape) is
what's verified, not the already-covered internals of oauth.py/identity.py/did.py.
"""

# Pytest fixtures work by shadowing the fixture name in test signatures
# pylint: disable=redefined-outer-name

from unittest.mock import patch, Mock

import pytest

from atproto_oauth_authn.authn import (
    resolve_user_did,
    get_pds_auth_servers,
    get_authn_url,
)
from atproto_oauth_authn.exceptions import SecurityError, IdentityResolutionError
from atproto_oauth_authn.oauth import PARRequestContext


# ---------------------------------------------------------------------------
# resolve_user_did
# ---------------------------------------------------------------------------

@patch("atproto_oauth_authn.authn.extract_pds_url", return_value="https://pds.example.com")
@patch("atproto_oauth_authn.authn.retrieve_did_document", return_value={"id": "did:plc:abc"})
@patch("atproto_oauth_authn.authn.resolve_identity", return_value="did:plc:abc")
def test_resolve_user_did_success(mock_resolve, mock_retrieve, mock_extract):
    pds_url, user_did = resolve_user_did("alice.bsky.social")

    mock_resolve.assert_called_once_with("alice.bsky.social")
    mock_retrieve.assert_called_once_with("did:plc:abc")
    mock_extract.assert_called_once_with({"id": "did:plc:abc"})
    assert pds_url == "https://pds.example.com"
    assert user_did == "did:plc:abc"


@patch("atproto_oauth_authn.authn.resolve_identity", side_effect=IdentityResolutionError("no such handle"))
def test_resolve_user_did_propagates_identity_resolution_failure(mock_resolve):
    with pytest.raises(IdentityResolutionError):
        resolve_user_did("nonexistent.bsky.social")


@patch("atproto_oauth_authn.authn.retrieve_did_document", side_effect=RuntimeError("network down"))
@patch("atproto_oauth_authn.authn.resolve_identity", return_value="did:plc:abc")
def test_resolve_user_did_propagates_did_document_failure(mock_resolve, mock_retrieve):
    with pytest.raises(RuntimeError):
        resolve_user_did("alice.bsky.social")


@patch("atproto_oauth_authn.authn.extract_pds_url", side_effect=ValueError("no PDS service entry"))
@patch("atproto_oauth_authn.authn.retrieve_did_document", return_value={"id": "did:plc:abc"})
@patch("atproto_oauth_authn.authn.resolve_identity", return_value="did:plc:abc")
def test_resolve_user_did_propagates_pds_extraction_failure(mock_resolve, mock_retrieve, mock_extract):
    with pytest.raises(ValueError):
        resolve_user_did("alice.bsky.social")


# ---------------------------------------------------------------------------
# get_pds_auth_servers
# ---------------------------------------------------------------------------

@patch("atproto_oauth_authn.authn.extract_auth_server", return_value=["https://auth.example.com"])
@patch("atproto_oauth_authn.authn.get_pds_metadata", return_value={"auth": {}})
@patch("atproto_oauth_authn.authn.valid_url")
def test_get_pds_auth_servers_success(mock_valid_url, mock_get_meta, mock_extract):
    servers = get_pds_auth_servers("https://pds.example.com")

    mock_valid_url.assert_called_once_with("https://pds.example.com")
    mock_get_meta.assert_called_once_with("https://pds.example.com")
    mock_extract.assert_called_once_with({"auth": {}})
    assert servers == ["https://auth.example.com"]


@patch("atproto_oauth_authn.authn.valid_url", side_effect=SecurityError("rejected"))
def test_get_pds_auth_servers_rejects_unsafe_pds_url(mock_valid_url):
    with pytest.raises(SecurityError):
        get_pds_auth_servers("http://169.254.169.254/")


@patch("atproto_oauth_authn.authn.get_pds_metadata", side_effect=RuntimeError("boom"))
@patch("atproto_oauth_authn.authn.valid_url")
def test_get_pds_auth_servers_propagates_metadata_failure(mock_valid_url, mock_get_meta):
    with pytest.raises(RuntimeError):
        get_pds_auth_servers("https://pds.example.com")


@patch("atproto_oauth_authn.authn.extract_auth_server", side_effect=KeyError("auth"))
@patch("atproto_oauth_authn.authn.get_pds_metadata", return_value={})
@patch("atproto_oauth_authn.authn.valid_url")
def test_get_pds_auth_servers_propagates_extraction_failure(mock_valid_url, mock_get_meta, mock_extract):
    with pytest.raises(KeyError):
        get_pds_auth_servers("https://pds.example.com")


# ---------------------------------------------------------------------------
# get_authn_url — the full orchestration Cards' modules/auth.py depends on
# ---------------------------------------------------------------------------

_AUTH_SERVER_METADATA = {
    "issuer": "https://auth.example.com",
    "pushed_authorization_request_endpoint": "https://auth.example.com/par",
    "revocation_endpoint": "https://auth.example.com/revoke",
}
_CLIENT_CONFIG = (
    "https://cards.example.com/oauth/client-metadata.json",
    "https://cards.example.com/oauth/callback",
)


def _par_response():
    response = Mock()
    response.json.return_value = {"request_uri": "urn:ietf:params:oauth:request_uri:abc123"}
    return response


@patch("atproto_oauth_authn.authn.send_par_request", return_value=("dpop-nonce-1", _par_response()))
@patch("atproto_oauth_authn.authn.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.authn.client_assertion_jwt", return_value="assertion-jwt")
@patch("atproto_oauth_authn.authn.build_client_config", return_value=_CLIENT_CONFIG)
@patch("atproto_oauth_authn.authn.get_pds_auth_server_metadata", return_value=_AUTH_SERVER_METADATA)
@patch("atproto_oauth_authn.authn.get_pds_auth_servers", return_value=["https://auth.example.com"])
@patch("atproto_oauth_authn.authn.resolve_user_did", return_value=("https://pds.example.com", "did:plc:abc"))
def test_get_authn_url_returns_expected_tuple_shape(
    mock_resolve_user_did,
    mock_get_pds_auth_servers,
    mock_get_metadata,
    mock_build_client_config,
    mock_client_assertion_jwt,
    mock_dpop_jwt,
    mock_send_par,
):
    """Cards' modules/auth.py destructures this return value positionally
    into 9 named variables — the order here is a load-bearing contract."""
    result = get_authn_url(
        "alice.bsky.social",
        "cards.example.com",
        dpop_private_jwk=None,
        client_secret_jwk=None,
        scope="atproto",
    )

    (
        code_verifier,
        state,
        dpop_nonce,
        par_response_json,
        auth_server_metadata,
        user_did,
        pds_url,
        client_id,
        revocation_endpoint,
    ) = result

    assert isinstance(code_verifier, str) and code_verifier
    assert isinstance(state, str) and state
    assert dpop_nonce == "dpop-nonce-1"
    assert par_response_json == {"request_uri": "urn:ietf:params:oauth:request_uri:abc123"}
    assert auth_server_metadata["issuer"] == "https://auth.example.com"
    assert user_did == "did:plc:abc"
    assert pds_url == "https://pds.example.com"
    assert client_id == "https://cards.example.com/oauth/client-metadata.json"
    assert revocation_endpoint == "https://auth.example.com/revoke"


@patch("atproto_oauth_authn.authn.send_par_request", return_value=("dpop-nonce-1", _par_response()))
@patch("atproto_oauth_authn.authn.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.authn.client_assertion_jwt", return_value="assertion-jwt")
@patch("atproto_oauth_authn.authn.build_client_config", return_value=_CLIENT_CONFIG)
@patch("atproto_oauth_authn.authn.get_pds_auth_server_metadata", return_value=_AUTH_SERVER_METADATA)
@patch("atproto_oauth_authn.authn.get_pds_auth_servers", return_value=["https://auth.example.com"])
@patch("atproto_oauth_authn.authn.resolve_user_did", return_value=("https://pds.example.com", "did:plc:abc"))
def test_get_authn_url_builds_par_context_from_username_and_scope(
    mock_resolve_user_did,
    mock_get_pds_auth_servers,
    mock_get_metadata,
    mock_build_client_config,
    mock_client_assertion_jwt,
    mock_dpop_jwt,
    mock_send_par,
):
    get_authn_url(
        "alice.bsky.social",
        "cards.example.com",
        dpop_private_jwk=None,
        client_secret_jwk=None,
        scope="atproto custom-scope",
    )

    assert mock_send_par.call_count == 1
    par_context = mock_send_par.call_args.kwargs["context"]
    assert isinstance(par_context, PARRequestContext)
    assert par_context.login_hint == "alice.bsky.social"
    assert par_context.scope == "atproto custom-scope"
    assert par_context.client_id == "https://cards.example.com/oauth/client-metadata.json"
    assert par_context.redirect_uri == "https://cards.example.com/oauth/callback"
    assert par_context.par_endpoint == "https://auth.example.com/par"
    assert par_context.response_type == "code"
    assert par_context.code_challenge_method == "S256"
    assert par_context.dpop_proof == "dpop-proof"

    # The DPoP proof used for the PAR request must be bound to the PAR
    # endpoint (not e.g. the auth or token endpoint) per RFC 9449.
    dpop_call_kwargs = mock_dpop_jwt.call_args.kwargs
    assert dpop_call_kwargs["url"] == "https://auth.example.com/par"
    assert dpop_call_kwargs["method"] == "POST"


@patch("atproto_oauth_authn.authn.get_pds_auth_servers")
@patch("atproto_oauth_authn.authn.resolve_user_did", side_effect=IdentityResolutionError("no such handle"))
def test_get_authn_url_propagates_unresolvable_handle(mock_resolve_user_did, mock_get_pds_auth_servers):
    with pytest.raises(IdentityResolutionError):
        get_authn_url("nonexistent.bsky.social", "cards.example.com")
    mock_get_pds_auth_servers.assert_not_called()


@patch("atproto_oauth_authn.authn.send_par_request", side_effect=RuntimeError("PAR request failed"))
@patch("atproto_oauth_authn.authn.authserver_dpop_jwt", return_value="dpop-proof")
@patch("atproto_oauth_authn.authn.client_assertion_jwt", return_value="assertion-jwt")
@patch(
    "atproto_oauth_authn.authn.build_client_config",
    return_value=("https://cards.example.com/oauth/client-metadata.json", "https://cards.example.com/oauth/callback"),
)
@patch(
    "atproto_oauth_authn.authn.get_pds_auth_server_metadata",
    return_value={
        "issuer": "https://auth.example.com",
        "pushed_authorization_request_endpoint": "https://auth.example.com/par",
        "revocation_endpoint": "https://auth.example.com/revoke",
    },
)
@patch("atproto_oauth_authn.authn.get_pds_auth_servers", return_value=["https://auth.example.com"])
@patch("atproto_oauth_authn.authn.resolve_user_did", return_value=("https://pds.example.com", "did:plc:abc"))
def test_get_authn_url_propagates_par_request_failure(
    mock_resolve_user_did,
    mock_get_pds_auth_servers,
    mock_get_metadata,
    mock_build_client_config,
    mock_client_assertion_jwt,
    mock_dpop_jwt,
    mock_send_par,
):
    with pytest.raises(RuntimeError):
        get_authn_url("alice.bsky.social", "cards.example.com")
