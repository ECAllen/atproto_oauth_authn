"""Tests for OAuth functionality."""

import re
from unittest.mock import patch, Mock
import pytest
from atproto_oauth_authn.oauth import (
    generate_oauth_state,
    generate_code_verifier,
    generate_code_challenge,
    send_par_request,
    PARRequest,
    _send_http_request,
    _process_par_response,
)
from atproto_oauth_authn.exceptions import OauthFlowError, InvalidParameterError


def test_generate_oauth_state():
    """Test generating OAuth state."""
    state = generate_oauth_state()
    assert isinstance(state, str)
    assert len(state) > 20  # Should be reasonably long

    # Generate another to ensure they're different
    state2 = generate_oauth_state()
    assert state != state2


def test_generate_code_verifier():
    """Test generating code verifier."""
    verifier = generate_code_verifier()
    assert isinstance(verifier, str)
    assert len(verifier) == 128  # Default length

    # Test with custom length
    verifier2 = generate_code_verifier(64)
    assert len(verifier2) == 64

    # Verify it's URL-safe base64
    assert re.match(r"^[A-Za-z0-9_-]+$", verifier)


def test_generate_code_verifier_invalid_length():
    """Test code verifier with invalid length."""
    with pytest.raises(InvalidParameterError):
        generate_code_verifier(42)  # Too short

    with pytest.raises(InvalidParameterError):
        generate_code_verifier(129)  # Too long


def test_generate_code_challenge():
    """Test generating code challenge from verifier."""
    verifier = "test_verifier"
    challenge = generate_code_challenge(verifier)

    assert isinstance(challenge, str)
    assert re.match(r"^[A-Za-z0-9_-]+$", challenge)  # URL-safe base64
    assert challenge != verifier  # Should be transformed


def test_par_request_validation():
    """Test PARRequest validation."""
    # Test valid request
    request = PARRequest(
        par_endpoint="https://auth.example.com/par",
        code_challenge="challenge123",
        state="state123",
        client_id="client123",
        redirect_uri="https://app.example.com/callback",
    )
    request.validate()  # Should not raise

    # Test missing required field
    invalid_request = PARRequest(
        par_endpoint="",  # Empty endpoint
        code_challenge="challenge123",
        state="state123",
        client_id="client123",
        redirect_uri="https://app.example.com/callback",
    )
    with pytest.raises(InvalidParameterError):
        invalid_request.validate()


def test_par_request_to_form_params():
    """Test PARRequest form parameter conversion."""
    request = PARRequest(
        par_endpoint="https://auth.example.com/par",
        code_challenge="challenge123",
        state="state123",
        client_id="client123",
        redirect_uri="https://app.example.com/callback",
        login_hint="user.example.com",
    )

    params = request.to_form_params()

    expected_params = {
        "response_type": "code",
        "code_challenge_method": "S256",
        "scope": "atproto transition:generic",
        "client_id": "client123",
        "redirect_uri": "https://app.example.com/callback",
        "code_challenge": "challenge123",
        "state": "state123",
        "login_hint": "user.example.com",
    }

    assert params == expected_params


def test_process_par_response():
    """Test PAR response processing."""
    # Test successful response
    response_data = {
        "request_uri": "urn:ietf:params:oauth:request_uri:example",
        "expires_in": 60,
    }

    request_uri, expires_in = _process_par_response(response_data)
    assert request_uri == "urn:ietf:params:oauth:request_uri:example"
    assert expires_in == 60

    # Test missing request_uri
    with pytest.raises(OauthFlowError):
        _process_par_response({})


@patch("atproto_oauth_authn.oauth.httpx.post")
def test_send_http_request_success(mock_post):
    """Test successful HTTP request."""
    mock_response = Mock()
    mock_response.json.return_value = {"request_uri": "test_uri", "expires_in": 60}
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    result = _send_http_request("https://example.com", {"param": "value"})

    assert result == {"request_uri": "test_uri", "expires_in": 60}
    mock_post.assert_called_once_with("https://example.com", data={"param": "value"})


@patch("atproto_oauth_authn.oauth.httpx.post")
@patch("atproto_oauth_authn.oauth.is_safe_url")
def test_send_par_request_success(mock_safe_url, mock_post):
    """Test successful PAR request."""
    mock_safe_url.return_value = True

    mock_response = Mock()
    mock_response.json.return_value = {
        "request_uri": "urn:ietf:params:oauth:request_uri:example",
        "expires_in": 60,
    }
    mock_response.raise_for_status.return_value = None
    mock_post.return_value = mock_response

    result = send_par_request(
        par_endpoint="https://auth.example.com/par",
        code_challenge="challenge123",
        state="state123",
        login_hint="user.example.com",
        client_id="client123",
        redirect_uri="https://app.example.com/callback",
    )

    assert result == ("urn:ietf:params:oauth:request_uri:example", 60)
    mock_post.assert_called_once()


def test_send_par_request_missing_params():
    """Test error handling for missing required parameters."""
    with pytest.raises(InvalidParameterError):
        send_par_request(
            par_endpoint="https://auth.example.com/par",
            code_challenge="challenge123",
            state="state123",
            # Missing client_id and redirect_uri
        )
