"""Tests for OAuth functionality."""

import pytest
import re
from unittest.mock import patch, MagicMock
from base64 import urlsafe_b64decode

from atproto_oauth_authn.oauth import (
    generate_oauth_state,
    generate_code_verifier,
    generate_code_challenge,
    send_par_request
)
from atproto_oauth_authn.exceptions import OauthFlowError


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
    assert re.match(r'^[A-Za-z0-9_-]+$', verifier)


def test_generate_code_challenge():
    """Test generating code challenge from verifier."""
    verifier = "test_verifier"
    challenge = generate_code_challenge(verifier)
    
    assert isinstance(challenge, str)
    assert re.match(r'^[A-Za-z0-9_-]+$', challenge)  # URL-safe base64
    assert challenge != verifier  # Should be transformed


@patch('atproto_oauth_authn.oauth.requests.post')
def test_send_par_request_success(mock_post, mock_response):
    """Test successful PAR request."""
    mock_post.return_value = mock_response({
        "request_uri": "urn:ietf:params:oauth:request_uri:example",
        "expires_in": 60
    })
    
    result = send_par_request(
        par_endpoint="https://auth.example.com/par",
        code_challenge="challenge123",
        state="state123",
        login_hint="user.example.com",
        client_id="client123",
        redirect_uri="https://app.example.com/callback"
    )
    
    assert result == "urn:ietf:params:oauth:request_uri:example"
    mock_post.assert_called_once()


@patch('atproto_oauth_authn.oauth.requests.post')
def test_send_par_request_error(mock_post, mock_response):
    """Test error handling in PAR request."""
    mock_post.return_value = mock_response(
        {"error": "invalid_request"},
        status_code=400
    )
    
    with pytest.raises(OauthFlowError):
        send_par_request(
            par_endpoint="https://auth.example.com/par",
            code_challenge="challenge123",
            state="state123"
        )


@patch('atproto_oauth_authn.oauth.requests.post')
def test_send_par_request_missing_response(mock_post, mock_response):
    """Test error handling when PAR response is missing required fields."""
    mock_post.return_value = mock_response({})  # Missing request_uri
    
    with pytest.raises(OauthFlowError):
        send_par_request(
            par_endpoint="https://auth.example.com/par",
            code_challenge="challenge123",
            state="state123"
        )
