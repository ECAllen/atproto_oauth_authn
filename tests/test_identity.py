"""Tests for identity resolution functions."""

import pytest
from unittest.mock import patch

from atproto_oauth_authn.identity import resolve_identity
from atproto_oauth_authn.exceptions import IdentityResolutionError


def test_resolve_identity_with_did():
    """Test that DIDs are returned as-is."""
    did = "did:plc:abcdefghijklmnopqrstuvwxyz"
    assert resolve_identity(did) == did


def test_resolve_identity_with_invalid_did():
    """Test that invalid DIDs raise an error."""
    with pytest.raises(IdentityResolutionError):
        resolve_identity("did:invalid")


@patch('atproto_oauth_authn.identity.requests.get')
def test_resolve_identity_with_handle(mock_get, mock_response):
    """Test that handles are resolved to DIDs."""
    mock_get.return_value = mock_response({
        "did": "did:plc:abcdefghijklmnopqrstuvwxyz"
    })
    
    result = resolve_identity("user.example.com")
    assert result == "did:plc:abcdefghijklmnopqrstuvwxyz"
    mock_get.assert_called_once()


@patch('atproto_oauth_authn.identity.requests.get')
def test_resolve_identity_with_handle_error(mock_get, mock_response):
    """Test that handle resolution errors are handled properly."""
    mock_get.return_value = mock_response({}, status_code=404)
    
    with pytest.raises(IdentityResolutionError):
        resolve_identity("nonexistent.example.com")


def test_resolve_identity_with_invalid_handle():
    """Test that invalid handles raise an error."""
    with pytest.raises(IdentityResolutionError):
        resolve_identity("not-a-valid-handle")
