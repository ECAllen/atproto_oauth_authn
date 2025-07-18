"""Tests for metadata retrieval functions."""

import pytest
from unittest.mock import patch

from atproto_oauth_authn.metadata import (
    get_pds_metadata,
    extract_auth_server,
    get_auth_server_metadata
)
from atproto_oauth_authn.exceptions import MetadataError


@patch('atproto_oauth_authn.metadata.requests.get')
def test_get_pds_metadata(mock_get, mock_response, sample_pds_metadata):
    """Test retrieving PDS metadata."""
    mock_get.return_value = mock_response(sample_pds_metadata)
    
    result = get_pds_metadata("https://example.pds.com")
    assert result == sample_pds_metadata
    mock_get.assert_called_once_with(
        "https://example.pds.com/.well-known/atproto-wellknown",
        timeout=10
    )


@patch('atproto_oauth_authn.metadata.requests.get')
def test_get_pds_metadata_error(mock_get, mock_response):
    """Test error handling when retrieving PDS metadata."""
    mock_get.return_value = mock_response({}, status_code=404)
    
    with pytest.raises(MetadataError):
        get_pds_metadata("https://example.pds.com")


def test_extract_auth_server(sample_pds_metadata):
    """Test extracting auth server from PDS metadata."""
    auth_servers = extract_auth_server(sample_pds_metadata)
    assert auth_servers == ["https://auth.example.com"]


def test_extract_auth_server_missing_auth():
    """Test error handling when auth info is missing from PDS metadata."""
    metadata = {"did": "did:plc:abcdefghijklmnopqrstuvwxyz"}
    
    with pytest.raises(MetadataError):
        extract_auth_server(metadata)


@patch('atproto_oauth_authn.metadata.requests.get')
def test_get_auth_server_metadata(mock_get, mock_response, sample_auth_server_metadata):
    """Test retrieving auth server metadata."""
    mock_get.return_value = mock_response(sample_auth_server_metadata)
    
    result = get_auth_server_metadata(["https://auth.example.com"])
    assert result == sample_auth_server_metadata
    mock_get.assert_called_once_with(
        "https://auth.example.com/.well-known/oauth-authorization-server",
        timeout=10
    )


@patch('atproto_oauth_authn.metadata.requests.get')
def test_get_auth_server_metadata_fallback(mock_get, mock_response, sample_auth_server_metadata):
    """Test fallback to openid-configuration when oauth-authorization-server fails."""
    # First request fails
    mock_get.side_effect = [
        mock_response({}, status_code=404),
        mock_response(sample_auth_server_metadata)
    ]
    
    result = get_auth_server_metadata(["https://auth.example.com"])
    assert result == sample_auth_server_metadata
    assert mock_get.call_count == 2


@patch('atproto_oauth_authn.metadata.requests.get')
def test_get_auth_server_metadata_multiple_servers(mock_get, mock_response, sample_auth_server_metadata):
    """Test trying multiple auth servers when the first one fails."""
    # First server fails completely, second succeeds
    mock_get.side_effect = [
        mock_response({}, status_code=404),
        mock_response({}, status_code=404),
        mock_response(sample_auth_server_metadata)
    ]
    
    result = get_auth_server_metadata([
        "https://auth1.example.com",
        "https://auth2.example.com"
    ])
    assert result == sample_auth_server_metadata
    assert mock_get.call_count == 3


@patch('atproto_oauth_authn.metadata.requests.get')
def test_get_auth_server_metadata_all_fail(mock_get, mock_response):
    """Test error handling when all auth servers fail."""
    mock_get.return_value = mock_response({}, status_code=404)
    
    with pytest.raises(MetadataError):
        get_auth_server_metadata(["https://auth.example.com"])
