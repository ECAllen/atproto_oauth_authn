"""Tests for metadata retrieval functions (now part of the oauth module)."""

from unittest.mock import patch, Mock

import httpx
import pytest
from atproto_oauth_authn.oauth import (
    get_pds_metadata,
    extract_auth_server,
    get_pds_auth_server_metadata,
)
from atproto_oauth_authn.exceptions import MetadataError


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_metadata(mock_get, mock_response, sample_pds_metadata):
    """Test retrieving PDS metadata."""
    mock_get.return_value = mock_response(sample_pds_metadata)

    result = get_pds_metadata("https://example.pds.com")
    assert result == sample_pds_metadata
    mock_get.assert_called_once()


def test_get_pds_metadata_missing_url():
    """Test error handling when no PDS URL is provided."""
    with pytest.raises(MetadataError):
        get_pds_metadata("")


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_metadata_http_error(mock_get, mock_response):
    """An HTTP error response is wrapped in MetadataError."""
    mock_get.return_value = mock_response({}, status_code=404)

    with pytest.raises(MetadataError):
        get_pds_metadata("https://example.pds.com")


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_metadata_network_error(mock_get):
    """A network failure is wrapped in MetadataError."""
    mock_get.side_effect = httpx.ConnectError("connection refused")

    with pytest.raises(MetadataError):
        get_pds_metadata("https://example.pds.com")


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_metadata_non_json(mock_get):
    """A non-JSON body is wrapped in MetadataError."""
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("no JSON body")
    mock_get.return_value = response

    with pytest.raises(MetadataError):
        get_pds_metadata("https://example.pds.com")


def test_extract_auth_server_standard():
    """Test extracting auth servers from standard OAuth metadata."""
    metadata = {"authorization_servers": ["https://auth.example.com"]}
    assert extract_auth_server(metadata) == ["https://auth.example.com"]


def test_extract_auth_server_fallback(sample_pds_metadata):
    """Test extracting the auth server from the AT Protocol auth.oauth2 structure."""
    assert extract_auth_server(sample_pds_metadata) == ["https://auth.example.com"]


def test_extract_auth_server_missing_auth():
    """Test error handling when auth info is missing from PDS metadata."""
    metadata = {"did": "did:plc:abcdefghijklmnopqrstuvwxyz"}

    with pytest.raises(MetadataError):
        extract_auth_server(metadata)


def test_extract_auth_server_empty_metadata():
    """Test error handling when metadata is empty."""
    with pytest.raises(MetadataError):
        extract_auth_server({})


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_auth_server_metadata(
    mock_get, mock_response, sample_auth_server_metadata
):
    """Test retrieving auth server metadata."""
    mock_get.return_value = mock_response(sample_auth_server_metadata)

    result = get_pds_auth_server_metadata(["https://auth.example.com"])
    assert result == sample_auth_server_metadata
    mock_get.assert_called_once()


def test_get_pds_auth_server_metadata_no_servers():
    """Test error handling when no auth servers are provided."""
    with pytest.raises(MetadataError):
        get_pds_auth_server_metadata([])


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_auth_server_metadata_fallback(
    mock_get, mock_response, sample_auth_server_metadata
):
    """Test fallback to the next auth server when the first one fails."""
    mock_get.side_effect = [
        mock_response({}, status_code=404),
        mock_response(sample_auth_server_metadata),
    ]

    result = get_pds_auth_server_metadata(
        ["https://auth1.example.com", "https://auth2.example.com"]
    )
    assert result == sample_auth_server_metadata
    assert mock_get.call_count == 2


@patch("atproto_oauth_authn.oauth.httpx.get")
def test_get_pds_auth_server_metadata_all_fail(mock_get, mock_response):
    """Test error handling when all auth servers fail."""
    mock_get.return_value = mock_response({}, status_code=404)

    with pytest.raises(MetadataError):
        get_pds_auth_server_metadata(["https://auth.example.com"])
