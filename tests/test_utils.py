"""Tests for utility functions."""

import pytest
from atproto_oauth_authn.utils import build_auth_url


def test_build_auth_url():
    """Test building an authorization URL."""
    auth_endpoint = "https://auth.example.com/authorize"
    client_id = "client123"
    request_uri = "urn:ietf:params:oauth:request_uri:example"
    
    url = build_auth_url(auth_endpoint, client_id, request_uri)
    
    assert url.startswith(auth_endpoint)
    assert f"client_id={client_id}" in url
    assert f"request_uri={request_uri}" in url
    assert "response_type=code" in url


def test_build_auth_url_with_special_chars():
    """Test building an authorization URL with special characters."""
    auth_endpoint = "https://auth.example.com/authorize"
    client_id = "client+123"
    request_uri = "urn:ietf:params:oauth:request_uri:example/123"
    
    url = build_auth_url(auth_endpoint, client_id, request_uri)
    
    # Check that special characters are properly URL-encoded
    assert "client%2B123" in url
    assert "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aexample%2F123" in url
