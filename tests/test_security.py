"""Tests for security functions."""

from atproto_oauth_authn.security import is_safe_url, KNOWN_AT_PROTOCOL_DOMAINS
from atproto_oauth_authn.exceptions import SecurityError
import pytest


def test_is_safe_url_with_known_domains():
    """Test that URLs from known domains are considered safe."""
    for domain in KNOWN_AT_PROTOCOL_DOMAINS:
        assert is_safe_url(f"https://{domain}/path") is True


def test_is_safe_url_with_subdomains():
    """Test that subdomains of known domains are considered safe."""
    assert is_safe_url("https://sub.bsky.social/path") is True
    assert is_safe_url("https://api.bsky.app/xrpc/path") is True


def test_is_safe_url_with_unknown_domains():
    """Test that URLs from unknown domains are considered unsafe."""
    assert is_safe_url("https://example.com/path") is False
    assert is_safe_url("https://malicious-site.com/path") is False


def test_is_safe_url_with_non_https():
    """Test that non-HTTPS URLs are considered unsafe."""
    with pytest.raises(SecurityError):
        is_safe_url("http://bsky.social/path")


def test_is_safe_url_with_invalid_urls():
    """Test that invalid URLs are considered unsafe."""
    with pytest.raises(SecurityError):
        is_safe_url("not-a-url")
    with pytest.raises(SecurityError):
        is_safe_url("")
    with pytest.raises(SecurityError):
        is_safe_url("ftp://bsky.social/path")


def test_is_safe_url_with_ip_addresses():
    """Test that IP addresses are considered unsafe."""
    with pytest.raises(SecurityError):
        is_safe_url("https://127.0.0.1/path")
    with pytest.raises(SecurityError):
        is_safe_url("https://192.168.1.1/path")
    with pytest.raises(SecurityError):
        is_safe_url("https://[::1]/path")
