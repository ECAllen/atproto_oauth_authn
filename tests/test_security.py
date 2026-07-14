"""Tests for security functions."""

import httpx
import pytest

from atproto_oauth_authn.exceptions import SecurityError
from atproto_oauth_authn.security import (
    KNOWN_AT_PROTOCOL_DOMAINS,
    _is_internal_hostname,
    _is_known_domain,
    create_hardened_client,
    valid_url,
    validate_scheme,
)


def test_valid_url_accepts_known_domains():
    """URLs on known AT Protocol domains pass validation without raising."""
    for domain in KNOWN_AT_PROTOCOL_DOMAINS:
        valid_url(f"https://{domain}/path")


def test_valid_url_accepts_subdomains():
    """Subdomains of known domains pass validation without raising."""
    valid_url("https://sub.bsky.social/path")
    valid_url("https://api.bsky.app/xrpc/path")


def test_valid_url_accepts_unknown_https_domains(caplog):
    """Unknown domains are allowed (federated protocol) but logged."""
    with caplog.at_level("WARNING"):
        valid_url("https://example.com/path")
    assert "not a known AT Protocol domain" in caplog.text


def test_valid_url_rejects_non_https():
    """Non-HTTPS URLs are rejected."""
    with pytest.raises(SecurityError):
        valid_url("http://bsky.social/path")
    with pytest.raises(SecurityError):
        valid_url("ftp://bsky.social/path")


def test_valid_url_rejects_invalid_urls():
    """Malformed URLs are rejected."""
    with pytest.raises(SecurityError):
        valid_url("not-a-url")
    with pytest.raises(SecurityError):
        valid_url("")


def test_valid_url_rejects_ip_addresses():
    """IP-literal hosts are rejected."""
    with pytest.raises(SecurityError):
        valid_url("https://127.0.0.1/path")
    with pytest.raises(SecurityError):
        valid_url("https://192.168.1.1/path")
    with pytest.raises(SecurityError):
        valid_url("https://[::1]/path")


def test_valid_url_rejects_internal_hostnames():
    """Internal/reserved hostnames are rejected."""
    with pytest.raises(SecurityError):
        valid_url("https://localhost/path")
    with pytest.raises(SecurityError):
        valid_url("https://myhost.local/path")
    with pytest.raises(SecurityError):
        valid_url("https://service.internal/path")
    with pytest.raises(SecurityError):
        valid_url("https://resolver.arpa/path")


def test_valid_url_rejects_embedded_credentials():
    """URLs carrying userinfo credentials are rejected."""
    with pytest.raises(SecurityError):
        valid_url("https://user:pass@bsky.social/path")
    with pytest.raises(SecurityError):
        valid_url("https://user@bsky.social/path")


def test_valid_url_rejects_explicit_port():
    """URLs with an explicit port are rejected."""
    with pytest.raises(SecurityError):
        valid_url("https://bsky.social:8080/path")


def test_validate_scheme():
    """Only https is an acceptable scheme."""
    assert validate_scheme("https") is True
    assert validate_scheme("http") is False
    assert validate_scheme("ftp") is False


def test_is_known_domain():
    """Known-domain matching covers exact domains and subdomains."""
    assert _is_known_domain("bsky.social")
    assert _is_known_domain("sub.bsky.social")
    assert not _is_known_domain("example.com")
    assert not _is_known_domain("notbsky.social")


def test_is_internal_hostname():
    """Internal hostname detection."""
    assert _is_internal_hostname("localhost")
    assert _is_internal_hostname("myhost.local")
    assert _is_internal_hostname("service.internal")
    assert _is_internal_hostname("resolver.arpa")
    assert not _is_internal_hostname("bsky.social")


def test_create_hardened_client():
    """The hardened client disables redirects and is a real httpx client."""
    client = create_hardened_client()
    try:
        assert isinstance(client, httpx.Client)
        assert client.follow_redirects is False
    finally:
        client.close()
