"""Tests for identity resolution functions."""

# The DNS-failure decorator param is unused when only its side_effect (not
# the mock itself) drives the test — that's a normal @patch pattern, not a
# real unused-argument bug.
# pylint: disable=unused-argument

from unittest.mock import patch, Mock
import dns.exception
import dns.resolver
import httpx
import pytest
from atproto_oauth_authn.identity import resolve_identity
from atproto_oauth_authn.exceptions import IdentityResolutionError, SecurityError


def _txt_answer(value: str):
    """Build a dns.resolver.resolve()-shaped return value for a single TXT record."""
    rdata = Mock()
    rdata.strings = [value.encode("utf-8")]
    return [rdata]


def test_resolve_identity_with_did():
    """Test that DIDs are returned as-is."""
    did = "did:plc:abcdefghijklmnopqrstuvwxyz"
    assert resolve_identity(did) == did


def test_resolve_identity_with_invalid_did():
    """Test that invalid DIDs raise an error."""
    with pytest.raises(IdentityResolutionError):
        resolve_identity("did:invalid")


def test_resolve_identity_with_invalid_handle():
    """Test that invalid handles raise an error."""
    with pytest.raises(IdentityResolutionError):
        resolve_identity("not-a-valid-handle")


@patch("atproto_oauth_authn.identity.dns.resolver.resolve")
def test_resolve_identity_via_dns_txt(mock_resolve):
    """A `_atproto.<handle>` TXT record of `did=...` resolves the handle,
    without ever falling through to the well-known HTTPS method."""
    mock_resolve.return_value = _txt_answer("did=did:plc:abcdefghijklmnopqrstuvwxyz")

    with patch("atproto_oauth_authn.identity.httpx.get") as mock_get:
        result = resolve_identity("alice.bsky.social")

    assert result == "did:plc:abcdefghijklmnopqrstuvwxyz"
    mock_resolve.assert_called_once_with("_atproto.alice.bsky.social", "TXT", lifetime=5.0)
    mock_get.assert_not_called()


@patch("atproto_oauth_authn.identity.httpx.get")
@patch("atproto_oauth_authn.identity.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
def test_resolve_identity_falls_back_to_well_known(mock_resolve, mock_get):
    """When the DNS TXT record is absent, resolution falls back to the
    HTTPS well-known method."""
    mock_get.return_value = httpx.Response(
        200, text="did:plc:abcdefghijklmnopqrstuvwxyz",
        request=httpx.Request("GET", "https://alice.example.com/.well-known/atproto-did"),
    )

    result = resolve_identity("alice.example.com")

    assert result == "did:plc:abcdefghijklmnopqrstuvwxyz"
    mock_get.assert_called_once()
    called_url = mock_get.call_args.args[0]
    assert called_url == "https://alice.example.com/.well-known/atproto-did"


@patch(
    "atproto_oauth_authn.identity.dns.resolver.resolve",
    side_effect=dns.exception.DNSException(),
)
def test_resolve_identity_dns_txt_malformed_did_falls_back(mock_resolve):
    """A TXT record present but not a well-formed `did=<valid DID>` is
    treated the same as no record — falls back to well-known."""
    with patch("atproto_oauth_authn.identity.httpx.get") as mock_get:
        mock_get.return_value = httpx.Response(
            200, text="did:plc:abcdefghijklmnopqrstuvwxyz",
            request=httpx.Request("GET", "https://alice.example.com/.well-known/atproto-did"),
        )
        result = resolve_identity("alice.example.com")
    assert result == "did:plc:abcdefghijklmnopqrstuvwxyz"


@patch("atproto_oauth_authn.identity.httpx.get")
@patch("atproto_oauth_authn.identity.dns.resolver.resolve", side_effect=dns.resolver.NoAnswer())
def test_resolve_identity_both_methods_fail_raises(mock_resolve, mock_get):
    """If neither DNS TXT nor well-known produce a DID, resolution fails
    with IdentityResolutionError (not a raw exception from either method)."""
    mock_get.return_value = httpx.Response(
        404, text="404 page not found",
        request=httpx.Request("GET", "https://nonexistent.example.com/.well-known/atproto-did"),
    )

    with pytest.raises(IdentityResolutionError):
        resolve_identity("nonexistent.example.com")


@patch("atproto_oauth_authn.identity.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
def test_resolve_identity_well_known_non_did_body_fails(mock_resolve):
    """A 200 response whose body isn't a valid DID is not treated as a match."""
    with patch("atproto_oauth_authn.identity.httpx.get") as mock_get:
        mock_get.return_value = httpx.Response(
            200, text="<html>not a did</html>",
            request=httpx.Request(
                "GET", "https://alice.example.com/.well-known/atproto-did"
            ),
        )
        with pytest.raises(IdentityResolutionError):
            resolve_identity("alice.example.com")


@patch("atproto_oauth_authn.identity.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
def test_resolve_identity_well_known_security_error_propagates(mock_resolve):
    """An SSRF-rejected well-known URL must propagate as SecurityError, not
    be swallowed as an ordinary resolution failure."""
    with patch(
        "atproto_oauth_authn.identity.valid_url", side_effect=SecurityError("rejected")
    ):
        with pytest.raises(SecurityError):
            resolve_identity("alice.example.com")
