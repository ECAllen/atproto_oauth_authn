"""Pytest configuration and fixtures for atproto-oauth-authn tests."""

import json
import pytest
from typing import Dict, Any


@pytest.fixture
def mock_response():
    """Create a mock response object with customizable status code and json content."""

    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
            self.text = json.dumps(json_data)
            self.content = json.dumps(json_data).encode("utf-8")

        def json(self):
            return self.json_data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP Error: {self.status_code}")
            return self

    return MockResponse


@pytest.fixture
def sample_did_document() -> Dict[str, Any]:
    """Return a sample DID document for testing."""
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:plc:abcdefghijklmnopqrstuvwxyz",
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://example.pds.com",
            }
        ],
    }


@pytest.fixture
def sample_pds_metadata() -> Dict[str, Any]:
    """Return a sample PDS metadata response for testing."""
    return {
        "did": "did:plc:abcdefghijklmnopqrstuvwxyz",
        "availableUserDomains": ["example.com"],
        "links": {
            "termsOfService": "https://example.com/tos",
            "privacyPolicy": "https://example.com/privacy",
        },
        "auth": {
            "oauth2": {
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "par_endpoint": "https://auth.example.com/par",
                "revocation_endpoint": "https://auth.example.com/revoke",
            }
        },
    }


@pytest.fixture
def sample_auth_server_metadata() -> Dict[str, Any]:
    """Return a sample auth server metadata response for testing."""
    return {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "pushed_authorization_request_endpoint": "https://auth.example.com/par",
        "revocation_endpoint": "https://auth.example.com/revoke",
        "scopes_supported": ["atproto", "transition:generic"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }
