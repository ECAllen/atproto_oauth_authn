"""AT Protocol OAuth Authentication Client.

This package provides a Python client for implementing OAuth authentication
with AT Protocol services like Bluesky. It handles the complete OAuth flow
including identity resolution, DID document retrieval, metadata discovery,
and secure authentication URL generation.

Key features:
- Identity resolution (handles to DIDs)
- DID document retrieval and parsing
- PDS and authorization server metadata discovery
- OAuth 2.0 PKCE flow implementation
- Security validation for URLs and domains
- Comprehensive error handling

Example usage:
    >>> import atproto_oauth_authn
    >>> auth_url = atproto_oauth_authn.get_authn_url("user.bsky.social", "https://myapp.com")
    >>> print(auth_url)
"""

import logging
from .identity import resolve_identity
from .did import get_did_document, retrieve_did_document, extract_pds_url
from .oauth import (
    generate_oauth_state,
    generate_code_challenge,
    send_par_request,
)
from .security import valid_url
from .exceptions import (
    AtprotoOauthError,
    IdentityResolutionError,
    DidDocumentError,
    MetadataError,
    OauthFlowError,
    SecurityError,
    InvalidParameterError,
)
from .authn import get_authn_url


logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"
"""AT Protocol OAuth authentication client."""

# Set up null handler to prevent "No handler found" warnings
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Version information
__version__ = "0.1.0"


__all__ = [
    # Core functionality
    "resolve_identity",
    "get_did_document",
    "retrieve_did_document",
    "extract_pds_url",
    "get_pds_metadata",
    "extract_auth_server",
    "get_auth_server_metadata",
    "generate_oauth_state",
    "generate_code_verifier",
    "generate_code_challenge",
    "send_par_request",
    "PARRequest",
    "valid_url",
    "build_auth_url",
    "get_authn_url",
    # Exceptions
    "AtprotoOauthError",
    "IdentityResolutionError",
    "DidDocumentError",
    "MetadataError",
    "OauthFlowError",
    "SecurityError",
    "InvalidParameterError",
]
