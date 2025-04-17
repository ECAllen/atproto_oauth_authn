# Public API exports
from .identity import resolve_identity
from .did import get_did_document, retrieve_did_document, extract_pds_url
from .metadata import (
    get_pds_metadata,
    extract_auth_server,
    get_auth_server_metadata,
)
from .oauth import (
    generate_oauth_state,
    generate_code_verifier,
    generate_code_challenge,
    send_par_request,
)
from .security import is_safe_url
from .utils import build_auth_url
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

import logging

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
    "is_safe_url",
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
