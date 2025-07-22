"""Custom exceptions for AT Protocol OAuth."""


class AtprotoOauthError(Exception):
    """Base exception for all atproto-oauth-authn errors."""


class IdentityResolutionError(AtprotoOauthError):
    """Failed to resolve a user identity."""


class DidDocumentError(AtprotoOauthError):
    """Error retrieving or parsing DID document."""


class MetadataError(AtprotoOauthError):
    """Error retrieving or parsing metadata."""


class OauthFlowError(AtprotoOauthError):
    """Error during OAuth flow."""


class SecurityError(AtprotoOauthError):
    """Security-related error."""


class InvalidParameterError(AtprotoOauthError):
    """Invalid parameter provided to a function."""
