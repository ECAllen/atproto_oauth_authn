"""Custom exceptions for AT Protocol OAuth."""


class AtprotoOauthError(Exception):
    """Base exception for all atproto-oauth-authn errors."""

    pass


class IdentityResolutionError(AtprotoOauthError):
    """Failed to resolve a user identity."""

    pass


class DidDocumentError(AtprotoOauthError):
    """Error retrieving or parsing DID document."""

    pass


class MetadataError(AtprotoOauthError):
    """Error retrieving or parsing metadata."""

    pass


class OauthFlowError(AtprotoOauthError):
    """Error during OAuth flow."""

    pass


class SecurityError(AtprotoOauthError):
    """Security-related error."""

    pass


class InvalidParameterError(AtprotoOauthError):
    """Invalid parameter provided to a function."""

    pass
