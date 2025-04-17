# OAuth Authentication for AT Protocol / Bluesky Social

A Python library for implementing OAuth authentication with the AT Protocol (Bluesky Social).

**Status: Under development - API may change**

This library implements the AT Protocol OAuth authentication flow as [documented in the specification](https://atproto.com/specs/oauth#identity-authentication).

## Features

- Handle resolution to DID
- DID document retrieval
- PDS metadata retrieval
- OAuth authorization flow with PKCE
- Pushed Authorization Requests (PAR)
- Security protections against SSRF attacks
- Comprehensive error handling
- Detailed logging

## Installation

```bash
pip install atproto-oauth-authn
```

## Quick Start

```python
import atproto_oauth_authn
import webbrowser

# Get the authentication URL for a user
auth_url = atproto_oauth_authn.get_authn_url(
    username="your.handle.bsky.social",
    app_url="your-app.example.com"
)

# Open the browser with the authorization URL
webbrowser.open(auth_url)
```

## Authentication Flow

1. Resolve a user's handle to their DID
2. Retrieve the DID document
3. Extract the PDS URL from the DID document
4. Get the PDS server metadata
5. Extract the authorization server URL
6. Get the authorization server metadata
7. Generate PKCE code verifier and challenge
8. Send a Pushed Authorization Request (PAR)
9. Redirect the user to the authorization URL
10. Handle the callback with the authorization code
11. Exchange the code for access and refresh tokens

## Example

See the `examples/bluesky_social_auth.py` file for a complete example of the authentication flow.

To run the example:

1. Create a `.env` file with:

```
USERNAME=your.handle.bsky.social
APP_URL=your-app.example.com
```

2. Run the example:

```bash
python examples/bluesky_social_auth.py
```

## Security

This library implements several security measures:

- PKCE (Proof Key for Code Exchange) for OAuth
- CSRF protection with state parameters
- SSRF protection for all HTTP requests
- Input validation
- Comprehensive error handling

## Error Handling

The library uses a hierarchy of custom exceptions:

- `AtprotoOauthError`: Base exception for all errors
- `IdentityResolutionError`: Failed to resolve a user identity
- `DidDocumentError`: Error retrieving or parsing DID document
- `MetadataError`: Error retrieving or parsing metadata
- `OauthFlowError`: Error during OAuth flow
- `SecurityError`: Security-related error
- `InvalidParameterError`: Invalid parameter provided to a function

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
