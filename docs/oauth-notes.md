# OAuth Notes

## Resources

<https://atproto.com/specs/oauth#identity-authentication>

<https://dev.to/pipodev/bluesky-oauth2-client-with-vanilla-javascript-1f6h>

<https://github.com/bluesky-social/cookbook/tree/main/python-oauth-web-app>

<https://github.com/bluesky-social/atproto/discussions/3075>

<https://docs.bsky.app/blog/oauth-atproto>

<https://github.com/pilcrowonpaper/atproto-oauth-example/tree/main>

<https://github.com/bluesky-social/proposals/tree/main/0004-oauth>

<https://post-pulse.com/oauth/jwks.json>

<https://medium.com/@sas.pogorelov/oauth-in-a-decentralized-environment-case-study-of-bluesky-f215cdbcadda>

## Steps

1) get users handle from form

2) retrieve the users DID

```javascript
    // ------------------------------------------
    //   Javascript
    // ------------------------------------------
    const USER_HANDLE = "madrilenyer.bsky.social";
    const APP_CLIENT_ID = "https://madrilenyer.neocities.org/bsky/oauth/client-metadata.json";
    const APP_CALLBACK_URL = "https://madrilenyer.neocities.org/bsky/oauth/callback/";

    let userDid = null;

    let url = "https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=" + USER_HANDLE;
    fetch( url ).then( response => {
        // Process the HTTP Response
        return response.json();
    }).then( data => {
        // Process the HTTP Response Body
        // Here, we gather the "did" item in the received json.
        userDid = data.did;
    });
```

3) retrieve the user DID document

We do this calling a specific API EndPoint (<https://plc.directory/>) followed with the user's did ("did:plc:tjc27aje4uwxtw5ab6wwm4km");

```javascript
    // ------------------------------------------
    //   Javascript
    // ------------------------------------------
    let userDidDocument = null;
    let userPDSURL = null;

    let url = "https://plc.directory/" + USER_HANDLE;
    fetch( url ).then( response => {
        // Process the HTTP Response
        return response.json();
    }).then( data => {
        // Process the HTTP Response Body
        userDidDocument = data;
        userPDSURL = userDidDocument.service[0].serviceEndpoint;
    });
```

4) get the URL of the PDS server from the DID doc

5) get the PDS server metadata, example:  <https://velvetfoot.us-east.host.bsky.network/.well-known/oauth-protected-resource>.

6) from the metadata extract the authorization server

7) get the metadata of the authorization server

authorization_endpoint: We will need this URL to request authorization to access to the user's token. In this case, this entry is: <https://bsky.social/oauth/authorize>

token_endpoint: This is the URL to request the user's access token In this case, this entry is: <https://bsky.social/oauth/token>

pushed_authorization_request_endpoint (PAR EndPoint): A "preRequirement". All calls to the Authorization Server, trying to obtain an user's token, must be validated, as per RFC 9126 In this
case, this entry is: <https://bsky.social/oauth/par>

```javascript
    // ------------------------------------------
    //   Javascript
    // ------------------------------------------
    let userAuthServerDiscovery = null;
    let userAuthorizationEndPoint = null;
    let userTokenEndPoint = null;
    let userPAREndPoint = null;

    let url = userAuthServerURL + "/.well-known/oauth-authorization-server";
    fetch( url ).then( response => {
        // Process the HTTP Response
        return response.json();
    }).then( data => {
        // Process the HTTP Response Body
        userAuthServerDiscovery   = data;
        userAuthorizationEndPoint = userAuthServerDiscovery.authorization_endpoint;
        userTokenEndPoint         = userAuthServerDiscovery.token_endpoint;
        userPAREndPoint           = userAuthServerDiscovery.pushed_authorization_request_endpoint;
    });
```

8) PAR Authorization POST to the pushed_authorization_request_endpoint (PAR EndPoint)

  response_type=code
    &code_challenge_method=S256
    &scope=atproto+transition%3Ageneric
    &client_id=https%3A%2F%2Fmadrilenyer.neocities.org%2Fbsky%2Foauth%2Fclient-metadata.json
    &redirect_uri=https%3A%2F%2Fmadrilenyer.neocities.org%2Fbsky%2Foauth%2Fcallback%2F
    &code_challenge=URQ-2arwHpJzNwcFPng-_IE3gRGGBN0SVoFMN7wEiWI
    &state=2e94cf77e8b0ba2209dc6dcb90018c8d044ac31cb526fc4823278585
    &login_hint=madrilenyer.bsky.social
9) from the response extract the request_uri
10) get the nonce from the response header
```javascript
dpopNonce = response.headers.get( "dpop-nonce" );
```

11) build URL for authentication

```javascript
let url = userAuthorizationEndPoint;
   url += "?client_id=" + encodeURIComponent( APP_CLIENT_ID );
   url += "&request_uri=" + encodeURIComponent( userAuthServerRequestURI );
```

12) Bluesky OAuth page then redirects to the "redirect_uri" in the PAR request

13) extract parameters from the URL after user lands on the callback page

iss: The "Authority"; in this case, the URL of the Bluesky Authorization Server

state: The "state" parameter we send before in the PAR Request, and
State

The state parameter should be a random string that is unpredictable and unique for each authorization request
It should be at least 32 bytes (converted to a hex or base64 string)
It serves as a CSRF (Cross-Site Request Forgery) protection mechanism
The client application must store this value and validate it when receiving the authorization response

code: A (one single use) code that the application needs to retrieves the user's access token from the server.

<https://madrilenyer.neocities.org/bsky/oauth/callback/>
    ?iss=https%3A%2F%2Fbsky.social
    &state=4e47aaac8cbd35ed1a2afff53ce6f4511898d7c2ef0e47b37d77110f
    &code=cod-b17f75f356b83f35e99c4d7664ed30442a9c79c5c37ecf88261d77db799d0c0f

```javascript
 // Retrieve the "search" part from the url
    let parsedSearch = new URLSearchParams(thisURL.search);

    // Retrieve the data.
    let receivedIss = parsedSearch.get("iss");
    let receivedState = parsedSearch.get("state");
    let receivedCode = parsedSearch.get("code");
```

14) use the DPOP-Proof to request the users token


Upon successful authorization by the user, the AS will issue an authorization code and redirect the user back to the client's redirect_uri with a code.

The client will use that code (along with PKCE), to contact the /token endpoint on the AS.

POST https://entryway.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded
DPoP: <DPOP_PROOF_JWT>

grant_type=authorization_code
&code=<AUTHORIZATION_CODE>
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
&client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fmy-app%2Foauth-callback

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
 "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
 "token_type": "DPoP",
 "expires_in": 2677,
 "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g"
}
