
# TODOs

- implement guidelines outlined in the reference here: https://github.com/bluesky-social/proposals/tree/main/0004-oauth

## Leftovers from exception-handling / lint cleanup (2026-07-14)

### Bugs / correctness
- [x] Fix typo in `build_client_config` (oauth.py): localhost redirect_uri
  was `http://127.0.01/oauth/callback` (missing digit) — fixed to
  `127.0.0.1`, regression test added (2026-08-11).
- [x] `resolve_user_did` (authn.py) docstring said it returns the PDS URL
  but it returns a `(pds_url, user_did)` tuple — docstring corrected
  (2026-08-11).
- `auth_server_post` never calls `raise_for_status()` — it returns error
  responses silently and every caller must remember to check; decide whether
  it should raise like the other request helpers.
  **Not fixed yet** — `auth_server_post` is what Cards' `/auth/logout`
  calls for token revocation. Making it raise on a non-2xx would turn a
  failed-revocation-at-the-auth-server into an unhandled 500 during logout
  instead of the current silent-log-and-continue. Needs a decision (and a
  matching update in Cards' `modules/auth.py`) before changing, not a
  same-sitting fix.
- Handle resolution in `identity.py` queries the handle's own domain for the
  `com.atproto.identity.resolveHandle` XRPC call; that assumption breaks for
  handles whose domain doesn't host a PDS/appview (works for *.bsky.social).
  **Not fixed yet** — the spec-correct fix (DNS TXT `_atproto.<handle>`
  lookup, falling back to `https://<handle>/.well-known/atproto-did`) is a
  real behavior change to how every login resolves a handle, including
  `*.statmeet.com` handles in production. Wants its own verification pass
  against real handles before landing, not a drive-by fix.

### Design decisions deferred
- `valid_url` rejects URLs with an explicit port (`may_have_port=False`) —
  will break self-hosted PDS instances on nonstandard ports; relax if needed
- Domain whitelist (`KNOWN_AT_PROTOCOL_DOMAINS`) is now warn-only since AT
  Protocol is federated; decide whether to keep, expand, or remove it
- `initial_token_request` re-fetches auth server metadata on every call
  (in-code TODO: "is this necessary?")
- Re-org atproto-specific helpers out of authn.py (in-code TODO)

### Packaging / housekeeping
- Move `pytest`/`pytest-cov` from runtime `dependencies` to a dev group in
  pyproject.toml; remove `requests` (imported nowhere, httpx is used)
- Remove duplicated NullHandler/`__version__` block in `__init__.py`
  (lines repeated twice)
- Add `.DS_Store` to .gitignore
- GitHub Actions workflows (Pylint, Ruff, Tests) are manually disabled on
  GitHub — re-enable via Actions tab when wanted; local runs are green
  (pylint 10/10, ruff clean, 72 tests passing)
