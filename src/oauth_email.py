"""
oauth_email.py

Microsoft OAuth2 (XOAUTH2) support for IMAP/SMTP — issue #725.

Personal Microsoft accounts (@hotmail / @outlook / @live) and Exchange Online
mailboxes no longer accept Basic Auth (username + password). This module
implements the OAuth2 **device code** flow — no redirect URI, so it works
headless / in Docker / behind Tailscale — plus refresh-token exchange, and
builds the SASL XOAUTH2 credential string consumed by imaplib/smtplib.

Design:
  - No new dependency: raw `requests` against the Microsoft identity platform
    v2.0 endpoints.
  - The client ID is **user-supplied** — an Azure app registration with
    "Allow public client flows" enabled and delegated IMAP.AccessAsUser.All +
    SMTP.Send + offline_access permissions. Provide it via the
    MS_OAUTH_CLIENT_ID env var or the `ms_oauth_client_id` key in
    data/settings.json. Tenant defaults to "common" (personal + work);
    override with MS_OAUTH_TENANT.
  - Refresh tokens live encrypted in email_accounts.oauth_refresh_token (the
    same Fernet path as the passwords). They rotate on each refresh, so
    `get_access_token` takes an `on_refresh` callback to persist the new one.
  - Access tokens (~1h) are cached in memory only, keyed by account id and
    guarded by a lock, so the background pollers and web requests don't
    stampede the token endpoint or race the rotating refresh token.

See docs: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
"""

import os
import json
import time
import logging
import threading
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


def _tenant() -> str:
    return os.environ.get("MS_OAUTH_TENANT", "common").strip() or "common"


def _authority() -> str:
    return f"https://login.microsoftonline.com/{_tenant()}/oauth2/v2.0"


# offline_access → refresh token; the outlook.office.com resource scopes are
# what Exchange Online validates for IMAP/SMTP XOAUTH2. openid/email identify
# the signed-in mailbox.
SCOPES = (
    "https://outlook.office.com/IMAP.AccessAsUser.All "
    "https://outlook.office.com/SMTP.Send "
    "offline_access openid email"
)

_SETTINGS_FILE = Path(__file__).resolve().parent.parent / "data" / "settings.json"

# account_id -> (access_token, expires_at_epoch)
_token_cache: dict[str, tuple[str, float]] = {}
_lock = threading.Lock()
_EXPIRY_SKEW = 300  # refresh 5 min before the token actually expires
_HTTP_TIMEOUT = 20


def resolve_client_id(explicit: str = "") -> str:
    """Resolve the Azure app client ID: explicit arg → env → settings.json."""
    if explicit and explicit.strip():
        return explicit.strip()
    env = os.environ.get("MS_OAUTH_CLIENT_ID", "").strip()
    if env:
        return env
    try:
        s = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
        return (s.get("ms_oauth_client_id") or "").strip()
    except Exception:
        return ""


def xoauth2_string(user: str, access_token: str) -> str:
    """Build the SASL XOAUTH2 initial-response string for IMAP/SMTP."""
    return f"user={user}\x01auth=Bearer {access_token}\x01\x01"


def start_device_flow(client_id: str) -> dict:
    """Begin the device code flow. Returns the raw Microsoft payload:
    device_code, user_code, verification_uri, expires_in, interval, message."""
    if not client_id:
        raise ValueError("No Microsoft OAuth client ID configured (set MS_OAUTH_CLIENT_ID)")
    r = requests.post(
        f"{_authority()}/devicecode",
        data={"client_id": client_id, "scope": SCOPES},
        timeout=_HTTP_TIMEOUT,
    )
    if r.status_code != 200:
        # Surface the AADSTS error_description from the body — a bare
        # "400 Bad Request" hides the real cause (public-client flows off,
        # wrong tenant, unknown client id, etc.).
        detail = ""
        try:
            j = r.json()
            detail = j.get("error_description") or j.get("error") or ""
        except Exception:
            detail = (r.text or "")[:300]
        # First line of error_description carries the AADSTSxxxxx code.
        first = detail.splitlines()[0] if detail else f"HTTP {r.status_code}"
        raise RuntimeError(f"Microsoft sign-in error: {first}")
    return r.json()


def poll_device_flow(client_id: str, device_code: str) -> dict:
    """Poll once for device-flow completion.

    Returns {"status": "pending"|"ok"|"error", ...}. On "ok" includes
    "refresh_token". "pending" covers authorization_pending / slow_down."""
    if not (client_id and device_code):
        return {"status": "error", "error": "missing client_id or device_code"}
    r = requests.post(
        f"{_authority()}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code,
        },
        timeout=_HTTP_TIMEOUT,
    )
    if r.status_code == 200:
        tok = r.json()
        return {"status": "ok", "refresh_token": tok.get("refresh_token", "")}
    try:
        err = (r.json() or {}).get("error", "")
    except Exception:
        err = ""
    if err in ("authorization_pending", "slow_down"):
        return {"status": "pending", "error": err}
    return {"status": "error", "error": err or f"HTTP {r.status_code}"}


def _refresh(client_id: str, refresh_token: str) -> dict:
    r = requests.post(
        f"{_authority()}/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": SCOPES,
        },
        timeout=_HTTP_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()  # access_token, refresh_token (rotated), expires_in


def get_access_token(account_id: str, client_id: str, refresh_token: str, on_refresh=None) -> str:
    """Return a valid access token, refreshing via the stored refresh token if
    the cached one is missing or near expiry. Caches per account in memory.

    `on_refresh(new_refresh_token)` is called when the refresh token rotates so
    the caller can persist the replacement (Microsoft rotates refresh tokens)."""
    if not (client_id and refresh_token):
        raise ValueError("OAuth is not configured for this account (missing client ID or refresh token)")
    key = account_id or ""
    with _lock:
        cached = _token_cache.get(key)
        if cached and time.time() < cached[1] - _EXPIRY_SKEW:
            return cached[0]
        tok = _refresh(client_id, refresh_token)
        access = tok["access_token"]
        expires_at = time.time() + int(tok.get("expires_in", 3600))
        _token_cache[key] = (access, expires_at)
        new_rt = tok.get("refresh_token")
        if new_rt and new_rt != refresh_token and on_refresh:
            try:
                on_refresh(new_rt)
            except Exception as e:
                logger.warning(f"Failed to persist rotated refresh token for {key!r}: {e}")
        return access


def invalidate(account_id: str) -> None:
    """Drop the cached access token for an account (e.g. after re-auth)."""
    with _lock:
        _token_cache.pop(account_id or "", None)
