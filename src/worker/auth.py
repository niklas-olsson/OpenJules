"""GitHub App authentication helper for generating installation access tokens via JWT."""

import logging
import os
import time
from typing import Optional
import httpx
import jwt

logger = logging.getLogger(__name__)


def generate_jwt(app_id: str | int, private_key_pem: str, expiration_seconds: int = 600) -> str:
    """Generates a GitHub App JWT bearer token valid for up to 10 minutes (RS256)."""
    now = int(time.time())
    payload = {
        "iat": now - 60,  # Issued 60 seconds in the past to allow for clock drift
        "exp": now + expiration_seconds,
        "iss": str(app_id),
    }
    encoded_jwt = jwt.encode(payload, private_key_pem, algorithm="RS256")
    return encoded_jwt


def load_private_key(key_content_or_path: str) -> str:
    """Reads private key from path if file exists, or returns raw string content."""
    if os.path.isfile(key_content_or_path):
        with open(key_content_or_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return key_content_or_path.strip()


def get_app_installation_token(
    app_id: str | int,
    private_key_or_path: str,
    installation_id: int | str,
    api_url: str = "https://api.github.com",
    *, safe_errors: bool = False, private_key_is_content: bool = False,
) -> Optional[str]:
    """Exchanges a GitHub App JWT for a short-lived installation access token."""
    try:
        # An admitted adapter's bounded, frozen snapshot is already key
        # content. Never reinterpret those bytes as a second file path.
        pem = private_key_or_path if private_key_is_content else load_private_key(private_key_or_path)
        app_jwt = generate_jwt(app_id, pem)

        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        endpoint = f"{api_url.rstrip('/')}/app/installations/{installation_id}/access_tokens"
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(endpoint, headers=headers)
            if resp.status_code in (200, 201):
                token_data = resp.json()
                return token_data.get("token")
            else:
                if safe_errors:
                    logger.error("GitHub App token exchange unavailable")
                else:
                    logger.error(
                        f"GitHub App token exchange failed ({resp.status_code}): {resp.text}"
                    )
    except Exception as e:
        if safe_errors:
            logger.error("GitHub App token exchange unavailable")
        else:
            logger.error(f"Failed to generate GitHub App installation token: {e}")
    return None
