"""
Shared session helper for post-auth exploits.
Returns (session_cookie, csrf_token) on success, None on failure.
"""
import re

import httpx

from .models import Target


def get_session(target: Target) -> tuple[str, str] | None:
    """Log in and return (TeamF1Login cookie, CSRF token). Token may be empty string."""
    try:
        resp = httpx.post(
            f"{target.base_url}/platform.cgi",
            headers={
                "Referer": f"{target.base_url}/platform.cgi"
            },
            data={
                "button.login.users.dashboard": "Login",
                "thispage": "index.html",
                "users.username": target.username,
                "users.password": target.password,
            },
            follow_redirects=True,
            timeout=10,
        )
        cookie = resp.cookies.get("TeamF1Login", "")
        if not cookie:
            return None
        token_match = re.search(r'name=["\']token["\'] value=["\']([^"\']+)["\']', resp.text)
        token = token_match.group(1) if token_match else ""
        return (cookie, token)
    except httpx.RequestError:
        return None
