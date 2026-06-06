# JFxploit — CLI toolkit for exploiting web interface vulnerabilities in JF routers.
# Copyright (C) 2026 JFC-Group (https://github.com/JFC-Group)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
