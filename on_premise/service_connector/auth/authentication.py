"""
JWT / Cognito authentication helpers and ``@token_required`` decorator.

Environment variables:
    BC_AUTH_URL — base URL of the BC-Auth service
"""

import os
from functools import wraps
from http.cookies import SimpleCookie

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from httpx import AsyncClient, Timeout


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------

async def get_token_from_request(request: Request) -> tuple[str, str]:
    """Extract access-token and id-token from headers or cookies."""
    token    = request.headers.get("access-token")
    id_token = request.headers.get("id-token")

    cookie = request.headers.get("cookie")
    if cookie:
        jar = SimpleCookie()
        jar.load(cookie)
        if not token and jar.get("authToken"):
            token = jar["authToken"].value
        if not id_token and jar.get("idToken"):
            id_token = jar["idToken"].value

    if not token or not id_token:
        raise HTTPException(
            status_code=401,
            detail="access-token and id-token are required (headers or Cookie).",
        )
    return token, id_token


# ---------------------------------------------------------------------------
# Cognito token validation
# ---------------------------------------------------------------------------

async def check_cognito_token(auth_type: str | None, token: str, id_token: str) -> dict:
    """Call BC-Auth service to validate tokens and retrieve user grants."""
    base_url = os.getenv("BC_AUTH_URL", "")
    path = (
        "/api/v1/admin-level-customer-authorization"
        if auth_type == "admin"
        else "/api/v1/shift-left-authorization"
    )
    headers = {"access-token": token, "id-token": id_token}

    async with AsyncClient(
        timeout=Timeout(connect=30.0, read=30.0, write=30.0, pool=2.0)
    ) as client:
        response = await client.get(base_url + path, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Token validation failed.")

    user_info = response.json().get("data", {})

    if "authenticated" in user_info and not user_info["authenticated"]:
        return JSONResponse(content=user_info, status_code=403)

    return {
        "username":     user_info.get("username"),
        "customerId":   user_info.get("customerId"),
        "customerName": user_info.get("customerName"),
        "permissions":  user_info.get("permissions"),
        "accessToken":  token,
        "idToken":      id_token,
    }


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def token_required(auth_type: str | None = None):
    """
    Endpoint decorator that:
      1. Extracts tokens from request headers / cookies.
      2. Validates them against BC-Auth.
      3. Attaches ``request.user_grants_info`` for downstream use.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            token, id_token = await get_token_from_request(request)
            user_grants_info = await check_cognito_token(auth_type, token, id_token)
            request.user_grants_info = user_grants_info  # type: ignore[attr-defined]
            return await func(request, *args, **kwargs)

        return wrapper
    return decorator

