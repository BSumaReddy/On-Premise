"""
RECS External API Connector.

Calls three external compliance-manager endpoints:
    /compliance-manager/assetInfo
    /compliance-manager/configuration
    /compliance-manager/vulnerability

Environment variables:
    RECS_TOOL_BASE_URL  — Base URL of the compliance-manager tool
    RECS_TOOL_TOKEN     — Bearer token (fallback if not passed per-request)
"""

import os

import httpx

from on_premise.utils.logging import logger

# ---------------------------------------------------------------------------
# Default token (can be overridden per-request)
# ---------------------------------------------------------------------------
# Token must be set via RECS_TOOL_TOKEN environment variable — never hardcode tokens
DEFAULT_TOKEN = os.getenv("RECS_TOOL_TOKEN", "")

TIMEOUT = httpx.Timeout(connect=30.0, read=60.0, write=30.0, pool=5.0)


def _headers(token: str | None = None) -> dict:
    tok = token or DEFAULT_TOKEN
    # Accept both "Bearer <token>" and raw token strings
    if not tok.startswith("Bearer "):
        tok = f"Bearer {tok}"
    return {"Authorization": tok, "Content-Type": "application/json"}


def _base_url() -> str:
    return os.getenv("RECS_TOOL_BASE_URL", "").rstrip("/")


# ---------------------------------------------------------------------------
# API-1 : /compliance-manager/assetInfo
# ---------------------------------------------------------------------------
async def fetch_asset_info(token: str | None = None) -> list[dict]:
    """
    Fetch the full list of on-premise assets.

    Returns:
        List of asset dicts from the external tool.
    """
    url = f"{_base_url()}/analyzer/compliance-manager/assetInfo"
    logger.info(f"RECSConnector.fetch_asset_info  url={url}")

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        response = await client.get(url, headers=_headers(token))

    response.raise_for_status()
    data = response.json()

    # Normalise: handle both {"assets": [...]} and plain list responses
    if isinstance(data, list):
        return data
    return data.get("assets", data.get("data", [data]))


# ---------------------------------------------------------------------------
# API-2 : /compliance-manager/configuration
# ---------------------------------------------------------------------------
async def fetch_configuration(asset_id: str, token: str | None = None) -> dict:
    """
    Fetch CIS configuration-assessment results for a single asset.

    Args:
        asset_id: Identifier of the asset.

    Returns:
        Dict containing configuration assessment data.
    """
    url = f"{_base_url()}/compliance-manager/configuration"
    logger.info(f"RECSConnector.fetch_configuration  asset_id={asset_id}")

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        response = await client.get(url, headers=_headers(token), params={"asset_id": asset_id})

    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# API-3 : /compliance-manager/vulnerability
# ---------------------------------------------------------------------------
async def fetch_vulnerability(asset_id: str, token: str | None = None) -> dict:
    """
    Fetch vulnerability details for a single asset.

    Args:
        asset_id: Identifier of the asset.

    Returns:
        Dict containing vulnerability data.
    """
    url = f"{_base_url()}/compliance-manager/vulnerability"
    logger.info(f"RECSConnector.fetch_vulnerability  asset_id={asset_id}")

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        response = await client.get(url, headers=_headers(token), params={"asset_id": asset_id})

    response.raise_for_status()
    return response.json()



