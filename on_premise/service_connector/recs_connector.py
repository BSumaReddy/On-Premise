"""
RECS External API Connector.

Calls three external compliance-manager endpoints:
    /analyzer/compliance-manager/assetInfo
    /analyzer/compliance-manager/configuration
    /analyzer/compliance-manager/vulnerability

Environment variables:
    RECS_TOOL_BASE_URL   — Base URL of the compliance-manager tool  (e.g. http://host:port)
    RECS_TOOL_TOKEN      — Bearer token (fallback if not passed per-request)
    RECS_CUSTOMER_NAME   — Customer name filter (default "Banyan Cloud")
"""

import os

import httpx

from on_premise.utils.logging import logger

# ---------------------------------------------------------------------------
# Defaults (overridable via env vars)
# ---------------------------------------------------------------------------
DEFAULT_TOKEN         = os.getenv("RECS_TOOL_TOKEN", "")
DEFAULT_CUSTOMER_NAME = os.getenv("RECS_CUSTOMER_NAME", "Banyan Cloud")
PAGE_SIZE             = 100
TIMEOUT               = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=5.0)
_MAX_PAGES            = 500   # safety cap — prevents infinite loops on bad API responses


def _sanitize_str(value: str | None) -> str:
    """
    Strip MongoDB/NoSQL operator injection characters from string query params.
    Prevents NoSQL injection via user-supplied customerName or filter values.
    """
    if not value:
        return ""
    # Remove $, {, } which are MongoDB operator prefixes
    return str(value).replace("$", "").replace("{", "").replace("}", "").strip()


def _headers(token: str | None = None) -> dict:
    tok = token or DEFAULT_TOKEN
    if tok and not tok.startswith("Bearer "):
        tok = f"Bearer {tok}"
    return {"Authorization": tok, "accept": "*/*"}


def _base_url() -> str:
    url = os.getenv("RECS_TOOL_BASE_URL", "").rstrip("/")
    if not url:
        raise ValueError("RECS_TOOL_BASE_URL env var is not set.")
    return url


# ---------------------------------------------------------------------------
# Pagination helper — fetches all pages and returns combined list
# ---------------------------------------------------------------------------
async def _fetch_all_pages(
    path: str,
    extra_params: dict | None = None,
    token: str | None = None,
) -> list[dict]:
    """
    Iterate through all pages of a paginated endpoint and return every record.

    Pagination params: page (1-based), limit, order=asc
    Response shape expected: { "data": [...], "recordsTotal": N }
    """
    url = f"{_base_url()}{path}"
    customer_name = _sanitize_str((extra_params or {}).get("customerName", DEFAULT_CUSTOMER_NAME))
    base_params = {"customerName": customer_name, "order": "asc"}
    if extra_params:
        base_params.update({k: v for k, v in extra_params.items() if k != "customerName"})

    all_records: list[dict] = []
    page = 1

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        while page <= _MAX_PAGES:
            params = {**base_params, "page": page, "limit": PAGE_SIZE}
            logger.info(f"RECSConnector  GET {url}  page={page}")
            response = await client.get(url, headers=_headers(token), params=params)
            response.raise_for_status()
            body = response.json()

            records = body.get("data", [])
            if not isinstance(records, list) or not records:
                break
            all_records.extend(records)

            total = int(body.get("recordsTotal", 0))
            if len(all_records) >= total:
                break
            page += 1

    logger.info(f"RECSConnector  {path}  total_fetched={len(all_records)}")
    return all_records


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------
async def ping_tool(token: str | None = None) -> dict:
    """Check whether the compliance-manager tool is reachable."""
    url = f"{_base_url()}/analyzer/compliance-manager/assetInfo"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), verify=False) as client:
            params = {"customerName": DEFAULT_CUSTOMER_NAME, "page": 1, "limit": 1, "order": "asc"}
            resp = await client.get(url, headers=_headers(token), params=params)
        return {"reachable": True, "status_code": resp.status_code, "url": url}
    except Exception as exc:
        logger.warning(f"ping_tool failed: {exc}")
        return {"reachable": False, "status_code": None, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# API-1 : /compliance-manager/assetInfo  — all assets
# ---------------------------------------------------------------------------
async def fetch_asset_info(
    customer_name: str | None = None,
    token: str | None = None,
) -> list[dict]:
    """
    Fetch ALL on-premise assets (all pages).

    Returns:
        List of asset dicts from the external tool.
    """
    cn = customer_name or DEFAULT_CUSTOMER_NAME
    return await _fetch_all_pages(
        "/analyzer/compliance-manager/assetInfo",
        extra_params={"customerName": cn},
        token=token,
    )


# ---------------------------------------------------------------------------
# API-2 : /compliance-manager/configuration  — all config records
# ---------------------------------------------------------------------------
async def fetch_all_configuration(
    customer_name: str | None = None,
    token: str | None = None,
) -> list[dict]:
    """
    Fetch ALL configuration-assessment records (all pages).

    Each record contains ``cisBenchmarkData`` list for CIS controls.

    Returns:
        List of config dicts, keyed by ``asset_id``.
    """
    cn = customer_name or DEFAULT_CUSTOMER_NAME
    return await _fetch_all_pages(
        "/analyzer/compliance-manager/configuration",
        extra_params={"customerName": cn},
        token=token,
    )


# ---------------------------------------------------------------------------
# API-3 : /compliance-manager/vulnerability  — all vulnerability records
# ---------------------------------------------------------------------------
async def fetch_all_vulnerability(
    customer_name: str | None = None,
    token: str | None = None,
) -> list[dict]:
    """
    Fetch ALL vulnerability records (all pages).

    Each record contains ``InstalledApplications`` list.

    Returns:
        List of vulnerability dicts, keyed by ``asset_id``.
    """
    cn = customer_name or DEFAULT_CUSTOMER_NAME
    return await _fetch_all_pages(
        "/analyzer/compliance-manager/vulnerability",
        extra_params={"customerName": cn},
        token=token,
    )


# ---------------------------------------------------------------------------
# Legacy per-asset helpers (kept for backwards compatibility)
# ---------------------------------------------------------------------------
async def fetch_configuration(asset_id: str, token: str | None = None) -> dict:
    """Fetch configuration data for a single asset_id (returns first matching record)."""
    records = await fetch_all_configuration(token=token)
    for r in records:
        if str(r.get("asset_id", "")) == str(asset_id):
            return r
    return {}


async def fetch_vulnerability(asset_id: str, token: str | None = None) -> dict:
    """Fetch vulnerability data for a single asset_id (returns first matching record)."""
    records = await fetch_all_vulnerability(token=token)
    for r in records:
        if str(r.get("asset_id", "")) == str(asset_id):
            return r
    return {}

