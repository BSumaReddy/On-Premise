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
DEFAULT_TOKEN = os.getenv("RECS_TOOL_TOKEN", "")
DEFAULT_CUSTOMER_NAME = os.getenv("RECS_CUSTOMER_NAME", "Banyan Cloud")
DEFAULT_WAZUH_BASE_URL = os.getenv("RECS_WAZUH_BASE_URL", "https://172.16.1.172:55000").rstrip("/")
DEFAULT_WAZUH_TOKEN = os.getenv("RECS_WAZUH_TOKEN", "")
DEFAULT_WAZUH_USERNAME = os.getenv("RECS_WAZUH_USERNAME", "")
DEFAULT_WAZUH_PASSWORD = os.getenv("RECS_WAZUH_PASSWORD", "")
DEFAULT_WAZUH_AUTH_PATH = os.getenv("RECS_WAZUH_AUTH_PATH", "/security/user/authenticate")
DEFAULT_WAZUH_CA_CHECKS_PATH_PREFIX = os.getenv("RECS_WAZUH_CA_CHECKS_PATH_PREFIX", "/sca")
DEFAULT_WAZUH_VULN_BASE_URL = os.getenv("RECS_WAZUH_VULN_BASE_URL", "https://localhost:9200").rstrip("/")
DEFAULT_WAZUH_VULN_INDEX = os.getenv("RECS_WAZUH_VULN_INDEX", "wazuh-states-vulnerabilities-*")
DEFAULT_WAZUH_VULN_USERNAME = os.getenv("RECS_WAZUH_VULN_USERNAME", "")
DEFAULT_WAZUH_VULN_PASSWORD = os.getenv("RECS_WAZUH_VULN_PASSWORD", "")
PAGE_SIZE = 100          # records per page when fetching all pages
TIMEOUT = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=5.0)


def _headers(token: str | None = None) -> dict:
    tok = token or DEFAULT_TOKEN
    if tok and not tok.startswith("Bearer "):
        tok = f"Bearer {tok}"
    return {"Authorization": tok, "accept": "*/*"}


def _base_url() -> str:
    return os.getenv("RECS_TOOL_BASE_URL", "").rstrip("/")


def _wazuh_headers(token: str | None = None) -> dict:
    tok = token or DEFAULT_WAZUH_TOKEN
    if tok and not tok.startswith("Bearer "):
        tok = f"Bearer {tok}"
    return {
        "Authorization": tok,
        "Content-Type": "application/json",
        "accept": "application/json",
    }


def _strip_bearer(token: str | None) -> str:
    """Normalize token for cases where caller sends bare token or Bearer token."""
    tok = (token or "").strip()
    if tok.lower().startswith("bearer "):
        return tok[7:].strip()
    return tok


async def _fetch_wazuh_auth_token(
    client: httpx.AsyncClient,
    base_url: str,
    username: str,
    password: str,
) -> str:
    """Get fresh Wazuh JWT from /security/user/authenticate?raw=true."""
    auth_url = f"{base_url}{DEFAULT_WAZUH_AUTH_PATH}"
    response = await client.post(
        auth_url,
        params={"raw": "true"},
        auth=(username, password),
        headers={"accept": "application/json"},
    )
    response.raise_for_status()

    body = response.text.strip()
    if not body:
        raise ValueError("Wazuh auth response token is empty")
    return body


def _parse_wazuh_items(body: dict | list) -> list[dict]:
    """Extract a list payload from common Wazuh response shapes."""
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)]

    if isinstance(body, dict):
        data = body.get("data", {})
        if isinstance(data, dict):
            items = data.get("affected_items")
            if isinstance(items, list):
                return [r for r in items if isinstance(r, dict)]

        direct = body.get("affected_items")
        if isinstance(direct, list):
            return [r for r in direct if isinstance(r, dict)]

    return []


async def _wazuh_get(
    path: str,
    token: str | None = None,
    base_url: str | None = None,
    params: dict | None = None,
) -> list[dict]:
    """Call a Wazuh GET endpoint and normalize list-like responses."""
    resolved_base_url = (base_url or DEFAULT_WAZUH_BASE_URL).rstrip("/")
    url = f"{resolved_base_url}{path}"

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        resolved_token = _strip_bearer(token) or _strip_bearer(DEFAULT_WAZUH_TOKEN)
        if not resolved_token and DEFAULT_WAZUH_USERNAME and DEFAULT_WAZUH_PASSWORD:
            resolved_token = await _fetch_wazuh_auth_token(
                client=client,
                base_url=resolved_base_url,
                username=DEFAULT_WAZUH_USERNAME,
                password=DEFAULT_WAZUH_PASSWORD,
            )

        if not resolved_token:
            raise ValueError(
                "Wazuh token missing. Pass X-Wazuh-Token or set RECS_WAZUH_TOKEN, "
                "or configure RECS_WAZUH_USERNAME/RECS_WAZUH_PASSWORD."
            )

        logger.info(f"RECSConnector  GET {url}  source=wazuh")
        response = await client.get(
            url,
            headers=_wazuh_headers(resolved_token),
            params={"pretty": "true", **(params or {})},
        )
        response.raise_for_status()
        body = response.json()

    return _parse_wazuh_items(body)


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
    customer_name = (extra_params or {}).get("customerName", DEFAULT_CUSTOMER_NAME)
    base_params = {"customerName": customer_name, "order": "asc"}
    if extra_params:
        base_params.update({k: v for k, v in extra_params.items() if k != "customerName"})

    all_records: list[dict] = []
    page = 1

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        while True:
            params = {**base_params, "page": page, "limit": PAGE_SIZE}
            logger.info(f"RECSConnector  GET {url}  page={page}")
            response = await client.get(url, headers=_headers(token), params=params)
            response.raise_for_status()
            body = response.json()

            records = body.get("data", [])
            if isinstance(records, list):
                all_records.extend(records)
            else:
                break

            total = body.get("recordsTotal", 0)
            if len(all_records) >= total or not records:
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


# ---------------------------------------------------------------------------
# Wazuh API : /agents?pretty=true  — all agents
# ---------------------------------------------------------------------------
async def fetch_wazuh_agents(
    token: str | None = None,
    base_url: str | None = None,
) -> list[dict]:
    """
    Fetch all Wazuh agents.

    Expected response shape (Wazuh):
        {"data": {"affected_items": [...]}}
    """
    return await _wazuh_get("/agents", token=token, base_url=base_url)


async def fetch_wazuh_services(agent_id: str, token: str | None = None, base_url: str | None = None) -> list[dict]:
    return await _wazuh_get(f"/syscollector/{agent_id}/services", token=token, base_url=base_url)


async def fetch_wazuh_ports(agent_id: str, token: str | None = None, base_url: str | None = None) -> list[dict]:
    return await _wazuh_get(f"/syscollector/{agent_id}/ports", token=token, base_url=base_url)


async def fetch_wazuh_processes(agent_id: str, token: str | None = None, base_url: str | None = None) -> list[dict]:
    return await _wazuh_get(f"/syscollector/{agent_id}/processes", token=token, base_url=base_url)


async def fetch_wazuh_sca_policies(agent_id: str, token: str | None = None, base_url: str | None = None) -> list[dict]:
    return await _wazuh_get(f"/sca/{agent_id}", token=token, base_url=base_url)


async def fetch_wazuh_sca_checks(
    agent_id: str,
    policy_id: str,
    token: str | None = None,
    base_url: str | None = None,
) -> list[dict]:
    """Fetch policy checks using the configured checks path prefix."""
    prefix = DEFAULT_WAZUH_CA_CHECKS_PATH_PREFIX.rstrip("/")
    return await _wazuh_get(f"{prefix}/{agent_id}/checks/{policy_id}", token=token, base_url=base_url)


async def fetch_wazuh_vulnerabilities(
    agent_id: str,
    base_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    index: str | None = None,
) -> list[dict]:
    """Query Wazuh vulnerability index for one agent id."""
    resolved_base_url = (base_url or DEFAULT_WAZUH_VULN_BASE_URL).rstrip("/")
    resolved_index = index or DEFAULT_WAZUH_VULN_INDEX
    resolved_username = username or DEFAULT_WAZUH_VULN_USERNAME
    resolved_password = password or DEFAULT_WAZUH_VULN_PASSWORD

    if not resolved_username or not resolved_password:
        logger.warning("Wazuh vulnerability auth is not configured; skipping vulnerabilities")
        return []

    url = f"{resolved_base_url}/{resolved_index}/_search"
    payload = {"query": {"term": {"agent.id": str(agent_id)}}}

    async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
        logger.info(f"RECSConnector  GET {url}  source=wazuh-vuln agent_id={agent_id}")
        response = await client.post(
            url,
            auth=(resolved_username, resolved_password),
            headers={"Content-Type": "application/json", "accept": "application/json"},
            json=payload,
            params={"pretty": "true"},
        )
        response.raise_for_status()
        body = response.json()

    hits = (((body.get("hits") or {}).get("hits")) or []) if isinstance(body, dict) else []
    if not isinstance(hits, list):
        return []

    out: list[dict] = []
    for item in hits:
        if not isinstance(item, dict):
            continue
        src = item.get("_source")
        if isinstance(src, dict):
            out.append(src)
    return out


