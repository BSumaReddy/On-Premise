"""
RECS On-Premise API Router.

3 Ingest APIs (one per collection) + Read endpoints.

────────────────────────────────────────────────────────────────────
INGEST APIs:
 POST /api/v1/recs/ingest/assets
      Calls external API-1 (/compliance-manager/assetInfo)
      → Inserts each asset as a separate doc into Collection-1
        (RECS_ONPREM_Asset_master_details)

 POST /api/v1/recs/ingest/details
      For each asset in Collection-1, calls:
        API-2 (/compliance-manager/configuration)
        API-3 (/compliance-manager/vulnerability)
      → Stores combined result into Collection-2
        (RECS_ONPREM_Asset_Details)

 POST /api/v1/recs/ingest/compliance
      For each asset in Collection-2, explodes
      Configuration_Assessment (cisBenchmarkData)
      → One document per CIS Control ID into Collection-3
        (RECS_ONPREM_Asset_final_Compliance)

────────────────────────────────────────────────────────────────────
READ APIs:
 GET  /api/v1/recs/assets                        List assets (Collection-1)
 GET  /api/v1/recs/assets/{details_id}           Single asset (Collection-1)
 GET  /api/v1/recs/assets/{details_id}/details   Config+Vuln (Collection-2)
 GET  /api/v1/recs/assets/{details_id}/compliance CIS controls (Collection-3)
────────────────────────────────────────────────────────────────────
All endpoints also available on /api/v2/ prefix.
"""

from fastapi import APIRouter, Request
import asyncio

from on_premise.db_adapter.mongo_connection import get_recs_db
from on_premise.helpers.recs_helper import (
    build_asset_details_doc,
    build_asset_master_doc,
    build_compliance_docs,
)
from on_premise.repository.recs_repo import (
    AssetComplianceRepository,
    AssetDetailsRepository,
    AssetMasterRepository,
)
import os

from on_premise.service_connector import recs_connector
from on_premise.utils.constants import ROUTER_PREFIXES
from on_premise.utils.custom_exceptions import CustomExceptions
from on_premise.utils.exception_handler import exception_handler
from on_premise.utils.logging import logger
from on_premise.utils.response_builder import ResponseBuilder

router = APIRouter(prefix=ROUTER_PREFIXES["base"], tags=["RECS On-Premise"])



# ---------------------------------------------------------------------------
# Helper — extract optional Bearer token from request headers
# ---------------------------------------------------------------------------
def _extract_tool_token(request: Request) -> str | None:
    """
    Read ``X-Tool-Token`` header as the compliance-manager Bearer token.
    Falls back to ``RECS_TOOL_TOKEN`` env-var / hardcoded default in the connector.
    """
    return request.headers.get("X-Tool-Token")


def _extract_wazuh_token(request: Request) -> str | None:
    """Read optional Wazuh token from request headers."""
    return request.headers.get("X-Wazuh-Token")


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _match_wazuh_agent(raw_asset: dict, wazuh_agents: list[dict]) -> dict:
    """Best-effort match of a Squeteek asset to one Wazuh agent."""
    asset_id = str(raw_asset.get("asset_id") or "").strip().lower()
    asset_name = str(raw_asset.get("asset_name") or "").strip().lower()
    asset_ip = str(raw_asset.get("ip_address") or "").strip()

    for agent in wazuh_agents:
        if not isinstance(agent, dict):
            continue
        agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip().lower()
        if asset_id and agent_id and asset_id == agent_id:
            return agent

        agent_name = str(agent.get("name") or "").strip().lower()
        if asset_name and agent_name and asset_name == agent_name:
            return agent

        agent_ip = str(agent.get("ip") or agent.get("ip_address") or "").strip()
        if asset_ip and agent_ip and asset_ip == agent_ip:
            return agent

    return {}


def _policy_id_from_sca_policy(policy: dict) -> str:
    """Best-effort policy-id extraction for Wazuh SCA checks API."""
    if not isinstance(policy, dict):
        return ""
    for key in ("policy_id", "id", "policy", "name"):
        val = policy.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


# ===========================================================================
# POST /recs/ingest/assets  — API-1 → Collection-1
# ===========================================================================

@router.post("/recs/ingest/assets", summary="Step-1: Fetch assets from API-1 → Collection-1")
@exception_handler
async def ingest_assets(request: Request):
    """
    Calls external **API-1** `/analyzer/compliance-manager/assetInfo` (all pages)
    and stores each asset as a **separate document** in
    **RECS_ONPREM_Asset_master_details** (Collection-1).

    - Generates a unique `details_id` (UUID) per asset.
    - Stores full raw payload in `Onprem_asset_info`.
    - Stores mandatory fields (`Onprem_Asset_name`, `Onprem_Asset_Ip`,
      `Onprem_Asset_id`, `Onprem_Asset_Type`, `Customer_Name`) at top level.
    - Sets `Onprem_SIEM_tool = Onprem_SIEM_tool`.

    Optional query param: `?customer_name=<name>` (default: env `RECS_CUSTOMER_NAME`)
    """
    tool_token    = _extract_tool_token(request)
    wazuh_token   = _extract_wazuh_token(request)
    customer_name = request.query_params.get("customer_name") or os.getenv("RECS_CUSTOMER_NAME", "Banyan Cloud")
    squeteek_enabled = _as_bool(
        request.query_params.get("squeteek_enabled"),
        _as_bool(os.getenv("RECS_ENABLE_SQUETEEK"), False),
    )
    wazuh_enabled = _as_bool(
        request.query_params.get("wazuh_enabled"),
        _as_bool(os.getenv("RECS_ENABLE_WAZUH"), True),
    )

    if not squeteek_enabled and not wazuh_enabled:
        raise CustomExceptions(msg="No data source enabled. Enable squeteek and/or wazuh.")

    tool_url      = os.getenv("RECS_TOOL_BASE_URL", "not set")
    db = get_recs_db()

    logger.info(
        f"RECS ingest/assets: customer={customer_name} squeteek_enabled={squeteek_enabled} wazuh_enabled={wazuh_enabled}"
    )

    raw_assets: list[dict] = []
    wazuh_agents: list[dict] = []

    tasks = []
    if squeteek_enabled:
        tasks.append(recs_connector.fetch_asset_info(customer_name=customer_name, token=tool_token))
    if wazuh_enabled:
        tasks.append(recs_connector.fetch_wazuh_agents(token=wazuh_token))

    api_results = await asyncio.gather(*tasks, return_exceptions=True)
    idx = 0
    if squeteek_enabled:
        sq_result = api_results[idx]
        idx += 1
        if isinstance(sq_result, Exception):
            logger.warning(f"Squeteek API-1 failed (non-fatal) — url={tool_url}  error={sq_result}")
        else:
            raw_assets = []
            for asset in (sq_result or []):
                if isinstance(asset, dict):
                    tagged_asset = dict(asset)
                    tagged_asset["_source_tool"] = "SequreTek"
                    raw_assets.append(tagged_asset)

    if wazuh_enabled:
        wz_result = api_results[idx]
        if isinstance(wz_result, Exception):
            logger.warning(f"Wazuh API failed: {wz_result}. Proceeding without wazuh enrichment.")
        else:
            wazuh_agents = wz_result or []

    # When squeteek is disabled/failed but wazuh is enabled,
    # build synthetic asset records from wazuh agents so they still get inserted.
    if not raw_assets and wazuh_agents:
        logger.info(f"No Squeteek assets — building {len(wazuh_agents)} records from Wazuh agents")
        for agent in wazuh_agents:
            raw_assets.append({
                "asset_id":    agent.get("id") or agent.get("agent_id") or "",
                "asset_name":  agent.get("name") or "",
                "ip_address":  agent.get("ip") or agent.get("ip_address") or "",
                "os":          (agent.get("os") or {}).get("full") or (agent.get("os") or {}).get("name") or "",
                "asset_type":  agent.get("type") or agent.get("group") or (agent.get("os") or {}).get("name") or "Unknown",
                "customerName": customer_name,
                "_wazuh_raw":  agent,
                "_source_tool": "Wazuh",
            })

    if not raw_assets:
        return (
            ResponseBuilder().success()
            .message("No assets from any source (Squeteek failed/disabled, Wazuh returned 0 agents).")
            .result_object({
                "total_assets": 0,
                "squeteek_enabled": squeteek_enabled,
                "wazuh_enabled": wazuh_enabled,
                "wazuh_records": len(wazuh_agents),
            })
            .get_response(add_pagination=False)
        )

    inserted, failed = 0, 0
    details_inserted, details_failed = 0, 0
    results = []
    for raw_asset in raw_assets:
        try:
            master_doc = build_asset_master_doc(raw_asset, source_tool=raw_asset.get("_source_tool"))
            details_id = await AssetMasterRepository.upsert_asset(master_doc, db)
            asset_id = str(master_doc.get("asset_id") or "")

            # Also hydrate Collection-2 in the same ingest step with source metadata.
            matched_wazuh_agent = _match_wazuh_agent(raw_asset, wazuh_agents) if wazuh_agents else {}
            details_doc = build_asset_details_doc(
                details_id=details_id,
                asset_id=asset_id,
                configuration_data={
                    "asset_name": master_doc.get("onprem_asset_name", ""),
                    "ip_address": master_doc.get("onprem_asset_ip", ""),
                },
                vulnerability_data={},
            )
            details_doc["raw_wazuh_agent"] = matched_wazuh_agent
            details_doc["source_flags"] = {
                "squeteek_enabled": squeteek_enabled,
                "wazuh_enabled": wazuh_enabled,
                "wazuh_matched": bool(matched_wazuh_agent),
            }

            try:
                await AssetDetailsRepository.upsert_asset_details(details_doc, db)
                details_inserted += 1
            except Exception as details_exc:
                details_failed += 1
                logger.error(f"Collection-2 upsert failed details_id={details_id}: {details_exc}")

            results.append({"details_id": details_id, "asset_id": asset_id, "status": "success"})
            inserted += 1
        except Exception as exc:
            logger.error(f"Collection-1 insert failed: {exc}")
            results.append({"asset_id": raw_asset.get("asset_id"), "status": "failed", "error": str(exc)})
            failed += 1

    return (
        ResponseBuilder().success()
        .message(f"Collection-1 ingestion done. Inserted={inserted}, Failed={failed}.")
        .result_object({
            "collection": "RECS_ONPREM_Asset_master_details",
            "customer_name": customer_name,
            "total_fetched": len(raw_assets),
            "inserted": inserted,
            "failed": failed,
            "wazuh_enabled": wazuh_enabled,
            "wazuh_records_fetched": len(wazuh_agents),
            "collection_2": {
                "collection": "RECS_ONPREM_Asset_Details",
                "upserted": details_inserted,
                "failed": details_failed,
            },
            "assets": results,
        })
        .get_response(add_pagination=False)
    )


# ===========================================================================
# POST /recs/ingest/details  — API-2 + API-3 → Collection-2
# ===========================================================================

@router.post("/recs/ingest/details", summary="Step-2: Fetch config+vuln from API-2 & API-3 → Collection-2")
@exception_handler
async def ingest_details(request: Request):
    """
    For every asset already stored in **Collection-1**, calls:

    - **API-2** `/analyzer/compliance-manager/configuration` — CIS benchmark data
    - **API-3** `/analyzer/compliance-manager/vulnerability` — installed app vulns

    Stores the combined result (matched by `asset_id`) into
    **RECS_ONPREM_Asset_Details** (Collection-2).

    Fields stored:
    - `Configuration_Assessment` ← `cisBenchmarkData` from API-2
    - `Vulnerabilities` ← `InstalledApplications` from API-3

    Optional query param: `?customer_name=<name>`
    """
    tool_token    = _extract_tool_token(request)
    wazuh_token   = _extract_wazuh_token(request)
    customer_name = request.query_params.get("customer_name") or os.getenv("RECS_CUSTOMER_NAME", "Banyan Cloud")
    squeteek_enabled = _as_bool(
        request.query_params.get("squeteek_enabled"),
        _as_bool(os.getenv("RECS_ENABLE_SQUETEEK"), False),
    )
    wazuh_enabled = _as_bool(
        request.query_params.get("wazuh_enabled"),
        _as_bool(os.getenv("RECS_ENABLE_WAZUH"), True),
    )

    if not squeteek_enabled and not wazuh_enabled:
        raise CustomExceptions(msg="No data source enabled. Enable squeteek and/or wazuh.")

    db = get_recs_db()

    # Fetch all assets from Collection-1
    all_assets = await AssetMasterRepository.get_all_assets(db, skip=0, limit=10000)
    if not all_assets:
        return (
            ResponseBuilder().success()
            .message("No assets found in Collection-1. Run /recs/ingest/assets first.")
            .result_object({"total": 0})
            .get_response(add_pagination=False)
        )

    config_records: list[dict] = []
    if squeteek_enabled:
        logger.info("RECS ingest/details: calling API-2 (configuration)")
        try:
            config_records = await recs_connector.fetch_all_configuration(
                customer_name=customer_name, token=tool_token
            )
        except Exception as e:
            logger.warning(f"API-2 failed: {e}. Proceeding with empty config.")

    config_by_asset_id = {
        str(r.get("asset_id", "")): r
        for r in config_records if isinstance(r, dict)
    }

    vuln_records: list[dict] = []
    if squeteek_enabled:
        logger.info("RECS ingest/details: calling API-3 (vulnerability)")
        try:
            vuln_records = await recs_connector.fetch_all_vulnerability(
                customer_name=customer_name, token=tool_token
            )
        except Exception as e:
            logger.warning(f"API-3 failed: {e}. Proceeding with empty vulns.")

    wazuh_agents: list[dict] = []
    if wazuh_enabled:
        try:
            wazuh_agents = await recs_connector.fetch_wazuh_agents(token=wazuh_token)
        except Exception as e:
            logger.warning(f"Wazuh agents fetch failed: {e}. Proceeding without wazuh details enrichment.")

    vuln_by_asset_id = {
        str(r.get("asset_id", "")): r
        for r in vuln_records if isinstance(r, dict)
    }

    inserted, failed = 0, 0
    results = []
    for asset in all_assets:
        details_id = str(asset.get("details_id") or "")
        asset_id = str(asset.get("asset_id") or asset.get("onprem_asset_id") or "")
        try:
            config_data = config_by_asset_id.get(str(asset_id), {})
            vuln_data   = vuln_by_asset_id.get(str(asset_id), {})
            details_doc = build_asset_details_doc(details_id, asset_id, config_data, vuln_data)

            # Keep the source tool in Collection-2 consistent with Collection-1.
            if asset.get("onprem_siem_tool"):
                details_doc["tool_name"] = asset.get("onprem_siem_tool")

            if wazuh_enabled and wazuh_agents:
                match_input = {
                    "asset_id": asset_id,
                    "asset_name": asset.get("onprem_asset_name") or asset.get("hostname") or "",
                    "ip_address": asset.get("onprem_asset_ip") or asset.get("ip_address") or "",
                }
                matched_agent = _match_wazuh_agent(match_input, wazuh_agents)
                agent_id = str(matched_agent.get("id") or matched_agent.get("agent_id") or "")

                if agent_id:
                    services_task = recs_connector.fetch_wazuh_services(agent_id=agent_id, token=wazuh_token)
                    ports_task = recs_connector.fetch_wazuh_ports(agent_id=agent_id, token=wazuh_token)
                    process_task = recs_connector.fetch_wazuh_processes(agent_id=agent_id, token=wazuh_token)
                    policies_task = recs_connector.fetch_wazuh_sca_policies(agent_id=agent_id, token=wazuh_token)
                    vulnerabilities_task = recs_connector.fetch_wazuh_vulnerabilities(agent_id=agent_id)

                    services, ports, processes, sca_policies, wazuh_vulns = await asyncio.gather(
                        services_task,
                        ports_task,
                        process_task,
                        policies_task,
                        vulnerabilities_task,
                        return_exceptions=True,
                    )

                    services = services if isinstance(services, list) else []
                    ports = ports if isinstance(ports, list) else []
                    processes = processes if isinstance(processes, list) else []
                    sca_policies = sca_policies if isinstance(sca_policies, list) else []
                    wazuh_vulns = wazuh_vulns if isinstance(wazuh_vulns, list) else []

                    sca_checks: list[dict] = []
                    for policy in sca_policies:
                        policy_id = _policy_id_from_sca_policy(policy)
                        if not policy_id:
                            continue
                        try:
                            checks = await recs_connector.fetch_wazuh_sca_checks(
                                agent_id=agent_id,
                                policy_id=policy_id,
                                token=wazuh_token,
                            )
                            sca_checks.extend(checks or [])
                        except Exception as checks_exc:
                            logger.warning(
                                f"Wazuh SCA checks fetch failed agent_id={agent_id} policy_id={policy_id}: {checks_exc}"
                            )

                    if services:
                        details_doc["services_application_details"] = services
                    if ports:
                        details_doc["open_ports"] = ports
                    if processes:
                        details_doc["process"] = processes
                    if sca_policies or sca_checks:
                        details_doc["policies_applied"] = {
                            "wazuh_sca_policies": sca_policies,
                            "wazuh_sca_checks": sca_checks,
                        }
                        details_doc["configuration_assessment"] = sca_checks or sca_policies
                    if wazuh_vulns:
                        details_doc["vulnerabilities"] = wazuh_vulns

                    details_doc["raw_wazuh"] = {
                        "agent": matched_agent,
                        "services": services,
                        "ports": ports,
                        "processes": processes,
                        "sca_policies": sca_policies,
                        "sca_checks": sca_checks,
                        "vulnerabilities": wazuh_vulns,
                    }

                    details_doc["source_flags"] = {
                        "squeteek_enabled": squeteek_enabled,
                        "wazuh_enabled": wazuh_enabled,
                        "wazuh_matched": True,
                        "wazuh_agent_id": agent_id,
                    }
                else:
                    details_doc["source_flags"] = {
                        "squeteek_enabled": squeteek_enabled,
                        "wazuh_enabled": wazuh_enabled,
                        "wazuh_matched": False,
                    }

            await AssetDetailsRepository.upsert_asset_details(details_doc, db)
            results.append({"details_id": details_id, "asset_id": asset_id, "status": "success"})
            inserted += 1
        except Exception as exc:
            logger.error(f"Collection-2 insert failed asset_id={asset_id}: {exc}")
            results.append({"details_id": details_id, "asset_id": asset_id, "status": "failed", "error": str(exc)})
            failed += 1

    return (
        ResponseBuilder().success()
        .message(f"Collection-2 ingestion done. Inserted={inserted}, Failed={failed}.")
        .result_object({
            "collection": "RECS_ONPREM_Asset_Details",
            "customer_name": customer_name,
            "config_records_from_api2": len(config_records),
            "vuln_records_from_api3": len(vuln_records),
            "total_assets_processed": len(all_assets),
            "inserted": inserted,
            "failed": failed,
            "squeteek_enabled": squeteek_enabled,
            "wazuh_enabled": wazuh_enabled,
            "wazuh_agents_fetched": len(wazuh_agents),
            "assets": results,
        })
        .get_response(add_pagination=False)
    )


# ===========================================================================
# POST /recs/ingest/compliance  — Collection-2 → Collection-3
# ===========================================================================

@router.post("/recs/ingest/compliance", summary="Step-3: Explode CIS controls from Collection-2 → Collection-3")
@exception_handler
async def ingest_compliance(request: Request):
    """
    Reads `Configuration_Assessment` (cisBenchmarkData) from every document
    in **Collection-2** (RECS_ONPREM_Asset_Details) and explodes it into
    **one document per CIS Control ID** in
    **RECS_ONPREM_Asset_final_Compliance** (Collection-3).

    Run this **after** `/recs/ingest/details`.
    """
    db = get_recs_db()

    # Read all details docs from Collection-2
    all_assets = await AssetMasterRepository.get_all_assets(db, skip=0, limit=10000)
    if not all_assets:
        return (
            ResponseBuilder().success()
            .message("No assets in Collection-1. Run /recs/ingest/assets first.")
            .result_object({"total": 0})
            .get_response(add_pagination=False)
        )

    total_controls = 0
    failed = 0
    results = []

    for asset in all_assets:
        details_id = str(asset.get("details_id") or "")
        asset_id = str(asset.get("asset_id") or asset.get("onprem_asset_id") or "")
        try:
            # Get Collection-2 record for this asset
            details_doc = await AssetDetailsRepository.get_by_details_id(details_id, db)
            if not details_doc:
                results.append({"details_id": details_id, "asset_id": asset_id,
                                 "status": "skipped", "reason": "not found in Collection-2"})
                continue

            # Configuration_Assessment holds the raw config data (cisBenchmarkData)
            config_data = details_doc.get("raw_configuration") or {}
            compliance_docs = build_compliance_docs(details_id, asset_id, config_data)

            if compliance_docs:
                await AssetComplianceRepository.bulk_upsert_controls(compliance_docs, db)

            total_controls += len(compliance_docs)
            results.append({
                "details_id": details_id,
                "asset_id": asset_id,
                "cis_controls_stored": len(compliance_docs),
                "status": "success",
            })
        except Exception as exc:
            logger.error(f"Collection-3 insert failed asset_id={asset_id}: {exc}")
            results.append({"details_id": details_id, "asset_id": asset_id,
                             "status": "failed", "error": str(exc)})
            failed += 1

    return (
        ResponseBuilder().success()
        .message(f"Collection-3 ingestion done. Total CIS controls stored={total_controls}, Failed={failed}.")
        .result_object({
            "collection": "RECS_ONPREM_Asset_final_Compliance",
            "total_assets_processed": len(all_assets),
            "total_cis_controls_stored": total_controls,
            "failed": failed,
            "assets": results,
        })
        .get_response(add_pagination=False)
    )





# ===========================================================================
# GET /recs/assets — list all assets (Collection-1)
# ===========================================================================

@router.get("/recs/assets", summary="List all ingested on-premise assets")
@exception_handler
async def list_assets(request: Request):
    """
    Returns a paginated list of assets from **RECS_ONPREM_Asset_master_details**.

    Query params:
    - `page`  (default 1)
    - `limit` (default 50)
    """
    page  = max(int(request.query_params.get("page",  1)), 1)
    limit = min(int(request.query_params.get("limit", 50)), 200)
    skip  = (page - 1) * limit

    db     = get_recs_db()
    assets = await AssetMasterRepository.get_all_assets(db, skip=skip, limit=limit)
    total  = await AssetMasterRepository.count_assets(db)

    return (
        ResponseBuilder()
        .success()
        .message("Assets fetched successfully.")
        .result_object({"total": total, "page": page, "limit": limit, "assets": assets})
        .get_response(add_pagination=False)
    )


# ===========================================================================
# GET /recs/assets/{details_id} — single asset master (Collection-1)
# ===========================================================================

@router.get("/recs/assets/{details_id}", summary="Get a single asset master document")
@exception_handler
async def get_asset(details_id: str, request: Request):
    """
    Returns the **RECS_ONPREM_Asset_master_details** document for the given `details_id`.
    """
    db     = get_recs_db()
    record = await AssetMasterRepository.get_asset_by_details_id(details_id, db)
    if not record:
        raise CustomExceptions(msg=f"Asset with details_id={details_id} not found.")

    return (
        ResponseBuilder()
        .success()
        .message("Asset fetched successfully.")
        .result_object(record)
        .get_response(add_pagination=False)
    )


# ===========================================================================
# GET /recs/assets/{details_id}/details — config + vuln (Collection-2)
# ===========================================================================

@router.get("/recs/assets/{details_id}/details", summary="Get configuration and vulnerability details")
@exception_handler
async def get_asset_details(details_id: str, request: Request):
    """
    Returns the **RECS_ONPREM_Asset_Details** document for the given asset,
    containing the raw API-2 (configuration) and API-3 (vulnerability) responses.
    """
    db     = get_recs_db()
    record = await AssetDetailsRepository.get_by_details_id(details_id, db)
    if not record:
        raise CustomExceptions(msg=f"Asset details for details_id={details_id} not found.")

    return (
        ResponseBuilder()
        .success()
        .message("Asset details fetched successfully.")
        .result_object(record)
        .get_response(add_pagination=False)
    )


# ===========================================================================
# GET /recs/assets/{details_id}/compliance — CIS controls (Collection-3)
# ===========================================================================

@router.get("/recs/assets/{details_id}/compliance", summary="Get CIS compliance controls for an asset")
@exception_handler
async def get_asset_compliance(details_id: str, request: Request):
    """
    Returns all **RECS_ONPREM_Asset_final_Compliance** documents for the given asset,
    one document per CIS Control ID.

    Optional query param:
    - `control_id` — filter by a specific CIS Control ID.
    """
    control_id_filter = request.query_params.get("control_id")
    db     = get_recs_db()

    if control_id_filter:
        records = await AssetComplianceRepository.get_by_control_id(control_id_filter, db)
        records = [r for r in records if r.get("details_id") == details_id]
    else:
        records = await AssetComplianceRepository.get_by_details_id(details_id, db)

    return (
        ResponseBuilder()
        .success()
        .message("Compliance data fetched successfully.")
        .result_object({"total": len(records), "controls": records})
        .get_response(add_pagination=False)
    )




