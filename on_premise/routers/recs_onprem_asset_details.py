"""
RECS Collection-2 Router — RECS_ONPREM_Asset_Details

 POST /api/v1/recs/ingest/details          Fetch API-2 + API-3 → Collection-2
 GET  /api/v1/recs/assets/{id}/details     Get config + vuln for one asset
"""

import asyncio
import os

from fastapi import APIRouter, Request

from on_premise.db_adapter.mongo_connection import get_recs_db
from on_premise.helpers.recs_helper import build_asset_details_doc
from on_premise.repository.recs_repo import AssetDetailsRepository, AssetMasterRepository
from on_premise.service_connector import recs_connector
from on_premise.utils.constants import ROUTER_PREFIXES
from on_premise.utils.custom_exceptions import CustomExceptions
from on_premise.utils.exception_handler import exception_handler
from on_premise.utils.logging import logger
from on_premise.utils.response_builder import ResponseBuilder

router = APIRouter(prefix=ROUTER_PREFIXES["base"], tags=["Collection-2: Asset Details"])


def _extract_tool_token(request: Request) -> str | None:
    return request.headers.get("X-Tool-Token")


# ===========================================================================
# POST /recs/ingest/details  — API-2 + API-3 → Collection-2
# ===========================================================================

@router.post("/recs/ingest/details", summary="Step-2: Fetch config+vuln from API-2 & API-3 → Collection-2")
@exception_handler
async def ingest_details(request: Request):
    """
    For every asset in **Collection-1**, calls **API-2** (configuration) and
    **API-3** (vulnerability) **in parallel**, matches records by `asset_id`,
    and stores the combined result into **recs_onprem_asset_details** (Collection-2).

    - `configuration_assessment` ← `cisBenchmarkData` from API-2
    - `vulnerabilities`          ← `InstalledApplications` from API-3

    Optional query param: `?customer_name=<name>`
    """
    tool_token    = _extract_tool_token(request)
    customer_name = request.query_params.get("customer_name") or os.getenv("RECS_CUSTOMER_NAME", "Banyan Cloud")
    db = get_recs_db()

    all_assets = await AssetMasterRepository.get_all_assets(db, skip=0, limit=10000)
    if not all_assets:
        return (
            ResponseBuilder().success()
            .message("No assets in Collection-1. Run /recs/ingest/assets first.")
            .result_object({"total": 0})
            .get_response(add_pagination=False)
        )

    # Call API-2 and API-3 in parallel
    logger.info("RECS ingest/details: calling API-2 + API-3 in parallel")
    config_records, vuln_records = await asyncio.gather(
        recs_connector.fetch_all_configuration(customer_name=customer_name, token=tool_token),
        recs_connector.fetch_all_vulnerability(customer_name=customer_name, token=tool_token),
        return_exceptions=True,
    )
    if isinstance(config_records, Exception):
        logger.warning(f"API-2 failed: {config_records}. Proceeding with empty config.")
        config_records = []
    if isinstance(vuln_records, Exception):
        logger.warning(f"API-3 failed: {vuln_records}. Proceeding with empty vulns.")
        vuln_records = []

    config_by_asset_id = {
        str(r.get("asset_id", "")): r for r in config_records if isinstance(r, dict)
    }
    vuln_by_asset_id = {
        str(r.get("asset_id", "")): r for r in vuln_records if isinstance(r, dict)
    }

    inserted, failed = 0, 0
    results = []
    for asset in all_assets:
        details_id = asset.get("details_id")
        asset_id   = asset.get("asset_id", "")
        try:
            config_data = config_by_asset_id.get(str(asset_id), {})
            vuln_data   = vuln_by_asset_id.get(str(asset_id), {})
            details_doc = build_asset_details_doc(details_id, asset_id, config_data, vuln_data)
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
            "collection": "recs_onprem_asset_details",
            "customer_name": customer_name,
            "config_records_from_api2": len(config_records),
            "vuln_records_from_api3": len(vuln_records),
            "total_assets_processed": len(all_assets),
            "inserted": inserted,
            "failed": failed,
            "assets": results,
        })
        .get_response(add_pagination=False)
    )


# ===========================================================================
# GET /recs/assets/{details_id}/details — config + vuln
# ===========================================================================

@router.get("/recs/assets/{details_id}/details", summary="Get configuration and vulnerability details")
@exception_handler
async def get_asset_details(details_id: str, request: Request):
    """
    Returns the **recs_onprem_asset_details** document for the given asset,
    containing the combined API-2 (configuration) and API-3 (vulnerability) data.
    """
    db     = get_recs_db()
    record = await AssetDetailsRepository.get_by_details_id(details_id, db)
    if not record:
        raise CustomExceptions(msg=f"Asset details for details_id={details_id} not found.")

    return (
        ResponseBuilder().success()
        .message("Asset details fetched successfully.")
        .result_object(record)
        .get_response(add_pagination=False)
    )

