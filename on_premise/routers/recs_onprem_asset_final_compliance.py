"""
RECS Collection-3 Router — RECS_ONPREM_Asset_final_Compliance

 POST /api/v1/recs/ingest/compliance       Explode CIS controls → Collection-3
 GET  /api/v1/recs/assets/{id}/compliance  Get CIS controls for one asset
"""

from fastapi import APIRouter, Request

from on_premise.db_adapter.mongo_connection import get_recs_db
from on_premise.helpers.recs_helper import build_compliance_docs
from on_premise.repository.recs_repo import (
    AssetComplianceRepository,
    AssetDetailsRepository,
    AssetMasterRepository,
)
from on_premise.utils.constants import ROUTER_PREFIXES
from on_premise.utils.exception_handler import exception_handler
from on_premise.utils.logging import logger
from on_premise.utils.response_builder import ResponseBuilder

router = APIRouter(prefix=ROUTER_PREFIXES["base"], tags=["Collection-3: Compliance"])


# ===========================================================================
# POST /recs/ingest/compliance  — Collection-2 → Collection-3
# ===========================================================================

@router.post("/recs/ingest/compliance", summary="Step-3: Explode CIS controls from Collection-2 → Collection-3")
@exception_handler
async def ingest_compliance(request: Request):
    """
    Reads `raw_configuration.cisBenchmarkData` from every document in
    **Collection-2** and explodes it into **one document per CIS Control ID**
    in **recs_onprem_asset_final_compliance** (Collection-3).

    Run this **after** `/recs/ingest/details`.
    """
    db = get_recs_db()

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
        details_id = asset.get("details_id")
        asset_id   = asset.get("asset_id", "")
        try:
            details_doc = await AssetDetailsRepository.get_by_details_id(details_id, db)
            if not details_doc:
                results.append({
                    "details_id": details_id, "asset_id": asset_id,
                    "status": "skipped", "reason": "not found in Collection-2",
                })
                continue

            config_data     = details_doc.get("raw_configuration") or {}
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
            results.append({
                "details_id": details_id, "asset_id": asset_id,
                "status": "failed", "error": str(exc),
            })
            failed += 1

    return (
        ResponseBuilder().success()
        .message(f"Collection-3 ingestion done. CIS controls stored={total_controls}, Failed={failed}.")
        .result_object({
            "collection": "recs_onprem_asset_final_compliance",
            "total_assets_processed": len(all_assets),
            "total_cis_controls_stored": total_controls,
            "failed": failed,
            "assets": results,
        })
        .get_response(add_pagination=False)
    )


# ===========================================================================
# GET /recs/assets/{details_id}/compliance — CIS controls
# ===========================================================================

@router.get("/recs/assets/{details_id}/compliance", summary="Get CIS compliance controls for an asset")
@exception_handler
async def get_asset_compliance(details_id: str, request: Request):
    """
    Returns all **recs_onprem_asset_final_compliance** documents for the given asset,
    one document per CIS Control ID.

    Optional query param: `?control_id=<id>` — filter by a specific CIS Control ID.
    """
    control_id_filter = request.query_params.get("control_id")
    db = get_recs_db()

    if control_id_filter:
        records = await AssetComplianceRepository.get_by_control_id(control_id_filter, db)
        records = [r for r in records if r.get("details_id") == details_id]
    else:
        records = await AssetComplianceRepository.get_by_details_id(details_id, db)

    return (
        ResponseBuilder().success()
        .message("Compliance data fetched successfully.")
        .result_object({"total": len(records), "controls": records})
        .get_response(add_pagination=False)
    )

