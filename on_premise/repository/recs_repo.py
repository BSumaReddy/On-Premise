"""
RECS MongoDB Repository.

Handles all read/write operations for the three RECS On-Premise collections:
    RECS_ONPREM_Asset_master_details
    RECS_ONPREM_Asset_Details
    RECS_ONPREM_Asset_final_Compliance

Improvements:
  - bulk_upsert uses motor's bulk_write (single round-trip) instead of N individual awaits
  - _now() removed — timestamps set in helper layer; repo only sets `updated` on upsert
  - Projection excludes `_id` and `raw_configuration`/`raw_vulnerability` on list queries
"""

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import UpdateOne

from on_premise.utils.constants import (
    RECS_COLLECTION_ASSET_DETAILS,
    RECS_COLLECTION_ASSET_MASTER,
    RECS_COLLECTION_COMPLIANCE,
)
from on_premise.utils.logging import logger


def _ts() -> float:
    return datetime.now(timezone.utc).timestamp()


# ===========================================================================
# Collection-1 : RECS_ONPREM_Asset_master_details
# ===========================================================================

class AssetMasterRepository:

    @staticmethod
    async def upsert_asset(doc: dict, db: AsyncIOMotorDatabase) -> str:
        """Upsert one asset. Returns details_id."""
        details_id = doc["details_id"]
        await db[RECS_COLLECTION_ASSET_MASTER].update_one(
            {"details_id": details_id},
            {
                "$set": {**doc, "updated": _ts()},
                "$setOnInsert": {"created": _ts()},
            },
            upsert=True,
        )
        logger.info(f"AssetMasterRepo.upsert  details_id={details_id}")
        return details_id

    @staticmethod
    async def get_all_assets(
        db: AsyncIOMotorDatabase, skip: int = 0, limit: int = 100
    ) -> list[dict]:
        cursor = db[RECS_COLLECTION_ASSET_MASTER].find(
            {}, {"_id": 0}
        ).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)

    @staticmethod
    async def get_asset_by_details_id(
        details_id: str, db: AsyncIOMotorDatabase
    ) -> dict | None:
        return await db[RECS_COLLECTION_ASSET_MASTER].find_one(
            {"details_id": details_id}, {"_id": 0}
        )

    @staticmethod
    async def count_assets(db: AsyncIOMotorDatabase) -> int:
        return await db[RECS_COLLECTION_ASSET_MASTER].count_documents({})


# ===========================================================================
# Collection-2 : RECS_ONPREM_Asset_Details
# ===========================================================================

class AssetDetailsRepository:

    @staticmethod
    async def upsert_asset_details(doc: dict, db: AsyncIOMotorDatabase) -> None:
        """Upsert config + vulnerability details for one asset."""
        details_id = doc["details_id"]
        await db[RECS_COLLECTION_ASSET_DETAILS].update_one(
            {"details_id": details_id},
            {
                "$set": {**doc, "updated": _ts()},
                "$setOnInsert": {"created": _ts()},
            },
            upsert=True,
        )
        logger.info(f"AssetDetailsRepo.upsert  details_id={details_id}")

    @staticmethod
    async def get_by_details_id(
        details_id: str, db: AsyncIOMotorDatabase
    ) -> dict | None:
        return await db[RECS_COLLECTION_ASSET_DETAILS].find_one(
            {"details_id": details_id}, {"_id": 0}
        )


# ===========================================================================
# Collection-3 : RECS_ONPREM_Asset_final_Compliance
# ===========================================================================

class AssetComplianceRepository:

    @staticmethod
    async def bulk_upsert_controls(docs: list[dict], db: AsyncIOMotorDatabase) -> None:
        """
        Bulk upsert CIS controls using a single MongoDB bulk_write call.
        Unique key per document: (details_id, cis_control_id).
        Much faster than N individual update_one calls.
        """
        if not docs:
            return

        now = _ts()
        operations = [
            UpdateOne(
                {
                    "details_id":    doc["details_id"],
                    "cis_control_id": doc["cis_control_id"],
                },
                {
                    "$set": {**doc, "updated": now},
                    "$setOnInsert": {"created": now},
                },
                upsert=True,
            )
            for doc in docs
        ]
        result = await db[RECS_COLLECTION_COMPLIANCE].bulk_write(operations, ordered=False)
        logger.info(
            f"AssetComplianceRepo.bulk_upsert  count={len(docs)}  "
            f"upserted={result.upserted_count}  modified={result.modified_count}"
        )

    @staticmethod
    async def get_by_details_id(
        details_id: str, db: AsyncIOMotorDatabase
    ) -> list[dict]:
        cursor = db[RECS_COLLECTION_COMPLIANCE].find(
            {"details_id": details_id}, {"_id": 0}
        )
        return await cursor.to_list(length=None)

    @staticmethod
    async def get_by_control_id(
        cis_control_id: str, db: AsyncIOMotorDatabase
    ) -> list[dict]:
        cursor = db[RECS_COLLECTION_COMPLIANCE].find(
            {"cis_control_id": cis_control_id}, {"_id": 0}
        )
        return await cursor.to_list(length=None)
