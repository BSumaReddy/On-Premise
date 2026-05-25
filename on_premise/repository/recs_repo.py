"""
RECS MongoDB Repository.

Handles all read/write operations for the four RECS On-Premise collections:
    RECS_ONPREM_Asset_master_details
    RECS_ONPREM_Asset_Details
    RECS_ONPREM_Asset_final_Compliance
    RECS_ONPREM_Asset_Application_Vulnerabilities
"""

from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from on_premise.utils.constants import (
    RECS_COLLECTION_ASSET_DETAILS,
    RECS_COLLECTION_ASSET_MASTER,
    RECS_COLLECTION_COMPLIANCE,
    RECS_COLLECTION_VULNERABILITIES,
)
from on_premise.utils.logging import logger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ===========================================================================
# Collection-1 : RECS_ONPREM_Asset_master_details
# ===========================================================================

class AssetMasterRepository:

    @staticmethod
    async def upsert_asset(doc: dict, db: AsyncIOMotorDatabase) -> str:
        """
        Insert or update an asset master document.
        Uses ``details_id`` as the unique key.

        Returns:
            The details_id of the upserted document.
        """
        details_id = doc["details_id"]
        doc["updated_at"] = _now()
        await db[RECS_COLLECTION_ASSET_MASTER].update_one(
            {"details_id": details_id},
            {"$set": doc, "$setOnInsert": {"created_at": _now()}},
            upsert=True,
        )
        logger.info(f"AssetMasterRepo.upsert_asset  details_id={details_id}")
        return details_id

    @staticmethod
    async def get_all_assets(db: AsyncIOMotorDatabase, skip: int = 0, limit: int = 100) -> list[dict]:
        cursor = db[RECS_COLLECTION_ASSET_MASTER].find(
            {}, {"_id": 0}
        ).skip(skip).limit(limit)
        return await cursor.to_list(length=limit)

    @staticmethod
    async def get_asset_by_details_id(details_id: str, db: AsyncIOMotorDatabase) -> dict | None:
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
    async def upsert_asset_details(doc: dict, db: AsyncIOMotorDatabase):
        """Upsert configuration + vulnerability details for one asset."""
        details_id = doc["details_id"]
        doc["updated_at"] = _now()
        await db[RECS_COLLECTION_ASSET_DETAILS].update_one(
            {"details_id": details_id},
            {"$set": doc, "$setOnInsert": {"created_at": _now()}},
            upsert=True,
        )
        logger.info(f"AssetDetailsRepo.upsert  details_id={details_id}")

    @staticmethod
    async def get_by_details_id(details_id: str, db: AsyncIOMotorDatabase) -> dict | None:
        return await db[RECS_COLLECTION_ASSET_DETAILS].find_one(
            {"details_id": details_id}, {"_id": 0}
        )


# ===========================================================================
# Collection-3 : RECS_ONPREM_Asset_final_Compliance
# ===========================================================================

class AssetComplianceRepository:

    @staticmethod
    async def upsert_control(doc: dict, db: AsyncIOMotorDatabase):
        """
        Upsert a single CIS control result.
        Unique key: (details_id, cis_control_id).
        """
        await db[RECS_COLLECTION_COMPLIANCE].update_one(
            {"details_id": doc["details_id"], "cis_control_id": doc["cis_control_id"]},
            {"$set": {**doc, "updated_at": _now()},
             "$setOnInsert": {"created_at": _now()}},
            upsert=True,
        )

    @staticmethod
    async def bulk_upsert_controls(docs: list[dict], db: AsyncIOMotorDatabase):
        for doc in docs:
            await AssetComplianceRepository.upsert_control(doc, db)
        logger.info(f"AssetComplianceRepo.bulk_upsert  count={len(docs)}")

    @staticmethod
    async def get_by_details_id(details_id: str, db: AsyncIOMotorDatabase) -> list[dict]:
        cursor = db[RECS_COLLECTION_COMPLIANCE].find(
            {"details_id": details_id}, {"_id": 0}
        )
        return await cursor.to_list(length=None)

    @staticmethod
    async def get_by_control_id(cis_control_id: str, db: AsyncIOMotorDatabase) -> list[dict]:
        cursor = db[RECS_COLLECTION_COMPLIANCE].find(
            {"cis_control_id": cis_control_id}, {"_id": 0}
        )
        return await cursor.to_list(length=None)


# ===========================================================================
# Collection-4 : RECS_ONPREM_Asset_Application_Vulnerabilities
# ===========================================================================

class AssetVulnerabilityRepository:

    @staticmethod
    async def upsert_vulnerability(doc: dict, db: AsyncIOMotorDatabase):
        """
        Upsert a single application vulnerability.
        Unique key: (details_id, application_name, cve_id).
        """
        await db[RECS_COLLECTION_VULNERABILITIES].update_one(
            {
                "details_id":       doc["details_id"],
                "application_name": doc["application_name"],
                "cve_id":           doc.get("cve_id", ""),
            },
            {"$set": {**doc, "updated_at": _now()},
             "$setOnInsert": {"created_at": _now()}},
            upsert=True,
        )

    @staticmethod
    async def bulk_upsert_vulnerabilities(docs: list[dict], db: AsyncIOMotorDatabase):
        for doc in docs:
            await AssetVulnerabilityRepository.upsert_vulnerability(doc, db)
        logger.info(f"AssetVulnRepo.bulk_upsert  count={len(docs)}")

    @staticmethod
    async def get_by_details_id(details_id: str, db: AsyncIOMotorDatabase) -> list[dict]:
        cursor = db[RECS_COLLECTION_VULNERABILITIES].find(
            {"details_id": details_id}, {"_id": 0}
        )
        return await cursor.to_list(length=None)

    @staticmethod
    async def get_by_application(
        details_id: str, application_name: str, db: AsyncIOMotorDatabase
    ) -> list[dict]:
        cursor = db[RECS_COLLECTION_VULNERABILITIES].find(
            {"details_id": details_id, "application_name": application_name}, {"_id": 0}
        )
        return await cursor.to_list(length=None)

