# on_premise/db_adapter/mongo_connection.py
"""
Async MongoDB connection for On-Premise RECS collections.

Environment variables:
    MONGO_DB_CLIENT_URL   — MongoDB connection string (general/infra)
    RECS_MONGO_DB_URL     — MongoDB connection string for RECS (recs_onprem_user)
    RECS_MONGO_DB_NAME    — Database name (default: recs_onprem)
"""

import os
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

_client: AsyncIOMotorClient | None = None
_recs_client: AsyncIOMotorClient | None = None


def get_mongo_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        url = os.getenv("MONGO_DB_CLIENT_URL", "mongodb://localhost:27017")
        _client = AsyncIOMotorClient(url)
    return _client


def get_recs_db() -> AsyncIOMotorDatabase:
    """
    Returns the RECS MongoDB database using a dedicated client.

    Uses RECS_MONGO_DB_URL (recs_onprem_user) if set,
    otherwise falls back to MONGO_DB_CLIENT_URL.
    """
    global _recs_client
    if _recs_client is None:
        url = os.getenv(
            "RECS_MONGO_DB_URL",
            os.getenv("MONGO_DB_CLIENT_URL", "mongodb://localhost:27017")
        )
        _recs_client = AsyncIOMotorClient(url)
    db_name = os.getenv("RECS_MONGO_DB_NAME", "recs_onprem")
    return _recs_client[db_name]
