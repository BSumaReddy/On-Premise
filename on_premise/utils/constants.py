"""
Router prefix constants and collection name constants for On-Premise APIs.
"""

ROUTER_PREFIXES = {
    "base":    "/api/v1",
    "base_v2": "/api/v2",
}

# ---------------------------------------------------------------------------
# RECS On-Premise MongoDB collection names (lowercase)
# ---------------------------------------------------------------------------
RECS_COLLECTION_ASSET_MASTER  = "recs_onprem_asset_master_details"
RECS_COLLECTION_ASSET_DETAILS = "recs_onprem_asset_details"
RECS_COLLECTION_COMPLIANCE    = "recs_onprem_asset_final_compliance"

# Tool identifier stored on every ingested document
RECS_TOOL_NAME = "Onprem_SIEM_tool"
