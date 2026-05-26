"""
Router prefix constants and collection name constants for On-Premise APIs.
"""

ROUTER_PREFIXES = {
    "base":    "/api/v1",
    "base_v2": "/api/v2",
}

# ---------------------------------------------------------------------------
# RECS On-Premise MongoDB collection names
# ---------------------------------------------------------------------------
RECS_COLLECTION_ASSET_MASTER    = "recs_onprem_asset_master_details"
RECS_COLLECTION_ASSET_DETAILS   = "recs_onprem_asset_details"
RECS_COLLECTION_COMPLIANCE      = "recs_onprem_asset_final_compliance"
RECS_COLLECTION_VULNERABILITIES = "recs_onprem_asset_application_vulnerabilities"

# Tool identifier stored on every ingested document
RECS_TOOL_NAME = "Onprem_SIEM_tool"
