"""
RECS Helper — data transformation and ingestion orchestration logic.

All MongoDB field names use lowercase snake_case.
"""

import uuid
from datetime import datetime, timezone

from on_premise.utils.constants import RECS_TOOL_NAME
from on_premise.utils.logging import logger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ts() -> float:
    """Epoch timestamp (double precision) as required by the schema."""
    return datetime.now(timezone.utc).timestamp()


# ===========================================================================
# Collection-1 builder  (RECS_ONPREM_Asset_master_details)
# ===========================================================================

def _normalize_tool_name(value: str | None) -> str:
    """Normalize source tool names to stable values stored in DB."""
    text = (value or "").strip()
    if not text:
        return RECS_TOOL_NAME

    low = text.lower()
    if "wazuh" in low:
        return "Wazuh"
    if "sequretek" in low or "squeteek" in low or "squeteek" in low:
        return "SequreTek"
    return text


def _extract_asset_type(raw_asset: dict) -> str:
    """Resolve asset type from common payload keys; never use tool name as type."""
    candidate_keys = [
        "asset_type", "assetType", "type", "category", "asset_category",
        "device_type", "deviceType", "resource_type", "ProductType",
    ]

    for key in candidate_keys:
        value = raw_asset.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    product = raw_asset.get("Product")
    if isinstance(product, str) and product.strip():
        product_clean = product.strip()
        if product_clean.lower() not in {"wazuh", "sequretek", "squeteek", "squeteek", "onprem_siem_tool"}:
            return product_clean

    os_value = raw_asset.get("os")
    if isinstance(os_value, dict):
        for k in ("type", "name", "full"):
            v = os_value.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    elif isinstance(os_value, str) and os_value.strip():
        return os_value.strip()

    return "Unknown"


def build_asset_master_doc(raw_asset: dict, source_tool: str | None = None) -> dict:
    """
    Create a Collection-1 document from a single raw asset dict returned by API-1.

    Mandatory schema fields are extracted at top level; full payload stored in
    ``Onprem_asset_info``.

    API-1 fields mapped:
        asset_id   → Onprem_Asset_id
        asset_name → Onprem_Asset_name
        ip_address → Onprem_Asset_Ip
        os         → (stored in asset_info)
        Product    → Onprem_Asset_Type (fallback)
        customerName → Customer_Name
        risk_score, criticality, location, Vendor, Version, assetOwner, updated_date
    """
    details_id = str(uuid.uuid4())
    now_ts = _ts()
    resolved_tool = _normalize_tool_name(source_tool or raw_asset.get("_source_tool") or raw_asset.get("tool_name"))
    resolved_asset_type = _extract_asset_type(raw_asset)

    return {
        # --- internal tracking ---
        "details_id":                          details_id,
        # --- schema fields ---
        "onprem_siem_tool":                    resolved_tool,
        "onprem_asset_name":                   raw_asset.get("asset_name") or "",
        "onprem_asset_ip":                     raw_asset.get("ip_address") or "",
        "onprem_asset_id":                     raw_asset.get("asset_id") or "",
        "onprem_asset_type":                   resolved_asset_type,
        "customer_name":                       raw_asset.get("customerName") or "",
        "encs_tags":                           {
            "criticality": raw_asset.get("criticality"),
            "location":    raw_asset.get("location"),
            "risk_score":  raw_asset.get("risk_score"),
            "vendor":      raw_asset.get("Vendor"),
            "version":     raw_asset.get("Version"),
            "asset_owner":  raw_asset.get("assetOwner"),
        },
        "onprem_asset_info":                   raw_asset,
        "last_configuration_assessment":       now_ts,
        "last_vulnerability_assessment":       now_ts,
        "created":                             now_ts,
        "updated":                             now_ts,
        "created_by":                          "system",
        "updated_by":                          "system",
        # --- convenience aliases (for repo queries) ---
        "asset_id":   raw_asset.get("asset_id") or "",
        "hostname":   raw_asset.get("asset_name") or "",
        "ip_address": raw_asset.get("ip_address") or "",
        "tool_name":  resolved_tool,
    }


# ===========================================================================
# Collection-2 builder  (RECS_ONPREM_Asset_Details)
# ===========================================================================

def build_asset_details_doc(
    details_id: str,
    asset_id: str,
    configuration_data: dict,
    vulnerability_data: dict,
) -> dict:
    """
    Combine API-2 + API-3 responses into a single Collection-2 document.

    API-2 fields mapped:
        cisBenchmarkData → Configuration_Assessment
    API-3 fields mapped:
        InstalledApplications → Vulnerabilities
    """
    now_ts = _ts()

    config_rec   = configuration_data if isinstance(configuration_data, dict) else {}
    vuln_rec     = vulnerability_data  if isinstance(vulnerability_data,  dict) else {}

    asset_name = (
        config_rec.get("asset_name") or vuln_rec.get("asset_name") or ""
    )
    ip_address = (
        config_rec.get("ip_address") or vuln_rec.get("ip_address") or ""
    )

    return {
        "details_id":                   details_id,
        "asset_id":                     asset_id,
        "tool_name":                    RECS_TOOL_NAME,
        # --- schema fields ---
        "onprem_asset_name":            asset_name,
        "onprem_asset_ip":              ip_address,
        "onprem_asset_id":              asset_id,
        "services_application_details": config_rec.get("services") or [],
        "process":                      config_rec.get("process") or [],
        "open_ports":                   config_rec.get("open_ports") or config_rec.get("openPorts") or [],
        "policies_applied":             config_rec.get("policies") or {},
        "configuration_assessment":     config_rec.get("cisBenchmarkData") or [],
        "vulnerabilities":              vuln_rec.get("InstalledApplications") or [],
        # --- raw payloads ---
        "raw_configuration":            config_rec,
        "raw_vulnerability":            vuln_rec,
        "created":                      now_ts,
        "updated":                      now_ts,
        "created_by":                   "system",
        "updated_by":                   "system",
    }


# ===========================================================================
# Collection-3 builder  (RECS_ONPREM_Asset_final_Compliance)
# Explode cisBenchmarkData → one doc per CIS Control ID
# ===========================================================================

def build_compliance_docs(details_id: str, asset_id: str, configuration_data: dict) -> list[dict]:
    """
    Explode configuration assessment data into one document per CIS Control ID.

    Reads ``cisBenchmarkData`` from the API-2 record.

    Expected cisBenchmarkData item shape (adapt to whatever the API returns):
        {
          "CIS_Control_id": "...",
          "control_title": "...",
          "Control_description": "...",
          "Security_Control_Type": "...",
          "Compliance_Status": "...",
          "Remediation_Suggestions": "...",
          ...
        }
    """
    config_rec: dict = configuration_data if isinstance(configuration_data, dict) else {}

    # Resolve the CIS controls list
    controls: list = config_rec.get("cisBenchmarkData") or []
    if not isinstance(controls, list):
        controls = []

    asset_name = config_rec.get("asset_name") or ""
    ip_address = config_rec.get("ip_address") or ""
    now_ts = _ts()

    docs = []
    for ctrl in controls:
        if not isinstance(ctrl, dict):
            continue
        docs.append({
            "compliance_id":            str(uuid.uuid4()),
            "details_id":               details_id,
            "asset_id":                 asset_id,
            "tool_name":                RECS_TOOL_NAME,
            # --- schema fields ---
            "onprem_asset_name":        asset_name,
            "onprem_asset_ip":          ip_address,
            "onprem_asset_id":          asset_id,
            "cis_control_id":           ctrl.get("CIS_Control_id") or ctrl.get("cis_control_id") or ctrl.get("control_id") or ctrl.get("id") or "",
            "cis_map_details":          ctrl.get("Cis_map_details") or ctrl.get("cis_map_details") or "",
            "bc_control_item_id":       ctrl.get("bc_control_item_id") or ctrl.get("BC_control_item_id") or "",
            "control_title":            ctrl.get("control_title") or ctrl.get("title") or "",
            "control_description":      ctrl.get("Control_description") or ctrl.get("control_description") or ctrl.get("description") or "",
            "security_control_type":    ctrl.get("Security_Control_Type") or ctrl.get("security_control_type") or "",
            "confidentiality":          ctrl.get("Confidentiality") or ctrl.get("confidentiality") or "",
            "integrity":                ctrl.get("Integrity") or ctrl.get("integrity") or "",
            "availability":             ctrl.get("Availability") or ctrl.get("availability") or "",
            "overall_risk":             ctrl.get("Overall_Risk") or ctrl.get("overall_risk") or "",
            "bc_hl_config_id":          ctrl.get("Bc_HL_Config_id") or ctrl.get("bc_hl_config_id") or {},
            "bc_privacy_config_id":     ctrl.get("BC_privacy_Config_id") or ctrl.get("bc_privacy_config_id") or {},
            "remediation_enabled":      ctrl.get("Remediation_enabled") or ctrl.get("remediation_enabled") or "",
            "remediation_suggestions":  ctrl.get("Remediation_Suggestions") or ctrl.get("remediation_suggestions") or ctrl.get("remediation") or "",
            "compliance_status":        ctrl.get("Compliance_Status") or ctrl.get("compliance_status") or ctrl.get("status") or ctrl.get("result") or "",
            # --- full raw item ---
            "configuration_data":       ctrl,
            "created":                  now_ts,
            "updated":                  now_ts,
            "created_by":               "system",
            "updated_by":               "system",
        })

    logger.info(f"build_compliance_docs  details_id={details_id}  controls={len(docs)}")
    return docs


# ===========================================================================
# Collection-4 builder  (RECS_ONPREM_Asset_Application_Vulnerabilities)
# ===========================================================================

def build_vulnerability_docs(details_id: str, asset_id: str, vulnerability_data: dict) -> list[dict]:
    """
    Explode vulnerability data into one document per InstalledApplications entry.

    Reads ``InstalledApplications`` from the API-3 record.

    Expected InstalledApplications item shape:
        {
          "application_name": "...",
          "cve_id": "...",
          "severity": "...",
          "cvss_score": ...,
          "description": "...",
          "fix_available": true/false,
          ...
        }
    """
    vuln_rec: dict = vulnerability_data if isinstance(vulnerability_data, dict) else {}

    apps: list = vuln_rec.get("InstalledApplications") or []
    if not isinstance(apps, list):
        apps = []

    now_ts = _ts()
    docs = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        docs.append({
            "vuln_id":          str(uuid.uuid4()),
            "details_id":       details_id,
            "asset_id":         asset_id,
            "tool_name":        RECS_TOOL_NAME,
            "application_name": app.get("application_name") or app.get("application") or app.get("app") or app.get("name") or "",
            "cve_id":           app.get("cve_id") or app.get("cve") or "",
            "severity":         app.get("severity") or "",
            "cvss_score":       app.get("cvss_score") or app.get("score") or "",
            "description":      app.get("description") or "",
            "fix_available":    app.get("fix_available") or False,
            "vulnerability_data": app,
            "created":          now_ts,
            "updated":          now_ts,
            "created_by":       "system",
            "updated_by":       "system",
        })

    logger.info(f"build_vulnerability_docs  details_id={details_id}  vulns={len(docs)}")
    return docs


# ===========================================================================
# Ingest summary builder
# ===========================================================================

def build_ingest_summary(results: list[dict]) -> dict:
    """Aggregate per-asset ingest results into a single summary dict."""
    total   = len(results)
    success = sum(1 for r in results if r.get("status") == "success")
    failed  = total - success
    return {
        "total_assets":          total,
        "successfully_ingested": success,
        "failed":                failed,
        "details":               results,
    }
