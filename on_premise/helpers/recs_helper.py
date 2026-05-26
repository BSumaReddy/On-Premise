"""
RECS Helper — data transformation and ingestion orchestration logic.

Responsibilities:
  1. Build Collection-1 documents from raw API-1 asset payloads.
  2. Build Collection-2 documents from API-2 + API-3 responses.
  3. Explode cisBenchmarkData into per-CIS-control documents (Collection-3).
  4. Explode InstalledApplications into per-application documents (Collection-4).
  5. Orchestrate the full ingest pipeline for a single asset.

Actual API response fields:
  API-1/2/3 shared: ip_address, customerName, updated_date, Product, Vendor, Version,
                    assetOwner, asset_id, asset_name, criticality, location, os, risk_score
  API-2 extra:      cisBenchmarkData  (list of CIS control objects)
  API-3 extra:      InstalledApplications (list of application/vulnerability objects),
                    risk_score_percentage
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

def build_asset_master_doc(raw_asset: dict) -> dict:
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

    return {
        # --- internal tracking ---
        "details_id":                          details_id,
        # --- schema fields ---
        "Onprem_SIEM_tool":                    RECS_TOOL_NAME,
        "Onprem_Asset_name":                   raw_asset.get("asset_name") or "",
        "Onprem_Asset_Ip":                     raw_asset.get("ip_address") or "",
        "Onprem_Asset_id":                     raw_asset.get("asset_id") or "",
        "Onprem_Asset_Type":                   raw_asset.get("Product") or raw_asset.get("os") or "",
        "Customer_Name":                       raw_asset.get("customerName") or "",
        "ENCS_Tags":                           {
            "criticality": raw_asset.get("criticality"),
            "location":    raw_asset.get("location"),
            "risk_score":  raw_asset.get("risk_score"),
            "Vendor":      raw_asset.get("Vendor"),
            "Version":     raw_asset.get("Version"),
            "assetOwner":  raw_asset.get("assetOwner"),
        },
        "Onprem_asset_info":                   raw_asset,
        "Last_Configuration_assessment":       now_ts,
        "Last_Vulnerability_Assessment":       now_ts,
        "Created":                             now_ts,
        "Updated":                             now_ts,
        "Created_By":                          "system",
        "Updated_By":                          "system",
        # --- convenience aliases (for repo queries) ---
        "asset_id":   raw_asset.get("asset_id") or "",
        "hostname":   raw_asset.get("asset_name") or "",
        "ip_address": raw_asset.get("ip_address") or "",
        "tool_name":  RECS_TOOL_NAME,
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
        "details_id":               details_id,
        "asset_id":                 asset_id,
        "tool_name":                RECS_TOOL_NAME,
        # --- schema fields ---
        "Onprem_Asset_name":        asset_name,
        "Onprem_Asset_Ip":          ip_address,
        "Onprem_Asset_id":          asset_id,
        "services_Application_Details": config_rec.get("services") or [],
        "Process":                  config_rec.get("process") or [],
        "Open_ports":               config_rec.get("open_ports") or config_rec.get("openPorts") or [],
        "Policies_Applied":         config_rec.get("policies") or {},
        "Configuration_Assessment": config_rec.get("cisBenchmarkData") or [],
        "Vulnerabilities":          vuln_rec.get("InstalledApplications") or [],
        # --- raw payloads ---
        "raw_configuration": config_rec,
        "raw_vulnerability":  vuln_rec,
        "Created":   now_ts,
        "Updated":   now_ts,
        "Created_By": "system",
        "Updated_By": "system",
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
            "compliance_id":        str(uuid.uuid4()),
            "details_id":           details_id,
            "asset_id":             asset_id,
            "tool_name":            RECS_TOOL_NAME,
            # --- schema fields ---
            "Onprem_Asset_name":    asset_name,
            "Onprem_Asset_Ip":      ip_address,
            "Onprem_Asset_id":      asset_id,
            "CIS_Control_id":       ctrl.get("CIS_Control_id") or ctrl.get("cis_control_id") or ctrl.get("control_id") or ctrl.get("id") or "",
            "Cis_map_details":      ctrl.get("Cis_map_details") or ctrl.get("cis_map_details") or "",
            "bc_control_item_id":   ctrl.get("bc_control_item_id") or "",
            "control_title":        ctrl.get("control_title") or ctrl.get("title") or "",
            "Control_description":  ctrl.get("Control_description") or ctrl.get("description") or "",
            "Security_Control_Type": ctrl.get("Security_Control_Type") or ctrl.get("security_control_type") or "",
            "Confidentiality":      ctrl.get("Confidentiality") or ctrl.get("confidentiality") or "",
            "Integrity":            ctrl.get("Integrity") or ctrl.get("integrity") or "",
            "Availability":         ctrl.get("Availability") or ctrl.get("availability") or "",
            "Overall_Risk":         ctrl.get("Overall_Risk") or ctrl.get("overall_risk") or "",
            "Bc_HL_Config_id":      ctrl.get("Bc_HL_Config_id") or {},
            "BC_privacy_Config_id": ctrl.get("BC_privacy_Config_id") or {},
            "Remediation_enabled":  ctrl.get("Remediation_enabled") or ctrl.get("remediation_enabled") or "",
            "Remediation_Suggestions": ctrl.get("Remediation_Suggestions") or ctrl.get("remediation") or "",
            "Compliance_Status":    ctrl.get("Compliance_Status") or ctrl.get("status") or ctrl.get("result") or "",
            # --- full raw item ---
            "configuration_data":   ctrl,
            "Created":   now_ts,
            "Updated":   now_ts,
            "Created_By": "system",
            "Updated_By": "system",
        })

    logger.info(f"build_compliance_docs  details_id={details_id}  controls={len(docs)}")
    return docs


# ===========================================================================
# Collection-4 builder  (RECS_ONPREM_Asset_Application_Vulnerabilities)
# Explode InstalledApplications → one doc per application entry
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
            "Created":   now_ts,
            "Updated":   now_ts,
            "Created_By": "system",
            "Updated_By": "system",
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
