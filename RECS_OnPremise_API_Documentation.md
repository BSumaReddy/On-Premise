# RECS On-Premise API — Full Documentation

---

## 📌 Overview

This service fetches On-Premise asset data from an external **compliance-manager tool**
and stores it into **3 MongoDB collections** in the `recs_onprem` database.

```
External Tool (172.16.1.212:18180)               Our Service (localhost:8001)
─────────────────────────────────────────────    ─────────────────────────────────────────
API-1: /compliance-manager/assetInfo          →  POST /api/v1/recs/ingest/assets
API-2: /compliance-manager/configuration      →  POST /api/v1/recs/ingest/details
API-3: /compliance-manager/vulnerability      →  POST /api/v1/recs/ingest/details
cisBenchmarkData (exploded from API-2 result) →  POST /api/v1/recs/ingest/compliance
```

---

## 🔐 Authentication

| Header | Required | Description |
|---|---|---|
| `X-Tool-Token` | ✅ For ingest APIs | Bearer token for external compliance-manager tool |
| `access-token` | For protected routes | Cognito access token |
| `id-token` | For protected routes | Cognito ID token |

---

## 📂 MongoDB Collections

| # | Collection Name | Stores |
|---|---|---|
| 1 | `RECS_ONPREM_Asset_master_details` | All assets fetched from API-1 |
| 2 | `RECS_ONPREM_Asset_Details` | Config (API-2) + Vulnerability (API-3) per asset |
| 3 | `RECS_ONPREM_Asset_final_Compliance` | One doc per CIS Control ID per asset |

---

## ✍️ INGEST APIs (Run in Order)

---

### 1️⃣ `POST /api/v1/recs/ingest/assets`
**Step 1 — Fetch assets from external API-1 → Insert into Collection-1**

#### What it does:
1. Calls external **API-1**: `GET /analyzer/compliance-manager/assetInfo?customerName=Banyan Cloud`
2. Fetches **all pages** (pagination handled automatically using `recordsTotal`)
3. For each asset in the response:
   - Generates a unique `details_id` (UUID)
   - Extracts mandatory fields: `Onprem_Asset_name`, `Onprem_Asset_Ip`, `Onprem_Asset_id`, `Onprem_Asset_Type`, `Customer_Name`
   - Stores full raw payload in `Onprem_asset_info` (jsonb)
   - Sets `Onprem_SIEM_tool = "Onprem_SIEM_tool"`
   - Stores `ENCS_Tags`: criticality, location, risk_score, Vendor, Version, assetOwner
4. Upserts each asset into **`RECS_ONPREM_Asset_master_details`** (no duplicates on re-run)

#### curl:
```bash
curl -X POST 'http://localhost:8001/api/v1/recs/ingest/assets?customer_name=Banyan%20Cloud' \
  -H 'X-Tool-Token: <YOUR_TOOL_TOKEN>'
```

#### Sample Response:
```json
{
  "status_code": 200,
  "message": "Collection-1 ingestion done. Inserted=27, Failed=0.",
  "data": {
    "collection": "RECS_ONPREM_Asset_master_details",
    "customer_name": "Banyan Cloud",
    "total_fetched": 27,
    "inserted": 27,
    "failed": 0,
    "assets": [
      { "details_id": "69b9ef4e-...", "asset_id": "825c55fc-...", "status": "success" }
    ]
  }
}
```

#### Document stored in Collection-1:
```json
{
  "details_id": "69b9ef4e-2cd2-4205-af28-66fa6467b22f",
  "Onprem_SIEM_tool": "Onprem_SIEM_tool",
  "Onprem_Asset_name": "server-01",
  "Onprem_Asset_Ip": "192.168.1.10",
  "Onprem_Asset_id": "825c55fc-0908-463b-a414-3e999c71e4da",
  "Onprem_Asset_Type": "Linux",
  "Customer_Name": "Banyan Cloud",
  "ENCS_Tags": { "criticality": "High", "location": "DC1", "risk_score": 12 },
  "Onprem_asset_info": { "...full raw API-1 response..." },
  "Last_Configuration_assessment": 1748181600.0,
  "Last_Vulnerability_Assessment": 1748181600.0,
  "Created": 1748181600.0,
  "Updated": 1748181600.0
}
```

---

### 2️⃣ `POST /api/v1/recs/ingest/details`
**Step 2 — Fetch config + vulnerability from API-2 & API-3 → Insert into Collection-2**

#### What it does:
1. Reads **all assets** already stored in Collection-1
2. Calls external **API-2**: `GET /analyzer/compliance-manager/configuration?customerName=Banyan Cloud` (all pages)
3. Calls external **API-3**: `GET /analyzer/compliance-manager/vulnerability?customerName=Banyan Cloud` (all pages)
4. Builds two lookup dictionaries keyed by `asset_id`:
   - `config_by_asset_id` → from API-2
   - `vuln_by_asset_id`   → from API-3
5. For each asset from Collection-1:
   - Matches its `asset_id` to the config and vuln lookups
   - Combines both into a single document
   - `Configuration_Assessment` ← `cisBenchmarkData` array from API-2
   - `Vulnerabilities` ← `InstalledApplications` array from API-3
6. Upserts into **`RECS_ONPREM_Asset_Details`**

#### curl:
```bash
curl -X POST 'http://localhost:8001/api/v1/recs/ingest/details?customer_name=Banyan%20Cloud' \
  -H 'X-Tool-Token: <YOUR_TOOL_TOKEN>'
```

#### Sample Response:
```json
{
  "status_code": 200,
  "message": "Collection-2 ingestion done. Inserted=27, Failed=0.",
  "data": {
    "collection": "RECS_ONPREM_Asset_Details",
    "customer_name": "Banyan Cloud",
    "config_records_from_api2": 27,
    "vuln_records_from_api3": 27,
    "total_assets_processed": 27,
    "inserted": 27,
    "failed": 0
  }
}
```

#### Document stored in Collection-2:
```json
{
  "details_id": "69b9ef4e-2cd2-4205-af28-66fa6467b22f",
  "asset_id": "825c55fc-0908-463b-a414-3e999c71e4da",
  "Onprem_Asset_name": "server-01",
  "Onprem_Asset_Ip": "192.168.1.10",
  "Onprem_Asset_id": "825c55fc-...",
  "Configuration_Assessment": [ "...cisBenchmarkData array from API-2..." ],
  "Vulnerabilities": [ "...InstalledApplications array from API-3..." ],
  "raw_configuration": { "...full API-2 record..." },
  "raw_vulnerability":  { "...full API-3 record..." },
  "Created": 1748181600.0,
  "Updated": 1748181600.0
}
```

---

### 3️⃣ `POST /api/v1/recs/ingest/compliance`
**Step 3 — Explode CIS controls from Collection-2 → Insert into Collection-3**

#### What it does:
1. Reads **all assets** from Collection-1
2. For each asset, fetches its **Collection-2** document
3. Reads `raw_configuration.cisBenchmarkData` (list of CIS controls)
4. **Explodes** the list → creates **one separate MongoDB document per CIS Control ID**
5. Each document contains all CIS control schema fields:
   - `CIS_Control_id`, `control_title`, `Control_description`
   - `Security_Control_Type`, `Compliance_Status`
   - `Confidentiality`, `Integrity`, `Availability`, `Overall_Risk`
   - `Remediation_enabled`, `Remediation_Suggestions`
   - `Bc_HL_Config_id`, `BC_privacy_Config_id`, `bc_control_item_id`
6. Upserts into **`RECS_ONPREM_Asset_final_Compliance`**
   - Unique key: `(details_id + CIS_Control_id)` — no duplicates on re-run

> ⚠️ **Currently stores 0 controls** because the external tool returns `"cisBenchmarkData": []` (empty).
> Once the external tool is populated with real CIS data, just re-run Step 2 + Step 3.

#### curl:
```bash
curl -X POST 'http://localhost:8001/api/v1/recs/ingest/compliance' \
  -H 'X-Tool-Token: <YOUR_TOOL_TOKEN>'
```

#### Sample Response:
```json
{
  "status_code": 200,
  "message": "Collection-3 ingestion done. Total CIS controls stored=0, Failed=0.",
  "data": {
    "collection": "RECS_ONPREM_Asset_final_Compliance",
    "total_assets_processed": 27,
    "total_cis_controls_stored": 0,
    "failed": 0
  }
}
```

#### Document stored in Collection-3 (when cisBenchmarkData is populated):
```json
{
  "compliance_id": "uuid-auto-generated",
  "details_id": "69b9ef4e-...",
  "asset_id": "825c55fc-...",
  "Onprem_Asset_name": "server-01",
  "Onprem_Asset_Ip": "192.168.1.10",
  "CIS_Control_id": "1.1.1",
  "Cis_map_details": "...",
  "bc_control_item_id": "...",
  "control_title": "Ensure filesystem integrity is configured",
  "Control_description": "...",
  "Security_Control_Type": "Automatic",
  "Compliance_Status": "Pass",
  "Confidentiality": "High",
  "Integrity": "High",
  "Availability": "Medium",
  "Overall_Risk": "Low",
  "Bc_HL_Config_id": {},
  "BC_privacy_Config_id": {},
  "Remediation_enabled": "Yes",
  "Remediation_Suggestions": "...",
  "Created": 1748181600.0,
  "Updated": 1748181600.0
}
```

---

## 📖 READ APIs

### `GET /api/v1/recs/assets`
List all ingested assets from Collection-1 (paginated)
```bash
curl -X GET 'http://localhost:8001/api/v1/recs/assets?page=1&limit=10'
```

### `GET /api/v1/recs/assets/{details_id}`
Get a single asset by `details_id` from Collection-1
```bash
curl -X GET 'http://localhost:8001/api/v1/recs/assets/69b9ef4e-2cd2-4205-af28-66fa6467b22f'
```

### `GET /api/v1/recs/assets/{details_id}/details`
Get configuration + vulnerability data from Collection-2
```bash
curl -X GET 'http://localhost:8001/api/v1/recs/assets/69b9ef4e-2cd2-4205-af28-66fa6467b22f/details'
```

### `GET /api/v1/recs/assets/{details_id}/compliance`
Get all CIS controls from Collection-3 for an asset.
Optional filter: `?control_id=1.1.1`
```bash
curl -X GET 'http://localhost:8001/api/v1/recs/assets/69b9ef4e-2cd2-4205-af28-66fa6467b22f/compliance'
```

---

## 🔁 Execution Order

```
Step 1:  POST /api/v1/recs/ingest/assets      ← Calls API-1 → Fills Collection-1 (27 assets)
Step 2:  POST /api/v1/recs/ingest/details     ← Calls API-2 + API-3 → Fills Collection-2 (27 docs)
Step 3:  POST /api/v1/recs/ingest/compliance  ← Reads Collection-2 → Fills Collection-3 (N CIS controls)
```

---

## ⚙️ Environment Variables (`environment.env`)

| Variable | Value | Description |
|---|---|---|
| `RECS_TOOL_BASE_URL` | `http://172.16.1.212:18180/` | External compliance-manager base URL |
| `RECS_TOOL_TOKEN` | `eyJ...` | Default Bearer token (update when expired) |
| `RECS_CUSTOMER_NAME` | `Banyan Cloud` | Default customer name for API queries |
| `MONGO_DB_CLIENT_URL` | `mongodb://recs_onprem_user:add4567@172.16.1.167:27018/recs_onprem?authSource=admin` | MongoDB with write access |
| `RECS_MONGO_DB_URL` | `mongodb://recs_onprem_user:add4567@172.16.1.167:27018/recs_onprem?authSource=admin` | Dedicated RECS MongoDB connection |
| `RECS_MONGO_DB_NAME` | `recs_onprem` | MongoDB database name |

---

## 🔄 Token Refresh (When 403 Error Occurs)

The Bearer token for the external compliance-manager tool expires every ~2 hours.

**To refresh:**
1. Open browser → go to `http://172.16.1.212:18180`
2. Open DevTools (F12) → Network tab
3. Click any request → copy `Authorization` header value (without `Bearer ` prefix)
4. Update `RECS_TOOL_TOKEN` in `environment.env`
5. Restart the app: `python app.py`

**Or pass it per-request without restarting:**
```bash
curl -X POST '...ingest/assets...' \
  -H 'X-Tool-Token: <FRESH_TOKEN_HERE>'
```

---

## 🏗️ Files Modified / Created

| File | What Changed |
|---|---|
| `on_premise/routers/recs_router.py` | Replaced single `/recs/ingest` with 3 separate ingest APIs |
| `on_premise/service_connector/recs_connector.py` | Fixed URLs (`/analyzer/` prefix), added pagination, added `ping_tool()`, switched to `customerName` param |
| `on_premise/helpers/recs_helper.py` | Mapped actual API fields (`asset_name`, `cisBenchmarkData`, `InstalledApplications`) |
| `on_premise/db_adapter/mongo_connection.py` | Added `_recs_client` using `RECS_MONGO_DB_URL` for correct write permissions |
| `environment.env` | Fixed `MONGO_DB_CLIENT_URL` to `recs_onprem_user`, added `RECS_MONGO_DB_URL`, `RECS_CUSTOMER_NAME` |

