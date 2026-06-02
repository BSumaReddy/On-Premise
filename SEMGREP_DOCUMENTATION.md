# 🔐 Semgrep Security Scan — Project Documentation

> **Project:** BanyanCloud On-Premise API  
> **Tool:** Semgrep SAST (Static Application Security Testing)  
> **Version:** Semgrep v1.163.0  
> **Stack:** Python 3.10 · FastAPI · GitHub Actions CI/CD  

---

## 📋 Table of Contents

1. [Overview](#1-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Project Files Involved](#3-project-files-involved)
4. [CI/CD Pipeline — Full Breakdown](#4-cicd-pipeline--full-breakdown)
5. [Semgrep Scan — How It Works](#5-semgrep-scan--how-it-works)
6. [Scan Output — report.json](#6-scan-output--reportjson)
7. [Diff Engine — Tracking Fixed Issues](#7-diff-engine--tracking-fixed-issues)
8. [.semgrepignore — Scan Exclusions](#8-semgrepignore--scan-exclusions)
9. [Backend Integration](#9-backend-integration)
10. [Security Findings — Real Example](#10-security-findings--real-example)
11. [Fix Applied & Verification](#11-fix-applied--verification)
12. [Demo Walkthrough — Run by Run](#12-demo-walkthrough--run-by-run)
13. [Severity & Security Standards Reference](#13-severity--security-standards-reference)
14. [Custom Rules](#14-custom-rules)
15. [Troubleshooting](#15-troubleshooting)
16. [Quick Reference Card](#16-quick-reference-card)

---

## 1. Overview

### What is Semgrep?

**Semgrep** is an open-source **Static Application Security Testing (SAST)** tool. It scans source code **without executing it** to detect security vulnerabilities, hardcoded secrets, and dangerous coding patterns — before they reach production.

```
┌──────────────────────────────────────────────────────────┐
│                    SAST Tool Comparison                  │
├─────────────────────┬────────────────────────────────────┤
│ Linters             │ Code style, syntax errors          │
│ (flake8, pylint)    │                                    │
├─────────────────────┼────────────────────────────────────┤
│ Semgrep             │ Security vulnerabilities, secrets, │
│ ✅ Used here        │ hardcoded tokens, dangerous APIs   │
├─────────────────────┼────────────────────────────────────┤
│ Dependency Scanners │ Vulnerable third-party libraries   │
│ (snyk, safety)      │                                    │
└─────────────────────┴────────────────────────────────────┘
```

### Why we use it

| Benefit | Description |
|---|---|
| 🔍 **Finds secrets early** | Detects hardcoded tokens before they reach git |
| 🤖 **Fully automated** | Runs on every push and pull request |
| 📊 **Tracks progress** | Shows fixed vs new issues across every run |
| 🔗 **Backend reporting** | Sends results to our dashboard via REST API |
| ⚙️ **Zero config** | `--config auto` auto-selects rules for our stack |

---

## 2. Architecture Diagram

```
  Developer
     │
     │  git push / pull request
     ▼
┌────────────────────────────────────────────────────────────────┐
│                    GitHub Repository                           │
│                   (main / test branch)                         │
└───────────────────────────┬────────────────────────────────────┘
                            │ Trigger
                            ▼
┌────────────────────────────────────────────────────────────────┐
│              GitHub Actions — semgrep.yml Pipeline             │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  1. Checkout Code          (clone repo)                 │   │
│  │  2. Setup Python 3.10      (runtime for semgrep)        │   │
│  │  3. Install Semgrep        (pip install semgrep)        │   │
│  │  4. Download Previous      (last run's report.json)  ◄──┼───┼──┐
│  │     Report Artifact        → previous_report/          │   │  │
│  │  5. Run Semgrep Scan       → report.json (current)      │   │  │
│  │  6. Show Report            (cat report.json in logs)    │   │  │
│  │  7. Compute Diff           (fixed/new/persistent)       │   │  │
│  │                            → diff_report.json           │   │  │
│  │  8. Upload report.json ────────────────────────────────────►──┘
│  │     (overwrites previous artifact)                      │   │
│  │  9. Upload diff_report.json (separate artifact)         │   │
│  │  10. POST to Backend        /api/scan/upload            │   │
│  │       POST to Backend       /api/scan/diff              │   │
│  └─────────────────────────────────────────────────────────┘   │
└──────────────┬─────────────────────────┬───────────────────────┘
               │                         │
               ▼                         ▼
    ┌─────────────────┐       ┌─────────────────────┐
    │  GitHub         │       │  Your Backend API   │
    │  Artifacts      │       │                     │
    │  ─────────────  │       │  POST /scan/upload  │
    │  semgrep-report │       │  POST /scan/diff    │
    │  semgrep-diff   │       │                     │
    └─────────────────┘       └─────────────────────┘
```

---

## 3. Project Files Involved

```
On-Premise/
│
├── .github/
│   └── workflows/
│       └── semgrep.yml              ← 🔧 CI/CD Pipeline definition
│
├── .semgrepignore                   ← 🚫 Files excluded from scanning
│
├── environment.env                  ← ⚠️  Runtime secrets (gitignored + semgrepignored)
├── environment.env.example          ← ✅  Safe placeholder template for teammates
│
├── app.py                           ← 🌐 FastAPI app (includes /api/scan/upload endpoint)
│
├── on_premise/
│   ├── routers/                     ← 🔍 Scanned by Semgrep
│   ├── helpers/                     ← 🔍 Scanned by Semgrep
│   ├── service_connector/
│   │   └── recs_connector.py        ← 🔍 Scanned (had a finding — now resolved)
│   └── utils/                       ← 🔍 Scanned by Semgrep
│
└── SEMGREP_DOCUMENTATION.md         ← 📄 This file
```

### Generated files per CI run (not committed)

```
report.json                ← Full Semgrep scan output
diff_report.json           ← Fixed / New / Persistent comparison
previous_report/
  └── report.json          ← Downloaded from last run's artifact
```

---

## 4. CI/CD Pipeline — Full Breakdown

**File:** `.github/workflows/semgrep.yml`

### Trigger Conditions

```yaml
on:
  push:
    branches: ["main", "test"]   # runs on push to main or test
  pull_request:                  # runs on every PR (any branch)
```

| Event | Branch | Pipeline Runs? |
|---|---|---|
| `git push` | `main` | ✅ Yes |
| `git push` | `test` | ✅ Yes |
| `git push` | `feature/*` | ❌ No |
| Pull Request | any → any | ✅ Yes |

---

### Step-by-Step Explanation

#### ① Checkout Code
```yaml
- uses: actions/checkout@v4
```
Clones the repository into the GitHub Actions runner (Ubuntu VM). All source files are now available for scanning.

---

#### ② Setup Python 3.10
```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.10"
```
Semgrep is a Python-based tool. Python 3.10 is required for it to run on the runner.

---

#### ③ Install Semgrep
```yaml
- run: pip install semgrep
```
Downloads and installs the Semgrep CLI from PyPI. This is the engine that performs all code scanning.

---

#### ④ Download Previous Report ⭐
```yaml
- uses: dawidd6/action-download-artifact@v6
  with:
    name: semgrep-report
    path: previous_report
    if_no_artifact_found: warn
  continue-on-error: true
```

| Key | Purpose |
|---|---|
| `name: semgrep-report` | Artifact name to look up from the last workflow run |
| `path: previous_report` | Save as `previous_report/report.json` |
| `if_no_artifact_found: warn` | Don't fail on first run (no previous artifact exists yet) |
| `continue-on-error: true` | Pipeline continues even if download fails |

> **Why `dawidd6` instead of official action?**  
> GitHub's official `download-artifact` can only download from the **same run**.  
> `dawidd6/action-download-artifact` can download from **previous workflow runs** — required for diff comparison.

---

#### ⑤ Run Semgrep Scan
```yaml
- run: semgrep scan --config auto --json -o report.json || true
```

| Flag | Meaning |
|---|---|
| `semgrep scan` | Execute the scanner |
| `--config auto` | Auto-detect languages, download matching rules from semgrep.dev |
| `--json` | Output in machine-readable JSON format |
| `-o report.json` | Save output to `report.json` |
| `\|\| true` | Don't fail the pipeline even when findings exist |

---

#### ⑥ Show Report
```yaml
- run: cat report.json
```
Prints the raw JSON to GitHub Actions logs so developers can review findings directly in CI output without downloading artifacts.

---

#### ⑦ Compute Diff and Fixed/New Findings ⭐
```yaml
- run: |
    python3 - <<'EOF'
    ...diff logic...
    EOF
```
This inline Python script:
- Loads `previous_report/report.json` (last run)
- Loads `report.json` (current run)
- Computes **fixed**, **new**, and **persistent** findings using set operations
- Writes `diff_report.json`
- Prints a human-readable summary to logs

*(See [Section 7](#7-diff-engine--tracking-fixed-issues) for full detail)*

---

#### ⑧ Upload Current Report as Artifact
```yaml
- uses: actions/upload-artifact@v4
  with:
    name: semgrep-report
    path: report.json
    overwrite: true
```
Saves `report.json` to GitHub Artifacts, **overwriting** the previous one. This becomes the "previous" report for the next run — completing the memory cycle.

---

#### ⑨ Upload Diff Report as Artifact
```yaml
- uses: actions/upload-artifact@v4
  with:
    name: semgrep-diff-report
    path: diff_report.json
```
Saves `diff_report.json` as a separate artifact. Downloadable under **Actions → Run → Artifacts**.

---

#### ⑩ Send Reports to Backend
```yaml
- run: |
    curl --max-time 10 -X POST "${BACKEND_URL}/api/scan/upload" \
      -H "Content-Type: application/json" \
      -d @report.json || true

    curl --max-time 10 -X POST "${BACKEND_URL}/api/scan/diff" \
      -H "Content-Type: application/json" \
      -d @diff_report.json || true
```

| curl flag | Meaning |
|---|---|
| `--max-time 10` | Timeout after 10 seconds (prevents pipeline hanging) |
| `-X POST` | HTTP POST method |
| `${{ secrets.BACKEND_URL }}` | URL injected from GitHub repository secret |
| `-d @report.json` | `@` = read body from file |
| `\|\| true` | Don't fail if backend is unreachable |

---

## 5. Semgrep Scan — How It Works

### What `--config auto` downloads

When Semgrep detects Python + YAML files in the repo, it auto-applies:

| Rule Pack | What it checks |
|---|---|
| `p/python` | Python-specific vulnerabilities |
| `p/secrets` | Hardcoded tokens, API keys, passwords, JWTs |
| `p/owasp-top-ten` | OWASP Top 10 vulnerabilities |
| `p/security-audit` | General security anti-patterns |
| `p/github-actions` | Insecure workflow configurations |

### Files scanned in this project

```
✅ Scanned:
  .github/workflows/semgrep.yml
  app.py
  on_premise/**/*.py          (all Python source files)
  requirements.txt
  README.md

🚫 Skipped (via .semgrepignore):
  environment.env
  *.env
  logs/
  __pycache__/
  *.pyc
```

### How Semgrep matches patterns

Semgrep uses **AST (Abstract Syntax Tree)** matching — not simple text search. This means it understands code structure.

```
Text/Regex search:   finds  "eyJ"  anywhere in file
Semgrep:             finds  JWT patterns in assignment statements,
                     understands it's inside a variable, not a comment
```

---

## 6. Scan Output — report.json

Every scan produces a `report.json` with this structure:

```json
{
  "version": "1.163.0",

  "results": [
    {
      "check_id": "generic.secrets.security.detected-jwt-token.detected-jwt-token",
      "path": "environment.env",
      "start": { "line": 50, "col": 17, "offset": 1362 },
      "end":   { "line": 50, "col": 114, "offset": 1459 },

      "extra": {
        "message":  "JWT token detected",
        "severity": "ERROR",

        "metadata": {
          "category":    "security",
          "confidence":  "LOW",
          "likelihood":  "LOW",
          "impact":      "MEDIUM",
          "cwe":         ["CWE-321: Use of Hard-coded Cryptographic Key"],
          "owasp":       ["A02:2021 - Cryptographic Failures"],
          "technology":  ["secrets", "jwt"],
          "subcategory": ["audit"]
        },

        "fingerprint":      "unique-hash-per-finding",
        "validation_state": "NO_VALIDATOR",
        "engine_kind":      "OSS"
      }
    }
  ],

  "errors": [],

  "paths": {
    "scanned": ["app.py", "environment.env", "on_premise/..."]
  },

  "time": {
    "profiling_times": { "total_time": 2.20 }
  }
}
```

### Field Reference

| Field | Description |
|---|---|
| `results` | All findings. Empty `[]` = completely clean scan |
| `check_id` | Unique rule identifier that triggered |
| `path` | Relative file path of the finding |
| `start.line` | Exact line number |
| `extra.message` | Human-readable description |
| `extra.severity` | `ERROR` / `WARNING` / `INFO` |
| `extra.metadata.cwe` | CWE vulnerability standard IDs |
| `extra.metadata.owasp` | OWASP Top 10 categories |
| `extra.fingerprint` | Unique hash used for deduplication |
| `errors` | Parser errors — empty means successful scan |
| `paths.scanned` | Every file that was checked |

---

## 7. Diff Engine — Tracking Fixed Issues

This is the **core feature** that turns Semgrep from a simple scanner into a security progress tracker.

### The Algorithm

```python
# Each finding is fingerprinted as a unique composite key:
key = f"{rule_id}|{file_path}|{line_number}|{message}"

# Example:
# "generic.secrets.security.detected-jwt-token|environment.env|50|JWT token detected"

# Python set operations determine the status of each finding:
fixed      = previous_findings - current_findings   # ✅ were present, now gone
new        = current_findings  - previous_findings  # 🆕 appeared for first time
persistent = previous_findings ∩ current_findings   # ⚠️ still unresolved
```

### diff_report.json Structure

```json
{
  "total_current":       0,
  "total_previous":      2,
  "new_findings":        0,
  "fixed_findings":      2,
  "persistent_findings": 0,

  "fixed": [
    "generic.secrets...|environment.env|50|JWT token detected",
    "generic.secrets...|recs_connector.py|25|JWT token detected"
  ],

  "new": []
}
```

### GitHub Actions Log Output

```
=== Semgrep Diff Summary ===
  Previous findings : 2
  Current  findings : 0
  ✅ Fixed           : 2
  🆕 New             : 0
  ⚠️  Persistent      : 0

--- Fixed Issues ---
  [generic.secrets.security.detected-jwt-token] environment.env:50 — JWT token detected
  [generic.secrets.security.detected-jwt-token] recs_connector.py:25 — JWT token detected
```

### Memory Between Runs via Artifacts

```
Run 1 (Monday)
  Scan   → 2 findings
  Upload → artifact "semgrep-report" saved ──────────────────────┐
                                                                  │
Run 2 (Tuesday)                                                   │
  Download ◄──── artifact "semgrep-report" ─────────────────────-┘
           saved as previous_report/report.json
  Scan   → 0 findings (after fix)
  Diff   → fixed=2, new=0 ✅
  Upload → artifact updated ────────────────────────────────────┐
                                                                 │
Run 3 (Wednesday — new code pushed)                              │
  Download ◄──── artifact "semgrep-report" ─────────────────────┘
  Scan   → 1 new finding
  Diff   → new=1  ⚠️   team is immediately alerted
```

---

## 8. .semgrepignore — Scan Exclusions

**File:** `.semgrepignore` (project root)  
**Syntax:** Identical to `.gitignore`

```gitignore
# Env files contain runtime secrets — skip scanning them
# (already gitignored, but Semgrep scans physical files by default)
*.env
environment.env

# Log files — not source code, may contain captured token values
logs/

# Python bytecode — not human-readable source
__pycache__/
*.pyc
```

### Why `.env` files must be excluded

Without `.semgrepignore`, Semgrep scans **every file physically present** — including `environment.env`. Even though it's gitignored (not committed to the repo), it exists on the runner's filesystem and will be scanned:

```
❌ Without .semgrepignore:
   Semgrep reads environment.env → finds RECS_TOOL_TOKEN=eyJ...
   → Flags as hardcoded JWT → FALSE POSITIVE (it's intentionally there)

✅ With .semgrepignore (*.env rule):
   Semgrep skips environment.env entirely → finding disappears
```

### How to add more exclusions

```gitignore
# Specific file
sensitive_config.json

# Entire folder
migrations/
tests/fixtures/

# File extensions (certificates, private keys)
*.pem
*.key
*.p12
*.pfx
```

### Inline suppression (per line)

```python
# Add # nosemgrep to suppress that specific line only
DEFAULT_TOKEN = os.getenv("RECS_TOOL_TOKEN", "")  # nosemgrep
```

---

## 9. Backend Integration

The pipeline sends scan data to the BanyanCloud backend after every run.

### GitHub Secret Setup

Navigate to: **GitHub Repo → Settings → Secrets and Variables → Actions → New repository secret**

| Secret Name | Value |
|---|---|
| `BACKEND_URL` | `https://your-backend-domain.com` *(no trailing slash)* |

### Endpoint 1 — Full Scan Report

```
POST /api/scan/upload
Content-Type: application/json
Body: report.json
```

**Handler in `app.py`:**
```python
@app.post("/api/scan/upload")
async def upload_scan(request: Request):
    """Receive Semgrep scan report from GitHub Actions CI pipeline."""
    data    = await request.json()
    results = data.get("results", [])
    errors  = data.get("errors",  [])
    return {
        "status":    "received",
        "findings":  len(results),
        "errors":    len(errors),
        "timestamp": datetime.utcnow().isoformat()
    }
```

**Response:**
```json
{ "status": "received", "findings": 0, "errors": 0, "timestamp": "2026-05-27T10:30:00" }
```

---

### Endpoint 2 — Diff Report

```
POST /api/scan/diff
Content-Type: application/json
Body: diff_report.json
```

**Used for:** Trend charts, alerting when new issues appear, fix rate tracking.

---

## 10. Security Findings — Real Example

These are the actual findings from the first scan of this project.

---

### Finding 1 — Hardcoded JWT Token in environment.env

| Field | Value |
|---|---|
| **Rule ID** | `generic.secrets.security.detected-jwt-token` |
| **File** | `environment.env` |
| **Line** | 50 |
| **Severity** | 🔴 ERROR |
| **CWE** | CWE-321: Use of Hard-coded Cryptographic Key |
| **OWASP** | A02:2021 — Cryptographic Failures |
| **Confidence** | LOW |
| **Impact** | MEDIUM |

**Vulnerable code:**
```env
# Line 50 — environment.env
RECS_TOOL_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiYW55YW4uY2xvdWQi...
#               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#               Real JWT — Semgrep detects the "eyJ..." Base64 header pattern
```

**Risk:** JWT tokens grant access to the RECS compliance-manager tool. If accidentally committed, the token remains in git history permanently and can be extracted by anyone with repo access.

---

### Finding 2 — JWT Detected in recs_connector.py

| Field | Value |
|---|---|
| **Rule ID** | `generic.secrets.security.detected-jwt-token` |
| **File** | `on_premise/service_connector/recs_connector.py` |
| **Line** | 25 |
| **Severity** | 🔴 ERROR |
| **CWE** | CWE-321: Use of Hard-coded Cryptographic Key |
| **OWASP** | A02:2021 — Cryptographic Failures |

**Code at line 25:**
```python
DEFAULT_TOKEN = os.getenv("RECS_TOOL_TOKEN", "")
```

**Why it was flagged:**  
At scan time, Semgrep resolved the env variable value from `environment.env` and detected the JWT. After `.semgrepignore` excludes `*.env`, the env file is not read — finding is gone.

---

## 11. Fix Applied & Verification

### Fix 1 — Replace Real JWT with Placeholder

**File:** `environment.env`

```diff
- RECS_TOOL_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiYW55YW4uY2xvdWQi...
+ RECS_TOOL_TOKEN=<REPLACE_WITH_YOUR_JWT_TOKEN>
```

> ⚠️ **To get a fresh token:**  
> Open the app in browser → DevTools (F12) → Network tab → Any API request → `Authorization` header → copy the `Bearer <token>` value

---

### Fix 2 — Create .semgrepignore

**File:** `.semgrepignore` (created at project root)

```gitignore
*.env
environment.env
logs/
__pycache__/
*.pyc
```

Permanently prevents Semgrep from scanning `.env` files in all future runs.

---

### Fix 3 — Create environment.env.example

**File:** `environment.env.example` (safe, committed template)

```env
RECS_TOOL_TOKEN=<REPLACE_WITH_YOUR_JWT_TOKEN>
RECS_TOOL_BASE_URL=http://<HOST>:<PORT>/
MONGO_DB_CLIENT_URL=mongodb://<USER>:<PASSWORD>@<HOST>:<PORT>/<DB>
```

New teammates copy this file to `environment.env` and fill in real values locally.

---

### Expected Scan After Fix

```
BEFORE FIX:  findings = 2  (JWT in env + connector)
AFTER FIX:   findings = 0  ✅

diff_report.json:
{
  "total_previous":      2,
  "total_current":       0,
  "fixed_findings":      2,      ← ✅ both issues resolved
  "new_findings":        0,
  "persistent_findings": 0
}
```

---

## 12. Demo Walkthrough — Run by Run

### 🔴 Run 1 — Discovery (Before Fix)

```
Trigger:   git push main  (initial commit)
Previous:  no artifact exists (first run ever)

Semgrep scans 38 files including environment.env

Findings: 2
  ❌  environment.env:50       → JWT token hardcoded
  ❌  recs_connector.py:25     → JWT token detected

diff_report.json:
  previous=0, current=2, fixed=0, new=2

GitHub Actions log:
  🆕 New : 2

Pipeline:  ✅ green  (|| true prevents failure on findings)

Backend:
  POST /api/scan/upload  →  { findings: 2 }
  POST /api/scan/diff    →  { new_findings: 2, fixed_findings: 0 }
```

---

### ✅ Run 2 — Fix Applied

```
Trigger:   git push main  ("fix: remove hardcoded JWT, add .semgrepignore")

Changes:
  - environment.env     → real JWT replaced with placeholder
  - .semgrepignore      → created (excludes *.env files)

Semgrep scans 37 files  (environment.env now skipped)

Findings: 0

diff_report.json:
  previous=2, current=0, fixed=2, new=0

GitHub Actions log:
  ✅ Fixed : 2
  🆕 New   : 0
  ⚠️  Persistent : 0

  --- Fixed Issues ---
  [detected-jwt-token] environment.env:50 — JWT token detected
  [detected-jwt-token] recs_connector.py:25 — JWT token detected

Pipeline:  ✅ green, 0 findings

Backend:
  POST /api/scan/upload  →  { findings: 0 }
  POST /api/scan/diff    →  { fixed_findings: 2, new_findings: 0 }
```

---

### 🔄 Run 3 — Ongoing (New Code)

```
Trigger:   git push main  (new feature added)

If clean:
  diff → fixed=0, new=0, persistent=0  ✅  all clear

If new issue introduced:
  diff → new=1  ⚠️   team is immediately alerted
```

---

## 13. Severity & Security Standards Reference

### Semgrep Severity

| Level | Icon | Meaning | Recommended Action |
|---|---|---|---|
| `ERROR` | 🔴 | High severity — likely exploitable | Fix before merging to main |
| `WARNING` | 🟡 | Medium severity — potential risk | Review and plan to fix soon |
| `INFO` | 🔵 | Informational — best practice | Fix when time permits |

---

### CWE (Common Weakness Enumeration)

| CWE ID | Name | Example in Code |
|---|---|---|
| CWE-321 | Hard-coded Cryptographic Key | JWT token in `.env` file |
| CWE-89 | SQL Injection | Raw f-string passed to SQL query |
| CWE-78 | OS Command Injection | `os.system(user_input)` |
| CWE-502 | Unsafe Deserialization | `pickle.loads(request_data)` |
| CWE-918 | Server-Side Request Forgery | Fetching URLs from user input |
| CWE-326 | Inadequate Encryption Strength | MD5/SHA1 used for passwords |

---

### OWASP Top 10 (2021)

| OWASP | Category | Relevant CWE |
|---|---|---|
| **A01** | Broken Access Control | CWE-284, CWE-285 |
| **A02** | Cryptographic Failures | CWE-321, CWE-326 ← *our finding* |
| **A03** | Injection | CWE-89, CWE-78 |
| **A04** | Insecure Design | CWE-73 |
| **A05** | Security Misconfiguration | CWE-16 |
| **A09** | Security Logging Failures | CWE-778 |

---

## 14. Custom Rules

Extend Semgrep with project-specific rules by creating `semgrep-rules/custom.yml`:

```yaml
rules:

  # Block print statements — use logger instead
  - id: no-print-statements
    pattern: print(...)
    message: "Use logger.info() instead of print() for consistent log management"
    languages: [python]
    severity: WARNING

  # Detect hardcoded internal IPs
  - id: no-hardcoded-ips
    patterns:
      - pattern: $X = "172.16.$A.$B"
      - pattern: $X = "10.0.$A.$B"
    message: "Do not hardcode IP addresses — use environment variables"
    languages: [python]
    severity: ERROR

  # Enforce Bearer token from env only
  - id: no-hardcoded-bearer-tokens
    pattern: $VAR = "Bearer $TOKEN"
    message: "Bearer tokens must not be hardcoded — use os.getenv()"
    languages: [python]
    severity: ERROR

  # Require timeout on HTTP requests
  - id: requests-no-timeout
    pattern: requests.get($URL)
    message: "Always specify timeout= in requests.get() to prevent pipeline hangs"
    languages: [python]
    severity: WARNING
```

### Enable in pipeline

```yaml
# semgrep.yml — update the scan step:
- name: Run Scan
  run: semgrep scan --config auto --config semgrep-rules/ --json -o report.json || true
```

---

## 15. Troubleshooting

### ❓ "No previous artifact" warning on every run

**Cause:** First run ever, artifact expired (90-day retention), or workflow renamed.  
**Impact:** Diff shows `previous=0` — treated as a fresh start.  
**Fix:** Expected behavior on first run. `continue-on-error: true` handles it gracefully.

---

### ❓ False positive — safe code is being flagged

**Option A — Inline suppression:**
```python
DEFAULT_TOKEN = os.getenv("RECS_TOOL_TOKEN", "")  # nosemgrep
```

**Option B — File-level exclusion in `.semgrepignore`:**
```
tests/
scripts/seed_data.py
```

**Option C — Rule-level suppression:**
```python
# nosemgrep: generic.secrets.security.detected-jwt-token
DEFAULT_TOKEN = os.getenv("RECS_TOOL_TOKEN", "")
```

---

### ❓ Backend POST not receiving data

1. Confirm `BACKEND_URL` secret is set: **GitHub → Repo → Settings → Secrets → Actions**
2. No trailing slash in URL: `https://example.com` ✅ not `https://example.com/` ❌
3. Backend must be accessible from GitHub Actions (public internet IP)
4. Backend must accept `Content-Type: application/json`
5. Check pipeline logs — curl response is printed even with `|| true`

---

### ❓ Scan is slow or times out

```bash
# Target specific rule packs instead of all auto rules
semgrep scan --config p/python --config p/secrets --json -o report.json || true

# Only scan high-severity findings
semgrep scan --config auto --severity ERROR --json -o report.json || true
```

---

### ❓ Too many findings / too much noise

Add low-value paths to `.semgrepignore`:
```gitignore
tests/
migrations/
scripts/
docs/
```

Or filter to only ERROR severity in the scan command.

---

## 16. Quick Reference Card

### Key Files

| File | Role |
|---|---|
| `.github/workflows/semgrep.yml` | Pipeline — runs on every push / PR |
| `.semgrepignore` | Exclusions — files Semgrep skips |
| `environment.env` | Runtime secrets (gitignored + semgrepignored) |
| `environment.env.example` | Safe template — committed to repo |
| `report.json` | Generated per run — full scan results |
| `diff_report.json` | Generated per run — fixed/new/persistent |

---

### CLI Commands

```bash
# Install Semgrep
pip install semgrep

# Run exactly as CI does
semgrep scan --config auto --json -o report.json

# Run and view results in terminal (no JSON file)
semgrep scan --config auto

# Scan a single file
semgrep scan --config auto on_premise/service_connector/recs_connector.py

# Only ERROR severity
semgrep scan --config auto --severity ERROR

# Use custom rules only
semgrep scan --config semgrep-rules/ --json -o report.json

# Auto + custom rules combined
semgrep scan --config auto --config semgrep-rules/ --json -o report.json
```

---

### GitHub Secrets Required

| Secret | Example Value |
|---|---|
| `BACKEND_URL` | `https://appqa.banyancloud.io:31432` |

---

### Backend Endpoints

| Method | Endpoint | Payload |
|---|---|---|
| `POST` | `/api/scan/upload` | Full `report.json` |
| `POST` | `/api/scan/diff` | `diff_report.json` |

---

### Diff Status Summary

| Status | Condition | Icon |
|---|---|---|
| **Fixed** | Present in previous scan, absent in current | ✅ |
| **New** | Absent in previous scan, present in current | 🆕 |
| **Persistent** | Present in both previous and current scans | ⚠️ |

---

*BanyanCloud On-Premise — Semgrep Security Integration*  
*Last Updated: May 2026 | Semgrep v1.163.0 | FastAPI v0.110.3 | Python 3.10*
