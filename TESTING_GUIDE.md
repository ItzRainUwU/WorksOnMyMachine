# WorksOnMyMachine — Testing & Demonstration Guide

This guide provides end-to-end instructions for testing **WorksOnMyMachine** using both real external GitHub repositories and built-in benchmark projects, across both the **Web Control Plane Dashboard** and the **Command-Line Interface (CLI)**.

---

## 1. Pick a Good Repository to Test

### Option A: Real External GitHub Repo — `flask-realworld-example-app` (Recommended for ZIP Upload)
* **GitHub Repository:** [`gothinkster/flask-realworld-example-app`](https://github.com/gothinkster/flask-realworld-example-app)
* **Direct ZIP Download Link:**  
  [https://github.com/gothinkster/flask-realworld-example-app/archive/refs/heads/master.zip](https://github.com/gothinkster/flask-realworld-example-app/archive/refs/heads/master.zip)
* **Why it's a great test candidate:**
  - Widely recognized open-source production reference project (3,000+ GitHub stars).
  - Unpacks 45 files across 9 directories into an isolated sandbox.
  - Automatically flags missing environment variables (`conduit/settings.py`) that detonate in cleanroom CI runners without safe defaults.

### Option B: Built-in Benchmark Target — `demo_targets/nightmare_ml_service` (Recommended for Full Auto-Heal & Video Demo)
* **Location in Workspace:** `demo_targets/nightmare_ml_service`
* **Why it's the ultimate test candidate:**
  - Specifically crafted to showcase **all 5 layers of cross-OS portability landmines**:
    1. **Compiler Diagnostics:** Missing CPython headers (`Python.h`) and PostgreSQL client (`libpq-dev`).
    2. **Shell Portability:** Entrypoint with Windows `\r\n` (CRLF) line endings and missing shebang.
    3. **Container Security:** Unpinned `FROM python:latest` mutable tag running as `root`.
    4. **Path Landmines:** Hardcoded Windows drive letter `C:\Users\Dev\models\weights.bin` and backslashes.
    5. **Environment Drift:** Missing `SECRET_MODEL_BUCKET` variable absent from `.env.example`.
  - Takes readiness from **0% $\rightarrow$ 100% CleanRoom Certified** in under 1 second.

---

## 2. Web UI Testing Workflow (Step-by-Step)

### Step 1: Launch the Local Server
Ensure the backend server is running on `http://127.0.0.1:8000/`:
```powershell
# Using the workspace virtual environment
& ".\.venv\Scripts\python.exe" -m uvicorn worksonmymachine.app:app --host 127.0.0.1 --port 8000
```
Open your browser to: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### Step 2: Test the "Drop Project ZIP" Feature
1. Download [`master.zip`](https://github.com/gothinkster/flask-realworld-example-app/archive/refs/heads/master.zip) from GitHub.
2. In the top navigation bar, click **Open workspace target**.
3. Drag and drop the downloaded `.zip` file onto the dashed upload area:  
   **"Drop a project ZIP here or click to browse - ZIP only"**.
4. **What to observe:**
   - The status pill transitions to `Scan Running` $\rightarrow$ `All Systems Operational`.
   - The active target updates to `.worksonmymachine/uploads/upload-...`.
   - The dashboard dynamically populates with findings, readiness gauge, and file tree.

### Step 3: Inspect "Cross-OS Bugs"
1. Click **Cross-OS Bugs** in the left sidebar (or URL `#bugs`).
2. Test the severity filter pills:
   - Click **High** to view critical breaking issues.
   - Click **Fixed** to view healed issues.
   - Click **All** to view full inventory.
3. Test search: Type `ENV` or `PATH` in the search box to filter rows live.

### Step 4: Inspect the "Dependency Graph"
1. Click **Dependency Graph** in the left sidebar (or URL `#graph`).
2. **What to observe:**
   - A wide interactive canvas mapping target files $\rightarrow$ Merkle certificate $\rightarrow$ detected package dependencies $\rightarrow$ Docker base image.
   - Click **View dependency graph as text** to verify screen-reader / accessible plain-text alternative.

### Step 5: Test "Auto-Heal & Certify"
1. Switch target to `demo_targets/nightmare_ml_service` via the top target dropdown.
2. Notice the initial score: **Linux Readiness: 0%** (Awaiting scan / Failed compatibility checks).
3. Click the bright green **Auto-Heal & Certify** button in the top right.
4. **What to observe:**
   - Score leaps from **0% $\rightarrow$ 100% CleanRoom Certified**.
   - The **Git Diff - Dockerfile** panel appears on the right showing the exact side-by-side color-coded unified diff:
     - `FROM python:latest` $\rightarrow$ `FROM python:3.11.9-slim`
     - Automated injection of required `apt-get install` packages.
     - Non-root user addition (`USER appuser`).
5. Click **View File** on the Git Diff panel:
   - Immediately navigates to **Build & Deploy** (`#build`) showing all copy-on-write healed files.

### Step 6: Download the Merkle Certificate
1. On the **Dashboard**, scroll to the **CleanRoom Certificate** drawer.
2. Click **Download certificate JSON** (or copy to clipboard).
3. Open the downloaded JSON to inspect:
   - Deterministic SHA-256 Merkle root hash.
   - Detailed file nodes with individual hashes.
   - `is_cleanroom_certified: true`.

---

## 3. CLI Testing Workflow (Exact Terminal Commands)

WorksOnMyMachine includes a robust CLI for local developer workflows and CI/CD pipelines.

Run these commands in PowerShell from the repository root (`d:\Development\WorksOnMyMachine`):

```powershell
# Set PYTHONPATH to src
$env:PYTHONPATH='src'
$PYTHON=".\.venv\Scripts\python.exe"
```

### 1. Fast Static Scan (Rich Table Output)
Scan a target and display detected landmines with categorized severity:
```powershell
& $PYTHON -m worksonmymachine scan nightmare_ml_service
```
*Expected output:* A formatted Rich table listing `DOCKER-SHELL-EXEC`, `PATH-WINDOWS-DRIVE`, `ENV-MISSING`, `SHELL-CRLF`, and a **Readiness score: 0.00/100**.

---

### 2. Compiler Log Diagnosis & Auto-Apt Package Resolver
Diagnose compiler errors from GCC, Clang, or Python.h and get the exact package manager fix:
```powershell
& $PYTHON -m worksonmymachine parse-log nightmare_ml_service
```
*Expected output:*
```text
Root cause: A Python extension is being compiled without the CPython development header...
Exact apt-get install fix: apt-get update && apt-get install -y --no-install-recommends build-essential g++ gcc libgl1 libglib2.0-0 libpq-dev python3-dev
```

---

### 3. Copy-on-Write Auto-Healing (Dry Run)
Simulate auto-healing without mutating your source repository:
```powershell
& $PYTHON -m worksonmymachine heal nightmare_ml_service
```
*Expected output:*
- **Before readiness score:** `0.00/100`
- **After readiness score:** `100.00/100`
- **CleanRoom status:** `Uncertified -> CleanRoom Certified (100%)`
- Unified diffs patching `.env.example`, `Dockerfile.broken`, `app.py`, `entrypoint.sh`, and `requirements.lock`.

---

### 4. Apply Safe Healing to the Target
To permanently write the auto-healed changes to disk:
```powershell
& $PYTHON -m worksonmymachine audit nightmare_ml_service --auto-heal --apply --yes
```

---

### 5. Generate a CleanRoom Reproducibility Certificate
Generate a deterministic Merkle proof:
```powershell
# Human-readable table
& $PYTHON -m worksonmymachine certify nightmare_ml_service

# Export as JSON file
& $PYTHON -m worksonmymachine certify nightmare_ml_service --json --output certificate.json
```

---

### 6. Cryptographically Sign & Verify a Certificate
Sign the certificate with HMAC-SHA256 for tamper evidence:
```powershell
# Sign certificate
& $PYTHON -m worksonmymachine certify nightmare_ml_service --signing-key "omnirush-secret-key" --signature-key-id "ci-runner-1" --json --output signed_cert.json

# Verify signature
& $PYTHON -m worksonmymachine verify-certificate signed_cert.json --verification-key "omnirush-secret-key"
# Outputs: valid
```

---

### 7. Export CI/CD Reports (SARIF, Markdown, JSON)
Integrate with GitHub Actions / CI runners:
```powershell
# Export GitHub Code Scanning SARIF report
& $PYTHON -m worksonmymachine audit nightmare_ml_service --format sarif --output audit.sarif

# Export GitHub PR Summary Markdown
& $PYTHON -m worksonmymachine audit nightmare_ml_service --format markdown --output audit.md
```

---

### 8. Live Real-Time File Watcher
Run a continuous background watcher that rescans as soon as you save any file:
```powershell
& $PYTHON -m worksonmymachine watch nightmare_ml_service
```
*(Press `Ctrl+C` to stop watching).*

---

## 4. Key Talking Points for Demo & Judges

When demonstrating WorksOnMyMachine to hackathon judges:

1. **Zero Untrusted Execution:** WorksOnMyMachine scans ASTs and parses manifests statically. It **never runs untrusted user code**, making it completely safe for CI runners and multi-tenant environments.
2. **Offline-First & Air-Gapped:** Zero external CDN dependencies, zero telemetry phone-homes, zero third-party cloud API costs.
3. **Deterministic Merkle Attestation:** Produces SLSA-compatible cleanroom proofs of reproducibility so teams can mathematically verify that builds are reproducible across operating systems.
4. **Copy-on-Write Isolation:** All auto-healing operations are virtualized first so developers can review side-by-side diffs before applying any changes.
