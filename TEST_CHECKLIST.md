# WorksOnMyMachine Test Checklist

Use this checklist from PowerShell at the project root:

```powershell
Set-Location "D:\Development\WorksOnMyMachine"
$env:PYTHONPATH = "src"
```

## 1. Automated checks

- [ ] Run the test suite:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m pytest -q
  ```

  Expected result: `55 passed, 2 skipped`.

- [ ] Check the dashboard JavaScript:

  ```powershell
  node --check src/worksonmymachine/static/app.js
  node --check src/worksonmymachine/static/icons.js
  ```

## 2. CLI scan and certificate

- [ ] Scan the intentionally broken fixture:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine scan nightmare_ml_service
  ```

  Confirm that a landmine issue table appears.

- [ ] Generate a certificate:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine certify nightmare_ml_service --output certificate.json
  ```

- [ ] Inspect the certificate:

  ```powershell
  $certificate = Get-Content ".\certificate.json" -Raw | ConvertFrom-Json
  $certificate.is_cleanroom_certified
  $certificate.linux_readiness_score
  $certificate.root_hash
  ```

  Expected: `is_cleanroom_certified` is `False`, and a Merkle root is present.

## 3. Export formats

- [ ] Generate a JSON audit report:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine audit nightmare_ml_service --format json --output audit.json
  ```

- [ ] Generate Markdown:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine audit nightmare_ml_service --format markdown --output audit.md
  ```

- [ ] Generate SARIF:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine audit nightmare_ml_service --format sarif --output audit.sarif
  ```

- [ ] Generate an auto-healing patch:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine audit nightmare_ml_service --format patch --auto-heal --output healed.patch
  ```

- [ ] Confirm the export files exist and are non-empty:

  ```powershell
  Get-Item ".\audit.json", ".\audit.md", ".\audit.sarif", ".\healed.patch"
  ```

- [ ] Validate the SARIF version:

  ```powershell
  $sarif = Get-Content ".\audit.sarif" -Raw | ConvertFrom-Json
  $sarif.version
  $sarif.runs[0].results.Count
  ```

  Expected: SARIF version `2.1.0` and at least one result.

## 4. Baseline and CI policy

- [ ] Create a baseline:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine audit nightmare_ml_service `
    --format json `
    --write-baseline `
    --baseline .worksonmymachine-baseline.json `
    --output baseline-audit.json
  ```

- [ ] Run a new-findings-only check:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine check nightmare_ml_service `
    --format json `
    --new-only `
    --baseline .worksonmymachine-baseline.json `
    --fail-on high `
    --output new-findings.json

  $LASTEXITCODE
  ```

  Expected exit code: `0`.

- [ ] Inspect the baseline result:

  ```powershell
  $newFindings = Get-Content ".\new-findings.json" -Raw | ConvertFrom-Json
  $newFindings.issues.Count
  $newFindings.suppressed_issue_count
  $newFindings.baseline_applied
  ```

  Expected: zero active issues, a positive suppressed count, and `True` for `baseline_applied`.

- [ ] Confirm a failing CI policy returns exit code `1`:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m worksonmymachine check nightmare_ml_service `
    --format sarif `
    --fail-on high `
    --output failing-check.sarif

  $LASTEXITCODE
  ```

  Expected exit code: `1`, because the fixture intentionally contains high-severity findings.

## 5. Start the API and dashboard

Open a second PowerShell window and run:

```powershell
Set-Location "D:\Development\WorksOnMyMachine"
$env:PYTHONPATH = "src"

& ".\.venv\Scripts\python.exe" -m uvicorn `
  --app-dir src `
  worksonmymachine.app:app `
  --host 127.0.0.1 `
  --port 8000
```

Leave this window running.

- [ ] Open the dashboard: <http://127.0.0.1:8000/>

- [ ] Check the health endpoint from another PowerShell window:

  ```powershell
  Invoke-RestMethod "http://127.0.0.1:8000/health"
  ```

  Expected status: `ok`.

## 6. API audit behavior

- [ ] Run an API audit:

  ```powershell
  $body = @{
      target = "nightmare_ml_service"
      auto_heal = $false
      new_only = $false
  } | ConvertTo-Json

  $report = Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/audit" `
    -ContentType "application/json" `
    -Body $body

  $report.issues.Count
  $report.certificate.is_cleanroom_certified
  $report.suppressed_issue_count
  ```

  Expected: findings are returned, the certificate is not cleanroom-certified, and the suppressed count is zero unless you configured suppressions.

- [ ] Test API baseline filtering:

  ```powershell
  $body = @{
      target = "nightmare_ml_service"
      auto_heal = $false
      new_only = $true
  } | ConvertTo-Json

  $newReport = Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/v1/audit" `
    -ContentType "application/json" `
    -Body $body

  $newReport.issues.Count
  $newReport.suppressed_issue_count
  $newReport.baseline_applied
  ```

  Expected after creating the baseline: zero active issues, a positive suppressed count, and `True` for `baseline_applied`.

## 7. Dashboard behavior

- [ ] Select `nightmare_ml_service` in the target selector.
- [ ] Click **Scan Repo**.
- [ ] Confirm the issue table, Linux readiness, dependency metrics, and execution log update.
- [ ] Click **Auto-Heal & Certify**.
- [ ] Confirm before/after certificate data and the Dockerfile diff appear.
- [ ] Confirm the source fixture is not modified in place.
- [ ] Open **Settings** and enable **New findings only**.
- [ ] Run the audit again.
- [ ] Confirm the baseline-filtered report has no active findings.
- [ ] Open the Reports drawer and download each artifact:
  - [ ] JSON
  - [ ] Certificate
  - [ ] Patch
  - [ ] SARIF
  - [ ] Markdown
- [ ] Confirm each downloaded file is non-empty and readable.

## 8. Cleanup

After testing, optionally remove generated files:

```powershell
Remove-Item `
  ".\certificate.json", `
  ".\audit.json", `
  ".\audit.md", `
  ".\audit.sarif", `
  ".\healed.patch", `
  ".\baseline-audit.json", `
  ".\new-findings.json", `
  ".\failing-check.sarif", `
  ".\.worksonmymachine-baseline.json" `
  -ErrorAction SilentlyContinue
```

Stop the API server with `Ctrl+C` when finished.

## Expected environment limitation

Docker is not installed in the current Windows environment. Docker build and
container smoke tests still need to be run on a Linux machine or CI runner.
