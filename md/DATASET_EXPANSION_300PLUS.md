# Dataset expansion to 300+ accepted events per class

This update adds one reproducible utility:

```text
simulation/expand_dataset.py
```

It does not edit processed CSV or NumPy arrays. It counts only schema-valid
common events and appends varied controlled samples through
`core.logger.log_event()`.

The default target is 310 events per approved class, giving a small margin
above the required 300.

## Apply the update

Extract this ZIP directly into:

```text
D:\honeypot_v2
```

The resulting path must be:

```text
D:\honeypot_v2\simulation\expand_dataset.py
```

## Run it

Stop `run.py` and the JSONL-to-n8n forwarder first so nothing else writes to
the raw log during expansion. The backend and frontend are not required.

Open PowerShell:

```powershell
cd D:\honeypot_v2
.\.venv\Scripts\Activate.ps1

python .\simulation\expand_dataset.py --dry-run
python .\simulation\expand_dataset.py --target 310
```

The script:

1. Reads `data\raw_logs\honeypot_events.jsonl`.
2. Ignores older records that do not satisfy the common schema.
3. Creates a timestamped backup beside the raw log.
4. Appends only the number of events still required for each label.
5. Interleaves the class plan so a chronological train/test split is not
   filled with one class at the end.
6. Validates every new event and verifies the final per-class counts.
7. Restores the backup automatically if expansion fails.

Expected final result:

```text
normal                   310
ssh_bruteforce           310
ftp_bruteforce           310
sql_injection            310
xss                      310
directory_scanning       310
port_scanning            310
other_anomaly            409 or more

PASS: Every approved label meets the requested target.
```

## Validate with the real dataset builder

Do not overwrite `data\processed` yet. Build into a temporary directory:

```powershell
$validationDir = Join-Path `
    $env:TEMP `
    ("honeypot_dataset_300plus_" + (Get-Date -Format "yyyyMMdd_HHmmss"))

python .\dataset\prepare_dataset.py `
    --input-jsonl .\data\raw_logs\honeypot_events.jsonl `
    --output-dir $validationDir

if ($LASTEXITCODE -ne 0) {
    throw "300+ validation build failed."
}

Get-Content `
    (Join-Path $validationDir "dataset_manifest.json") `
    -Raw

git status --short
```

Every label in the manifest must be at least 300. The new utility and this
guide may appear as untracked files until they are intentionally committed.
Raw JSONL data and its timestamped backup should remain ignored by Git.
