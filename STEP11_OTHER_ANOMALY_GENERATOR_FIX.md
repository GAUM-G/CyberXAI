# Step 11: Isolated `other_anomaly` generator correction

## Why this change is required

The first controlled expansion reused only 28 source addresses for generated
`other_anomaly` authentication failures. That created short bursts from each
source and made the events behaviourally similar to SSH brute force.

The LSTM quality diagnostic showed the resulting problem:

- all 25 test `other_anomaly` sequences were misclassified;
- 21 of those 25 sequences were nearest to SSH brute-force training data;
- 17 of the 25 test sequences had four events, while training contained only
  one length-four `other_anomaly` sequence.

This is a generator/data-distribution defect, not an LSTM masking defect.

## Files in this correction

- `simulation/expand_dataset.py`
- `tests/test_dataset_expansion.py`
- `STEP11_OTHER_ANOMALY_GENERATOR_FIX.md`

## Behavioural correction

Generated `other_anomaly` events now represent isolated, pre-threshold
authentication probes:

- one non-repeating source address per generated probe;
- one unique session identifier per probe;
- `event="ssh_login_attempt"`;
- `attack_type="authentication_probe"`;
- `severity="info"`;
- `status="failed"`;
- `attempt_count=1`, below the threshold of 3.

SSH brute-force generation remains unchanged and continues to reuse sources,
use warning severity, and record an attempt count at or above the threshold.

## Installation verification

Run from the project root:

```powershell
python -m unittest discover `
    -s tests `
    -p "test_dataset_expansion.py" `
    -v
```

Then run the full suite:

```powershell
python -m unittest discover -s tests -v
```

Do not restore or regenerate the dataset until both suites pass.

## Recovery source

The verified recovery file is:

```text
data/raw_logs/honeypot_events.pre_expansion_20260726_125741Z.jsonl
```

It contains 905 schema-valid events:

```text
normal=154
ssh_bruteforce=119
ftp_bruteforce=38
sql_injection=98
xss=32
directory_scanning=48
port_scanning=7
other_anomaly=409
```

The recovery file must remain unchanged. Before regeneration, copy it to a
new timestamped safety backup and restore the current
`honeypot_events.jsonl` from the verified recovery file. Then run a dry run,
expand to 510 per class with the deterministic seed, and verify all 4,080
events and per-class counts before rebuilding downstream artifacts.
