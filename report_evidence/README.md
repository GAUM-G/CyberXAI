# Verified report evidence

Latest run: `20260907_final_report_evidence`

Commands (from repository root):

```powershell
& data/runtime/python312/python.exe scripts/report_evidence.py inspect --run-dir "D:\honeypot_v2\report_evidence\runs\20260907_final_report_evidence"
& data/runtime/python312/python.exe scripts/report_evidence.py offline --run-dir "D:\honeypot_v2\report_evidence\runs\20260907_final_report_evidence"
& data/runtime/python312/python.exe scripts/report_evidence.py live --run-dir "D:\honeypot_v2\report_evidence\runs\20260907_final_report_evidence"
& data/runtime/python312/python.exe scripts/report_evidence.py render --run-dir "D:\honeypot_v2\report_evidence\runs\20260907_final_report_evidence"
& data/runtime/python312/python.exe scripts/report_evidence.py all-offline
& data/runtime/python312/python.exe scripts/audit_lstm_generalization.py --seed 42
& data/runtime/python312/python.exe scripts/audit_lstm_generalization.py --seed 43
& data/runtime/python312/python.exe scripts/audit_lstm_generalization.py --seed 44
```

`offline` runs inference only and verifies protected hashes. The separate LSTM audit uses source-IP-hash group-isolated train/validation/test partitions, training-only preprocessing and best-validation-loss checkpoint selection; it does not promote the candidate. `live` uses alternate localhost ports, isolated run files, disabled backend delivery and disabled external notifications. `render` builds every chart from CSV, stages the LSTM audit evidence, generates editable/rendered diagrams, Markdown, DOCX, traceability files and a sanitized ZIP.
