# sakshipromptnew package

This package contains the regenerated implementation, evaluation, and results material for the honeypot/Hybrid IDS project, including the complete LSTM accuracy investigation.

## LSTM result that should be cited

- The active legacy LSTM reproduces `1.0000` accuracy and macro F1 on 816 saved chronological-holdout sequences.
- That result is not the preferred generalization estimate: 791/816 legacy test rows (`96.94%`) share a source hash with training, 816/816 reuse a training service/event/path template, and the train-end and test-start timestamps are identical.
- No byte-identical train/test sequences were found. The detected issue is related-group/template overlap, not literal duplicated sequences.
- A three-seed `source_ip_hash` group-isolated audit produced mean test accuracy `0.9761` with population standard deviation `0.0035` (range `0.9718-0.9803`).
- Mean macro F1 was `0.9675` with population standard deviation `0.0033` (range `0.9635-0.9715`). Mean balanced accuracy was approximately `0.9785`.
- Source-group overlap was zero in every outer train/test and inner train/validation split.
- Templates still repeat across groups. External, template-isolated, or campaign-isolated validation remains required.
- The active runtime checkpoint was not modified. The seed-42 checkpoint and matching preprocessor are reproducible audit candidates only and were not promoted.

## Package layout

- `reports/`: final DOCX/PDF report sections, full implementation report, and model-evaluation PDF.
- `evidence/`: complete sanitized evidence run with tables, figures, diagrams, predictions, manifests, integrity checks, and LSTM robustness artifacts.
- `reproducibility/`: report generator and LSTM audit script.
- `archives/`: the separately generated verified evidence ZIP.

The raw isolated producer event stream, databases, credentials, tokens, secrets, and local configuration are intentionally excluded.
