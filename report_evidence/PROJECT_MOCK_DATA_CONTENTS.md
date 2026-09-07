# project mock data package

This archive contains the corrected, sanitized implementation and results material for the final-year mock evaluation.

## Result to cite for the LSTM

- Primary internal estimate: source-IP-hash group-isolated three-seed audit.
- Accuracy: `0.9761` mean, population SD `0.0035`, range `0.9718-0.9803`.
- Macro F1: `0.9675` mean, population SD `0.0033`, range `0.9635-0.9715`.
- Balanced accuracy: approximately `0.9785` mean.
- Outer train/test and inner train/validation source-group overlap: zero in every run.
- The legacy chronological holdout reproduced `1.0000`, but it is not the primary generalization result: 791/816 test rows share a source hash with training, all 816 reuse a training service/event/path template, and the boundary timestamp is identical.
- No byte-identical train/test sequences were found. Template/campaign-isolated and external validation remain required.
- The active runtime LSTM was not modified; audit candidates were not promoted.

## Archive layout

- `reports/`: final report-sections DOCX/PDF, complete implementation report, quantitative model report, architecture explanation, and source Markdown.
- `evidence/`: expanded sanitized evidence archive containing tables, 300-DPI PNGs, SVGs, editable diagram sources, samples, predictions, manifests, checks, and LSTM robustness artifacts.
- `reproducibility/`: reusable evidence, LSTM-audit, report, and architecture builders.
- `archives/`: the standalone sanitized verified-evidence ZIP.

Raw producer event streams, databases, credentials, tokens, secrets, local configuration, and active model files are intentionally excluded.
