# Limitations and Missing Evidence

- No college DOCX/PDF template or Phase 1 report was present in the supplied workspace; the requested Times New Roman academic formatting was applied directly.
- The active LSTM's 1.0000 legacy saved-holdout result is reproduced, but 791/816 test rows share a source hash with training, all 816 reuse a training service/event/path template, and the boundary timestamp is identical. It is not used as the primary generalization estimate.
- A three-seed source-IP-hash group-isolated LSTM audit achieved 0.9761 mean test accuracy (population SD 0.0035) and 0.9675 mean macro F1 (SD 0.0033), with zero source-group overlap in every run. The active checkpoint remained unchanged; the packaged seed-42 checkpoint is an unpromoted candidate.
- Source-group isolation does not eliminate every dependency: service/event/path templates still repeat across groups. External capture, template-isolated or campaign-isolated validation remains unavailable and is required before deployment claims.
- Rules-only and complete-hybrid aggregate accuracy are unsupported by the saved feature arrays because they omit the raw stateful causal stream. A substitute fusion formula was not invented.
- Isolation Forest is binary anomaly detection; its operating-point accuracy/F1 is not directly comparable to multiclass metrics and its score is not calibrated probability.
- No separate validation split exists in the active saved preprocessing artifacts. The separate robustness audit does use group-isolated validation partitions and best-validation-loss checkpoint selection.
- End-to-end database/network latency, queue backlog, sustained throughput, process-level CPU/RAM, calibration error and an external dataset were not measured. The LSTM audit reports repeated-seed mean, population standard deviation and range, but three seeds are not a formal confidence interval.
- External Telegram delivery was deliberately disabled; webhook or Telegram receipt is not claimed.
- SQLite samples are read-only and sanitized. Production logs, database, models, tokens and configuration were not packaged.
- `CURRENT_SYSTEM_WORKFLOW.md`, `SETUP.md`, and `website/README_MERN_SETUP.md` still describe authenticated analyst access, while the current Flask routes/templates and root README implement a login-free localhost defender dashboard. The report follows the executable code; the backend `users` table and authentication routes are treated as legacy compatibility surfaces.
- An intermediate evidence-harness attempt processed the logger's reverse-chronological display list and therefore failed the inference contract. The final run reads the isolated JSONL in append/chronological order; the failed attempt is retained in `logs/live_run_attempt_reverse_order_failure.json` and no production detection logic was changed.
- Only browser/application screenshots genuinely captured from the running UI may be called screenshots. Missing views are listed in the manual checklist below.
