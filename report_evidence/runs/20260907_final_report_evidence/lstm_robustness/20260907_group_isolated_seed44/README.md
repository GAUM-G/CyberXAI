# LSTM generalization audit

- Active model changed: **No**
- Original test source-overlap rate: **96.94%**
- Original test event/path-template overlap: **100.00%**
- Group-isolated train/validation/test rows: **2778/591/711**
- Best epoch by validation loss: **39** of 40 completed
- Group-isolated validation accuracy: **0.9848**
- Group-isolated test accuracy: **0.9761**
- Group-isolated test macro F1: **0.9675**

The candidate checkpoint is audit-only and was not promoted. See `audit_results.json`,
`test_predictions.csv`, and `test_confusion_matrix.csv` for traceable evidence.
