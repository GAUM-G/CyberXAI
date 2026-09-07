# LSTM generalization audit

- Active model changed: **No**
- Original test source-overlap rate: **96.94%**
- Original test event/path-template overlap: **100.00%**
- Group-isolated train/validation/test rows: **2779/591/710**
- Best epoch by validation loss: **38** of 40 completed
- Group-isolated validation accuracy: **0.9712**
- Group-isolated test accuracy: **0.9803**
- Group-isolated test macro F1: **0.9715**

The candidate checkpoint is audit-only and was not promoted. See `audit_results.json`,
`test_predictions.csv`, and `test_confusion_matrix.csv` for traceable evidence.
