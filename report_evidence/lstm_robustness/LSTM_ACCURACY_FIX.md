# LSTM Accuracy Investigation and Corrective Evaluation

## Finding

The original `1.0000` value is a valid reproduction on the saved chronological
holdout, but it is not a defensible independent-generalization estimate.

- 791 of 816 original test rows (96.94%) use pseudonymous source identities
  also present in training.
- 816 of 816 test rows reuse a service/event/path template seen in training.
- The final training timestamp and first test timestamp are identical.
- There are no byte-identical train/test sequence arrays, so the problem is
  related-group and template overlap rather than literal array duplication.

## Correction applied

`scripts/audit_lstm_generalization.py` creates group-isolated train,
validation, and test partitions using `source_ip_hash`. It fits feature
engineering/preprocessing on training data, keeps validation and test sources
out of training, applies early stopping by validation loss, and writes a
candidate bundle without modifying the active model.

Across independent seeds 42, 43, and 44:

- Test accuracy range: 0.9718 to 0.9803.
- Mean test accuracy: 0.9761 (population standard deviation 0.0035).
- Test macro-F1 range: 0.9635 to 0.9715.
- Mean test macro-F1: 0.9675 (population standard deviation 0.0033).

The complete seed-42 candidate bundle contains its matching fitted
preprocessor, feature order, split assignments, checkpoint, history,
predictions, confusion matrix, and metrics in
`20260907_candidate_bundle_seed42/`.

## Reporting decision

Report `1.0000` only as the legacy chronological-holdout reproduction. Use
`0.9761 +/- 0.0035` accuracy and `0.9675 +/- 0.0033` macro F1 as the stronger
three-run source-group-isolated result. This corrects the evaluation design;
it does not manipulate the model score.

## Remaining limitation

The dataset is synthetic and event/path templates still repeat across source
groups. Final claims should therefore remain limited to this local dataset.
The next stronger test is a separately generated campaign/template-held-out
or external dataset evaluation.

