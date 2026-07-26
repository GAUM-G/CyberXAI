# Step 7 sequence-context correction

This update keeps the chronological 80/20 row split and training-only fitting
of the preprocessing transformer.

It changes only LSTM sequence construction:

- Training sequence targets remain inside the training split.
- Test sequence targets remain inside the test split.
- A test sequence may use earlier training rows and earlier test-row features
  from the same `source_ip_hash + service` group.
- Future events and context labels are never used.
- Short histories are left-padded with all-zero timesteps.
- The future LSTM must mask all-zero padded timesteps before recurrent layers.

With the current 4,080-row dataset and sequence length 10, the expected array
shapes are:

```text
X_train_sequences.npy : (3264, 10, 23)
X_test_sequences.npy  : (816, 10, 23)
y_train_sequences.npy : (3264,)
y_test_sequences.npy  : (816,)
```

The encoded feature count should remain 23. The exact third dimension should
always match the encoded feature count in `preprocessing_manifest.json`.

Run the tests before rebuilding artifacts:

```powershell
python -m unittest discover -s tests -p "test_preprocessing.py" -v
python -m unittest discover -s tests -p "test_feature_engineering.py" -v
```

Then rerun preprocessing:

```powershell
python .\preprocessing\preprocess_dataset.py `
    --input-csv ".\data\processed\honeypot_dataset.csv" `
    --output-dir ".\data\ml_ready" `
    --test-size 0.2 `
    --sequence-length 10
```

Do not train the LSTM until the generated manifest and sequence arrays have
been verified.
