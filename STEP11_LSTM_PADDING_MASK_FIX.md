# Step 11 LSTM Padding-Mask Correction

This correction prevents leading zero-padding from changing the LSTM hidden
state.

## Files

- `machine_learning/lstm_model.py`
- `tests/test_lstm_model.py`

`train_lstm.py` does not need to change. The model infers the exact-zero
left-padding created by preprocessing, compacts the real timesteps, and passes
them to PyTorch using `pack_padded_sequence`.

## Safety properties

- leading padding is excluded from the recurrent computation;
- real events remain in chronological order;
- mixed sequence lengths are supported in the same batch;
- all-zero sequences are rejected;
- zero gaps after real data are rejected;
- the existing model configuration and trainer interface remain compatible.

## Test

```powershell
python -m unittest discover -s tests -p "test_lstm_model.py" -v
```

Expected result: six tests pass.

Do not load an older checkpoint into the corrected model. Retrain the LSTM
after the focused test and the existing full test suite both pass.
