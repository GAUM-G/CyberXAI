"""Audit LSTM generalization with source-group-isolated validation and test sets.

This script deliberately writes only to report_evidence/lstm_robustness.  It
does not replace the production preprocessor, arrays, model, or metrics.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import random
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import joblib
import torch
from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_engineering.engineer_features import FeatureEngineeringState, engineer_rows
from machine_learning.lstm_model import LSTMClassifier
from machine_learning.train_lstm import calculate_class_weights, set_random_seed
from preprocessing.preprocess_dataset import (
    LABEL_TO_INDEX,
    MODEL_FEATURES,
    build_preprocessor,
    create_sequences,
    encode_labels,
    read_dataset,
    rows_to_matrix,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--dataset", type=Path, default=ROOT / "data/processed/honeypot_dataset.csv")
    value.add_argument("--output-dir", type=Path)
    value.add_argument("--max-epochs", type=int, default=40)
    value.add_argument("--patience", type=int, default=6)
    value.add_argument("--batch-size", type=int, default=64)
    value.add_argument("--hidden-size", type=int, default=64)
    value.add_argument("--dropout", type=float, default=0.30)
    value.add_argument("--learning-rate", type=float, default=0.001)
    value.add_argument("--weight-decay", type=float, default=0.0001)
    value.add_argument("--random-state", type=int, default=42)
    return value


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def choose_group_split(rows: list[dict], random_state: int) -> tuple[np.ndarray, np.ndarray, dict]:
    labels = np.asarray([row["label"] for row in rows])
    groups = np.asarray([row["source_ip_hash"] for row in rows])
    all_labels = sorted(set(labels))
    overall = Counter(labels)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    choices = []
    for fold, (train_index, test_index) in enumerate(splitter.split(np.zeros(len(rows)), labels, groups)):
        train_labels = Counter(labels[train_index])
        test_labels = Counter(labels[test_index])
        if any(train_labels[label] == 0 or test_labels[label] == 0 for label in all_labels):
            continue
        size_error = abs(len(test_index) / len(rows) - 0.20)
        distribution_error = sum(
            abs(test_labels[label] / len(test_index) - overall[label] / len(rows))
            for label in all_labels
        )
        choices.append((size_error + distribution_error, fold, train_index, test_index))
    if not choices:
        raise RuntimeError("No group-isolated fold retained every class")
    _, fold, train_index, test_index = min(choices, key=lambda item: (item[0], item[1]))
    train_groups = set(groups[train_index])
    test_groups = set(groups[test_index])
    if train_groups & test_groups:
        raise RuntimeError("Group isolation failed")
    return train_index, test_index, {
        "fold": int(fold),
        "train_rows": int(len(train_index)),
        "test_rows": int(len(test_index)),
        "train_groups": len(train_groups),
        "test_groups": len(test_groups),
        "group_overlap": 0,
        "test_class_counts": dict(Counter(labels[test_index])),
    }


def prepare(rows: list[dict], sequence_length: int = 10):
    engineered = engineer_rows([dict(row) for row in rows], state=FeatureEngineeringState())
    return engineered, rows_to_matrix(engineered), encode_labels(engineered)


def evaluate(model: LSTMClassifier, features: np.ndarray, labels: np.ndarray, class_names: list[str]):
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(np.ascontiguousarray(features, dtype=np.float32)))
        probabilities = torch.softmax(logits, dim=1).cpu().numpy()
    predictions = probabilities.argmax(axis=1)
    ids = list(range(len(class_names)))
    metrics = {
        "samples": len(labels),
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "macro_f1": float(f1_score(labels, predictions, labels=ids, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(labels, predictions, labels=ids, average="weighted", zero_division=0)),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=ids).tolist(),
        "classification_report": classification_report(labels, predictions, labels=ids, target_names=class_names, output_dict=True, zero_division=0),
    }
    return metrics, predictions, probabilities


def byte_keys(array: np.ndarray) -> list[bytes]:
    return [np.ascontiguousarray(item).tobytes() for item in array]


def original_split_audit(dataset_rows: list[dict]) -> dict:
    base = ROOT / "data/ml_ready"
    train_sequences = np.load(base / "X_train_sequences.npy", allow_pickle=False)
    test_sequences = np.load(base / "X_test_sequences.npy", allow_pickle=False)
    train_count = len(train_sequences)
    train_rows = dataset_rows[:train_count]
    test_rows = dataset_rows[train_count:]
    train_sources = {row["source_ip_hash"] for row in train_rows}
    train_templates = {(row["service"], row["event"], row["request_path"]) for row in train_rows}
    exact_train_sequences = set(byte_keys(train_sequences))
    return {
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_end_timestamp": train_rows[-1]["_timestamp"],
        "test_start_timestamp": test_rows[0]["_timestamp"],
        "boundary_timestamp_equal": train_rows[-1]["_timestamp"] == test_rows[0]["_timestamp"],
        "test_rows_from_sources_seen_in_train": sum(row["source_ip_hash"] in train_sources for row in test_rows),
        "source_overlap_rate": sum(row["source_ip_hash"] in train_sources for row in test_rows) / len(test_rows),
        "test_rows_with_event_path_template_seen_in_train": sum((row["service"], row["event"], row["request_path"]) in train_templates for row in test_rows),
        "template_overlap_rate": sum((row["service"], row["event"], row["request_path"]) in train_templates for row in test_rows) / len(test_rows),
        "exact_test_sequences_seen_in_train": sum(key in exact_train_sequences for key in byte_keys(test_sequences)),
    }


def main() -> int:
    args = parser().parse_args()
    if args.max_epochs < 1 or args.patience < 1:
        raise ValueError("max-epochs and patience must be positive")
    output = args.output_dir or ROOT / "report_evidence/lstm_robustness" / datetime.now().strftime("%Y%m%d_%H%M%S")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    set_random_seed(args.random_state)

    rows, read_stats = read_dataset(args.dataset)
    original_audit = original_split_audit(rows)
    outer_train_index, test_index, test_split = choose_group_split(rows, args.random_state)
    outer_train_rows = [rows[index] for index in outer_train_index]
    test_rows = [rows[index] for index in test_index]
    inner_train_index, validation_index, validation_split = choose_group_split(outer_train_rows, args.random_state + 1)
    train_rows = [outer_train_rows[index] for index in inner_train_index]
    validation_rows = [outer_train_rows[index] for index in validation_index]

    train_engineered, train_matrix, train_labels = prepare(train_rows)
    validation_engineered, validation_matrix, validation_labels = prepare(validation_rows)
    test_engineered, test_matrix, test_labels = prepare(test_rows)
    preprocessor = build_preprocessor()
    train_features = np.asarray(preprocessor.fit_transform(train_matrix), dtype=np.float32)
    validation_features = np.asarray(preprocessor.transform(validation_matrix), dtype=np.float32)
    test_features = np.asarray(preprocessor.transform(test_matrix), dtype=np.float32)
    train_sequences, train_targets = create_sequences(train_features, train_labels, train_engineered, sequence_length=10, pad_short_history=True)
    validation_sequences, validation_targets = create_sequences(validation_features, validation_labels, validation_engineered, sequence_length=10, pad_short_history=True)
    test_sequences, test_targets = create_sequences(test_features, test_labels, test_engineered, sequence_length=10, pad_short_history=True)

    class_names = [label for label, _ in sorted(LABEL_TO_INDEX.items(), key=lambda item: item[1])]
    model = LSTMClassifier(input_size=train_sequences.shape[2], num_classes=len(class_names), hidden_size=args.hidden_size, dropout=args.dropout)
    weights = torch.tensor(calculate_class_weights(train_targets, len(class_names)), dtype=torch.float32)
    criterion = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay)
    generator = torch.Generator().manual_seed(args.random_state)
    loader = DataLoader(TensorDataset(torch.from_numpy(train_sequences), torch.from_numpy(train_targets)), batch_size=args.batch_size, shuffle=True, generator=generator, num_workers=0)

    history = []
    best_loss = float("inf")
    best_state = None
    best_epoch = 0
    stale_epochs = 0
    validation_tensor = torch.from_numpy(validation_sequences)
    for epoch in range(1, args.max_epochs + 1):
        model.train()
        total_loss = 0.0
        correct = 0
        count = 0
        for features, labels in loader:
            optimizer.zero_grad()
            scores = model(features)
            loss = criterion(scores, labels)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += float(loss.item()) * len(labels)
            correct += int((scores.argmax(1) == labels).sum().item())
            count += len(labels)
        model.eval()
        with torch.no_grad():
            validation_scores = model(validation_tensor)
            validation_loss = float(criterion(validation_scores, torch.from_numpy(validation_targets)).item())
            validation_accuracy = float((validation_scores.argmax(1).numpy() == validation_targets).mean())
        history.append({"epoch": epoch, "training_loss": total_loss / count, "training_accuracy": correct / count, "validation_loss": validation_loss, "validation_accuracy": validation_accuracy})
        if validation_loss < best_loss - 1e-4:
            best_loss = validation_loss
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= args.patience:
                break
    if best_state is None:
        raise RuntimeError("Training produced no candidate checkpoint")
    model.load_state_dict(best_state)

    train_metrics, _, _ = evaluate(model, train_sequences, train_targets, class_names)
    validation_metrics, _, _ = evaluate(model, validation_sequences, validation_targets, class_names)
    test_metrics, test_predictions, test_probabilities = evaluate(model, test_sequences, test_targets, class_names)
    prediction_rows = []
    for index, (actual, predicted, probabilities) in enumerate(zip(test_targets, test_predictions, test_probabilities)):
        row = {"sample_index": index, "true_label": class_names[int(actual)], "predicted_label": class_names[int(predicted)], "confidence": float(np.max(probabilities))}
        row.update({f"p_{name}": float(probabilities[class_index]) for class_index, name in enumerate(class_names)})
        prediction_rows.append(row)
    confusion_rows = []
    for actual_index, actual in enumerate(class_names):
        for predicted_index, predicted in enumerate(class_names):
            confusion_rows.append({"actual": actual, "predicted": predicted, "count": test_metrics["confusion_matrix"][actual_index][predicted_index]})

    checkpoint = {
        "format_version": "1.0",
        "model_name": "LSTMClassifier",
        "purpose": "group-isolated robustness candidate; not promoted",
        "model_config": model.get_config(),
        "model_state_dict": model.state_dict(),
        "label_mapping": LABEL_TO_INDEX,
        "sequence_length": 10,
        "best_epoch": best_epoch,
        "random_state": args.random_state,
        "epochs_completed": len(history),
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "weight_decay": args.weight_decay,
    }
    torch.save(checkpoint, output / "lstm_group_isolated_candidate.pt")
    joblib.dump(preprocessor, output / "preprocessor_group_isolated.joblib")
    feature_names = [str(name) for name in preprocessor.get_feature_names_out(MODEL_FEATURES).tolist()]
    write_json(output / "feature_names.json", feature_names)
    assignments = []
    for split_name, split_rows in (("train", train_rows), ("validation", validation_rows), ("test", test_rows)):
        assignments.extend({"event_id": row["event_id"], "source_ip_hash": row["source_ip_hash"], "split": split_name, "label": row["label"]} for row in split_rows)
    write_csv(output / "split_assignments.csv", assignments)
    write_csv(output / "training_history.csv", history)
    write_csv(output / "test_predictions.csv", prediction_rows)
    write_csv(output / "test_confusion_matrix.csv", confusion_rows)
    results = {
        "status": "complete",
        "purpose": "diagnose the original perfect holdout result without changing the active model",
        "active_model_modified": False,
        "dataset_modified": False,
        "read_stats": read_stats,
        "original_split_audit": original_audit,
        "group_isolated_split": {"test": test_split, "validation_within_outer_train": validation_split, "train_rows": len(train_rows), "validation_rows": len(validation_rows), "test_rows": len(test_rows)},
        "configuration": {"max_epochs": args.max_epochs, "epochs_completed": len(history), "best_epoch": best_epoch, "patience": args.patience, "batch_size": args.batch_size, "hidden_size": args.hidden_size, "dropout": args.dropout, "learning_rate": args.learning_rate, "weight_decay": args.weight_decay, "random_state": args.random_state, "split_group": "source_ip_hash"},
        "metrics": {"train": train_metrics, "validation": validation_metrics, "test": test_metrics},
        "interpretation_rule": "A lower group-isolated score indicates optimistic original splitting. A still-perfect score indicates a highly separable/template-limited synthetic dataset and requires external or template-held-out data, not score manipulation.",
    }
    write_json(output / "audit_results.json", results)
    summary = f"""# LSTM generalization audit

- Active model changed: **No**
- Original test source-overlap rate: **{original_audit['source_overlap_rate']:.2%}**
- Original test event/path-template overlap: **{original_audit['template_overlap_rate']:.2%}**
- Group-isolated train/validation/test rows: **{len(train_rows)}/{len(validation_rows)}/{len(test_rows)}**
- Best epoch by validation loss: **{best_epoch}** of {len(history)} completed
- Group-isolated validation accuracy: **{validation_metrics['accuracy']:.4f}**
- Group-isolated test accuracy: **{test_metrics['accuracy']:.4f}**
- Group-isolated test macro F1: **{test_metrics['macro_f1']:.4f}**

The candidate checkpoint is audit-only and was not promoted. See `audit_results.json`,
`test_predictions.csv`, and `test_confusion_matrix.csv` for traceable evidence.
"""
    (output / "README.md").write_text(summary, encoding="utf-8")
    print(json.dumps({"status": "complete", "output_dir": str(output), "best_epoch": best_epoch, "validation_accuracy": validation_metrics["accuracy"], "test_accuracy": test_metrics["accuracy"], "test_macro_f1": test_metrics["macro_f1"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
