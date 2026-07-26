"""Train and evaluate the Step 11 PyTorch LSTM classifier."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Sequence

import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from machine_learning.lstm_model import LSTMClassifier
else:
    from .lstm_model import LSTMClassifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("data/ml_ready"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/ml_ready/models"),
    )
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--hidden-size", type=int, default=64)
    parser.add_argument("--num-layers", type=int, default=1)
    parser.add_argument("--dropout", type=float, default=0.30)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--weight-decay", type=float, default=0.0001)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--device",
        choices=("cpu", "cuda"),
        default="cpu",
    )

    return parser


def set_random_seed(random_state: int) -> None:
    random.seed(random_state)
    np.random.seed(random_state)
    torch.manual_seed(random_state)


def load_artifacts(input_dir: Path):
    filenames = {
        "X_train": "X_train_sequences.npy",
        "y_train": "y_train_sequences.npy",
        "X_test": "X_test_sequences.npy",
        "y_test": "y_test_sequences.npy",
    }

    arrays = {}

    for name, filename in filenames.items():
        path = input_dir / filename

        if not path.exists():
            raise FileNotFoundError(f"Missing required artifact: {path}")

        arrays[name] = np.load(path, allow_pickle=False)

    mapping_path = input_dir / "label_mapping.json"

    if not mapping_path.exists():
        raise FileNotFoundError(
            f"Missing required artifact: {mapping_path}"
        )

    with mapping_path.open("r", encoding="utf-8") as file:
        label_mapping = json.load(file)

    return (
        arrays["X_train"],
        arrays["y_train"],
        arrays["X_test"],
        arrays["y_test"],
        label_mapping,
    )


def validate_artifacts(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    label_mapping: dict[str, int],
) -> None:
    if X_train.ndim != 3 or X_test.ndim != 3:
        raise ValueError(
            "Sequence features must have shape "
            "(samples, time_steps, features)"
        )

    if y_train.ndim != 1 or y_test.ndim != 1:
        raise ValueError("Sequence labels must be one-dimensional")

    if len(X_train) != len(y_train):
        raise ValueError("Training feature/label counts do not match")

    if len(X_test) != len(y_test):
        raise ValueError("Testing feature/label counts do not match")

    if X_train.shape[1:] != X_test.shape[1:]:
        raise ValueError(
            "Training and testing sequence shapes do not match"
        )

    if not np.isfinite(X_train).all():
        raise ValueError("Training features contain NaN or infinity")

    if not np.isfinite(X_test).all():
        raise ValueError("Testing features contain NaN or infinity")

    class_ids = sorted(int(value) for value in label_mapping.values())
    expected_ids = list(range(len(label_mapping)))

    if class_ids != expected_ids:
        raise ValueError(
            "Label mapping must contain consecutive class IDs "
            "starting from zero"
        )

    valid_ids = set(expected_ids)

    if not set(np.unique(y_train)).issubset(valid_ids):
        raise ValueError("Training labels contain unknown class IDs")

    if not set(np.unique(y_test)).issubset(valid_ids):
        raise ValueError("Testing labels contain unknown class IDs")

    missing_training_classes = valid_ids - set(np.unique(y_train))

    if missing_training_classes:
        raise ValueError(
            "Training data is missing class IDs: "
            f"{sorted(missing_training_classes)}"
        )


def calculate_class_weights(
    labels: np.ndarray,
    num_classes: int,
) -> np.ndarray:
    counts = np.bincount(labels, minlength=num_classes)

    if np.any(counts == 0):
        raise ValueError(
            "Cannot calculate weights because a class has zero "
            "training samples"
        )

    return len(labels) / (num_classes * counts)


def evaluate_model(
    model: LSTMClassifier,
    features: np.ndarray,
    labels: np.ndarray,
    class_names: list[str],
    device: torch.device,
) -> dict:
    model.eval()

    inputs = torch.from_numpy(
        np.ascontiguousarray(features, dtype=np.float32)
    ).to(device)

    with torch.no_grad():
        scores = model(inputs)
        predictions = scores.argmax(dim=1).cpu().numpy()

    class_ids = list(range(len(class_names)))

    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy": float(
            balanced_accuracy_score(labels, predictions)
        ),
        "macro_f1": float(
            f1_score(
                labels,
                predictions,
                labels=class_ids,
                average="macro",
                zero_division=0,
            )
        ),
        "weighted_f1": float(
            f1_score(
                labels,
                predictions,
                labels=class_ids,
                average="weighted",
                zero_division=0,
            )
        ),
        "confusion_matrix": confusion_matrix(
            labels,
            predictions,
            labels=class_ids,
        ).tolist(),
        "prediction_counts": {
            class_names[index]: int(np.sum(predictions == index))
            for index in class_ids
        },
        "classification_report": classification_report(
            labels,
            predictions,
            labels=class_ids,
            target_names=class_names,
            output_dict=True,
            zero_division=0,
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.epochs <= 0:
        raise ValueError("epochs must be greater than zero")

    if args.batch_size <= 0:
        raise ValueError("batch-size must be greater than zero")

    if args.device == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA was requested but is unavailable")

    set_random_seed(args.random_state)

    device = torch.device(args.device)

    (
        X_train,
        y_train,
        X_test,
        y_test,
        label_mapping,
    ) = load_artifacts(args.input_dir)

    validate_artifacts(
        X_train,
        y_train,
        X_test,
        y_test,
        label_mapping,
    )

    X_train = np.ascontiguousarray(X_train, dtype=np.float32)
    X_test = np.ascontiguousarray(X_test, dtype=np.float32)
    y_train = np.ascontiguousarray(y_train, dtype=np.int64)
    y_test = np.ascontiguousarray(y_test, dtype=np.int64)

    class_names = [
        label
        for label, _ in sorted(
            label_mapping.items(),
            key=lambda item: int(item[1]),
        )
    ]

    num_classes = len(class_names)
    input_size = int(X_train.shape[2])
    sequence_length = int(X_train.shape[1])

    class_weights = calculate_class_weights(
        y_train,
        num_classes,
    )

    dataset = TensorDataset(
        torch.from_numpy(X_train),
        torch.from_numpy(y_train),
    )

    generator = torch.Generator()
    generator.manual_seed(args.random_state)

    loader = DataLoader(
        dataset,
        batch_size=args.batch_size,
        shuffle=True,
        num_workers=0,
        generator=generator,
    )

    model = LSTMClassifier(
        input_size=input_size,
        num_classes=num_classes,
        hidden_size=args.hidden_size,
        num_layers=args.num_layers,
        dropout=args.dropout,
    ).to(device)

    loss_function = nn.CrossEntropyLoss(
        weight=torch.tensor(
            class_weights,
            dtype=torch.float32,
            device=device,
        )
    )

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=args.learning_rate,
        weight_decay=args.weight_decay,
    )

    history = []

    print(f"[LSTM] Device: {device}")
    print(f"[LSTM] Training sequences: {len(X_train)}")
    print(f"[LSTM] Testing sequences: {len(X_test)}")
    print(f"[LSTM] Sequence shape: ({sequence_length}, {input_size})")
    print(f"[LSTM] Classes: {num_classes}")

    for epoch in range(1, args.epochs + 1):
        model.train()

        running_loss = 0.0
        correct = 0
        processed = 0

        for batch_features, batch_labels in loader:
            batch_features = batch_features.to(device)
            batch_labels = batch_labels.to(device)

            optimizer.zero_grad()

            scores = model(batch_features)
            loss = loss_function(scores, batch_labels)

            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            batch_count = batch_labels.size(0)

            running_loss += loss.item() * batch_count
            correct += (
                scores.argmax(dim=1) == batch_labels
            ).sum().item()
            processed += batch_count

        epoch_loss = running_loss / processed
        epoch_accuracy = correct / processed

        history.append(
            {
                "epoch": epoch,
                "loss": epoch_loss,
                "accuracy": epoch_accuracy,
            }
        )

        if epoch == 1 or epoch % 5 == 0 or epoch == args.epochs:
            print(
                f"[LSTM] Epoch {epoch:03d}/{args.epochs} "
                f"loss={epoch_loss:.6f} "
                f"accuracy={epoch_accuracy:.4f}"
            )

    train_metrics = evaluate_model(
        model,
        X_train,
        y_train,
        class_names,
        device,
    )

    test_metrics = evaluate_model(
        model,
        X_test,
        y_test,
        class_names,
        device,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)

    model_path = args.output_dir / "lstm_classifier.pt"
    metrics_path = args.output_dir / "lstm_metrics.json"

    checkpoint = {
        "format_version": "1.0",
        "model_name": "LSTMClassifier",
        "model_config": model.get_config(),
        "model_state_dict": model.state_dict(),
        "label_mapping": label_mapping,
        "sequence_length": sequence_length,
        "random_state": args.random_state,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "weight_decay": args.weight_decay,
        "class_weights": class_weights.tolist(),
    }

    torch.save(checkpoint, model_path)

    metrics_payload = {
        "framework": "PyTorch",
        "torch_version": torch.__version__,
        "device": str(device),
        "data": {
            "training_sequences": len(X_train),
            "testing_sequences": len(X_test),
            "sequence_length": sequence_length,
            "input_features": input_size,
            "num_classes": num_classes,
        },
        "label_mapping": label_mapping,
        "class_weights": {
            class_names[index]: float(class_weights[index])
            for index in range(num_classes)
        },
        "training_history": history,
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
    }

    with metrics_path.open("w", encoding="utf-8") as file:
        json.dump(metrics_payload, file, indent=2)

    print(
        f"[LSTM] Training accuracy: "
        f"{train_metrics['accuracy']:.4f}"
    )
    print(
        f"[LSTM] Test accuracy: "
        f"{test_metrics['accuracy']:.4f}"
    )
    print(
        f"[LSTM] Test macro F1: "
        f"{test_metrics['macro_f1']:.4f}"
    )
    print(f"[LSTM] Model saved: {model_path.resolve()}")
    print(f"[LSTM] Metrics saved: {metrics_path.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
