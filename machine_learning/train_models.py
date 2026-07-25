"""Train Step 10 Decision Tree, Random Forest, and Isolation Forest models."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from machine_learning.traditional_models import train_and_save_models
else:
    from .traditional_models import train_and_save_models


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("data/ml_ready"),
        help="Step 8 ML-ready artifact directory (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/ml_ready/models"),
        help="generated model directory (default: %(default)s)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="deterministic random seed (default: %(default)s)",
    )
    parser.add_argument(
        "--forest-trees",
        type=int,
        default=200,
        help="Random Forest tree count (default: %(default)s)",
    )
    parser.add_argument(
        "--isolation-trees",
        type=int,
        default=200,
        help="Isolation Forest tree count (default: %(default)s)",
    )
    parser.add_argument(
        "--isolation-contamination",
        type=float,
        default=0.05,
        help="expected normal-training outlier fraction (default: %(default)s)",
    )
    parser.add_argument(
        "--tree-max-depth",
        type=int,
        default=12,
        help="Decision Tree maximum depth (default: %(default)s)",
    )
    parser.add_argument(
        "--forest-max-depth",
        type=int,
        default=16,
        help="Random Forest maximum tree depth (default: %(default)s)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = train_and_save_models(
        args.input_dir,
        args.output_dir,
        random_state=args.random_state,
        forest_trees=args.forest_trees,
        isolation_trees=args.isolation_trees,
        isolation_contamination=args.isolation_contamination,
        tree_max_depth=args.tree_max_depth,
        forest_max_depth=args.forest_max_depth,
    )

    data = manifest["data"]
    models = manifest["models"]
    print(
        f"[ML] Train/Test rows: {data['train_rows']}/{data['test_rows']}"
    )
    print(f"[ML] Encoded features: {data['encoded_features']}")
    print(
        "[ML] Normal rows for Isolation Forest: "
        f"{data['normal_training_rows']}"
    )
    print(
        "[ML] Decision Tree classes: "
        f"{len(models['decision_tree']['classes_trained'])}"
    )
    print(
        "[ML] Random Forest classes: "
        f"{len(models['random_forest']['classes_trained'])}"
    )
    print(
        "[ML] Isolation Forest test anomalies: "
        f"{models['isolation_forest']['test_prediction_counts']['anomaly']}"
    )
    print(f"[ML] Output: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
