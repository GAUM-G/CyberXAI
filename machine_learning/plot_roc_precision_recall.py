"""Plot ROC and precision-recall curves from evaluated model predictions.

The evaluation evidence exports one CSV per model with ``true_label`` and a
continuous ``attack_score``.  This script treats every non-``normal`` label as
the positive (attack) class so supervised classifiers and the Isolation Forest
can be compared on the same binary detection task.

Run from the project root with::

    python -m machine_learning.plot_roc_precision_recall

An explicit prediction directory and output directory can also be supplied::

    python -m machine_learning.plot_roc_precision_recall \
        --predictions-dir report_evidence/runs/<run>/predictions \
        --output-dir data/ml_ready/evaluation/graphs
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import matplotlib

# A non-interactive backend makes the script work on servers and in CI.
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MultipleLocator, PercentFormatter
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "ml_ready" / "evaluation" / "graphs"

MODEL_ORDER = (
    "decision_tree",
    "random_forest",
    "lstm_classifier",
    "isolation_forest",
)
MODEL_NAMES = {
    "decision_tree": "Decision Tree",
    "random_forest": "Random Forest",
    "lstm_classifier": "LSTM Classifier",
    "isolation_forest": "Isolation Forest",
}
MODEL_COLORS = {
    "decision_tree": "#0072B2",
    "random_forest": "#009E73",
    "lstm_classifier": "#D55E00",
    "isolation_forest": "#CC79A7",
}


@dataclass(frozen=True)
class CurveData:
    """Continuous scores and derived curve metrics for one evaluated model."""

    model: str
    truth: np.ndarray
    scores: np.ndarray
    fpr: np.ndarray
    tpr: np.ndarray
    recall: np.ndarray
    precision: np.ndarray
    roc_auc: float
    average_precision: float

    @property
    def prevalence(self) -> float:
        return float(np.mean(self.truth))


def _latest_predictions_dir() -> Path:
    """Resolve the prediction exports from ``latest_run.txt`` or newest run."""

    latest_run_file = PROJECT_ROOT / "report_evidence" / "latest_run.txt"
    if latest_run_file.is_file():
        latest_run = Path(latest_run_file.read_text(encoding="utf-8").strip())
        if not latest_run.is_absolute():
            latest_run = PROJECT_ROOT / latest_run
        candidate = latest_run / "predictions"
        if candidate.is_dir():
            return candidate

    runs_dir = PROJECT_ROOT / "report_evidence" / "runs"
    candidates = [path for path in runs_dir.glob("*/predictions") if path.is_dir()]
    if candidates:
        return max(candidates, key=lambda path: path.stat().st_mtime)

    raise FileNotFoundError(
        "No evaluated prediction directory was found. Pass --predictions-dir "
        "with a directory containing *_predictions.csv files."
    )


def _read_curve_data(path: Path) -> CurveData:
    """Load and validate one model's binary attack scores."""

    truth: list[int] = []
    scores: list[float] = []
    reported_models: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"true_label", "attack_score"}
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")

        for line_number, row in enumerate(reader, start=2):
            label = (row.get("true_label") or "").strip().lower()
            score_text = (row.get("attack_score") or "").strip()
            if not label or not score_text:
                raise ValueError(f"{path}:{line_number} has an empty label or score")
            try:
                score = float(score_text)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{line_number} has a non-numeric attack_score"
                ) from exc
            if not np.isfinite(score):
                raise ValueError(f"{path}:{line_number} has a non-finite score")

            truth.append(0 if label == "normal" else 1)
            scores.append(score)
            if row.get("model"):
                reported_models.add(row["model"].strip().lower())

    if not truth:
        raise ValueError(f"{path} contains no predictions")
    if len(set(truth)) != 2:
        raise ValueError(f"{path} must contain both normal and attack examples")
    if len(reported_models) > 1:
        raise ValueError(f"{path} contains predictions from multiple models")

    model = next(iter(reported_models), path.stem.removesuffix("_predictions"))
    truth_array = np.asarray(truth, dtype=np.int8)
    score_array = np.asarray(scores, dtype=np.float64)
    fpr, tpr, _ = roc_curve(truth_array, score_array)
    precision, recall, _ = precision_recall_curve(truth_array, score_array)

    return CurveData(
        model=model,
        truth=truth_array,
        scores=score_array,
        fpr=fpr,
        tpr=tpr,
        recall=recall,
        precision=precision,
        roc_auc=float(roc_auc_score(truth_array, score_array)),
        average_precision=float(average_precision_score(truth_array, score_array)),
    )


def load_curves(predictions_dir: Path) -> list[CurveData]:
    """Load all supported evaluated-model prediction exports."""

    predictions_dir = predictions_dir.resolve()
    if not predictions_dir.is_dir():
        raise FileNotFoundError(f"Prediction directory does not exist: {predictions_dir}")

    curves: list[CurveData] = []
    for model in MODEL_ORDER:
        path = predictions_dir / f"{model}_predictions.csv"
        if path.is_file():
            curves.append(_read_curve_data(path))

    if not curves:
        raise FileNotFoundError(
            f"No supported *_predictions.csv files were found in {predictions_dir}"
        )
    return curves


def _style_axis(
    ax: plt.Axes,
    *,
    xlabel: str,
    ylabel: str,
    xlim: tuple[float, float] = (0.0, 1.0),
    ylim: tuple[float, float] = (0.0, 1.0),
    x_step: float = 0.1,
    y_step: float = 0.1,
    decimals: int = 0,
) -> None:
    """Apply consistent percentage axes, including focused/zoomed views."""

    ax.set_xlim(*xlim)
    ax.set_ylim(*ylim)
    ax.set_xlabel(xlabel, fontsize=13, labelpad=9)
    ax.set_ylabel(ylabel, fontsize=13, labelpad=9)
    ax.xaxis.set_major_locator(MultipleLocator(x_step))
    ax.yaxis.set_major_locator(MultipleLocator(y_step))
    ax.xaxis.set_minor_locator(MultipleLocator(x_step / 2.0))
    ax.yaxis.set_minor_locator(MultipleLocator(y_step / 2.0))
    ax.xaxis.set_major_formatter(PercentFormatter(xmax=1.0, decimals=decimals))
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0, decimals=decimals))
    ax.tick_params(axis="both", which="major", labelsize=10, length=6)
    ax.tick_params(axis="both", which="minor", length=3)
    ax.grid(which="major", color="#CBD5E1", linewidth=0.8, alpha=0.8)
    ax.grid(which="minor", color="#E2E8F0", linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_color("#64748B")


def _save_figure(fig: plt.Figure, output_dir: Path, stem: str, formats: Iterable[str]) -> None:
    for extension in formats:
        destination = output_dir / f"{stem}.{extension}"
        fig.savefig(destination, dpi=300, bbox_inches="tight", facecolor="white")
        print(f"[CURVES] Saved: {destination}")


def plot_roc(curves: list[CurveData], output_dir: Path, formats: Iterable[str]) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.subplots_adjust(left=0.075, right=0.985, top=0.82, bottom=0.24, wspace=0.20)
    for ax in axes:
        for curve in curves:
            ax.plot(
                curve.fpr,
                curve.tpr,
                drawstyle="steps-post",
                color=MODEL_COLORS.get(curve.model),
                linewidth=2.7,
                marker="o",
                markersize=3.5,
                markevery=max(1, len(curve.fpr) // 18),
                label=(
                    f"{MODEL_NAMES.get(curve.model, curve.model.replace('_', ' ').title())} "
                    f"(AUC = {curve.roc_auc:.4f})"
                ),
            )

    axes[0].plot(
        [0, 1], [0, 1], linestyle="--", color="#475569", linewidth=1.5,
        label="Chance baseline (AUC = 0.5000)",
    )
    axes[0].set_title("Complete ROC range", fontsize=15, pad=11, weight="bold")
    _style_axis(
        axes[0], xlabel="False Positive Rate", ylabel="True Positive Rate",
        x_step=0.1, y_step=0.1,
    )

    axes[1].set_title("Focused top-left region", fontsize=15, pad=11, weight="bold")
    _style_axis(
        axes[1], xlabel="False Positive Rate", ylabel="True Positive Rate",
        xlim=(0.0, 0.08), ylim=(0.96, 1.001), x_step=0.01, y_step=0.005,
        decimals=1,
    )
    axes[1].axvspan(0.0, 0.01, color="#DCFCE7", alpha=0.55, zorder=0)
    axes[1].text(
        0.005, 0.9615, "<= 1% FPR", ha="center", va="bottom",
        fontsize=9, color="#166534",
    )

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="lower center", bbox_to_anchor=(0.5, 0.015),
        ncol=3, fontsize=10, frameon=True, framealpha=0.97,
    )
    fig.suptitle(
        "ROC Curves: Attack vs Normal Traffic",
        fontsize=19, weight="bold",
    )
    _save_figure(fig, output_dir, "new roc", formats)
    plt.close(fig)


def plot_precision_recall(
    curves: list[CurveData], output_dir: Path, formats: Iterable[str]
) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.subplots_adjust(left=0.075, right=0.985, top=0.82, bottom=0.24, wspace=0.20)
    prevalence = float(np.mean([curve.prevalence for curve in curves]))
    for ax in axes:
        for curve in curves:
            ax.plot(
                curve.recall,
                curve.precision,
                drawstyle="steps-post",
                color=MODEL_COLORS.get(curve.model),
                linewidth=2.7,
                marker="o",
                markersize=3.5,
                markevery=max(1, len(curve.recall) // 18),
                label=(
                    f"{MODEL_NAMES.get(curve.model, curve.model.replace('_', ' ').title())} "
                    f"(AP = {curve.average_precision:.4f})"
                ),
            )

    axes[0].axhline(
        prevalence, linestyle="--", color="#475569", linewidth=1.5,
        label=f"Attack prevalence baseline ({prevalence:.1%})",
    )
    axes[0].set_title("Complete precision-recall range", fontsize=15, pad=11, weight="bold")
    _style_axis(
        axes[0], xlabel="Recall", ylabel="Precision", x_step=0.1, y_step=0.1,
    )

    axes[1].set_title("Focused high-performance region", fontsize=15, pad=11, weight="bold")
    _style_axis(
        axes[1], xlabel="Recall", ylabel="Precision",
        xlim=(0.94, 1.001), ylim=(0.985, 1.0005),
        x_step=0.01, y_step=0.0025, decimals=1,
    )

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles, labels, loc="lower center", bbox_to_anchor=(0.5, 0.015),
        ncol=3, fontsize=10, frameon=True, framealpha=0.97,
    )
    fig.suptitle(
        "Precision-Recall Curves: Attack vs Normal Traffic",
        fontsize=19, weight="bold",
    )
    _save_figure(fig, output_dir, "newprecall", formats)
    plt.close(fig)


def write_metrics(curves: list[CurveData], output_dir: Path) -> Path:
    """Write the plotted summary values for traceability."""

    destination = output_dir / "roc_precision_recall_metrics.csv"
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("model", "samples", "attack_prevalence", "roc_auc", "average_precision"),
        )
        writer.writeheader()
        for curve in curves:
            writer.writerow(
                {
                    "model": curve.model,
                    "samples": len(curve.truth),
                    "attack_prevalence": curve.prevalence,
                    "roc_auc": curve.roc_auc,
                    "average_precision": curve.average_precision,
                }
            )
    print(f"[CURVES] Saved: {destination}")
    return destination


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot ROC and precision-recall curves from evaluated predictions."
    )
    parser.add_argument(
        "--predictions-dir",
        type=Path,
        help="Directory containing the evaluated *_predictions.csv exports.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Figure destination (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--format",
        choices=("png", "svg", "both"),
        default="both",
        help="Image format to generate (default: both).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    predictions_dir = args.predictions_dir or _latest_predictions_dir()
    formats = ("png", "svg") if args.format == "both" else (args.format,)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    curves = load_curves(predictions_dir)
    plot_roc(curves, args.output_dir, formats)
    plot_precision_recall(curves, args.output_dir, formats)
    write_metrics(curves, args.output_dir)

    print(
        f"[CURVES] Complete: plotted {len(curves)} models from "
        f"{predictions_dir.resolve()}"
    )


if __name__ == "__main__":
    main()
