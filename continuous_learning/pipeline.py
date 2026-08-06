"""Build, evaluate, version, promote and roll back IDS model candidates.

The pipeline is deliberately offline. Live honeypot and IDS services must be
stopped before a candidate is promoted so an in-memory model can never be
partially replaced. Analyst feedback is append-only in SQLite; only the latest
review for each event is used to prepare the next sanitized dataset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dataset.labeling import APPROVED_LABELS
from dataset.prepare_dataset import (
    prepare_events,
    read_jsonl,
    write_dataset,
)


CONTINUOUS_LEARNING_VERSION = "1.0"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_LOG = PROJECT_ROOT / "data" / "raw_logs" / "honeypot_events.jsonl"
DEFAULT_DATABASE = PROJECT_ROOT / "website" / "backend" / "data" / "honeypot.db"
DEFAULT_ACTIVE_DIR = PROJECT_ROOT / "data" / "ml_ready"
DEFAULT_REGISTRY_DIR = PROJECT_ROOT / "data" / "continuous_learning"
REGISTRY_FILENAME = "registry.json"
MANIFEST_FILENAME = "continuous_learning_manifest.json"
ACTIVE_METADATA_FILENAME = "active_model.json"

MODEL_INPUT_FILES = (
    "preprocessor.joblib",
    "feature_names.json",
    "label_mapping.json",
    "preprocessing_manifest.json",
)
MODEL_FILES = (
    "decision_tree.joblib",
    "random_forest.joblib",
    "isolation_forest.joblib",
    "lstm_classifier.pt",
    "lstm_metrics.json",
    "training_manifest.json",
)
EVALUATION_FILES = (
    "evaluation_report.json",
    "evaluation_summary.csv",
    "confusion_matrices.json",
    "model_selection.json",
    "evaluation_manifest.json",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(value: datetime | None = None) -> str:
    return (value or _utc_now()).isoformat().replace("+00:00", "Z")


def _version_id(value: datetime | None = None) -> str:
    return (value or _utc_now()).strftime("v%Y%m%dT%H%M%SZ")


def _normalized_label(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def load_latest_feedback(database_path: Path) -> dict[str, dict[str, Any]]:
    """Read the latest append-only analyst decision for each reviewed event."""

    database_path = Path(database_path)
    if not database_path.is_file():
        return {}

    connection = sqlite3.connect(f"file:{database_path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='analyst_feedback'"
        ).fetchone()
        if table is None:
            return {}
        rows = connection.execute(
            """
            SELECT feedback.*
            FROM analyst_feedback AS feedback
            INNER JOIN (
              SELECT event_id, MAX(id) AS latest_id
              FROM analyst_feedback
              GROUP BY event_id
            ) AS latest ON latest.latest_id = feedback.id
            ORDER BY feedback.id ASC
            """
        ).fetchall()
    finally:
        connection.close()

    return {
        str(row["event_id"]).strip().lower(): dict(row)
        for row in rows
        if str(row["event_id"] or "").strip()
    }


def apply_analyst_feedback(
    rows: Sequence[Mapping[str, Any]],
    feedback_by_event: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Apply latest reviews without adding analyst text to model features."""

    corrected: list[dict[str, Any]] = []
    applied = 0
    false_positive_corrections = 0
    confirmed_attack_reviews = 0
    missing_events = set(feedback_by_event)

    for source_row in rows:
        row = dict(source_row)
        event_id = str(row.get("event_id") or "").strip().lower()
        feedback = feedback_by_event.get(event_id)
        if feedback is not None:
            missing_events.discard(event_id)
            verdict = str(feedback.get("verdict") or "").strip().lower()
            if verdict == "false_positive":
                row["label"] = "normal"
                applied += 1
                false_positive_corrections += 1
            elif verdict == "confirmed_attack":
                original = _normalized_label(feedback.get("original_attack_type"))
                if original in APPROVED_LABELS and original != "normal":
                    row["label"] = original
                elif row.get("label") == "normal":
                    row["label"] = "other_anomaly"
                applied += 1
                confirmed_attack_reviews += 1
        corrected.append(row)

    counts = Counter(str(row.get("label")) for row in corrected)
    return corrected, {
        "latest_reviews_loaded": len(feedback_by_event),
        "reviews_applied": applied,
        "confirmed_attack_reviews": confirmed_attack_reviews,
        "false_positive_corrections": false_positive_corrections,
        "reviewed_events_missing_from_raw_log": len(missing_events),
        "reviewed_event_ids_missing_from_raw_log": sorted(missing_events),
        "label_counts_after_feedback": {
            label: int(counts.get(label, 0)) for label in APPROVED_LABELS
        },
        "analyst_identity_used_as_model_input": False,
        "analyst_notes_used_as_model_input": False,
        "severity_override_used_as_training_label": False,
    }


def prepare_candidate_dataset(
    raw_log_path: Path,
    database_path: Path,
    output_dir: Path,
    *,
    hash_salt: str = "honeypot-dataset-v1",
) -> dict[str, Any]:
    """Create a sanitized dataset snapshot with latest feedback corrections."""

    raw_log_path = Path(raw_log_path).resolve()
    if not raw_log_path.is_file():
        raise FileNotFoundError(f"raw honeypot log not found: {raw_log_path}")

    events, malformed = read_jsonl(raw_log_path)
    rows, rejected, stats = prepare_events(events, hash_salt=hash_salt)
    feedback = load_latest_feedback(database_path)
    rows, feedback_stats = apply_analyst_feedback(rows, feedback)
    rejected = [*malformed, *rejected]

    label_counts = Counter(row["label"] for row in rows)
    stats = {
        **stats,
        "total_events": stats["total_events"] + len(malformed),
        "rejected_events": stats["rejected_events"] + len(malformed),
        "labels": {
            label: int(label_counts.get(label, 0)) for label in APPROVED_LABELS
        },
    }
    manifest = write_dataset(
        rows,
        rejected,
        stats,
        output_dir=Path(output_dir),
        source=str(raw_log_path),
    )
    manifest.update(
        {
            "continuous_learning_version": CONTINUOUS_LEARNING_VERSION,
            "feedback": feedback_stats,
            "safety": {
                **manifest.get("sanitization", {}),
                "latest_feedback_only": True,
                "analyst_notes_used_as_model_input": False,
                "analyst_identity_used_as_model_input": False,
                "raw_logs_modified": False,
            },
        }
    )
    _atomic_write_json(Path(output_dir) / "dataset_manifest.json", manifest)
    return manifest


def _selected_metrics(report: Mapping[str, Any]) -> dict[str, Any]:
    selection = report.get("selection", {})
    selected = selection.get("best_tabular_classifier", {}).get("selected_model")
    results = report.get("model_results", {})
    if selected not in {"decision_tree", "random_forest"} or selected not in results:
        raise ValueError("evaluation report is missing the selected tabular model")
    metrics = results[selected].get("metrics", {})
    fpr = metrics.get("false_positive_rate", {}).get("normal_as_attack")
    required = {
        "f1_macro": metrics.get("f1_macro"),
        "recall_macro": metrics.get("recall_macro"),
        "balanced_accuracy": metrics.get("balanced_accuracy"),
        "false_positive_rate": fpr,
        "test_rows": metrics.get("test_rows"),
    }
    if any(value is None for value in required.values()):
        raise ValueError("evaluation report is missing promotion metrics")
    return {"model": selected, **required}


def compare_evaluations(
    baseline_report: Mapping[str, Any] | None,
    candidate_report: Mapping[str, Any],
    *,
    max_f1_regression: float = 0.005,
    max_recall_regression: float = 0.01,
    max_fpr_increase: float = 0.01,
    minimum_test_rows: int = 10,
) -> dict[str, Any]:
    """Return transparent quality gates used by the promotion command."""

    candidate = _selected_metrics(candidate_report)
    if baseline_report is None:
        return {
            "decision": "manual_review",
            "reason": "No active evaluation report is available for comparison.",
            "baseline": None,
            "candidate": candidate,
            "gates": [],
            "all_quality_gates_passed": False,
        }

    baseline = _selected_metrics(baseline_report)
    gates = [
        {
            "name": "minimum_test_rows",
            "passed": int(candidate["test_rows"]) >= int(minimum_test_rows),
            "candidate": int(candidate["test_rows"]),
            "required": int(minimum_test_rows),
        },
        {
            "name": "macro_f1_non_regression",
            "passed": float(candidate["f1_macro"])
            >= float(baseline["f1_macro"]) - max_f1_regression,
            "baseline": float(baseline["f1_macro"]),
            "candidate": float(candidate["f1_macro"]),
            "allowed_regression": float(max_f1_regression),
        },
        {
            "name": "macro_recall_non_regression",
            "passed": float(candidate["recall_macro"])
            >= float(baseline["recall_macro"]) - max_recall_regression,
            "baseline": float(baseline["recall_macro"]),
            "candidate": float(candidate["recall_macro"]),
            "allowed_regression": float(max_recall_regression),
        },
        {
            "name": "false_positive_rate_non_regression",
            "passed": float(candidate["false_positive_rate"])
            <= float(baseline["false_positive_rate"]) + max_fpr_increase,
            "baseline": float(baseline["false_positive_rate"]),
            "candidate": float(candidate["false_positive_rate"]),
            "allowed_increase": float(max_fpr_increase),
        },
    ]
    all_passed = all(gate["passed"] for gate in gates)
    return {
        "decision": "promote" if all_passed else "retain_active",
        "reason": (
            "Candidate passed every configured quality gate."
            if all_passed
            else "Candidate failed one or more quality gates."
        ),
        "baseline": baseline,
        "candidate": candidate,
        "gates": gates,
        "all_quality_gates_passed": all_passed,
        "comparison_limit": (
            "Metrics may use different chronological holdouts when new events "
            "or feedback changed the dataset; promotion remains an explicit "
            "analyst action."
        ),
    }


def _run_command(arguments: Sequence[str], *, cwd: Path) -> None:
    print("[CONTINUOUS LEARNING]", " ".join(arguments))
    subprocess.run(list(arguments), cwd=cwd, check=True)


def _version_files(version_dir: Path) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for path in sorted(version_dir.rglob("*")):
        if path.is_file() and path.name != MANIFEST_FILENAME:
            relative = path.relative_to(version_dir).as_posix()
            files[relative] = {
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
    return files


def _load_registry(registry_dir: Path) -> dict[str, Any]:
    value = _read_json(registry_dir / REGISTRY_FILENAME, {})
    if not isinstance(value, Mapping):
        value = {}
    return {
        "continuous_learning_version": CONTINUOUS_LEARNING_VERSION,
        "active_version": value.get("active_version"),
        "versions": list(value.get("versions", [])),
        "rollbacks": list(value.get("rollbacks", [])),
    }


def _record_version(registry_dir: Path, entry: Mapping[str, Any]) -> None:
    registry = _load_registry(registry_dir)
    registry["versions"] = [
        item
        for item in registry["versions"]
        if item.get("version_id") != entry.get("version_id")
    ]
    registry["versions"].append(dict(entry))
    registry["versions"].sort(key=lambda item: str(item.get("created_at_utc", "")))
    _atomic_write_json(registry_dir / REGISTRY_FILENAME, registry)


def train_candidate(
    *,
    version_id: str,
    raw_log_path: Path,
    database_path: Path,
    registry_dir: Path,
    active_dir: Path,
    epochs: int,
    random_state: int,
    test_size: float,
    sequence_length: int,
    forest_trees: int,
    isolation_trees: int,
) -> dict[str, Any]:
    """Build one immutable candidate directory and register its outcome."""

    # Keep status, feedback export and registry operations usable even on a PC
    # where the heavier ML dependencies have not yet been loaded.
    from machine_learning.evaluate_models import evaluate_models
    from machine_learning.traditional_models import train_and_save_models
    from preprocessing.preprocess_dataset import preprocess_dataset

    registry_dir = Path(registry_dir).resolve()
    version_dir = registry_dir / "versions" / version_id
    if version_dir.exists():
        raise FileExistsError(f"model version already exists: {version_id}")

    dataset_dir = version_dir / "dataset"
    ml_ready_dir = version_dir / "ml_ready"
    model_dir = ml_ready_dir / "models"
    evaluation_dir = ml_ready_dir / "evaluation"
    version_dir.mkdir(parents=True, exist_ok=False)

    try:
        dataset_manifest = prepare_candidate_dataset(
            raw_log_path,
            database_path,
            dataset_dir,
        )
        if dataset_manifest["accepted_events"] < 20:
            raise ValueError("at least 20 accepted events are required for retraining")
        if dataset_manifest["labels"].get("normal", 0) < 2:
            raise ValueError("at least two normal events are required for retraining")

        preprocess_manifest = preprocess_dataset(
            dataset_dir / "honeypot_dataset.csv",
            ml_ready_dir,
            test_size=test_size,
            sequence_length=sequence_length,
        )
        training_manifest = train_and_save_models(
            ml_ready_dir,
            model_dir,
            random_state=random_state,
            forest_trees=forest_trees,
            isolation_trees=isolation_trees,
        )
        _run_command(
            [
                sys.executable,
                "-m",
                "machine_learning.train_lstm",
                "--input-dir",
                str(ml_ready_dir),
                "--output-dir",
                str(model_dir),
                "--epochs",
                str(epochs),
                "--random-state",
                str(random_state),
                "--device",
                "cpu",
            ],
            cwd=PROJECT_ROOT,
        )
        evaluation_report = evaluate_models(
            ml_ready_dir,
            model_dir,
            evaluation_dir,
            batch_size=256,
            warmup_runs=1,
            timing_runs=5,
            device_name="cpu",
            selection_tolerance=1e-12,
        )

        baseline_path = Path(active_dir) / "evaluation" / "evaluation_report.json"
        baseline_report = _read_json(baseline_path)
        comparison = compare_evaluations(baseline_report, evaluation_report)
        manifest = {
            "continuous_learning_version": CONTINUOUS_LEARNING_VERSION,
            "version_id": version_id,
            "created_at_utc": _utc_iso(),
            "status": "candidate",
            "source": {
                "raw_log": str(Path(raw_log_path).resolve()),
                "feedback_database": str(Path(database_path).resolve()),
            },
            "dataset": {
                "accepted_events": dataset_manifest["accepted_events"],
                "rejected_events": dataset_manifest["rejected_events"],
                "labels": dataset_manifest["labels"],
                "feedback": dataset_manifest["feedback"],
            },
            "preprocessing": {
                "train_rows": preprocess_manifest["split"]["train_rows"],
                "test_rows": preprocess_manifest["split"]["test_rows"],
                "encoded_features": preprocess_manifest["features"][
                    "encoded_feature_count"
                ],
            },
            "training": {
                "random_state": random_state,
                "lstm_epochs": epochs,
                "traditional_models": list(training_manifest["models"]),
            },
            "evaluation": comparison,
            "promotion": {
                "automatic_promotion": False,
                "requires_explicit_analyst_command": True,
                "live_services_must_be_stopped": True,
                "rollback_retained": True,
            },
            "safety": {
                "raw_logs_modified": False,
                "feedback_store_modified": False,
                "active_model_modified_during_retraining": False,
                "test_rows_used_for_model_fit": False,
                "automatic_host_blocking": False,
            },
        }
        manifest["files"] = _version_files(version_dir)
        _atomic_write_json(version_dir / MANIFEST_FILENAME, manifest)
        _record_version(
            registry_dir,
            {
                "version_id": version_id,
                "created_at_utc": manifest["created_at_utc"],
                "status": "candidate",
                "decision": comparison["decision"],
                "path": str(version_dir),
            },
        )
        return manifest
    except Exception:
        shutil.rmtree(version_dir, ignore_errors=True)
        raise


def _verify_candidate(version_dir: Path) -> dict[str, Any]:
    manifest_path = version_dir / MANIFEST_FILENAME
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, Mapping):
        raise ValueError(f"invalid candidate manifest: {manifest_path}")
    expected_files = manifest.get("files", {})
    if not isinstance(expected_files, Mapping) or not expected_files:
        raise ValueError("candidate manifest does not contain file hashes")
    for relative, metadata in expected_files.items():
        path = version_dir / str(relative)
        if not path.is_file() or _sha256_file(path) != metadata.get("sha256"):
            raise ValueError(f"candidate artifact hash mismatch: {relative}")
    if manifest.get("evaluation", {}).get("decision") != "promote":
        raise ValueError("candidate did not pass promotion quality gates")
    return dict(manifest)


def promote_candidate(
    version_id: str,
    *,
    registry_dir: Path,
    active_dir: Path,
    services_stopped: bool,
) -> dict[str, Any]:
    """Promote a verified candidate and retain the previous active tree."""

    if not services_stopped:
        raise ValueError("promotion requires --confirm-services-stopped")

    registry_dir = Path(registry_dir).resolve()
    active_dir = Path(active_dir).resolve()
    version_dir = registry_dir / "versions" / version_id
    manifest = _verify_candidate(version_dir)
    candidate_tree = version_dir / "ml_ready"
    for relative in (*MODEL_INPUT_FILES,):
        if not (candidate_tree / relative).is_file():
            raise FileNotFoundError(f"candidate is missing {relative}")
    for relative in MODEL_FILES:
        if not (candidate_tree / "models" / relative).is_file():
            raise FileNotFoundError(f"candidate is missing models/{relative}")
    for relative in EVALUATION_FILES:
        if not (candidate_tree / "evaluation" / relative).is_file():
            raise FileNotFoundError(f"candidate is missing evaluation/{relative}")

    active_dir.parent.mkdir(parents=True, exist_ok=True)
    rollbacks_dir = registry_dir / "rollbacks"
    rollbacks_dir.mkdir(parents=True, exist_ok=True)
    rollback_id = f"rollback-{_version_id()[1:]}"
    rollback_dir = rollbacks_dir / rollback_id
    staging_dir = active_dir.parent / f".{active_dir.name}.candidate-{version_id}"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    shutil.copytree(candidate_tree, staging_dir)
    _atomic_write_json(
        staging_dir / ACTIVE_METADATA_FILENAME,
        {
            "version_id": version_id,
            "promoted_at_utc": _utc_iso(),
            "rollback_id": rollback_id if active_dir.exists() else None,
            "manifest_sha256": _sha256_file(version_dir / MANIFEST_FILENAME),
        },
    )

    moved_active = False
    try:
        if active_dir.exists():
            active_dir.rename(rollback_dir)
            moved_active = True
        staging_dir.rename(active_dir)
    except Exception:
        if active_dir.exists() and active_dir != rollback_dir:
            shutil.rmtree(active_dir, ignore_errors=True)
        if moved_active and rollback_dir.exists():
            rollback_dir.rename(active_dir)
        raise

    registry = _load_registry(registry_dir)
    registry["active_version"] = version_id
    registry["rollbacks"].append(
        {
            "rollback_id": rollback_id,
            "created_at_utc": _utc_iso(),
            "replaced_by": version_id,
            "path": str(rollback_dir) if moved_active else None,
        }
    )
    for entry in registry["versions"]:
        if entry.get("version_id") == version_id:
            entry["status"] = "active"
            entry["promoted_at_utc"] = _utc_iso()
    _atomic_write_json(registry_dir / REGISTRY_FILENAME, registry)
    return {
        "active_version": version_id,
        "rollback_id": rollback_id if moved_active else None,
        "active_dir": str(active_dir),
        "automatic_promotion": False,
    }


def rollback_active(
    rollback_id: str,
    *,
    registry_dir: Path,
    active_dir: Path,
    services_stopped: bool,
) -> dict[str, Any]:
    """Restore one retained active model tree."""

    if not services_stopped:
        raise ValueError("rollback requires --confirm-services-stopped")
    registry_dir = Path(registry_dir).resolve()
    active_dir = Path(active_dir).resolve()
    source = registry_dir / "rollbacks" / rollback_id
    if not source.is_dir():
        raise FileNotFoundError(f"rollback was not found: {rollback_id}")

    displaced = registry_dir / "rollbacks" / f"replaced-{_version_id()[1:]}"
    if active_dir.exists():
        active_dir.rename(displaced)
    try:
        source.rename(active_dir)
    except Exception:
        if displaced.exists():
            displaced.rename(active_dir)
        raise

    metadata = _read_json(active_dir / ACTIVE_METADATA_FILENAME, {})
    registry = _load_registry(registry_dir)
    registry["active_version"] = metadata.get("version_id")
    registry["rollbacks"].append(
        {
            "rollback_id": displaced.name,
            "created_at_utc": _utc_iso(),
            "reason": f"displaced during rollback to {rollback_id}",
            "path": str(displaced),
        }
    )
    _atomic_write_json(registry_dir / REGISTRY_FILENAME, registry)
    return {
        "restored_rollback": rollback_id,
        "active_version": registry["active_version"],
        "new_rollback": displaced.name,
    }


def registry_status(registry_dir: Path, active_dir: Path) -> dict[str, Any]:
    registry = _load_registry(Path(registry_dir))
    active_metadata = _read_json(Path(active_dir) / ACTIVE_METADATA_FILENAME, {})
    return {
        **registry,
        "active_metadata": active_metadata,
        "active_artifacts_present": all(
            (Path(active_dir) / name).is_file() for name in MODEL_INPUT_FILES
        )
        and all(
            (Path(active_dir) / "models" / name).is_file() for name in MODEL_FILES
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-dir", type=Path, default=DEFAULT_REGISTRY_DIR)
    parser.add_argument("--active-dir", type=Path, default=DEFAULT_ACTIVE_DIR)
    commands = parser.add_subparsers(dest="command", required=True)

    status = commands.add_parser("status", help="show model registry status")
    status.set_defaults(action="status")

    prepare = commands.add_parser("prepare", help="prepare feedback-corrected data only")
    prepare.add_argument("--raw-log", type=Path, default=DEFAULT_RAW_LOG)
    prepare.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.set_defaults(action="prepare")

    retrain = commands.add_parser("retrain", help="build and evaluate a candidate")
    retrain.add_argument("--raw-log", type=Path, default=DEFAULT_RAW_LOG)
    retrain.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    retrain.add_argument("--version-id", default=None)
    retrain.add_argument("--epochs", type=int, default=20)
    retrain.add_argument("--random-state", type=int, default=42)
    retrain.add_argument("--test-size", type=float, default=0.2)
    retrain.add_argument("--sequence-length", type=int, default=10)
    retrain.add_argument("--forest-trees", type=int, default=200)
    retrain.add_argument("--isolation-trees", type=int, default=200)
    retrain.set_defaults(action="retrain")

    promote = commands.add_parser("promote", help="promote a quality-gated candidate")
    promote.add_argument("version_id")
    promote.add_argument("--confirm-services-stopped", action="store_true")
    promote.set_defaults(action="promote")

    rollback = commands.add_parser("rollback", help="restore a retained active model")
    rollback.add_argument("rollback_id")
    rollback.add_argument("--confirm-services-stopped", action="store_true")
    rollback.set_defaults(action="rollback")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "status":
        result = registry_status(args.registry_dir, args.active_dir)
    elif args.action == "prepare":
        result = prepare_candidate_dataset(
            args.raw_log,
            args.database,
            args.output_dir,
        )
    elif args.action == "retrain":
        if args.epochs < 1:
            raise ValueError("epochs must be positive")
        result = train_candidate(
            version_id=args.version_id or _version_id(),
            raw_log_path=args.raw_log,
            database_path=args.database,
            registry_dir=args.registry_dir,
            active_dir=args.active_dir,
            epochs=args.epochs,
            random_state=args.random_state,
            test_size=args.test_size,
            sequence_length=args.sequence_length,
            forest_trees=args.forest_trees,
            isolation_trees=args.isolation_trees,
        )
    elif args.action == "promote":
        result = promote_candidate(
            args.version_id,
            registry_dir=args.registry_dir,
            active_dir=args.active_dir,
            services_stopped=args.confirm_services_stopped,
        )
    else:
        result = rollback_active(
            args.rollback_id,
            registry_dir=args.registry_dir,
            active_dir=args.active_dir,
            services_stopped=args.confirm_services_stopped,
        )

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
