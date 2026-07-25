from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np

from machine_learning.traditional_models import (
    MODEL_ARTIFACT_FILES,
    fit_traditional_models,
    load_ml_ready_artifacts,
    train_and_save_models,
)


LABEL_MAPPING = {
    "normal": 0,
    "ssh_bruteforce": 1,
    "ftp_bruteforce": 2,
    "sql_injection": 3,
    "xss": 4,
    "directory_scanning": 5,
    "port_scanning": 6,
    "other_anomaly": 7,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def make_arrays(seed: int = 7):
    generator = np.random.default_rng(seed)
    normal = generator.normal(0.0, 0.25, size=(36, 6))
    ssh = generator.normal(3.0, 0.25, size=(18, 6))
    xss = generator.normal(-3.0, 0.25, size=(18, 6))
    X_train = np.vstack([normal, ssh, xss]).astype(np.float32)
    y_train = np.asarray(
        [LABEL_MAPPING["normal"]] * len(normal)
        + [LABEL_MAPPING["ssh_bruteforce"]] * len(ssh)
        + [LABEL_MAPPING["xss"]] * len(xss),
        dtype=np.int64,
    )
    X_test = np.vstack(
        [
            generator.normal(0.0, 0.25, size=(8, 6)),
            generator.normal(3.0, 0.25, size=(6, 6)),
            generator.normal(-3.0, 0.25, size=(6, 6)),
            generator.normal(8.0, 0.25, size=(4, 6)),
        ]
    ).astype(np.float32)
    y_test = np.asarray(
        [0] * 8 + [1] * 6 + [4] * 6 + [7] * 4,
        dtype=np.int64,
    )
    return X_train, X_test, y_train, y_test


def write_ml_ready(
    root: Path,
    *,
    arrays=None,
    safety_overrides=None,
) -> Path:
    ml_ready = root / "ml_ready"
    ml_ready.mkdir(parents=True, exist_ok=True)
    X_train, X_test, y_train, y_test = arrays or make_arrays()
    values = {
        "X_train.npy": X_train,
        "X_test.npy": X_test,
        "y_train.npy": y_train,
        "y_test.npy": y_test,
    }
    for filename, value in values.items():
        np.save(ml_ready / filename, value, allow_pickle=False)

    feature_names = [f"numeric__feature_{index}" for index in range(X_train.shape[1])]
    write_json(ml_ready / "feature_names.json", feature_names)
    write_json(ml_ready / "label_mapping.json", LABEL_MAPPING)

    safety = {
        "input_dataset_modified": False,
        "preprocessor_fitted_on_test_data": False,
        "raw_payload_used_as_direct_model_input": False,
        "direct_identifiers_used_as_model_inputs": False,
        "labels_used_for_feature_engineering": False,
        "future_events_used_for_feature_engineering": False,
    }
    safety.update(safety_overrides or {})
    manifest = {
        "preprocessing_version": "1.0",
        "split": {
            "strategy": "chronological",
            "train_rows": len(X_train),
            "test_rows": len(X_test),
            "transform_fit_scope": "training_rows_only",
        },
        "features": {
            "encoded_feature_count": X_train.shape[1],
            "engineering_scope": {
                "history": "current and past events only",
                "label_used": False,
            },
        },
        "labels": {"mapping": LABEL_MAPPING},
        "arrays": {
            filename: {
                "shape": list(value.shape),
                "dtype": str(value.dtype),
            }
            for filename, value in values.items()
        },
        "safety": safety,
        "files": {
            filename: {"sha256": sha256_file(ml_ready / filename)}
            for filename in (
                *values,
                "feature_names.json",
                "label_mapping.json",
            )
        },
    }
    write_json(ml_ready / "preprocessing_manifest.json", manifest)
    return ml_ready


def train_for_test(input_dir: Path, output_dir: Path):
    return train_and_save_models(
        input_dir,
        output_dir,
        forest_trees=20,
        isolation_trees=20,
        tree_max_depth=6,
        forest_max_depth=8,
    )


class ArtifactValidationTests(unittest.TestCase):
    def test_missing_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(Path(temporary))
            (input_dir / "X_test.npy").unlink()
            with self.assertRaisesRegex(FileNotFoundError, "X_test.npy"):
                load_ml_ready_artifacts(input_dir)

    def test_non_finite_features_are_rejected(self):
        arrays = list(make_arrays())
        arrays[0][0, 0] = np.nan
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(Path(temporary), arrays=tuple(arrays))
            with self.assertRaisesRegex(ValueError, "non-finite"):
                load_ml_ready_artifacts(input_dir)

    def test_train_test_feature_mismatch_is_rejected(self):
        X_train, X_test, y_train, y_test = make_arrays()
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(
                Path(temporary),
                arrays=(X_train, X_test[:, :-1], y_train, y_test),
            )
            with self.assertRaisesRegex(ValueError, "same feature count"):
                load_ml_ready_artifacts(input_dir)

    def test_unknown_label_index_is_rejected(self):
        X_train, X_test, y_train, y_test = make_arrays()
        y_test[0] = 99
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(
                Path(temporary),
                arrays=(X_train, X_test, y_train, y_test),
            )
            with self.assertRaisesRegex(ValueError, "unknown label"):
                load_ml_ready_artifacts(input_dir)

    def test_input_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(Path(temporary))
            feature_names = json.loads(
                (input_dir / "feature_names.json").read_text(encoding="utf-8")
            )
            feature_names[0] = "numeric__changed_after_manifest"
            write_json(input_dir / "feature_names.json", feature_names)
            with self.assertRaisesRegex(ValueError, "hash does not match"):
                load_ml_ready_artifacts(input_dir)

    def test_unsafe_preprocessing_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(
                Path(temporary),
                safety_overrides={"preprocessor_fitted_on_test_data": True},
            )
            with self.assertRaisesRegex(ValueError, "unsafe"):
                load_ml_ready_artifacts(input_dir)

    def test_two_normal_training_rows_are_required(self):
        X_train, X_test, y_train, y_test = make_arrays()
        y_train[:] = LABEL_MAPPING["ssh_bruteforce"]
        y_train[0] = LABEL_MAPPING["normal"]
        with tempfile.TemporaryDirectory() as temporary:
            input_dir = write_ml_ready(
                Path(temporary),
                arrays=(X_train, X_test, y_train, y_test),
            )
            with self.assertRaisesRegex(ValueError, "two normal"):
                load_ml_ready_artifacts(input_dir)


class ModelTrainingTests(unittest.TestCase):
    def test_trains_three_expected_models(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = load_ml_ready_artifacts(write_ml_ready(root))
            result = fit_traditional_models(
                artifacts,
                forest_trees=12,
                isolation_trees=12,
            )

        self.assertEqual(len(artifacts.X_test), len(result.decision_tree_predictions))
        self.assertEqual(len(artifacts.X_test), len(result.random_forest_predictions))
        self.assertEqual(len(artifacts.X_test), len(result.isolation_forest_predictions))
        self.assertEqual(36, result.normal_training_rows)

    def test_classifiers_do_not_use_test_labels_for_fit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_dir = write_ml_ready(root / "first")
            X_train, X_test, y_train, y_test = make_arrays()
            changed_y_test = np.roll(y_test, 5)
            second_dir = write_ml_ready(
                root / "second",
                arrays=(X_train, X_test, y_train, changed_y_test),
            )
            first = fit_traditional_models(
                load_ml_ready_artifacts(first_dir),
                forest_trees=12,
                isolation_trees=12,
            )
            second = fit_traditional_models(
                load_ml_ready_artifacts(second_dir),
                forest_trees=12,
                isolation_trees=12,
            )

        np.testing.assert_array_equal(
            first.decision_tree_predictions,
            second.decision_tree_predictions,
        )
        np.testing.assert_array_equal(
            first.random_forest_predictions,
            second.random_forest_predictions,
        )

    def test_isolation_forest_ignores_non_normal_training_rows(self):
        X_train, X_test, y_train, y_test = make_arrays()
        changed_X_train = X_train.copy()
        changed_X_train[y_train != LABEL_MAPPING["normal"]] += 1000.0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_dir = write_ml_ready(
                root / "first",
                arrays=(X_train, X_test, y_train, y_test),
            )
            second_dir = write_ml_ready(
                root / "second",
                arrays=(changed_X_train, X_test, y_train, y_test),
            )
            first = fit_traditional_models(
                load_ml_ready_artifacts(first_dir),
                forest_trees=12,
                isolation_trees=12,
            )
            second = fit_traditional_models(
                load_ml_ready_artifacts(second_dir),
                forest_trees=12,
                isolation_trees=12,
            )

        np.testing.assert_allclose(
            first.isolation_forest_scores,
            second.isolation_forest_scores,
        )

    def test_prediction_values_are_valid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = load_ml_ready_artifacts(write_ml_ready(root))
            result = fit_traditional_models(
                artifacts,
                forest_trees=12,
                isolation_trees=12,
            )

        allowed = set(LABEL_MAPPING.values())
        self.assertTrue(set(result.decision_tree_predictions.tolist()) <= allowed)
        self.assertTrue(set(result.random_forest_predictions.tolist()) <= allowed)
        self.assertTrue(
            set(result.isolation_forest_predictions.tolist()) <= {-1, 1}
        )
        self.assertTrue(np.isfinite(result.isolation_forest_scores).all())

    def test_same_seed_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = load_ml_ready_artifacts(write_ml_ready(root))
            first = fit_traditional_models(
                artifacts,
                random_state=19,
                forest_trees=12,
                isolation_trees=12,
            )
            second = fit_traditional_models(
                artifacts,
                random_state=19,
                forest_trees=12,
                isolation_trees=12,
            )

        np.testing.assert_array_equal(
            first.random_forest_predictions,
            second.random_forest_predictions,
        )
        np.testing.assert_allclose(
            first.isolation_forest_scores,
            second.isolation_forest_scores,
        )


class PublishedArtifactTests(unittest.TestCase):
    def test_saved_bundles_are_self_describing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir = write_ml_ready(root)
            output_dir = root / "models"
            train_for_test(input_dir, output_dir)
            decision_bundle = joblib.load(output_dir / "decision_tree.joblib")
            isolation_bundle = joblib.load(output_dir / "isolation_forest.joblib")

        self.assertEqual("decision_tree", decision_bundle["model_name"])
        self.assertEqual("training_rows_only", decision_bundle["fit_scope"])
        self.assertEqual(6, len(decision_bundle["feature_names"]))
        self.assertEqual(LABEL_MAPPING, decision_bundle["label_mapping"])
        self.assertEqual(
            "normal_training_features_only",
            isolation_bundle["fit_scope"],
        )
        self.assertNotIn("X_train", decision_bundle)
        self.assertNotIn("y_train", isolation_bundle)

    def test_manifest_records_leakage_safety_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = train_for_test(
                write_ml_ready(root),
                root / "models",
            )

        safety = manifest["safety"]
        self.assertTrue(safety["chronological_split_preserved"])
        self.assertFalse(safety["supervised_models_fitted_on_test_rows"])
        self.assertFalse(safety["test_labels_used_for_model_fit"])
        self.assertFalse(safety["isolation_forest_used_labels_as_features"])
        self.assertTrue(
            safety["training_labels_used_only_to_select_normal_rows"]
        )
        self.assertEqual(
            "normal_training_features_only",
            safety["isolation_forest_fit_scope"],
        )
        self.assertFalse(safety["raw_payload_used_as_direct_model_input"])
        self.assertFalse(safety["model_selection_performed"])

    def test_output_files_and_hashes_match_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_dir = root / "models"
            manifest = train_for_test(write_ml_ready(root), output_dir)

            self.assertTrue((output_dir / "training_manifest.json").is_file())
            for filename in MODEL_ARTIFACT_FILES:
                self.assertTrue((output_dir / filename).is_file())
                self.assertEqual(
                    manifest["files"][filename]["sha256"],
                    sha256_file(output_dir / filename),
                )


if __name__ == "__main__":
    unittest.main()
