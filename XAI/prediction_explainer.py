"""Generate safe, per-event Step 15 explanations for Hybrid IDS decisions.

Tree SHAP explains the selected Step 12 tabular classifier.  Deterministic
reason builders explain whichever component made the final hybrid decision,
including rules, LSTM sequence inference, and Isolation Forest.  The module is
inference-only: it never fits a model, writes an artifact, or changes a
prediction.
"""

from __future__ import annotations

import importlib
import math
from typing import Any, Mapping, Sequence

import numpy as np


XAI_VERSION = "1.0"
DEFAULT_TOP_FEATURES = 5


def _display_name(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    special = {
        "ftp": "FTP",
        "http": "HTTP",
        "ssh": "SSH",
        "sql_injection": "SQL injection",
        "xss": "XSS",
        "lstm_classifier": "LSTM classifier",
        "isolation_forest": "Isolation Forest",
        "decision_tree": "Decision Tree",
        "random_forest": "Random Forest",
        "other_anomaly": "unknown anomaly",
    }
    return special.get(text, text.replace("_", " "))


def _finite_float(value: Any, *, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a finite number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field} must be a finite number")
    return number


def _select_output_values(
    raw_values: Any,
    *,
    class_position: int,
    feature_count: int,
) -> np.ndarray:
    """Normalize SHAP's legacy and current multi-output return shapes."""

    if isinstance(raw_values, (list, tuple)):
        if not 0 <= class_position < len(raw_values):
            raise ValueError("SHAP output does not contain the explained class")
        values = np.asarray(raw_values[class_position], dtype=float)
    else:
        values = np.asarray(raw_values, dtype=float)

    if values.ndim == 1 and values.shape == (feature_count,):
        selected = values
    elif values.ndim == 2 and values.shape == (1, feature_count):
        selected = values[0]
    elif (
        values.ndim == 2
        and values.shape[0] == feature_count
        and class_position < values.shape[1]
    ):
        selected = values[:, class_position]
    elif (
        values.ndim == 3
        and values.shape[0] == 1
        and values.shape[1] == feature_count
        and class_position < values.shape[2]
    ):
        selected = values[0, :, class_position]
    elif (
        values.ndim == 3
        and values.shape[0] == 1
        and values.shape[2] == feature_count
        and class_position < values.shape[1]
    ):
        selected = values[0, class_position, :]
    else:
        raise ValueError(
            "SHAP returned an unsupported feature-contribution shape"
        )

    selected = np.asarray(selected, dtype=float).reshape(-1)
    if selected.shape != (feature_count,) or not np.isfinite(selected).all():
        raise ValueError("SHAP returned invalid feature contributions")
    return selected


def _select_base_value(value: Any, *, class_position: int) -> float:
    values = np.asarray(value, dtype=float)
    if values.ndim == 0:
        selected = float(values)
    else:
        flattened = values.reshape(-1)
        if class_position >= len(flattened):
            raise ValueError("SHAP base value does not contain explained class")
        selected = float(flattened[class_position])
    if not math.isfinite(selected):
        raise ValueError("SHAP returned a non-finite base value")
    return selected


def _factor_summary(factors: Sequence[Mapping[str, Any]]) -> str:
    parts: list[str] = []
    for factor in factors:
        points = factor.get("points")
        if isinstance(points, bool) or not isinstance(points, int) or points <= 0:
            continue
        name = str(factor.get("factor", "factor")).replace("_", " ")
        parts.append(f"{name} +{points}")
    return ", ".join(parts) if parts else "no risk points"


class PredictionExplainer:
    """Explain one Hybrid IDS result without changing the inference path."""

    def __init__(
        self,
        *,
        feature_names: Sequence[str],
        label_mapping: Mapping[str, int],
        tabular_model_name: str,
        tabular_estimator: Any,
        max_features: int = DEFAULT_TOP_FEATURES,
        shap_module: Any | None = None,
    ) -> None:
        names = tuple(str(name).strip() for name in feature_names)
        if not names or any(not name for name in names):
            raise ValueError("feature names must be non-empty")
        if len(names) != len(set(names)):
            raise ValueError("feature names must be unique")
        if isinstance(max_features, bool) or not isinstance(max_features, int):
            raise ValueError("max features must be an integer")
        if not 1 <= max_features <= len(names):
            raise ValueError("max features must be within feature count")

        mapping = {
            str(name).strip().lower(): int(index)
            for name, index in label_mapping.items()
        }
        if not mapping:
            raise ValueError("label mapping must be non-empty")
        if not hasattr(tabular_estimator, "classes_"):
            raise ValueError("tabular estimator must expose classes_")

        self.feature_names = names
        self.label_mapping = mapping
        self.tabular_model_name = str(tabular_model_name).strip().lower()
        self.tabular_estimator = tabular_estimator
        self.max_features = max_features
        self._shap_module = shap_module
        self._tree_explainer: Any | None = None
        self._status = "unavailable"
        self._status_reason = "shap_dependency_missing"
        self._initialize_shap()

    @property
    def status(self) -> str:
        return self._status

    @property
    def status_reason(self) -> str:
        return self._status_reason

    def _initialize_shap(self) -> None:
        if self._shap_module is None:
            try:
                self._shap_module = importlib.import_module("shap")
            except (ImportError, ModuleNotFoundError):
                return
            except Exception:
                self._status_reason = "shap_dependency_load_failed"
                return

        try:
            self._tree_explainer = self._shap_module.TreeExplainer(
                self.tabular_estimator,
                feature_names=list(self.feature_names),
                feature_perturbation="tree_path_dependent",
            )
        except Exception:
            self._tree_explainer = None
            self._status_reason = "shap_explainer_initialization_failed"
            return

        self._status = "ready"
        self._status_reason = "ready"

    def _class_position(self, attack_type: str) -> tuple[int, int]:
        normalized = str(attack_type).strip().lower()
        if normalized not in self.label_mapping:
            raise ValueError("tabular attack type is missing from label mapping")
        class_index = self.label_mapping[normalized]
        classes = np.asarray(self.tabular_estimator.classes_).reshape(-1)
        positions = np.flatnonzero(classes == class_index)
        if len(positions) != 1:
            raise ValueError("tabular class is missing from estimator classes")
        return class_index, int(positions[0])

    def _shap_explanation(
        self,
        encoded: np.ndarray,
        *,
        ids_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        tabular = ids_result.get("components", {}).get("tabular", {})
        attack_type = str(tabular.get("attack_type", "")).strip().lower()
        class_index, class_position = self._class_position(attack_type)
        final_model = str(ids_result.get("model_used", "")).strip().lower()
        final_attack = str(ids_result.get("attack_type", "")).strip().lower()
        supports_final = (
            self.tabular_model_name in final_model
            and final_attack == attack_type
        )

        base = {
            "status": self._status,
            "reason": self._status_reason,
            "explainer": "TreeExplainer",
            "scope": "selected_tabular_component",
            "explained_model": self.tabular_model_name,
            "explained_attack_type": attack_type,
            "explained_class_index": class_index,
            "supports_final_decision": supports_final,
            "top_features": [],
            "feature_count": len(self.feature_names),
        }
        if self._tree_explainer is None:
            return base

        try:
            raw_values = self._tree_explainer.shap_values(
                encoded,
                check_additivity=True,
            )
            contributions = _select_output_values(
                raw_values,
                class_position=class_position,
                feature_count=len(self.feature_names),
            )
            base_value = _select_base_value(
                self._tree_explainer.expected_value,
                class_position=class_position,
            )
        except Exception:
            base.update(
                {
                    "status": "unavailable",
                    "reason": "shap_explanation_failed",
                }
            )
            return base

        feature_values = encoded[0]
        ranked = sorted(
            range(len(self.feature_names)),
            key=lambda index: (
                -abs(float(contributions[index])),
                self.feature_names[index],
            ),
        )
        top_features = []
        for index in ranked[: self.max_features]:
            contribution = float(contributions[index])
            direction = (
                "supports_explained_class"
                if contribution > 0
                else "opposes_explained_class"
                if contribution < 0
                else "neutral"
            )
            top_features.append(
                {
                    "feature": self.feature_names[index],
                    "value": round(float(feature_values[index]), 6),
                    "shap_value": round(contribution, 6),
                    "direction": direction,
                }
            )

        base.update(
            {
                "status": "ready",
                "reason": "ready",
                "base_value": round(base_value, 6),
                "explained_output": round(
                    base_value + float(contributions.sum()),
                    6,
                ),
                "absolute_contribution_total": round(
                    float(np.abs(contributions).sum()),
                    6,
                ),
                "top_features": top_features,
            }
        )
        return base

    @staticmethod
    def _rule_reason(
        ids_result: Mapping[str, Any],
        rule_findings: Sequence[Mapping[str, Any]],
    ) -> str:
        attack_type = str(ids_result.get("attack_type", "unknown"))
        display_attack = _display_name(attack_type)
        matching = [
            finding
            for finding in rule_findings
            if str(finding.get("attack_type", "")).strip().lower()
            == attack_type.strip().lower()
        ]
        strongest = max(
            matching or list(rule_findings),
            key=lambda finding: float(finding.get("confidence", 0.0)),
            default={},
        )
        matched_rules = [
            str(item)
            for item in strongest.get("matched_rules", [])
            if str(item).strip()
        ]
        evidence = strongest.get("evidence", {})
        if not isinstance(evidence, Mapping):
            evidence = {}

        if "repeated_login_failures" in matched_rules:
            count = int(evidence.get("failure_count", 0))
            window = int(round(float(evidence.get("window_seconds", 60))))
            return (
                f"{display_attack} was detected because {count} failed login "
                f"attempts occurred within {window} seconds for the same "
                "source and service."
            )

        pattern_count = evidence.get("pattern_match_count")
        if isinstance(pattern_count, int) and pattern_count > 0:
            return (
                f"{display_attack} was detected because {pattern_count} "
                "sanitized security pattern"
                f"{'s' if pattern_count != 1 else ''} matched the event. "
                "Raw attacker text is not included in the explanation."
            )

        rules = ", ".join(matched_rules) if matched_rules else "a security rule"
        return f"{display_attack} was detected by deterministic rule evidence: {rules}."

    @staticmethod
    def _decision_reason(
        ids_result: Mapping[str, Any],
        rule_findings: Sequence[Mapping[str, Any]],
    ) -> str:
        model = str(ids_result.get("model_used", "")).strip().lower()
        attack_type = str(ids_result.get("attack_type", "unknown"))
        display_attack = _display_name(attack_type)
        confidence = ids_result.get("confidence")
        confidence_text = (
            "without a calibrated probability"
            if confidence is None
            else f"with {float(confidence) * 100:.1f}% confidence"
        )
        components = ids_result.get("components", {})

        if model == "rules":
            return PredictionExplainer._rule_reason(
                ids_result,
                rule_findings,
            )
        if "+" in model and "lstm_classifier" in model:
            return (
                f"{_display_name(model.split('+', 1)[0])} and the LSTM "
                f"classifier agreed on {display_attack} {confidence_text}."
            )
        if model in {"decision_tree", "random_forest"}:
            return (
                f"{_display_name(model)} classified the event as "
                f"{display_attack} {confidence_text}."
            )
        if model == "lstm_classifier":
            sequence = components.get("sequence", {})
            context = int(sequence.get("context_events", 0))
            return (
                f"The LSTM classifier detected {display_attack} "
                f"{confidence_text} using {context} causal event"
                f"{'s' if context != 1 else ''}."
            )
        if model == "isolation_forest":
            score = _finite_float(
                ids_result.get("anomaly_score"),
                field="anomaly score",
            )
            return (
                "Isolation Forest flagged an unknown anomaly with anomaly "
                f"score {score:.4f}; this score is not a probability."
            )
        if str(ids_result.get("prediction", "")).lower() == "normal":
            return (
                "No rule, known attack, causal sequence attack, or unknown "
                "anomaly was detected."
            )
        return str(ids_result.get("fusion_reason", "Hybrid IDS decision produced."))

    @staticmethod
    def _threat_reason(ids_result: Mapping[str, Any]) -> str:
        level = str(ids_result.get("threat_level", "Unknown"))
        score = int(ids_result.get("threat_score", 0))
        factors = ids_result.get("threat_factors", [])
        factor_text = _factor_summary(
            factors if isinstance(factors, Sequence) else []
        )
        return f"Threat level is {level} ({score}/100): {factor_text}."

    @staticmethod
    def _feature_reason(shap_result: Mapping[str, Any]) -> str:
        if shap_result.get("status") != "ready":
            return (
                "SHAP feature contributions are unavailable for this event; "
                "the decision and threat reasons remain available."
            )
        top_features = shap_result.get("top_features", [])
        if not top_features:
            return "SHAP returned no ranked tabular feature contributions."
        top = top_features[0]
        direction = str(top["direction"]).replace("_", " ")
        scope = (
            "the final decision"
            if shap_result.get("supports_final_decision")
            else "the selected tabular component, not the final decision source"
        )
        return (
            f"The strongest SHAP feature was {top['feature']} "
            f"({direction}); it explains {scope}."
        )

    def explain(
        self,
        *,
        encoded: np.ndarray,
        ids_result: Mapping[str, Any],
        rule_findings: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Return SHAP contributions and verifiable human-readable reasons."""

        values = np.asarray(encoded, dtype=float)
        expected_shape = (1, len(self.feature_names))
        if values.shape != expected_shape:
            raise ValueError(
                f"encoded features must have shape {expected_shape}"
            )
        if not np.isfinite(values).all():
            raise ValueError("encoded features must be finite")
        if not isinstance(ids_result, Mapping):
            raise ValueError("IDS result must be a mapping")

        shap_result = self._shap_explanation(values, ids_result=ids_result)
        decision_reason = self._decision_reason(ids_result, rule_findings)
        threat_reason = self._threat_reason(ids_result)
        feature_reason = self._feature_reason(shap_result)
        return {
            "xai_version": XAI_VERSION,
            "method": "shap_tree_and_deterministic_reasoning",
            "lime_used": False,
            "shap": shap_result,
            "human_reason": {
                "decision": decision_reason,
                "threat": threat_reason,
                "feature": feature_reason,
                "summary": " ".join(
                    (decision_reason, threat_reason, feature_reason)
                ),
            },
            "privacy": {
                "raw_payload_included": False,
                "source_ip_included": False,
                "credentials_included": False,
            },
            "safety": {
                "prediction_changed": False,
                "model_fit_called": False,
                "artifact_written": False,
            },
        }
