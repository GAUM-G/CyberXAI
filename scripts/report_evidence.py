"""Reproducible evidence builder for report Sections 3.2 and 4.

Modes:
  inspect      repository, environment, database, and artifact inventory
  offline      fresh inference with the protected saved models
  live         bounded localhost honeypot run using isolated files/no webhooks
  render       CSV-backed figures, diagrams, Markdown, DOCX, indices, ZIP
  all-offline  inspect + offline + render
  all          inspect + offline + live + render

The script never fits, promotes, or overwrites a model and never writes to the
production database/log files.  Live mode uses alternate localhost ports and
redirects the logger and IDS result paths into the selected run directory.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPORT_ROOT = ROOT / "report_evidence"
RUNS_ROOT = REPORT_ROOT / "runs"
LSTM_ROBUSTNESS_ROOT = REPORT_ROOT / "lstm_robustness"
PYTHON = ROOT / "data" / "runtime" / "python312" / "python.exe"
MODEL_ROOT = ROOT / "data" / "ml_ready"
MODEL_DIR = MODEL_ROOT / "models"
DATASET_PATH = ROOT / "data" / "processed" / "honeypot_dataset.csv"
DATASET_MANIFEST = ROOT / "data" / "processed" / "dataset_manifest.json"
DB_PATH = ROOT / "website" / "backend" / "data" / "honeypot.db"

PALETTE = {
    "navy": "#16324F", "blue": "#2E74B5", "cyan": "#20A4C7",
    "green": "#2B8A6E", "amber": "#D99000", "red": "#C33C54",
    "slate": "#667085", "light": "#EAF0F6", "ink": "#17212B",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fields: list[str] | None = None) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0]) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def init_run(run_dir: Path) -> Path:
    run_dir = run_dir.resolve()
    for name in ("tables", "figures", "diagrams", "samples", "predictions", "screenshots", "logs", "offline_evaluation"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    (REPORT_ROOT / "latest_run.txt").write_text(str(run_dir) + "\n", encoding="utf-8")
    return run_dir


def resolve_run(value: str | None) -> Path:
    if value:
        return init_run(Path(value))
    return init_run(RUNS_ROOT / new_run_id())


def command_output(command: list[str], cwd: Path = ROOT) -> str:
    try:
        proc = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, timeout=30)
        return (proc.stdout or proc.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable: {exc}"


def ps_json(script: str) -> Any:
    out = command_output(["powershell", "-NoProfile", "-Command", f"$ErrorActionPreference='Stop'; {script} | ConvertTo-Json -Compress"])
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"status": "unavailable", "detail": out}


def package_versions() -> dict[str, str]:
    packages = ["flask", "numpy", "pandas", "sklearn", "joblib", "torch", "shap", "psutil", "matplotlib", "docx"]
    result: dict[str, str] = {}
    for name in packages:
        try:
            module = __import__(name)
            result[name] = str(getattr(module, "__version__", "installed/version-unreported"))
        except Exception as exc:
            result[name] = f"unavailable: {type(exc).__name__}"
    return result


def inspect_database(run_dir: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(DB_PATH), "access": "read-only", "tables": []}
    try:
        conn = sqlite3.connect(f"file:{DB_PATH.resolve()}?mode=ro", uri=True)
        names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for name in names:
            cols = [{"name": row[1], "type": row[2], "not_null": bool(row[3]), "primary_key": bool(row[5])} for row in conn.execute(f'PRAGMA table_info("{name}")')]
            count = int(conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            result["tables"].append({"name": name, "rows": count, "columns": cols})
        safe_samples = []
        if "ids_results" in names:
            cur = conn.execute("SELECT event_id, timestamp, service, attack_type, prediction, confidence, threat_level, threat_score, model_used FROM ids_results ORDER BY id DESC LIMIT 5")
            fields = [item[0] for item in cur.description]
            safe_samples = [dict(zip(fields, row)) for row in cur.fetchall()]
        conn.close()
        write_csv(run_dir / "samples" / "database_ids_results_sample.csv", safe_samples)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def inspect_mode(run_dir: Path) -> dict[str, Any]:
    manifest_paths = [
        DATASET_MANIFEST,
        MODEL_ROOT / "preprocessing_manifest.json",
        MODEL_DIR / "training_manifest.json",
        MODEL_DIR / "lstm_metrics.json",
        MODEL_ROOT / "evaluation" / "evaluation_manifest.json",
    ]
    tracked = [
        MODEL_ROOT / "preprocessor.joblib", MODEL_ROOT / "feature_names.json", MODEL_ROOT / "label_mapping.json",
        MODEL_DIR / "decision_tree.joblib", MODEL_DIR / "random_forest.joblib",
        MODEL_DIR / "isolation_forest.joblib", MODEL_DIR / "lstm_classifier.pt",
    ]
    artifacts = []
    for path in tracked + manifest_paths:
        try:
            artifacts.append({"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": sha256(path)})
        except OSError as exc:
            artifacts.append({"path": str(path.relative_to(ROOT)), "status": f"unavailable: {exc}"})

    environment = {
        "collected_at_utc": utc_now(),
        "host_scope": "local evaluation/demonstration host; not asserted to be the student's personal laptop",
        "os": ps_json("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture,BuildNumber"),
        "cpu": ps_json("Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors"),
        "computer": ps_json("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,@{n='TotalPhysicalMemoryGB';e={[math]::Round($_.TotalPhysicalMemory/1GB,2)}}"),
        "gpu": ps_json("Get-CimInstance Win32_VideoController | Select-Object Name,@{n='AdapterRAMGB';e={[math]::Round($_.AdapterRAM/1GB,2)}},DriverVersion"),
        "storage": ps_json("Get-Volume -DriveLetter D | Select-Object DriveLetter,FileSystem,@{n='SizeGB';e={[math]::Round($_.Size/1GB,2)}},@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,2)}}"),
        "python": sys.version.replace("\n", " "),
        "node": command_output(["node", "--version"]),
        "npm": command_output(["cmd", "/c", "npm", "--version"]),
        "packages": package_versions(),
        "gpu_used_for_model_evaluation": False,
        "model_device": "cpu",
    }
    database = inspect_database(run_dir)
    repo = {
        "root": str(ROOT), "branch": command_output(["git", "branch", "--show-current"]),
        "commit": command_output(["git", "rev-parse", "HEAD"]),
        "working_tree_before_run": command_output(["git", "status", "--short"]),
    }
    payload = {"environment": environment, "repository": repo, "artifacts": artifacts, "database": database}
    write_json(run_dir / "environment.json", environment)
    write_json(run_dir / "samples" / "database_schema.json", database)
    write_json(run_dir / "logs" / "inspection.json", payload)
    return payload


def load_saved_models():
    import joblib
    import numpy as np
    import torch
    from machine_learning.lstm_model import LSTMClassifier

    labels = read_json(MODEL_ROOT / "label_mapping.json")
    features = read_json(MODEL_ROOT / "feature_names.json")
    X = np.load(MODEL_ROOT / "X_test.npy", allow_pickle=False)
    y = np.load(MODEL_ROOT / "y_test.npy", allow_pickle=False)
    Xs = np.load(MODEL_ROOT / "X_test_sequences.npy", allow_pickle=False)
    ys = np.load(MODEL_ROOT / "y_test_sequences.npy", allow_pickle=False)
    dt_bundle = joblib.load(MODEL_DIR / "decision_tree.joblib")
    rf_bundle = joblib.load(MODEL_DIR / "random_forest.joblib")
    if_bundle = joblib.load(MODEL_DIR / "isolation_forest.joblib")
    checkpoint = torch.load(MODEL_DIR / "lstm_classifier.pt", map_location="cpu", weights_only=True)
    cfg = checkpoint["model_config"]
    lstm = LSTMClassifier(input_size=int(cfg["input_size"]), num_classes=int(cfg["num_classes"]), hidden_size=int(cfg["hidden_size"]), num_layers=int(cfg["num_layers"]), dropout=float(cfg["dropout"]))
    lstm.load_state_dict(checkpoint["model_state_dict"], strict=True)
    lstm.eval()
    return labels, features, X, y, Xs, ys, dt_bundle["estimator"], rf_bundle["estimator"], if_bundle["estimator"], lstm


def raw_test_rows(labels_by_index: dict[int, str], expected_y) -> list[dict[str, str]]:
    rows = read_csv(DATASET_PATH)
    rows.sort(key=lambda row: (row.get("timestamp_utc", ""), row.get("event_id", "")))
    test = rows[-len(expected_y):]
    actual = [labels_by_index[int(v)] for v in expected_y]
    observed = [row["label"] for row in test]
    if actual != observed:
        raise RuntimeError("Raw dataset last rows do not align with saved y_test.npy; event IDs cannot be asserted")
    return test


def benchmark(callable_obj, rows: int, runs: int = 12) -> tuple[Any, dict[str, float]]:
    import numpy as np
    callable_obj()
    values = []
    output = None
    for _ in range(runs):
        started = time.perf_counter_ns()
        output = callable_obj()
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    return output, {"median_total_ms": float(np.median(values)), "mean_total_ms": float(np.mean(values)), "p95_total_ms": float(np.percentile(values, 95)), "median_per_sample_ms": float(np.median(values) / rows), "runs": runs}


def offline_mode(run_dir: Path) -> dict[str, Any]:
    import joblib
    import numpy as np
    import torch
    from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
        classification_report, confusion_matrix, f1_score, precision_recall_curve, roc_auc_score, roc_curve)
    from machine_learning.evaluate_models import evaluate_models

    before = {p: sha256(p) for p in MODEL_DIR.iterdir() if p.is_file()}
    verified = evaluate_models(
        MODEL_ROOT,
        MODEL_DIR,
        run_dir / "offline_evaluation",
        batch_size=256,
        warmup_runs=2,
        timing_runs=12,
        device_name="cpu",
        selection_tolerance=1e-12,
    )
    labels, features, X, y, Xs, ys, dt, rf, iso, lstm = load_saved_models()
    names = {int(index): name for name, index in labels.items()}
    ordered_names = [names[i] for i in range(len(names))]
    raw_rows = raw_test_rows(names, y)
    sample_ids = [row["event_id"] for row in raw_rows]
    normal_index = int(labels["normal"])
    attack_truth = (y != normal_index).astype(int)

    results: dict[str, Any] = {}
    metrics_rows = []
    perclass_rows = []
    binary_rows = []
    latency_rows = []
    cm_rows = []
    norm_rows = []
    curve_rows = []

    supervised = {"decision_tree": dt, "random_forest": rf}
    for model_name, estimator in supervised.items():
        pred, timing = benchmark(lambda e=estimator: e.predict(X).astype(int), len(X))
        probs = estimator.predict_proba(X)
        attack_score = 1.0 - probs[:, list(estimator.classes_).index(normal_index)]
        report = classification_report(y, pred, labels=list(range(len(names))), target_names=ordered_names, output_dict=True, zero_division=0)
        cm = confusion_matrix(y, pred, labels=list(range(len(names))))
        results[model_name] = {"pred": pred, "probs": probs, "attack_score": attack_score, "timing": timing}
        metrics_rows.append({"run_id": run_dir.name, "model": model_name, "task": "multiclass", "samples": len(y), "accuracy": accuracy_score(y,pred), "balanced_accuracy": balanced_accuracy_score(y,pred), "macro_precision": report["macro avg"]["precision"], "macro_recall": report["macro avg"]["recall"], "macro_f1": f1_score(y,pred,average="macro"), "weighted_f1": f1_score(y,pred,average="weighted")})
        for label in ordered_names:
            perclass_rows.append({"run_id": run_dir.name, "model": model_name, "class": label, **{k: report[label][k] for k in ("precision","recall","f1-score","support")}})
        for i,a in enumerate(ordered_names):
            for j,p in enumerate(ordered_names):
                cm_rows.append({"run_id": run_dir.name,"model":model_name,"actual":a,"predicted":p,"count":int(cm[i,j])})
                norm_rows.append({"run_id":run_dir.name,"model":model_name,"actual":a,"predicted":p,"proportion":float(cm[i,j]/cm[i].sum()) if cm[i].sum() else 0.0})
        fpr,tpr,_ = roc_curve(attack_truth, attack_score)
        precision,recall,_ = precision_recall_curve(attack_truth, attack_score)
        for x,z in zip(fpr,tpr): curve_rows.append({"run_id":run_dir.name,"model":model_name,"curve":"roc","x":x,"y":z,"x_label":"false_positive_rate","y_label":"true_positive_rate"})
        for x,z in zip(recall,precision): curve_rows.append({"run_id":run_dir.name,"model":model_name,"curve":"pr","x":x,"y":z,"x_label":"recall","y_label":"precision"})
        pred_attack = (pred != normal_index).astype(int)
        tn,fp,fn,tp = confusion_matrix(attack_truth,pred_attack,labels=[0,1]).ravel()
        binary_rows.append({"run_id":run_dir.name,"model":model_name,"task":"attack_vs_normal","samples":len(y),"tn":tn,"fp":fp,"fn":fn,"tp":tp,"fpr":fp/(fp+tn) if fp+tn else 0,"fnr":fn/(fn+tp) if fn+tp else 0,"roc_auc":roc_auc_score(attack_truth,attack_score),"average_precision":average_precision_score(attack_truth,attack_score),"score_type":"1 - P(normal)"})
        latency_rows.append({"run_id":run_dir.name,"model":model_name,"samples":len(y),"device":"cpu",**timing})
        pred_rows=[]
        for i,(truth,guess) in enumerate(zip(y,pred)):
            row={"run_id":run_dir.name,"sample_id":sample_ids[i],"split":"original_chronological_test","model":model_name,"true_label":names[int(truth)],"predicted_label":names[int(guess)],"attack_score":float(attack_score[i])}
            for cls_idx, cls_name in enumerate(ordered_names): row[f"p_{cls_name}"]=float(probs[i, list(estimator.classes_).index(cls_idx)])
            pred_rows.append(row)
        write_csv(run_dir/"predictions"/f"{model_name}_predictions.csv",pred_rows)

    tensor=torch.from_numpy(Xs)
    def lstm_call():
        with torch.inference_mode():
            chunks=[torch.softmax(lstm(tensor[i:i+256]),dim=1).cpu().numpy() for i in range(0,len(tensor),256)]
        return np.concatenate(chunks)
    lstm_probs,lstm_timing=benchmark(lstm_call,len(Xs))
    lstm_pred=lstm_probs.argmax(axis=1)
    lstm_attack_truth=(ys!=normal_index).astype(int)
    lstm_attack_score=1-lstm_probs[:,normal_index]
    rep=classification_report(ys,lstm_pred,labels=list(range(len(names))),target_names=ordered_names,output_dict=True,zero_division=0)
    cm=confusion_matrix(ys,lstm_pred,labels=list(range(len(names))))
    metrics_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","task":"multiclass_sequence","samples":len(ys),"accuracy":accuracy_score(ys,lstm_pred),"balanced_accuracy":balanced_accuracy_score(ys,lstm_pred),"macro_precision":rep["macro avg"]["precision"],"macro_recall":rep["macro avg"]["recall"],"macro_f1":f1_score(ys,lstm_pred,average="macro"),"weighted_f1":f1_score(ys,lstm_pred,average="weighted")})
    for label in ordered_names: perclass_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","class":label,**{k:rep[label][k] for k in ("precision","recall","f1-score","support")}})
    for i,a in enumerate(ordered_names):
        for j,p in enumerate(ordered_names):
            cm_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","actual":a,"predicted":p,"count":int(cm[i,j])})
            norm_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","actual":a,"predicted":p,"proportion":float(cm[i,j]/cm[i].sum()) if cm[i].sum() else 0.0})
    fpr,tpr,_=roc_curve(lstm_attack_truth,lstm_attack_score); precision,recall,_=precision_recall_curve(lstm_attack_truth,lstm_attack_score)
    for x,z in zip(fpr,tpr): curve_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","curve":"roc","x":x,"y":z,"x_label":"false_positive_rate","y_label":"true_positive_rate"})
    for x,z in zip(recall,precision): curve_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","curve":"pr","x":x,"y":z,"x_label":"recall","y_label":"precision"})
    pa=(lstm_pred!=normal_index).astype(int); tn,fp,fn,tp=confusion_matrix(lstm_attack_truth,pa,labels=[0,1]).ravel()
    binary_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","task":"attack_vs_normal","samples":len(ys),"tn":tn,"fp":fp,"fn":fn,"tp":tp,"fpr":fp/(fp+tn),"fnr":fn/(fn+tp),"roc_auc":roc_auc_score(lstm_attack_truth,lstm_attack_score),"average_precision":average_precision_score(lstm_attack_truth,lstm_attack_score),"score_type":"1 - P(normal)"})
    latency_rows.append({"run_id":run_dir.name,"model":"lstm_classifier","samples":len(ys),"device":"cpu",**lstm_timing})
    write_csv(run_dir/"predictions"/"lstm_classifier_predictions.csv",[{"run_id":run_dir.name,"sample_id":f"sequence-{i:04d}","split":"original_chronological_test","model":"lstm_classifier","true_label":names[int(t)],"predicted_label":names[int(p)],"attack_score":float(lstm_attack_score[i]),**{f"p_{n}":float(lstm_probs[i,j]) for j,n in enumerate(ordered_names)}} for i,(t,p) in enumerate(zip(ys,lstm_pred))])

    iso_pred,iso_timing=benchmark(lambda:iso.predict(X),len(X)); anomaly_score=-iso.decision_function(X)
    pred_attack=(iso_pred==-1).astype(int); tn,fp,fn,tp=confusion_matrix(attack_truth,pred_attack,labels=[0,1]).ravel()
    fpr,tpr,_=roc_curve(attack_truth,anomaly_score); precision,recall,_=precision_recall_curve(attack_truth,anomaly_score)
    for x,z in zip(fpr,tpr): curve_rows.append({"run_id":run_dir.name,"model":"isolation_forest","curve":"roc","x":x,"y":z,"x_label":"false_positive_rate","y_label":"true_positive_rate"})
    for x,z in zip(recall,precision): curve_rows.append({"run_id":run_dir.name,"model":"isolation_forest","curve":"pr","x":x,"y":z,"x_label":"recall","y_label":"precision"})
    binary_rows.append({"run_id":run_dir.name,"model":"isolation_forest","task":"binary_anomaly","samples":len(y),"tn":tn,"fp":fp,"fn":fn,"tp":tp,"fpr":fp/(fp+tn),"fnr":fn/(fn+tp),"roc_auc":roc_auc_score(attack_truth,anomaly_score),"average_precision":average_precision_score(attack_truth,anomaly_score),"score_type":"negative decision_function; continuous, not calibrated probability"})
    latency_rows.append({"run_id":run_dir.name,"model":"isolation_forest","samples":len(y),"device":"cpu",**iso_timing})
    write_csv(run_dir/"predictions"/"isolation_forest_predictions.csv",[{"run_id":run_dir.name,"sample_id":sample_ids[i],"split":"original_chronological_test","model":"isolation_forest","true_label":names[int(y[i])],"predicted_label":"anomaly" if iso_pred[i]==-1 else "inlier","attack_score":float(anomaly_score[i])} for i in range(len(y))])

    dataset_manifest=read_json(DATASET_MANIFEST); prep=read_json(MODEL_ROOT/"preprocessing_manifest.json")
    class_rows=[{"run_id":run_dir.name,"class":name,"total":dataset_manifest["labels"][name],"train":prep["labels"]["train_counts"][name],"validation":0,"test":prep["labels"]["test_counts"][name]} for name in ordered_names]
    summary_rows=[{"run_id":run_dir.name,"dataset_version":dataset_manifest["dataset_version"],"raw":dataset_manifest["total_events"],"accepted":dataset_manifest["accepted_events"],"rejected":dataset_manifest["rejected_events"],"duplicates_removed":dataset_manifest["duplicate_events"],"train":prep["split"]["train_rows"],"validation":0,"test":prep["split"]["test_rows"],"encoded_features":prep["features"]["encoded_feature_count"],"sequence_length":prep["sequences"]["length"]}]
    write_csv(run_dir/"tables"/"dataset_summary.csv",summary_rows); write_csv(run_dir/"tables"/"class_distribution.csv",class_rows)
    write_csv(run_dir/"tables"/"model_metrics.csv",metrics_rows); write_csv(run_dir/"tables"/"per_class_metrics.csv",perclass_rows)
    write_csv(run_dir/"tables"/"binary_metrics.csv",binary_rows); write_csv(run_dir/"tables"/"model_latency.csv",latency_rows)
    write_csv(run_dir/"tables"/"confusion_raw.csv",cm_rows); write_csv(run_dir/"tables"/"confusion_normalized.csv",norm_rows)
    write_csv(run_dir/"tables"/"curves.csv",curve_rows)
    history=read_json(MODEL_DIR/"lstm_metrics.json")["training_history"]
    write_csv(run_dir/"tables"/"lstm_training_history.csv",[{"run_id":run_dir.name,**row} for row in history])
    safe_fields=["event_id","timestamp_utc","source_ip_scope","source_port","destination_port","service","protocol","event_type","event","severity","status","username_present","session_id_present","request_method","request_path","payload_length","label"]
    selected=[]
    for wanted in ("normal","sql_injection","xss","ssh_bruteforce","ftp_bruteforce","other_anomaly"):
        row=next(item for item in raw_rows if item["label"]==wanted)
        selected.append({field:row.get(field,"") for field in safe_fields})
    write_csv(run_dir/"samples"/"sanitized_test_inputs.csv",selected,safe_fields)

    # Actual tree SHAP on a fixed, documented 256-row held-out sample.
    try:
        import shap
        explainer=shap.TreeExplainer(dt); sample=X[:min(256,len(X))]; values=explainer.shap_values(sample)
        array=np.asarray(values)
        if array.ndim==3 and array.shape[2]==len(names): array=np.moveaxis(array,2,0)
        if array.ndim==2: global_values=np.abs(array).mean(axis=0); example_values=array[0]
        else: global_values=np.abs(array).mean(axis=(0,1)); predicted=int(dt.predict(X[:1])[0]); example_values=array[predicted,0]
        global_rows=sorted([{"run_id":run_dir.name,"feature":features[i],"mean_abs_shap":float(global_values[i]),"sample_count":len(sample),"model":"decision_tree"} for i in range(len(features))],key=lambda r:r["mean_abs_shap"],reverse=True)
        example_rows=sorted([{"run_id":run_dir.name,"sample_id":sample_ids[0],"feature":features[i],"feature_value":float(X[0,i]),"shap_value":float(example_values[i]),"model":"decision_tree"} for i in range(len(features))],key=lambda r:abs(r["shap_value"]),reverse=True)
        write_csv(run_dir/"tables"/"shap_global.csv",global_rows); write_csv(run_dir/"tables"/"shap_example.csv",example_rows)
    except Exception as exc:
        write_json(run_dir/"logs"/"shap_error.json",{"error":f"{type(exc).__name__}: {exc}"})

    after={p:sha256(p) for p in MODEL_DIR.iterdir() if p.is_file()}
    if before!=after: raise RuntimeError("Protected model hashes changed during evaluation")
    payload={"generated_at_utc":utc_now(),"run_id":run_dir.name,"evaluation_kind":"fresh offline inference on original saved holdout","model_fit_called":False,"protected_models_modified":False,"verified_evaluator":verified,"prediction_rows":{"tabular":len(y),"sequence":len(ys)},"event_id_alignment_verified":True,"limitations":["The saved holdout is not a new independent dataset.","The chronological boundary timestamp is identical and source/session/template isolation was not recorded.","Rules-only and complete hybrid aggregate accuracy are not claimed because saved arrays do not preserve the raw causal event stream contract for a directly comparable replay."]}
    write_json(run_dir/"logs"/"offline_run.json",payload)
    return payload


def free_port(preferred: int) -> int:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1",preferred)); return preferred
        except OSError:
            sock.bind(("127.0.0.1",0)); return int(sock.getsockname()[1])


def live_mode(run_dir: Path) -> dict[str, Any]:
    """Run actual local honeypots in this short-lived process with isolated I/O."""
    import urllib.request
    from core import logger
    live_events_path = (run_dir / "samples" / "live_events.jsonl").resolve()
    live_results_path = (run_dir / "samples" / "live_ids_results.jsonl").resolve()
    if run_dir.resolve() not in live_events_path.parents or run_dir.resolve() not in live_results_path.parents:
        raise RuntimeError("isolated live output escaped the selected run directory")
    live_events_path.unlink(missing_ok=True)
    live_results_path.unlink(missing_ok=True)
    logger.LOG_FILE=live_events_path; logger.N8N_WEBHOOK_URL=""; logger.EVENT_COLLECTOR_URL=""
    def read_live_events() -> list[dict[str, Any]]:
        records=[]
        if not live_events_path.exists():
            return records
        for line in live_events_path.read_text(encoding="utf-8").splitlines():
            try:
                value=json.loads(line)
                if isinstance(value,dict): records.append(value)
            except json.JSONDecodeError:
                continue
        return records
    from core.launcher import start_all
    from simulation.sim_ssh import simulate_ssh_bruteforce
    from simulation.sim_ftp import simulate_ftp_bruteforce
    from simulation.sim_http import simulate_http_attacks
    from machine_learning.hybrid_ids import load_hybrid_artifacts, HybridIDSEngine
    from intelligent_agents.orchestrator import IntelligentAgentOrchestrator
    ssh_port,ftp_port,http_port=free_port(32222),free_port(32121),free_port(38080)
    started=time.perf_counter(); started_utc=utc_now(); start_all(ssh_host="127.0.0.1",ssh_port=ssh_port,ftp_host="127.0.0.1",ftp_port=ftp_port,http_host="127.0.0.1",http_port=http_port); time.sleep(1.2)
    scenarios=[]
    def run_scenario(name,expected,fn):
        before=len(read_live_events()); begin=utc_now(); t0=time.perf_counter(); error=""
        try: fn()
        except Exception as exc: error=f"{type(exc).__name__}: {exc}"
        time.sleep(.3); events=read_live_events()[before:]; scenarios.append({"run_id":run_dir.name,"scenario":name,"expected":expected,"started_at_utc":begin,"duration_ms":round((time.perf_counter()-t0)*1000,3),"events_captured":len(events),"event_ids":";".join(str(e.get("event_id","")) for e in events),"status":"completed" if events and not error else "partial_or_failed","error":error})
    run_scenario("normal_http_get","normal",lambda:urllib.request.urlopen(f"http://127.0.0.1:{http_port}/",timeout=5).read())
    run_scenario("ssh_bounded_bruteforce","ssh_bruteforce",lambda:simulate_ssh_bruteforce(port=ssh_port,delay=.05))
    run_scenario("ftp_bounded_bruteforce","ftp_bruteforce",lambda:simulate_ftp_bruteforce(port=ftp_port,delay=.05))
    run_scenario("http_supported_attacks","multiple_supported_http",lambda:simulate_http_attacks(port=http_port,delay=.05))
    events=read_live_events()
    artifacts=load_hybrid_artifacts(MODEL_ROOT,MODEL_DIR,MODEL_ROOT/"evaluation"/"model_selection.json",device_name="cpu")
    engine=HybridIDSEngine(artifacts); agents=IntelligentAgentOrchestrator(daily_report_directory=run_dir/"samples"/"daily_reports")
    output=[]; failures=[]
    for event in events:
        t0=time.perf_counter_ns()
        try:
            result=engine.process_event(event); result["agents"]=agents.process(event,result); result["e2e_local_processing_ms"]=(time.perf_counter_ns()-t0)/1_000_000; output.append(result)
        except Exception as exc: failures.append({"event_id":event.get("event_id"),"error":f"{type(exc).__name__}: {exc}"})
    ids_path=live_results_path
    ids_path.write_text("".join(json.dumps(item,ensure_ascii=False)+"\n" for item in output),encoding="utf-8")
    by_id={str(item.get("event_id")):item for item in output}
    for scenario in scenarios:
        ids=[item for item in str(scenario.get("event_ids","")).split(";") if item]
        observed=[by_id[item] for item in ids if item in by_id]
        scenario["events_processed"]=len(observed)
        scenario["attack_predictions"]=sum(item.get("prediction")=="attack" for item in observed)
        scenario["normal_predictions"]=sum(item.get("prediction")=="normal" for item in observed)
        scenario["observed_attack_types"]=";".join(f"{k}:{v}" for k,v in sorted(Counter(str(item.get("attack_type")) for item in observed).items()))
    write_csv(run_dir/"tables"/"live_scenarios.csv",scenarios)
    write_csv(run_dir/"tables"/"live_latency.csv",[{"run_id":run_dir.name,"event_id":r["event_id"],"timestamp":r["timestamp"],"service":r["service"],"prediction":r["prediction"],"attack_type":r["attack_type"],"threat_level":r["threat_level"],"latency_ms":r["e2e_local_processing_ms"]} for r in output])
    write_csv(run_dir/"samples"/"live_events_sanitized.csv",[{"run_id":run_dir.name,"event_id":e.get("event_id"),"timestamp":e.get("timestamp"),"service":e.get("service"),"event":e.get("event"),"producer_attack_type":e.get("attack_type"),"severity":e.get("severity"),"status":e.get("status"),"request_path":e.get("request_path")} for e in events])
    # Aggregate by second from actual captured timestamps.
    buckets=Counter(str(e.get("timestamp", ""))[:19] for e in events); processed=Counter(str(r.get("timestamp", ""))[:19] for r in output)
    keys=sorted(set(buckets)|set(processed)); write_csv(run_dir/"tables"/"live_timeline.csv",[{"run_id":run_dir.name,"second":k,"captured":buckets[k],"processed":processed[k]} for k in keys])
    # Capture one genuine application screenshot from the isolated dashboard.
    screenshot_status={"status":"not_attempted"}
    try:
        import threading
        import dashboard.app as dashboard_module
        from werkzeug.serving import make_server
        dashboard_module.IDS_RESULTS_FILE=ids_path
        dashboard_module.IDS_RESULTS_API_URL=""
        dashboard_module.EVENT_STATS_API_URL="http://127.0.0.1:1/api/events/stats"
        dashboard_module.PORTAL_API_URL="http://127.0.0.1:1"
        app=dashboard_module.create_dashboard_app(); dashboard_port=free_port(35050)
        server=make_server("127.0.0.1",dashboard_port,app); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start(); time.sleep(.5)
        edge_candidates=[Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")]
        edge=next((p for p in edge_candidates if p.is_file()),None)
        if edge:
            target=run_dir/"screenshots"/"01_system_monitor.png"
            try:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as api:
                    browser=api.chromium.launch(headless=True,executable_path=str(edge),args=["--no-first-run"])
                    page=browser.new_page(viewport={"width":1440,"height":1200})
                    page.goto(f"http://127.0.0.1:{dashboard_port}",wait_until="domcontentloaded",timeout=15000)
                    page.wait_for_timeout(4000)
                    page.screenshot(path=str(target),full_page=False)
                    browser.close()
                screenshot_status={"status":"captured" if target.is_file() else "failed","path":str(target),"method":"Playwright with installed Microsoft Edge"}
            except Exception as browser_exc:
                screenshot_status={"status":"failed","path":str(target),"detail":f"{type(browser_exc).__name__}: {browser_exc}"}
        else: screenshot_status={"status":"unavailable","detail":"Microsoft Edge executable was not found"}
        server.shutdown(); thread.join(timeout=3)
    except Exception as exc:
        screenshot_status={"status":"failed","detail":f"{type(exc).__name__}: {exc}"}
    payload={"run_id":run_dir.name,"kind":"fresh bounded localhost network demonstration","started_at_utc":started_utc,"ended_at_utc":utc_now(),"duration_seconds":round(time.perf_counter()-started,3),"ports":{"ssh":ssh_port,"ftp":ftp_port,"http":http_port},"external_notifications_enabled":False,"event_collector_enabled":False,"storage":"isolated run directory","events_captured":len(events),"events_processed":len(output),"processing_failures":failures,"scenarios":scenarios,"dashboard_screenshot":screenshot_status,"host_firewall_changed":False}
    write_json(run_dir/"logs"/"live_run.json",payload)
    return payload


def setup_plotting():
    os.environ.setdefault("MPLCONFIGDIR",str(ROOT/"tmp"/"matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family":"DejaVu Sans","font.size":9,"axes.titlesize":12,"axes.titleweight":"bold","axes.labelcolor":PALETTE["ink"],"text.color":PALETTE["ink"],"axes.edgecolor":"#BCC7D3","grid.color":"#DCE4EC","figure.facecolor":"white","axes.facecolor":"white"})
    return plt


def savefig(fig, path: Path) -> None:
    # The report contract requires print-ready raster figures.  Keep SVG as the
    # editable/vector counterpart and export PNGs at a true 300 DPI.
    png_path = path.with_suffix(".png")
    svg_path = path.with_suffix(".svg")
    fig.tight_layout()
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    fig.savefig(svg_path, bbox_inches="tight")
    # Matplotlib writes harmless trailing spaces into SVG path data.  Normalize
    # them so repository whitespace checks stay useful and deterministic.
    svg_text = svg_path.read_text(encoding="utf-8")
    svg_path.write_text(
        "\n".join(line.rstrip() for line in svg_text.splitlines()) + "\n",
        encoding="utf-8",
    )


def stage_lstm_robustness(run_dir: Path) -> None:
    """Copy the completed robustness audit and expose report-ready CSVs."""
    summary_path=LSTM_ROBUSTNESS_ROOT/"aggregate_summary.json"
    rows_path=LSTM_ROBUSTNESS_ROOT/"aggregate_results.csv"
    if not summary_path.exists() or not rows_path.exists():
        raise FileNotFoundError("LSTM robustness audit is required before report rendering")
    destination=run_dir/"lstm_robustness"
    shutil.copytree(LSTM_ROBUSTNESS_ROOT,destination,dirs_exist_ok=True)
    rows=read_csv(rows_path)
    write_csv(run_dir/"tables"/"lstm_group_isolated_runs.csv",[{"report_run_id":run_dir.name,**row} for row in rows])
    summary=read_json(summary_path)
    mean_balanced=sum(float(row["test_balanced_accuracy"]) for row in rows)/len(rows)
    std_balanced=(sum((float(row["test_balanced_accuracy"])-mean_balanced)**2 for row in rows)/len(rows))**0.5
    write_csv(run_dir/"tables"/"lstm_evaluation_scope_summary.csv",[
      {"run_id":run_dir.name,"evaluation":"legacy chronological holdout","runs":1,"test_samples":"816","accuracy_mean":1.0,"accuracy_std":0.0,"balanced_accuracy_mean":1.0,"macro_f1_mean":1.0,"macro_f1_std":0.0,"source_group_overlap":"791/816 test rows","template_overlap":"816/816 test rows","interpretation":"reproduced but optimistic; not independent generalization"},
      {"run_id":run_dir.name,"evaluation":"source-group-isolated holdouts","runs":summary["runs"],"test_samples":"710, 710, 711","accuracy_mean":summary["accuracy"]["mean"],"accuracy_std":summary["accuracy"]["population_std"],"balanced_accuracy_mean":mean_balanced,"macro_f1_mean":summary["macro_f1"]["mean"],"macro_f1_std":summary["macro_f1"]["population_std"],"source_group_overlap":"0 in every run","template_overlap":"templates still repeat across groups","interpretation":"primary defensible internal LSTM estimate; external validation still required"},
    ])
    legacy={row["model"]:row for row in read_csv(run_dir/"tables"/"model_metrics.csv")}
    write_csv(run_dir/"tables"/"primary_model_metrics.csv",[
      {"run_id":run_dir.name,"model":"Decision Tree","evaluation_scope":"legacy chronological holdout","runs":1,"test_samples":"816","accuracy_mean":f'{float(legacy["decision_tree"]["accuracy"]):.4f}',"accuracy_std":"n/a","balanced_accuracy_mean":f'{float(legacy["decision_tree"]["balanced_accuracy"]):.4f}',"balanced_accuracy_std":"n/a","macro_f1_mean":f'{float(legacy["decision_tree"]["macro_f1"]):.4f}',"macro_f1_std":"n/a","interpretation":"selected tabular model; controlled holdout"},
      {"run_id":run_dir.name,"model":"Random Forest","evaluation_scope":"legacy chronological holdout","runs":1,"test_samples":"816","accuracy_mean":f'{float(legacy["random_forest"]["accuracy"]):.4f}',"accuracy_std":"n/a","balanced_accuracy_mean":f'{float(legacy["random_forest"]["balanced_accuracy"]):.4f}',"balanced_accuracy_std":"n/a","macro_f1_mean":f'{float(legacy["random_forest"]["macro_f1"]):.4f}',"macro_f1_std":"n/a","interpretation":"tabular comparison; controlled holdout"},
      {"run_id":run_dir.name,"model":"LSTM","evaluation_scope":"source-group-isolated holdouts","runs":summary["runs"],"test_samples":"710/710/711","accuracy_mean":f'{float(summary["accuracy"]["mean"]):.4f}',"accuracy_std":f'{float(summary["accuracy"]["population_std"]):.4f}',"balanced_accuracy_mean":f'{mean_balanced:.4f}',"balanced_accuracy_std":f'{std_balanced:.4f}',"macro_f1_mean":f'{float(summary["macro_f1"]["mean"]):.4f}',"macro_f1_std":f'{float(summary["macro_f1"]["population_std"]):.4f}',"interpretation":"preferred internal LSTM estimate; candidate not promoted"},
    ])


def render_figures(run_dir: Path) -> None:
    import numpy as np
    plt=setup_plotting(); figs=run_dir/"figures"; tables=run_dir/"tables"
    rows=read_csv(tables/"class_distribution.csv"); names=[r["class"].replace("_","\n") for r in rows]; total=[int(r["total"]) for r in rows]
    fig,ax=plt.subplots(figsize=(9,4.5)); bars=ax.bar(names,total,color=PALETTE["blue"]); ax.bar_label(bars,padding=3); ax.set(ylabel="Accepted records",title="Accepted dataset class distribution"); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"dataset_class_distribution"); plt.close(fig)
    train=[int(r["train"]) for r in rows]; test=[int(r["test"]) for r in rows]; x=np.arange(len(names)); fig,ax=plt.subplots(figsize=(9,4.8)); ax.bar(x-.2,train,.4,label="Train",color=PALETTE["navy"]); ax.bar(x+.2,test,.4,label="Test",color=PALETTE["cyan"]); ax.set_xticks(x,names); ax.set(ylabel="Records",title="Chronological split by class"); ax.legend(); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"train_test_distribution"); plt.close(fig)
    metrics=read_csv(tables/"primary_model_metrics.csv"); models=[r["model"] for r in metrics]; keys=["accuracy_mean","balanced_accuracy_mean","macro_f1_mean"]; x=np.arange(len(models)); fig,ax=plt.subplots(figsize=(9,5)); width=.24
    std_keys=["accuracy_std","balanced_accuracy_std","macro_f1_std"]
    for k,(key,std_key) in enumerate(zip(keys,std_keys)):
        errors=[0.0 if r[std_key]=="n/a" else float(r[std_key]) for r in metrics]
        ax.bar(x+(k-1)*width,[float(r[key]) for r in metrics],width,yerr=errors,capsize=4,label=key.replace("_mean"," ").replace("_"," "))
    ax.set_xticks(x,["Decision Tree\nlegacy holdout","Random Forest\nlegacy holdout","LSTM\nsource-group audit"]); ax.set_ylim(.90,1.005); ax.set(ylabel="Score",title="Primary reported metrics by explicitly labelled evaluation scope"); ax.legend(ncol=3); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"model_metric_comparison"); plt.close(fig)
    binary=read_csv(tables/"binary_metrics.csv"); x=np.arange(len(binary)); fig,ax=plt.subplots(figsize=(9,4.5)); ax.bar(x-.18,[float(r["fpr"]) for r in binary],.36,label="FPR",color=PALETTE["amber"]); ax.bar(x+.18,[float(r["fnr"]) for r in binary],.36,label="FNR",color=PALETTE["red"]); ax.set_xticks(x,[r["model"] for r in binary]); ax.set(ylabel="Rate",title="Attack-versus-normal error rates"); ax.legend(); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"binary_fpr_fnr"); plt.close(fig)
    curves=read_csv(tables/"curves.csv")
    for kind,title,xlab,ylab in (("roc","ROC curves: attack versus normal","False positive rate","True positive rate"),("pr","Precision-recall curves: attack versus normal","Recall","Precision")):
        fig,ax=plt.subplots(figsize=(6.8,5.5))
        for model in sorted({r["model"] for r in curves}):
            pts=[r for r in curves if r["curve"]==kind and r["model"]==model]; ax.plot([float(r["x"]) for r in pts],[float(r["y"]) for r in pts],label=model,linewidth=2)
        if kind=="roc": ax.plot([0,1],[0,1],"--",color=PALETTE["slate"],label="chance")
        ax.set(xlabel=xlab,ylabel=ylab,title=title,xlim=(0,1),ylim=(0,1.02)); ax.legend(fontsize=8); ax.grid(alpha=.5); savefig(fig,figs/f"{kind}_curves"); plt.close(fig)
    lat=read_csv(tables/"model_latency.csv"); fig,ax=plt.subplots(figsize=(8,4.5)); bars=ax.bar([r["model"] for r in lat],[float(r["median_total_ms"]) for r in lat],color=[PALETTE["blue"],PALETTE["cyan"],PALETTE["green"],PALETTE["amber"]]); ax.bar_label(bars,fmt="%.3f ms",padding=3); ax.set(ylabel="Median batch latency (ms)",title="Saved-model inference latency on CPU (816 samples)"); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"model_latency"); plt.close(fig)
    hist=read_csv(tables/"lstm_training_history.csv"); fig,ax1=plt.subplots(figsize=(8,4.8)); epochs=[int(r["epoch"]) for r in hist]; line1=ax1.plot(epochs,[float(r["loss"]) for r in hist],color=PALETTE["red"],label="Training loss"); ax1.set(xlabel="Epoch",ylabel="Loss",title="Recorded LSTM training history (saved artifact)"); ax2=ax1.twinx(); line2=ax2.plot(epochs,[float(r["accuracy"]) for r in hist],color=PALETTE["blue"],label="Training accuracy"); ax2.set_ylabel("Accuracy"); ax1.legend(line1+line2,[l.get_label() for l in line1+line2],loc="center right"); ax1.grid(alpha=.4); savefig(fig,figs/"lstm_training_history"); plt.close(fig)
    robust=read_csv(tables/"lstm_evaluation_scope_summary.csv"); x=np.arange(len(robust)); fig,ax=plt.subplots(figsize=(8.4,4.8)); width=.32; acc=[float(r["accuracy_mean"]) for r in robust]; f1=[float(r["macro_f1_mean"]) for r in robust]; acc_err=[float(r["accuracy_std"]) for r in robust]; f1_err=[float(r["macro_f1_std"]) for r in robust]; ax.bar(x-width/2,acc,width,yerr=acc_err,capsize=5,label="Accuracy",color=PALETTE["blue"]); ax.bar(x+width/2,f1,width,yerr=f1_err,capsize=5,label="Macro F1",color=PALETTE["green"]); ax.set_xticks(x,["Legacy chronological\nholdout","Source-group-isolated\n3-run mean"]); ax.set_ylim(.90,1.01); ax.set(ylabel="Score",title="LSTM evaluation design comparison"); ax.legend(); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"lstm_robustness_comparison"); plt.close(fig)
    for kind,field,title,fmt in (("raw","count","Raw-count confusion matrices","d"),("normalized","proportion","Row-normalized confusion matrices",".2f")):
        data=read_csv(tables/f"confusion_{kind}.csv"); models=sorted({r["model"] for r in data}); classes=sorted({r["actual"] for r in data},key=lambda n:read_json(MODEL_ROOT/"label_mapping.json")[n]); fig,axes=plt.subplots(1,len(models),figsize=(5.2*len(models),4.8),squeeze=False)
        for ax,model in zip(axes[0],models):
            sub=[r for r in data if r["model"]==model]; matrix=np.array([[float(next(r[field] for r in sub if r["actual"]==a and r["predicted"]==p)) for p in classes] for a in classes]); im=ax.imshow(matrix,cmap="Blues",vmin=0,vmax=(matrix.max() if kind=="raw" else 1)); ax.set_xticks(range(len(classes)),[c.replace("_","\n") for c in classes],rotation=55,ha="right",fontsize=7); ax.set_yticks(range(len(classes)),[c.replace("_"," ") for c in classes],fontsize=7); ax.set(title=model,xlabel="Predicted",ylabel="Actual")
            for i in range(len(classes)):
                for j in range(len(classes)): ax.text(j,i,format(int(matrix[i,j]) if kind=="raw" else matrix[i,j],fmt),ha="center",va="center",fontsize=6,color="white" if matrix[i,j]>(matrix.max()/2) else PALETTE["ink"])
        fig.suptitle(title,fontweight="bold"); savefig(fig,figs/f"confusion_{kind}"); plt.close(fig)
    per=read_csv(tables/"per_class_metrics.csv"); model="decision_tree"; subset=[r for r in per if r["model"]==model]; x=np.arange(len(subset)); fig,ax=plt.subplots(figsize=(9,4.8)); w=.25
    for i,key in enumerate(("precision","recall","f1-score")): ax.bar(x+(i-1)*w,[float(r[key]) for r in subset],w,label=key)
    ax.set_xticks(x,[r["class"].replace("_","\n") for r in subset]); ax.set_ylim(0,1.05); ax.set(ylabel="Score",title="Decision Tree per-class performance"); ax.legend(); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"per_class_decision_tree"); plt.close(fig)
    for filename,field,title in (("shap_example.csv","shap_value","Decision Tree SHAP explanation for one held-out event"),("shap_global.csv","mean_abs_shap","Global Decision Tree SHAP importance (first 256 test rows)")):
        path=tables/filename
        if path.exists():
            data=read_csv(path)[:12][::-1]; values=[float(r[field]) for r in data]; fig,ax=plt.subplots(figsize=(8,5.2)); ax.barh([r["feature"].replace("numeric__","").replace("categorical__","") for r in data],values,color=[PALETTE["red"] if v<0 else PALETTE["blue"] for v in values]); ax.set(xlabel="SHAP contribution" if field=="shap_value" else "Mean absolute SHAP value",title=title); ax.grid(axis="x",alpha=.5); savefig(fig,figs/path.stem); plt.close(fig)
    if (tables/"live_timeline.csv").exists():
        data=read_csv(tables/"live_timeline.csv"); fig,ax=plt.subplots(figsize=(9,4.2)); x=np.arange(len(data)); ax.plot(x,[int(r["captured"]) for r in data],marker="o",label="Captured"); ax.plot(x,[int(r["processed"]) for r in data],marker="s",label="Processed"); ax.set_xticks(x,[r["second"][-8:] for r in data],rotation=45); ax.set(ylabel="Events per second",xlabel="UTC time",title="Fresh live demonstration event flow"); ax.legend(); ax.grid(alpha=.5); savefig(fig,figs/"live_events_timeline"); plt.close(fig)
    if (tables/"live_latency.csv").exists():
        data=read_csv(tables/"live_latency.csv"); fig,ax=plt.subplots(figsize=(7.5,4.3)); ax.hist([float(r["latency_ms"]) for r in data],bins=min(15,max(5,len(data)//3)),color=PALETTE["green"],edgecolor="white"); ax.set(xlabel="In-process detection + agents latency (ms)",ylabel="Events",title="Fresh live pipeline latency distribution"); ax.grid(axis="y",alpha=.5); savefig(fig,figs/"live_latency_distribution"); plt.close(fig)


def render_diagrams(run_dir: Path) -> None:
    diagrams=run_dir/"diagrams"
    sources={
      "use_case.puml":"""@startuml\nleft to right direction\nactor Attacker\nactor Analyst\nrectangle Framework {\n usecase \"Interact with SSH/FTP/HTTP decoys\" as U1\n usecase \"Submit safe portal SQLi/XSS probes\" as U2\n usecase \"Monitor events and IDS decisions\" as U3\n usecase \"Review SHAP and agent analysis\" as U4\n usecase \"Submit analyst feedback\" as U5\n usecase \"Approve simulated IPS action\" as U6\n usecase \"Prepare gated offline retraining candidate\" as U7\n}\nAttacker --> U1\nAttacker --> U2\nAnalyst --> U3\nAnalyst --> U4\nAnalyst --> U5\nAnalyst --> U6\nAnalyst --> U7\n@enduml\n""",
      "activity.puml":"""@startuml\nstart\n:Receive and validate common event;\n:Sanitize and engineer causal features;\n:Run rules, selected Decision Tree, Isolation Forest and LSTM;\nif (Rule finding?) then (yes)\n  :Use strongest deterministic rule;\nelseif (Known/sequence attack?) then (yes)\n  :Use classifier evidence;\nelseif (Unknown anomaly?) then (yes)\n  :Classify as other anomaly;\nelse (no)\n  :Classify as normal;\nendif\n:Compute threat score and SHAP-supported explanation;\n:Run six deterministic agents;\n:Persist result and show dashboard;\n:Recommend simulation-only response;\nstop\n@enduml\n""",
      "context_dfd.mmd":"""flowchart LR\n A[Attacker / test client] -->|SSH, FTP, HTTP interactions| P((Secure intelligent detection framework))\n P -->|Decoy responses| A\n P -->|Events, decisions, explanations, recommendations| N[Defender / analyst]\n N -->|Feedback and approved simulated actions| P\n P -.->|Sanitized alert payload when explicitly enabled| X[Local n8n / Telegram path]\n""",
      "level1_dfd.mmd":"""flowchart LR\n A[Attacker / test client] -->|Interactions| P1((1.0 Honeypot and decoy portal))\n P1 -->|Common events| D1[(D1 JSONL event log)]\n P1 -->|Events| D2[(D2 SQLite store)]\n D1 --> P2((2.0 Rules + ML inference))\n P2 -->|IDS result| D3[(D3 IDS results)]\n P2 --> P3((3.0 Threat, XAI and agents))\n P3 -->|Analysis and recommendation| D3\n D2 --> P4((4.0 Defender dashboard))\n D3 --> P4\n N[Analyst] <-->|Review / feedback / simulated IPS| P4\n P4 --> D4[(D4 Feedback and IPS audit tables)]\n D4 --> P5((5.0 Offline retraining gate))\n P5 -->|Human-approved candidate / rollback metadata| D5[(D5 Model artifacts)]\n D5 --> P2\n"""
    }
    for name,text in sources.items(): (diagrams/name).write_text(text,encoding="utf-8")
    plt=setup_plotting()
    from matplotlib.patches import Ellipse, FancyBboxPatch, Rectangle, Circle, Polygon
    def arrow(ax,a,b,label=""):
        ax.annotate("",xy=b,xytext=a,arrowprops=dict(arrowstyle="->",color=PALETTE["slate"],lw=1.5));
        if label: ax.text((a[0]+b[0])/2,(a[1]+b[1])/2+.2,label,fontsize=7,ha="center",bbox=dict(fc="white",ec="none",pad=.3))
    fig,ax=plt.subplots(figsize=(11,6)); ax.set_xlim(0,11); ax.set_ylim(0,7); ax.axis("off"); ax.add_patch(Rectangle((2,0.6),8.5,5.8,fill=False,lw=1.5,ec=PALETTE["navy"])); ax.text(6.25,6.15,"Secure intelligent detection framework",ha="center",weight="bold")
    for x,name in ((.8,"Attacker /\ntest client"),(.8,"Defender /\nanalyst")): pass
    def actor(x,y,name): ax.add_patch(Circle((x,y+.55),.18,fill=False)); ax.plot([x,x],[y+.35,y-.2],color=PALETTE["ink"]); ax.plot([x-.28,x+.28],[y+.15,y+.15],color=PALETTE["ink"]); ax.plot([x,x-.25],[y-.2,y-.55],color=PALETTE["ink"]); ax.plot([x,x+.25],[y-.2,y-.55],color=PALETTE["ink"]); ax.text(x,y-.9,name,ha="center",fontsize=8)
    actor(.8,4.8,"Attacker / test client"); actor(.8,1.9,"Defender / analyst")
    cases=[(4,5.2,"Interact with SSH / FTP / HTTP decoys"),(8,5.2,"Submit safe portal SQLi / XSS probes"),(4,3.7,"Monitor events and IDS decisions"),(8,3.7,"Review SHAP and agent analysis"),(4,2.2,"Submit analyst feedback"),(8,2.2,"Approve simulated IPS action"),(6,1.05,"Prepare gated offline retraining candidate")]
    for x,y,label in cases: ax.add_patch(Ellipse((x,y),3.1,.75,fc="#F6F9FC",ec=PALETTE["blue"])); ax.text(x,y,label,ha="center",va="center",fontsize=7.5,wrap=True)
    arrow(ax,(1.1,5),(2.45,5.2)); arrow(ax,(1.1,5),(6.45,5.2));
    for target in ((2.45,3.7),(6.45,3.7),(2.45,2.2),(6.45,2.2),(4.45,1.05)): arrow(ax,(1.1,2.1),target)
    ax.set_title("UML Use Case Diagram",pad=10); savefig(fig,diagrams/"use_case"); plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,10)); ax.set_xlim(0,8); ax.set_ylim(0,12); ax.axis("off"); steps=[(10.7,"Receive and validate event"),(9.5,"Sanitize and engineer causal features"),(8.3,"Run rules + DT + IF + LSTM"),(5.5,"Fuse decision using implemented precedence"),(4.2,"Compute threat severity and explanation"),(2.9,"Run six deterministic agents"),(1.6,"Persist and display; recommend simulated response")]
    ax.add_patch(Circle((4,11.5),.16,color=PALETTE["ink"])); prev=(4,11.34)
    for y,label in steps:
        ax.add_patch(FancyBboxPatch((1.5,y-.35),5,.7,boxstyle="round,pad=0.08,rounding_size=.12",fc="#F6F9FC",ec=PALETTE["blue"])); ax.text(4,y,label,ha="center",va="center",fontsize=8); arrow(ax,prev,(4,y+.35)); prev=(4,y-.35)
        if y==8.3:
            ax.add_patch(Polygon([[4,7.45],[5.1,6.75],[4,6.05],[2.9,6.75]],closed=True,fc="#FFF7E6",ec=PALETTE["amber"])); ax.text(4,6.75,"Rule / classifier / anomaly evidence?",ha="center",va="center",fontsize=7); arrow(ax,prev,(4,7.45)); prev=(4,6.05)
    arrow(ax,prev,(4,.75)); ax.add_patch(Circle((4,.55),.18,fill=False,ec=PALETTE["ink"],lw=1.5)); ax.add_patch(Circle((4,.55),.1,color=PALETTE["ink"])); ax.set_title("Activity Diagram — Online Detection and Response",pad=12); savefig(fig,diagrams/"activity"); plt.close(fig)
    def box(ax,xy,w,h,text,kind="entity"):
        x,y=xy
        if kind=="process": patch=FancyBboxPatch((x,y),w,h,boxstyle="round,pad=.08,rounding_size=.2",fc="#EDF5FC",ec=PALETTE["blue"],lw=1.5)
        elif kind=="store": patch=Rectangle((x,y),w,h,fc="#F8FAFC",ec=PALETTE["green"],lw=1.5)
        else: patch=Rectangle((x,y),w,h,fc="#FFF7E6",ec=PALETTE["amber"],lw=1.5)
        ax.add_patch(patch); ax.text(x+w/2,y+h/2,text,ha="center",va="center",fontsize=8,wrap=True)
        if kind=="store": ax.plot([x+.12,x+.12],[y+.06,y+h-.06],color=PALETTE["green"],lw=1)
    fig,ax=plt.subplots(figsize=(10,5.5)); ax.set_xlim(0,10); ax.set_ylim(0,6); ax.axis("off"); box(ax,(.3,2.3),1.8,1.1,"Attacker /\ntest client"); box(ax,(3.3,1.8),3.4,2.1,"Secure intelligent\ndetection framework","process"); box(ax,(7.9,2.3),1.8,1.1,"Defender /\nanalyst"); arrow(ax,(2.1,3),(3.3,3),"Interactions"); arrow(ax,(3.3,2.5),(2.1,2.5),"Decoy responses"); arrow(ax,(6.7,3.2),(7.9,3.2),"Events, IDS, XAI"); arrow(ax,(7.9,2.5),(6.7,2.5),"Feedback / simulated action"); ax.set_title("Context Data Flow Diagram",pad=12); savefig(fig,diagrams/"context_dfd"); plt.close(fig)
    fig,ax=plt.subplots(figsize=(13,7.5)); ax.set_xlim(0,13); ax.set_ylim(0,8); ax.axis("off"); box(ax,(.2,5.7),1.6,.9,"Attacker","entity"); box(ax,(2.2,5.4),2.2,1.4,"1.0 Honeypots +\ndecoy portal","process"); box(ax,(5.1,6.2),2.2,.8,"D1 JSONL events","store"); box(ax,(5.1,4.9),2.2,.8,"D2 SQLite store","store"); box(ax,(7.8,5.4),2.2,1.4,"2.0 Rules + ML\ninference","process"); box(ax,(10.5,6.2),2.2,.8,"D3 IDS results","store"); box(ax,(7.8,3.0),2.2,1.2,"3.0 Threat + XAI\n+ agents","process"); box(ax,(10.5,3.0),2.2,1.2,"4.0 Dashboard","process"); box(ax,(10.5,1.0),2.2,.8,"D4 Feedback + IPS audit","store"); box(ax,(7.8,.7),2.2,1.4,"5.0 Offline\nretraining gate","process"); box(ax,(5.1,.9),2.2,.8,"D5 Model artifacts","store"); box(ax,(.2,2.9),1.6,.9,"Analyst","entity")
    arrow(ax,(1.8,6.15),(2.2,6.15),"interactions"); arrow(ax,(4.4,6.3),(5.1,6.6),"events"); arrow(ax,(4.4,5.8),(5.1,5.3),"events"); arrow(ax,(7.3,6.6),(7.8,6.15),"stream"); arrow(ax,(10,6.15),(10.5,6.6),"result"); arrow(ax,(8.9,5.4),(8.9,4.2),"components"); arrow(ax,(10,3.6),(10.5,3.6),"analysis"); arrow(ax,(10.5,3.3),(1.8,3.35),"monitoring output"); arrow(ax,(1.8,3.1),(10.5,1.4),"feedback/action"); arrow(ax,(10.5,1.4),(10,1.4),"reviewed data"); arrow(ax,(7.8,1.4),(7.3,1.3),"candidate metadata"); arrow(ax,(6.2,1.7),(8.1,5.4),"approved model"); ax.set_title("Level 1 Data Flow Diagram",pad=12); savefig(fig,diagrams/"level1_dfd"); plt.close(fig)


def table_md(rows: list[dict[str,str]], fields: list[str], headings: list[str] | None=None, limit: int | None=None) -> str:
    if limit: rows=rows[:limit]
    headings=headings or fields
    lines=["| "+" | ".join(headings)+" |","|"+"|".join(["---"]*len(fields))+"|"]
    for row in rows: lines.append("| "+" | ".join(str(row.get(f,"" )).replace("|","\\|") for f in fields)+" |")
    return "\n".join(lines)


def build_markdown(run_dir: Path) -> tuple[str,str]:
    env=read_json(run_dir/"environment.json"); dataset=read_csv(run_dir/"tables"/"dataset_summary.csv")[0]; classes=read_csv(run_dir/"tables"/"class_distribution.csv"); metrics=read_csv(run_dir/"tables"/"model_metrics.csv"); primary_metrics=read_csv(run_dir/"tables"/"primary_model_metrics.csv"); binary=read_csv(run_dir/"tables"/"binary_metrics.csv"); latency=read_csv(run_dir/"tables"/"model_latency.csv"); robust=read_csv(run_dir/"tables"/"lstm_evaluation_scope_summary.csv"); robust_runs=read_csv(run_dir/"tables"/"lstm_group_isolated_runs.csv"); db=read_json(run_dir/"samples"/"database_schema.json"); prep=read_json(MODEL_ROOT/"preprocessing_manifest.json"); train=read_json(MODEL_DIR/"training_manifest.json"); lstm=read_json(MODEL_DIR/"lstm_metrics.json"); features=read_json(MODEL_ROOT/"feature_names.json")
    feature_defs=prep["features"]["engineered_definitions"]
    feature_rows=[{"feature":f,"definition":feature_defs.get(f.replace("numeric__",""),"Raw numeric field, standardized using training-set statistics." if f.startswith("numeric__") else "One-hot category; unknown test categories ignored.")} for f in features]
    model_rows=[
      {"component":"Rules","role":"Deterministic signature/threshold precedence","configuration":"RuleBasedDetector; strongest rule wins"},
      {"component":"Decision Tree","role":"Selected tabular known-attack classifier","configuration":"gini, depth 12, leaf 2, balanced, seed 42"},
      {"component":"Random Forest","role":"Evaluated candidate; not selected","configuration":"200 trees, depth 16, sqrt, leaf 2, balanced_subsample, seed 42"},
      {"component":"Isolation Forest","role":"Unknown-anomaly signal","configuration":"200 estimators, contamination 0.05; fit on 431 normal training rows"},
      {"component":"LSTM (active runtime)","role":"Causal sequence classifier; legacy chronological split","configuration":"23→64 hidden→8; 1 layer; dropout 0.30; sequence 10; 50 epochs; Adam lr 0.001; weighted CE; CPU"},
      {"component":"LSTM (audit candidates)","role":"Leakage-resistant robustness evaluation; not promoted","configuration":"Source-IP-hash group-isolated train/validation/test; seeds 42–44; max 40 epochs; best validation-loss checkpoint"},
    ]
    hardware=f"Windows evaluation host: {env['os']}; CPU: {env['cpu']}; RAM/system: {env['computer']}; GPU: {env['gpu']} (not used); storage: {env['storage']}. Python {env['python'].split()[0]}, Node {env['node']}, npm {env['npm']}."
    impl=f"""## 3.2 Implementation Details

The implemented prototype is a loopback-oriented defensive laboratory. SSH (2222), FTP (2121), and HTTP (8080) honeypots plus the React decoy portal (5173) create common-schema telemetry. The real-time pipeline validates and sanitizes each event, engineers causal features, runs deterministic rules and three saved-model roles, fuses the evidence, assigns a four-level threat score, adds a tree-SHAP explanation where supported, and invokes six deterministic operational agents. The Express/SQLite service (5000) persists telemetry and review records; the Flask defender dashboard (5050) displays the system monitor, honeypot activity, IDS/XAI/agents, analyst feedback, and simulation-only IPS records. The attacker portal remains separate from defender access.

### 3.2.1 Algorithm / Methodology / Techniques

#### Implemented workflow

1. **Capture.** Socket/HTTP services emulate bounded interactions; the portal safely simulates SQL-injection and XSS disclosures without dumping a real database or executing arbitrary JavaScript.
2. **Normalize and persist.** `core.event_schema` enforces the common event contract. `core.logger` writes JSONL, publishes SSE, and can queue events to the backend. Dataset preparation removes direct identifiers, hashes source IPs, records scope, redacts credentials, rejects invalid records, and deduplicates event IDs.
3. **Prepare evaluation data.** Dataset version {read_json(DATASET_MANIFEST)['dataset_version']} contains {dataset['accepted']} accepted events from {dataset['raw']} input events; {dataset['rejected']} were rejected and {dataset['duplicates_removed']} duplicate event IDs were removed. The active saved artifacts use a chronological {dataset['train']}/{dataset['test']} split with no separate validation set. The LSTM robustness audit separately uses source-IP-hash group-isolated train/validation/test partitions for seeds 42–44, with preprocessing fitted only on each training partition.
4. **Engineer features causally.** History is grouped by pseudonymous source and service. Counts use current/past 60-second windows; username repetition and sessions use 300 seconds. Numerical missing values use training medians and standard scaling; categorical values use a training-fitted one-hot encoder with unknown values ignored. Direct IDs, free text, raw payload, and label are excluded.
5. **Infer and audit.** Rules, the selected Decision Tree, Isolation Forest, and active LSTM run from protected saved artifacts. LSTM sequences contain ten grouped causal steps and left-zero padding, which the model masks before the recurrent layer. The separate audit trained three candidate LSTMs only for evaluation; their checkpoints and matching preprocessors were preserved but were not promoted into runtime.
6. **Fuse.** A deterministic rule has first priority. Otherwise a tabular attack is used, averaging confidence only when LSTM agrees; next comes an LSTM non-normal class at confidence ≥0.60; then Isolation Forest may produce `other_anomaly` with null probability confidence. Otherwise the event is normal. Isolation score is `-decision_function`, not a probability.
7. **Explain and operationalize.** The tree explainer produces local SHAP contributions for the selected tabular model. Human text combines protected model evidence and fusion rationale. Six deterministic agents run in order: detection, correlation, severity review, explanation, response recommendation, and daily report. They are not LLM agents and cannot overwrite protected IDS fields.
8. **Review and response.** Analysts can inspect, filter, provide feedback, and approve simulated IPS actions. The policy never changes the host firewall; recommendations and actions remain auditable in SQLite.
9. **Learn offline.** Reviewed data can be prepared for candidate retraining, evaluated against quality gates, then promoted or rolled back with human control. This report's robustness audit trained isolated evaluation candidates, selected each best epoch by validation loss, and left the active checkpoint untouched.

#### Main pipeline pseudocode

```text
for each validated common_event in chronological order:
    neutral_event = remove producer attack label from inference input
    row = sanitize_and_normalize(neutral_event)
    features = causal_feature_engineering(row, prior_group_history)
    encoded = fitted_preprocessor.transform(features)
    rules = rule_detector.inspect(common_event)
    dt_label, dt_probability = selected_tree.predict(encoded)
    anomaly, anomaly_score = isolation_forest.predict(encoded)
    lstm_label, lstm_probability = lstm.predict(last_10_grouped_events)
    decision = implemented_precedence(rules, dt, lstm_at_0.60, anomaly)
    threat = stateful_threat_reporter.assess(decision)
    explanation = tree_SHAP_and_human_reason(encoded, decision)
    agents = run_in_fixed_order_without_mutating_protected_fields()
    persist_and_display(decision, threat, explanation, agents)
    recommend_simulation_only_response()
```

**Table 3.2.1-1. Implemented model roles and verifiable configuration**

{table_md(model_rows,['component','role','configuration'],['Component','Actual role','Verified configuration'])}

**Table 3.2.1-2. Production feature order and definition**

{table_md(feature_rows,['feature','definition'],['Encoded feature','Definition / preprocessing'])}

Source references: `core/honeypots/*`, `core/event_schema.py`, `core/logger.py`, `dataset/prepare_dataset.py`, `feature_engineering/engineer_features.py`, `preprocessing/preprocess_dataset.py`, `machine_learning/hybrid_ids.py`, `machine_learning/threat_reporting.py`, `XAI/prediction_explainer.py`, `intelligent_agents/orchestrator.py`, `website/backend/*.js`, `dashboard/app.py`, `continuous_learning/pipeline.py`, and `scripts/audit_lstm_generalization.py`.

### 3.2.2 Use Case Diagram / Activity Diagram / DFD

![Figure 3.2.2-1. UML use-case diagram.](diagrams/use_case.png)

**Figure 3.2.2-1. UML use-case diagram.** The attacker/test client can interact only with decoys; the defender/analyst reviews evidence and controls feedback, simulated response, and offline candidate preparation.

![Figure 3.2.2-2. Online-detection activity diagram.](diagrams/activity.png)

**Figure 3.2.2-2. Activity diagram.** The activity follows the exact runtime order and distinguishes inference, explanation, agents, persistence, and recommendation-only response.

![Figure 3.2.2-3. Context DFD.](diagrams/context_dfd.png)

**Figure 3.2.2-3. Context DFD.** External boundary flows are interactions/decoy replies and defender evidence/feedback; the optional notification path is explicitly conditional.

![Figure 3.2.2-4. Level 1 DFD.](diagrams/level1_dfd.png)

**Figure 3.2.2-4. Level 1 DFD.** JSONL, SQLite, IDS results, review/audit data, and protected model artifacts are shown as separate stores. Offline retraining is separated from online inference.

Editable sources are supplied as PlantUML (`.puml`) and Mermaid (`.mmd`) alongside rendered PNG/SVG files.

### 3.2.3 Hardware and Software Specifications

{hardware}

The implementation uses Flask, Express, React/Vite, SQLite, NumPy, scikit-learn, Joblib, PyTorch, SHAP, psutil, and Matplotlib. Exact package versions are preserved in `environment.json`. The report run used CPU inference even if a GPU was installed. Browser screenshots beyond the included captured view require the manual checklist because no college template or browser-driver package was supplied.
"""

    live_note="No fresh live run was executed in this package; live-only charts are intentionally omitted."
    if (run_dir/"logs"/"live_run.json").exists():
        live=read_json(run_dir/"logs"/"live_run.json"); scenario_note=" ".join(f"{s['scenario']}: {s['events_processed']} processed, {s['attack_predictions']} attack and {s['normal_predictions']} normal decisions ({s['observed_attack_types'] or 'no output'})." for s in live["scenarios"]); live_note=f"Fresh isolated localhost demonstration: {live['events_captured']} events captured, {live['events_processed']} processed, {len(live['processing_failures'])} processing failures; external notification delivery was disabled. {scenario_note} The isolated normal GET was classified as directory scanning, an observed false positive that requires follow-up."
    results=f"""# 4 Result and Discussion

This chapter separates two scopes: fresh inference against the protected legacy holdout, and a three-seed LSTM robustness audit using source-group-isolated train/validation/test partitions. The audit fitted evaluation candidates but did not promote or overwrite the active runtime model. Protected artifact hashes were checked before and after the audit.

## 4.1 Sample of Inputs/Dataset/Database Used/ and Outputs/Screen Shots

**Table 4.1-1. Dataset summary (run {run_dir.name})**

{table_md([dataset],['dataset_version','raw','accepted','rejected','duplicates_removed','train','validation','test','encoded_features'],['Version','Input','Accepted','Rejected','Duplicates','Train','Validation','Test','Features'])}

**Table 4.1-2. Class distribution**

{table_md(classes,['class','total','train','test'],['Class','Total','Train','Test'])}

![Figure 4.1-1. Accepted class distribution.](figures/dataset_class_distribution.png)

![Figure 4.1-2. Chronological train/test distribution.](figures/train_test_distribution.png)

The data originated from `data/raw_logs/honeypot_events.jsonl` and the controlled expansion workflow, then was sanitized into `data/processed/honeypot_dataset.csv`. Representative rows are in `samples/sanitized_test_inputs.csv`; direct IPs, credentials, payload JSON, and personal identifiers are excluded.

The read-only database inventory found {len(db.get('tables',[]))} application tables: {', '.join(item['name'] for item in db.get('tables',[]))}. Their exact columns, types, row counts, and sanitized IDS samples are in `samples/database_schema.json` and `samples/database_ids_results_sample.csv`. Relationships are mostly enforced by shared `event_id`/recommendation IDs in application code; SQLite foreign-key declarations were not found in the production schema and are not claimed.

Prediction-level outputs for every supported saved-model evaluation are in `predictions/`. Tabular rows use verified original event IDs; sequence rows use stable sequence sample IDs because the saved sequence array does not retain event IDs. Component probabilities, continuous attack scores, predictions, and truth labels are retained. The sanitized package includes `samples/live_events_sanitized.csv` plus `samples/live_ids_results.jsonl`; the complete isolated producer event stream stays only in the local run directory and is excluded from the ZIP.

{live_note}

Application screenshot evidence is tracked in `screenshots/manual_screenshot_checklist.csv`. Generated diagrams and charts are not represented as application screenshots. External Telegram receipt is pending by design because this run disabled notifications and did not expose secrets.

## 4.2 Evaluation Parameters

Let TP, TN, FP, and FN denote attack/normal outcomes, with **attack as positive** and normal as negative. Accuracy = (TP+TN)/(TP+TN+FP+FN). Precision = TP/(TP+FP). Recall or detection rate = TP/(TP+FN). F1 = 2·Precision·Recall/(Precision+Recall). FPR = FP/(FP+TN); FNR = FN/(FN+TP). Zero denominators are reported as zero by the evaluation implementation rather than causing an error.

For eight-class classification, per-class precision/recall/F1 and support are computed one-vs-rest. Macro averages give every class equal weight; weighted averages weight by support; balanced accuracy is mean class recall. Confusion matrices use actual classes as rows and predicted classes as columns; both raw counts and row-normalized proportions are reported.

ROC uses continuous `1-P(normal)` for supervised models and negative Isolation Forest `decision_function` for anomaly detection. ROC-AUC integrates TPR against FPR. The precision-recall curve also uses continuous scores, and `average_precision_score` is reported (stepwise average precision, not trapezoidal PR-AUC). The anomaly score direction was checked so higher means more anomalous and is not called a calibrated probability.

Latency is wall-clock inference time after artifact loading, with one warm-up and 12 repeated batches of 816 samples; median, mean, p95, and per-sample derived values are preserved. If live mode was run, `e2e_local_processing_ms` spans event-to-result computation inside the evidence harness (hybrid inference, threat/XAI and agents), excluding network capture and backend persistence. Functional test pass rates are not presented as detection accuracy.

## 4.3 Performance Evaluation (Tables/Graphs/Charts)

**Table 4.3-1. Primary reported multiclass metrics by evaluation scope**

{table_md(primary_metrics,['model','evaluation_scope','runs','test_samples','accuracy_mean','accuracy_std','balanced_accuracy_mean','macro_f1_mean','macro_f1_std'],['Model','Evaluation scope','Runs','Test n','Accuracy','Accuracy SD','Balanced accuracy','Macro F1','Macro F1 SD'])}

![Figure 4.3-1. Primary reported metrics with explicit evaluation scopes.](figures/model_metric_comparison.png)

Decision Tree remains the selected tabular classifier: its macro F1 is approximately 0.958 while Random Forest is approximately 0.951 and has a materially larger normal-event false-positive rate. The primary LSTM row now uses the three-run source-group-isolated estimate: 0.9761 accuracy and 0.9675 macro F1. The legacy 1.0000 reproduction appears only in the explicitly labelled comparison below and must not be quoted as the final generalization result.

**Table 4.3-2. LSTM evaluation-scope comparison**

{table_md(robust,['evaluation','runs','test_samples','accuracy_mean','accuracy_std','balanced_accuracy_mean','macro_f1_mean','macro_f1_std','source_group_overlap','template_overlap'],['Evaluation','Runs','Test n','Accuracy mean','Accuracy SD','Balanced accuracy','Macro F1 mean','Macro F1 SD','Source-group overlap','Template overlap'])}

![Figure 4.3-2. LSTM legacy holdout versus source-group-isolated audit.](figures/lstm_robustness_comparison.png)

The original chronological split has important dependence: 791 of 816 test rows (96.94%) have a source hash already present in training, all 816 reuse a service/event/path template found in training, and the train-end and test-start timestamps are identical. There are no byte-identical train/test sequences, so the concern is related-group/template overlap rather than literal sequence duplication. In three source-group-isolated runs, source overlap was zero in every run. Test accuracy was 0.9761 mean with 0.0035 population standard deviation (range 0.9718–0.9803); macro F1 was 0.9675 mean with 0.0033 standard deviation (range 0.9635–0.9715). These are the preferred internal LSTM estimates. Templates still repeat across groups, so an external or template/campaign-isolated dataset remains necessary. Seed-level results and exact split assignments are packaged under `lstm_robustness/`. The seed-42 bundle is a reproducible candidate only; it was not promoted.

**Table 4.3-3. Source-group-isolated LSTM seed-level results**

{table_md(robust_runs,['seed','best_epoch','train_rows','validation_rows','test_rows','validation_accuracy','test_accuracy','test_balanced_accuracy','test_macro_f1'],['Seed','Best epoch','Train','Validation','Test','Validation accuracy','Test accuracy','Balanced accuracy','Macro F1'])}

![Figure 4.3-3. Raw-count confusion matrices.](figures/confusion_raw.png)

![Figure 4.3-4. Row-normalized confusion matrices.](figures/confusion_normalized.png)

![Figure 4.3-5. Decision Tree per-class precision/recall/F1.](figures/per_class_decision_tree.png)

**Table 4.3-4. Binary attack-versus-normal evaluation**

{table_md(binary,['model','samples','tn','fp','fn','tp','fpr','fnr','roc_auc','average_precision','score_type'],['Model','n','TN','FP','FN','TP','FPR','FNR','ROC-AUC','Average precision','Continuous score'])}

![Figure 4.3-6. Binary false-positive/false-negative comparison.](figures/binary_fpr_fnr.png)

Isolation Forest ranks attacks well (ROC/PR evidence in the CSV) but at its saved contamination operating point detects only a small fraction of attacks. This is not directly comparable to eight-class accuracy and indicates threshold calibration work, not a failed classifier replacement.

![Figure 4.3-7. ROC curves.](figures/roc_curves.png)

![Figure 4.3-8. Precision-recall curves.](figures/pr_curves.png)

![Figure 4.3-9. Local Decision Tree SHAP explanation.](figures/shap_example.png)

![Figure 4.3-10. Global Decision Tree SHAP summary.](figures/shap_global.png)

The global SHAP plot is mean absolute contribution on the first 256 chronologically held-out tabular rows; the local plot is one traceable held-out event. SHAP describes the selected tree's contribution, not the rule, LSTM, anomaly model, or a causal explanation of attacker intent.

**Table 4.3-5. CPU inference latency**

{table_md(latency,['model','samples','median_total_ms','mean_total_ms','p95_total_ms','median_per_sample_ms'],['Model','n','Median batch ms','Mean batch ms','p95 batch ms','Median ms/sample'])}

![Figure 4.3-11. Saved-model inference latency.](figures/model_latency.png)

![Figure 4.3-12. Saved legacy LSTM training history.](figures/lstm_training_history.png)

Rules-only and full-hybrid aggregate accuracy are intentionally not fabricated: the saved feature arrays omit the raw stateful event stream required for a faithful, directly aligned replay. Live mode demonstrates the real runtime path separately but its scenario labels and small controlled sample do not constitute a generalization benchmark. Source-group isolation has now been measured for LSTM, but external/template/campaign isolation, calibration and sustained-load evaluation remain open. Exact unsupported/missing evidence is listed in `limitations_and_missing_evidence.md`.
"""
    (run_dir/"implementation_details.md").write_text(impl,encoding="utf-8")
    (run_dir/"results_and_discussion.md").write_text(results,encoding="utf-8")
    return impl,results


def add_page_number(paragraph) -> None:
    from docx.oxml import OxmlElement
    run=paragraph.add_run(); begin=OxmlElement("w:fldChar"); begin.set("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}fldCharType","begin"); instr=OxmlElement("w:instrText"); instr.set("{http://www.w3.org/XML/1998/namespace}space","preserve"); instr.text=" PAGE "; end=OxmlElement("w:fldChar"); end.set("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}fldCharType","end"); run._r.extend([begin,instr,end])


def build_docx(run_dir: Path, impl: str, results: str) -> None:
    from docx import Document
    from docx.enum.section import WD_SECTION
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
    from docx.shared import Cm, Inches, Pt, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    doc=Document(); sec=doc.sections[0]; sec.page_width=Cm(21); sec.page_height=Cm(29.7); sec.top_margin=Cm(2.54); sec.bottom_margin=Cm(2.54); sec.left_margin=Cm(3.0); sec.right_margin=Cm(2.5)
    styles=doc.styles; normal=styles["Normal"]; normal.font.name="Times New Roman"; normal.font.size=Pt(12); normal._element.rPr.rFonts.set(qn("w:eastAsia"),"Times New Roman"); normal.paragraph_format.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY; normal.paragraph_format.line_spacing=1.5; normal.paragraph_format.space_after=Pt(6)
    for name,size,align in (("Heading 1",16,WD_ALIGN_PARAGRAPH.CENTER),("Heading 2",12,WD_ALIGN_PARAGRAPH.LEFT),("Heading 3",12,WD_ALIGN_PARAGRAPH.LEFT),("Heading 4",12,WD_ALIGN_PARAGRAPH.LEFT)):
        s=styles[name]; s.font.name="Times New Roman"; s.font.size=Pt(size); s.font.bold=True; s.font.color.rgb=RGBColor(0,0,0); s._element.rPr.rFonts.set(qn("w:eastAsia"),"Times New Roman"); s.paragraph_format.alignment=align; s.paragraph_format.space_before=Pt(10); s.paragraph_format.space_after=Pt(6); s.paragraph_format.keep_with_next=True
    footer=sec.footer.paragraphs[0]; footer.alignment=WD_ALIGN_PARAGRAPH.CENTER; add_page_number(footer)
    def p(text="",bold=False,center=False,italic=False):
        par=doc.add_paragraph(); par.alignment=WD_ALIGN_PARAGRAPH.CENTER if center else WD_ALIGN_PARAGRAPH.JUSTIFY; run=par.add_run(text); run.bold=bold; run.italic=italic; run.font.name="Times New Roman"; run.font.size=Pt(12); return par
    def heading(text,level): doc.add_heading(text,level=level)
    def bullet(text):
        par=doc.add_paragraph(style="List Bullet"); par.paragraph_format.left_indent=Cm(.7); par.paragraph_format.first_line_indent=Cm(-.35); par.add_run(text)
    def table(title,rows,fields,heads):
        title_paragraph=p(title,bold=True,center=True)
        title_paragraph.paragraph_format.keep_with_next=True
        t=doc.add_table(rows=1,cols=len(fields)); t.alignment=WD_TABLE_ALIGNMENT.CENTER; t.style="Table Grid"
        for i,h in enumerate(heads): cell=t.rows[0].cells[i]; cell.text=h; cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
        for row in rows:
            cells=t.add_row().cells
            for i,f in enumerate(fields):
                value=str(row.get(f,""))
                try:
                    if "." in value and len(value)>8:
                        value=f"{float(value):.4f}"
                except ValueError:
                    pass
                cells[i].text=value
        for row in t.rows:
            for cell in row.cells:
                for par in cell.paragraphs:
                    par.paragraph_format.line_spacing=1; par.paragraph_format.space_after=Pt(0)
                    for run in par.runs: run.font.name="Times New Roman"; run.font.size=Pt(9)
        doc.add_paragraph()
    def figure(path,caption,width=6.4):
        if path.exists():
            par=doc.add_paragraph(); par.alignment=WD_ALIGN_PARAGRAPH.CENTER; par.add_run().add_picture(str(path),width=Inches(width))
            cap=p(caption,center=True,italic=True); cap.paragraph_format.keep_with_next=False
    heading("3.2 Implementation Details",1)
    p("The implemented prototype is a loopback-oriented defensive laboratory. SSH, FTP, and HTTP honeypots plus the React decoy portal create common-schema telemetry. The real-time pipeline validates and sanitizes each event, engineers causal features, runs deterministic rules and saved-model roles, fuses evidence, assigns a four-level threat score, adds supported SHAP evidence, and invokes six deterministic operational agents. Express/SQLite persists telemetry and review records; the Flask defender dashboard displays monitoring, IDS/XAI/agents, analyst feedback, and simulation-only IPS records.")
    heading("3.2.1 Algorithm / Methodology / Techniques",2)
    for title,text in [
      ("Honeypot layer","SSH (2222), FTP (2121), and HTTP (8080) emulate bounded services. The React portal (5173) safely simulates SQLi/XSS disclosures and records activity without dumping a real database or executing unrestricted JavaScript."),
      ("Event handling","The common-event schema is validated, written to JSONL, streamed to the dashboard and optionally queued to the backend. Dataset preparation hashes source IPs, records address scope, redacts credentials, rejects invalid rows, and deduplicates event IDs."),
      ("Dataset preparation","The verified dataset has 5,193 source events, 4,080 accepted rows, 1,113 rejected rows and zero duplicate accepted event IDs. Eight classes contain 510 accepted rows each before the chronological split."),
      ("Features and preprocessing","Twelve numeric inputs and four categorical fields become 23 encoded features. Stateful features use only current and past events grouped by source hash and service. Numerical imputation/scaling and one-hot categories are fitted on training data only."),
      ("Models","Decision Tree is the selected tabular classifier; Random Forest remains a candidate. Isolation Forest is fit only on normal training rows and supplies an anomaly score. The active LSTM uses 10×23 causal sequences, 64 hidden units, one layer, dropout 0.30, class-weighted cross entropy and Adam on CPU. A separate three-seed source-group-isolated audit trained evaluation candidates and did not promote them."),
      ("Runtime fusion and threat","Deterministic rules have priority. Otherwise the selected tree is used, LSTM can supply a sequence decision at confidence ≥0.60, and Isolation Forest is the unknown-anomaly fallback. Threat scoring maps 0–24 Low, 25–49 Medium, 50–74 High and 75–100 Critical."),
      ("Explanations and agents","Tree SHAP supports the selected tree only. Six deterministic agents execute detection, correlation, severity review, explanation, response recommendation and daily reporting. They are not LLMs and cannot change protected IDS fields."),
      ("Application and learning","Express/SQLite stores events/results/feedback/IPS audit data; Flask is the local defender UI. IPS is simulation-only. Feedback can enter a human-gated offline candidate, promotion and rollback workflow. The robustness audit trained isolated candidates, selected by validation loss, but did not promote or overwrite the active model."),
    ]:
        heading(title,3); p(text)
    heading("Stepwise pseudocode",3)
    for line in ["Validate common event; neutralize producer label.","Sanitize and causally engineer grouped history features.","Transform with the training-fitted preprocessor.","Run rules, selected Decision Tree, Isolation Forest and LSTM.","Fuse by implemented precedence and compute threat severity.","Generate supported SHAP/human explanation.","Run six deterministic agents without changing protected output.","Persist, display and recommend simulation-only response."]:
        bullet(line)
    model_rows=[{"component":"Rules","role":"Deterministic precedence","configuration":"Strongest matched rule"},{"component":"Decision Tree","role":"Selected tabular classifier","configuration":"gini; depth 12; leaf 2; balanced"},{"component":"Random Forest","role":"Candidate classifier","configuration":"200 trees; depth 16; sqrt; leaf 2"},{"component":"Isolation Forest","role":"Unknown anomaly","configuration":"200 estimators; contamination 0.05"},{"component":"LSTM (active)","role":"Runtime sequence classifier; legacy split","configuration":"10×23; hidden 64; 1 layer; 50 epochs"},{"component":"LSTM (audit)","role":"Group-isolated candidates; not promoted","configuration":"Seeds 42–44; max 40 epochs; best validation loss"}]
    table("Table 3.2.1-1. Implemented model roles and configuration",model_rows,["component","role","configuration"],["Component","Actual role","Configuration"])
    feature_rows=read_json(MODEL_ROOT/"feature_names.json"); table("Table 3.2.1-2. Production feature order",[{"number":i+1,"feature":f} for i,f in enumerate(feature_rows)],["number","feature"],["No.","Encoded feature"])
    p("Supporting sources: core/honeypots, core/event_schema.py, core/logger.py, dataset/prepare_dataset.py, feature_engineering/engineer_features.py, preprocessing/preprocess_dataset.py, machine_learning/hybrid_ids.py, machine_learning/threat_reporting.py, XAI/prediction_explainer.py, intelligent_agents/orchestrator.py, website/backend, dashboard/app.py, continuous_learning/pipeline.py and scripts/audit_lstm_generalization.py.")
    heading("3.2.2 Use Case Diagram / Activity Diagram / DFD",2)
    for name,caption in [("use_case","Figure 3.2.2-1. UML use-case diagram: decoy interactions and analyst-controlled defensive functions."),("activity","Figure 3.2.2-2. Activity diagram: implemented online inference and response flow."),("context_dfd","Figure 3.2.2-3. Context DFD: external entities and framework boundary flows."),("level1_dfd","Figure 3.2.2-4. Level 1 DFD: processes, stores and separate offline retraining gate.")]: figure(run_dir/"diagrams"/f"{name}.png",caption)
    doc.add_page_break(); heading("3.2.3 Hardware and Software Specifications",2)
    env=read_json(run_dir/"environment.json"); specs=[{"item":"OS","value":f"{env['os'].get('Caption')} {env['os'].get('OSArchitecture')}; build {env['os'].get('BuildNumber')}"},{"item":"CPU","value":f"{env['cpu'].get('Name')}; {env['cpu'].get('NumberOfCores')} cores / {env['cpu'].get('NumberOfLogicalProcessors')} logical processors"},{"item":"RAM/system","value":f"{env['computer'].get('TotalPhysicalMemoryGB')} GB; {env['computer'].get('Manufacturer')} {env['computer'].get('Model')}"},{"item":"GPU","value":f"{env['gpu'].get('Name')}; driver {env['gpu'].get('DriverVersion')}; not used for this evaluation"},{"item":"Storage","value":f"Drive {env['storage'].get('DriveLetter')}: {env['storage'].get('FileSystem')}; {env['storage'].get('SizeGB')} GB total, {env['storage'].get('FreeGB')} GB free"},{"item":"Runtime","value":f"Python {env['python'].split()[0]}; Node {env['node']}; npm {env['npm']}"},{"item":"Stack","value":"Flask, Express, React/Vite, SQLite, NumPy, scikit-learn, Joblib, PyTorch, SHAP, psutil, Matplotlib"}]
    table("Table 3.2.3-1. Measured evaluation environment",specs,["item","value"],["Item","Verified value"]); p("This is the host used for this evidence run and is not asserted to be the student's personal laptop. Exact dependency versions are in environment.json.")
    doc.add_page_break(); heading("4 Result and Discussion",1); p("Results below separate fresh inference against the protected legacy holdout from a three-seed LSTM robustness audit using source-group-isolated train/validation/test partitions. The audit fitted evaluation candidates but did not promote or overwrite the active runtime model. Live evidence, where included, is separately labelled.")
    heading("4.1 Sample of Inputs/Dataset/Database Used/ and Outputs/Screen Shots",2)
    ds=read_csv(run_dir/"tables"/"dataset_summary.csv"); table("Table 4.1-1. Dataset summary",ds,["raw","accepted","rejected","duplicates_removed","train","validation","test","encoded_features"],["Input","Accepted","Rejected","Duplicates","Train","Validation","Test","Features"])
    classes=read_csv(run_dir/"tables"/"class_distribution.csv"); table("Table 4.1-2. Class distribution",classes,["class","total","train","test"],["Class","Total","Train","Test"]); figure(run_dir/"figures"/"dataset_class_distribution.png","Figure 4.1-1. Accepted dataset class distribution."); figure(run_dir/"figures"/"train_test_distribution.png","Figure 4.1-2. Chronological train/test distribution.")
    db=read_json(run_dir/"samples"/"database_schema.json"); p(f"Read-only inspection found {len(db.get('tables',[]))} application tables. Exact columns/types/counts and sanitized sample records are supplied with the evidence package.")
    purposes={"users":"Legacy portal authentication records; no defender login UI","honeypot_events":"Normalized captured events","ids_results":"Hybrid decisions, components, XAI and agents","analyst_feedback":"Human review verdicts/overrides","ips_recommendations":"Policy recommendations","ips_actions":"Simulation-only action audit"}
    table("Table 4.1-3. Application database inventory",[{"table":item["name"],"rows":item["rows"],"purpose":purposes.get(item["name"],"Application persistence")} for item in db.get("tables",[])],["table","rows","purpose"],["Table","Rows","Purpose"])
    samples=read_csv(run_dir/"samples"/"sanitized_test_inputs.csv")
    table("Table 4.1-4. Representative sanitized held-out inputs",samples,["event_id","service","event","request_path","label"],["Event ID","Service","Event","Path","True label"])
    predictions=read_csv(run_dir/"predictions"/"decision_tree_predictions.csv")
    chosen=[]
    seen=set()
    for row in predictions:
        if row["true_label"] not in seen:
            chosen.append(row); seen.add(row["true_label"])
        if len(chosen)==6: break
    table("Table 4.1-5. Traceable Decision Tree output samples",chosen,["sample_id","true_label","predicted_label","attack_score"],["Sample/event ID","True label","Predicted label","Attack score"])
    if (run_dir/"tables"/"live_scenarios.csv").exists():
        live_rows=read_csv(run_dir/"tables"/"live_scenarios.csv")
        table("Table 4.1-6. Fresh bounded localhost scenarios",live_rows,["scenario","expected","events_captured","events_processed","attack_predictions","normal_predictions","status"],["Scenario","Independent expectation","Captured","Processed","Attack","Normal","Status"])
        p("All 125 captured events were processed after preserving chronological file order, with zero processing failures. The single normal HTTP GET was classified as directory scanning (a directly observed false positive). SSH produced 15 ssh_bruteforce and one other_anomaly result; the broader FTP scenario generated many connection/session events and mixed classifier outputs; the HTTP attack scenario produced SQL-injection, XSS, directory-scanning, brute-force and one normal result. These small controlled scenarios demonstrate operation, not generalization accuracy.")
    if (run_dir/"screenshots"/"01_system_monitor.png").exists():
        figure(run_dir/"screenshots"/"01_system_monitor.png","Figure 4.1-3. Genuine Flask defender dashboard during the isolated evidence run.")
    p("Application screenshot evidence is separated from generated figures. The package contains a manual screenshot checklist for views not captured automatically. Telegram receipt is not claimed because external notifications were disabled for this evidence run.")
    heading("4.2 Evaluation Parameters",2)
    for text in ["Attack is the positive binary class and normal is negative. Accuracy=(TP+TN)/(TP+TN+FP+FN); Precision=TP/(TP+FP); Recall=TP/(TP+FN); F1=2PR/(P+R); FPR=FP/(FP+TN); FNR=FN/(FN+TP). Zero denominators are reported as zero.","For eight classes, per-class metrics are one-vs-rest. Macro averages weight classes equally; weighted averages weight by support; balanced accuracy is mean class recall. Confusion matrices use actual rows and predicted columns.","ROC/PR use 1−P(normal) for supervised models and negative Isolation Forest decision_function for anomaly detection. Average precision is reported, not trapezoidal PR-AUC. The anomaly score is continuous but not calibrated probability.","Latency excludes artifact loading and uses one warm-up plus 12 repeated 816-sample batches. Functional test pass rates are not detection accuracy."]:
        p(text)
    heading("4.3 Performance Evaluation (Tables/Graphs/Charts)",2)
    primary_metrics=read_csv(run_dir/"tables"/"primary_model_metrics.csv"); table("Table 4.3-1. Primary reported multiclass metrics by evaluation scope",primary_metrics,["model","evaluation_scope","runs","test_samples","accuracy_mean","accuracy_std","balanced_accuracy_mean","macro_f1_mean","macro_f1_std"],["Model","Evaluation scope","Runs","Test n","Accuracy","Acc. SD","Balanced acc.","Macro F1","F1 SD"]); figure(run_dir/"figures"/"model_metric_comparison.png","Figure 4.3-1. Primary metrics with explicit evaluation scopes.")
    p("Decision Tree remains the selected tabular model. The primary LSTM row uses the three-run source-group-isolated result: 0.9761 mean accuracy and 0.9675 mean macro F1. The 1.0000 result is retained only below as an explicitly labelled legacy-holdout reproduction and must not be quoted as final generalization performance.")
    robust=read_csv(run_dir/"tables"/"lstm_evaluation_scope_summary.csv")
    table("Table 4.3-2. LSTM evaluation-scope comparison",robust,["evaluation","runs","test_samples","accuracy_mean","accuracy_std","balanced_accuracy_mean","macro_f1_mean","macro_f1_std"],["Evaluation","Runs","Test n","Accuracy mean","Accuracy SD","Balanced acc.","Macro F1","F1 SD"])
    figure(run_dir/"figures"/"lstm_robustness_comparison.png","Figure 4.3-2. Legacy holdout versus source-group-isolated LSTM audit.",width=6.2)
    p("The original split has 791/816 test rows (96.94%) whose source hash is present in training, all 816 reuse a service/event/path template found in training, and the boundary timestamp is identical. No byte-identical train/test sequences were found; the risk is related-group/template overlap. Across source-group-isolated seeds 42–44, source overlap was zero. Mean test accuracy was 0.9761 (population SD 0.0035; range 0.9718–0.9803) and mean macro F1 was 0.9675 (SD 0.0033; range 0.9635–0.9715). These are the preferred internal LSTM estimates. Templates still repeat across groups, so external or template/campaign-isolated validation remains required. The seed-42 bundle is a candidate only and was not promoted.")
    robust_runs=read_csv(run_dir/"tables"/"lstm_group_isolated_runs.csv")
    table("Table 4.3-3. Source-group-isolated LSTM seed-level results",robust_runs,["seed","best_epoch","train_rows","validation_rows","test_rows","validation_accuracy","test_accuracy","test_balanced_accuracy","test_macro_f1"],["Seed","Best epoch","Train","Validation","Test","Val. acc.","Test acc.","Balanced acc.","Macro F1"])
    for name,caption in [("confusion_raw","Figure 4.3-3. Raw-count confusion matrices."),("confusion_normalized","Figure 4.3-4. Row-normalized confusion matrices."),("per_class_decision_tree","Figure 4.3-5. Decision Tree per-class metrics.")]: figure(run_dir/"figures"/f"{name}.png",caption)
    doc.add_page_break()
    binary=read_csv(run_dir/"tables"/"binary_metrics.csv"); table("Table 4.3-4. Binary attack-versus-normal metrics",binary,["model","fpr","fnr","roc_auc","average_precision"],["Model","FPR","FNR","ROC-AUC","Average precision"])
    for name,caption in [("binary_fpr_fnr","Figure 4.3-6. False-positive and false-negative rates."),("roc_curves","Figure 4.3-7. ROC curves using continuous scores."),("pr_curves","Figure 4.3-8. Precision-recall curves using continuous scores."),("shap_example","Figure 4.3-9. Local Decision Tree SHAP explanation."),("shap_global","Figure 4.3-10. Mean absolute SHAP on the first 256 held-out rows.")]: figure(run_dir/"figures"/f"{name}.png",caption)
    doc.add_page_break()
    latency=read_csv(run_dir/"tables"/"model_latency.csv"); table("Table 4.3-5. CPU inference latency",latency,["model","samples","median_total_ms","mean_total_ms","p95_total_ms","median_per_sample_ms"],["Model","n","Median ms","Mean ms","p95 ms","Median ms/sample"]); figure(run_dir/"figures"/"model_latency.png","Figure 4.3-11. CPU saved-model inference latency."); figure(run_dir/"figures"/"lstm_training_history.png","Figure 4.3-12. Recorded legacy LSTM training history.")
    if (run_dir/"figures"/"live_events_timeline.png").exists(): figure(run_dir/"figures"/"live_events_timeline.png","Figure 4.3-13. Fresh bounded localhost event flow."); figure(run_dir/"figures"/"live_latency_distribution.png","Figure 4.3-14. Fresh live pipeline latency distribution.")
    heading("Discussion and limitations",3); p("Isolation Forest needs threshold calibration. LSTM source isolation is measured, but controlled templates still repeat; external/template/campaign validation remains required. Rules-only and full-hybrid accuracy is unavailable from the saved arrays.")
    doc.core_properties.title="Verified Implementation and Results Material — Sections 3.2 and 4"; doc.core_properties.subject=f"Run {run_dir.name}"; doc.core_properties.author="Project evidence generator"
    doc.save(run_dir/"report_sections.docx")


def finalize(run_dir: Path) -> None:
    limitations="""# Limitations and Missing Evidence

- No college DOCX/PDF template or Phase 1 report was present in the supplied workspace; the requested Times New Roman academic formatting was applied directly.
- The active LSTM's 1.0000 legacy saved-holdout result is reproduced, but 791/816 test rows share a source hash with training, all 816 reuse a training service/event/path template, and the boundary timestamp is identical. It is not used as the primary generalization estimate.
- A three-seed source-IP-hash group-isolated LSTM audit achieved 0.9761 mean test accuracy (population SD 0.0035) and 0.9675 mean macro F1 (SD 0.0033), with zero source-group overlap in every run. The active checkpoint remained unchanged; the packaged seed-42 checkpoint is an unpromoted candidate.
- Source-group isolation does not eliminate every dependency: service/event/path templates still repeat across groups. External capture, template-isolated or campaign-isolated validation remains unavailable and is required before deployment claims.
- Rules-only and complete-hybrid aggregate accuracy are unsupported by the saved feature arrays because they omit the raw stateful causal stream. A substitute fusion formula was not invented.
- Isolation Forest is binary anomaly detection; its operating-point accuracy/F1 is not directly comparable to multiclass metrics and its score is not calibrated probability.
- No separate validation split exists in the active saved preprocessing artifacts. The separate robustness audit does use group-isolated validation partitions and best-validation-loss checkpoint selection.
- End-to-end database/network latency, queue backlog, sustained throughput, process-level CPU/RAM, calibration error and an external dataset were not measured. The LSTM audit reports repeated-seed mean, population standard deviation and range, but three seeds are not a formal confidence interval.
- External Telegram delivery was deliberately disabled; webhook or Telegram receipt is not claimed.
- SQLite samples are read-only and sanitized. Production logs, database, models, tokens and configuration were not packaged.
- `CURRENT_SYSTEM_WORKFLOW.md`, `SETUP.md`, and `website/README_MERN_SETUP.md` still describe authenticated analyst access, while the current Flask routes/templates and root README implement a login-free localhost defender dashboard. The report follows the executable code; the backend `users` table and authentication routes are treated as legacy compatibility surfaces.
- An intermediate evidence-harness attempt processed the logger's reverse-chronological display list and therefore failed the inference contract. The final run reads the isolated JSONL in append/chronological order; the failed attempt is retained in `logs/live_run_attempt_reverse_order_failure.json` and no production detection logic was changed.
- Only browser/application screenshots genuinely captured from the running UI may be called screenshots. Missing views are listed in the manual checklist below.
"""
    (run_dir/"limitations_and_missing_evidence.md").write_text(limitations,encoding="utf-8")
    checklist=[
      {"section":"3.2","item":"Implementation narrative, pseudocode, model and feature tables","status":"complete","evidence":"implementation_details.md; report_sections.docx"},
      {"section":"3.2.1","item":"Algorithm, methodology, techniques, pseudocode, model roles and feature order","status":"complete","evidence":"implementation_details.md; report_sections.docx; logs/inspection.json"},
      {"section":"3.2.2","item":"Use case, activity, context DFD, Level 1 DFD; editable + PNG/SVG","status":"complete","evidence":"diagrams/"},
      {"section":"3.2.3","item":"Measured hardware/software specifications","status":"complete","evidence":"environment.json"},
      {"section":"4","item":"Result and discussion introduction and evidence-scope separation","status":"complete","evidence":"results_and_discussion.md; report_sections.docx"},
      {"section":"4.1","item":"Dataset, DB schema/samples, sanitized inputs, prediction outputs","status":"complete","evidence":"tables/; samples/; predictions/"},
      {"section":"4.1","item":"System Monitor screenshot captured; deeper requested views","status":"partially_complete_manual_capture_pending","evidence":"screenshots/01_system_monitor.png; screenshots/manual_screenshot_checklist.csv"},
      {"section":"4.2","item":"Definitions/formulas and score directions","status":"complete","evidence":"results_and_discussion.md"},
      {"section":"4.3","item":"Fresh offline models, LSTM source-group audit, CSV-backed tables/graphs, SHAP, timing","status":"complete","evidence":"offline_evaluation/; lstm_robustness/; tables/; figures/"},
      {"section":"4.3","item":"Rules-only/full-hybrid comparable aggregate metrics","status":"unsupported","evidence":"limitations_and_missing_evidence.md"},
    ]; write_csv(run_dir/"section_completion_checklist.csv",checklist)
    shots=[
      {"screen":"System Monitor","action":"Captured automatically from the isolated Flask dashboard","evidence":"125 events, 59 threats, service/navigation counters and live feed","filename":"01_system_monitor.png","caption":"Genuine defender system monitor with isolated live telemetry."},
      {"screen":"Honeypot activity","action":"Open Honeypot section and filter SQL Injection/XSS","evidence":"Traceable event IDs and captured records","filename":"02_honeypot_filter.png","caption":"Filtered attacker activity."},
      {"screen":"IDS incident detail","action":"Open a processed attack result","evidence":"Prediction, components, confidence, threat level/score","filename":"03_ids_detail.png","caption":"Hybrid IDS result and component evidence."},
      {"screen":"XAI","action":"Open XAI panel for the same event","evidence":"SHAP status/features and human reason","filename":"04_xai_detail.png","caption":"Tree-SHAP-supported explanation."},
      {"screen":"Agents","action":"Open Agents section","evidence":"Fixed run order and six agent outputs","filename":"05_agents.png","caption":"Deterministic post-inference agent analysis."},
      {"screen":"Analyst feedback","action":"Submit a sanitized demo verdict","evidence":"Verdict, timestamp, severity override/audit","filename":"06_feedback.png","caption":"Analyst review record."},
      {"screen":"Simulated IPS","action":"Open IPS recommendation/action detail","evidence":"simulation mode, no firewall change, audit entry","filename":"07_simulated_ips.png","caption":"Simulation-only response recommendation."},
      {"screen":"Alert receipt","action":"Only after explicit authorization and configured Telegram","evidence":"Actual message and matching event ID; redact chat identity/token","filename":"08_alert_receipt.png","caption":"Externally received alert (pending; not claimed)."},
    ]; write_csv(run_dir/"screenshots"/"manual_screenshot_checklist.csv",shots)
    artifact_metadata=[
      {"artifact_id":"Table 3.2.1-1","artifact_type":"table","title":"Implemented model roles and configuration","data_source":"source inspection; training and preprocessing manifests","run_id":run_dir.name,"sample_count":"not applicable","units":"configuration","scope":"Verified from code"},
      {"artifact_id":"Table 3.2.1-2","artifact_type":"table","title":"Production feature order","data_source":"data/ml_ready/feature_names.json","run_id":run_dir.name,"sample_count":"23 encoded features","units":"features","scope":"Verified from code"},
      {"artifact_id":"Table 3.2.3-1","artifact_type":"table","title":"Measured evaluation environment","data_source":"environment.json","run_id":run_dir.name,"sample_count":"one host","units":"hardware/software versions","scope":"Verified from code"},
      {"artifact_id":"Table 4.1-1","artifact_type":"table","title":"Dataset summary","data_source":"tables/dataset_summary.csv","run_id":run_dir.name,"sample_count":"5,193 raw; 4,080 accepted","units":"events/rows","scope":"Verified from code"},
      {"artifact_id":"Table 4.1-2","artifact_type":"table","title":"Class distribution","data_source":"tables/class_distribution.csv","run_id":run_dir.name,"sample_count":"4,080 accepted","units":"rows","scope":"Verified from code"},
      {"artifact_id":"Table 4.1-3","artifact_type":"table","title":"Application database inventory","data_source":"samples/database_schema.json","run_id":run_dir.name,"sample_count":"six tables","units":"tables/rows","scope":"Verified from code"},
      {"artifact_id":"Table 4.1-4","artifact_type":"table","title":"Representative sanitized held-out inputs","data_source":"samples/sanitized_test_inputs.csv","run_id":run_dir.name,"sample_count":"representative subset","units":"events","scope":"Fresh offline measurement"},
      {"artifact_id":"Table 4.1-5","artifact_type":"table","title":"Traceable Decision Tree output samples","data_source":"predictions/decision_tree_predictions.csv","run_id":run_dir.name,"sample_count":"six displayed of 816","units":"predictions","scope":"Fresh offline measurement"},
      {"artifact_id":"Table 4.1-6","artifact_type":"table","title":"Fresh bounded localhost scenarios","data_source":"tables/live_scenarios.csv","run_id":run_dir.name,"sample_count":"four scenarios; 125 events","units":"events/predictions","scope":"Fresh live measurement"},
      {"artifact_id":"Table 4.3-1","artifact_type":"table","title":"Primary reported multiclass metrics by evaluation scope","data_source":"tables/primary_model_metrics.csv","run_id":run_dir.name,"sample_count":"tabular 816; LSTM audit 710/710/711","units":"rates","scope":"Explicitly labelled legacy tabular holdout and fresh LSTM robustness audit"},
      {"artifact_id":"Table 4.3-2","artifact_type":"table","title":"LSTM evaluation-scope comparison","data_source":"tables/lstm_evaluation_scope_summary.csv","run_id":run_dir.name,"sample_count":"legacy 816; audit 710/710/711","units":"rates","scope":"Legacy reproduction and fresh robustness audit"},
      {"artifact_id":"Table 4.3-3","artifact_type":"table","title":"Source-group-isolated LSTM seed-level results","data_source":"tables/lstm_group_isolated_runs.csv","run_id":run_dir.name,"sample_count":"three seeds; test 710/710/711","units":"rows/epochs/rates","scope":"Fresh robustness audit"},
      {"artifact_id":"Table 4.3-4","artifact_type":"table","title":"Binary attack-versus-normal metrics","data_source":"tables/binary_metrics.csv","run_id":run_dir.name,"sample_count":"816 per model","units":"rates/area","scope":"Fresh offline measurement"},
      {"artifact_id":"Table 4.3-5","artifact_type":"table","title":"CPU inference latency","data_source":"tables/model_latency.csv","run_id":run_dir.name,"sample_count":"816 per batch; 12 repetitions","units":"milliseconds","scope":"Fresh offline measurement"},
      {"artifact_id":"Figures 3.2.2-1 to 3.2.2-4","artifact_type":"diagram","title":"Use case, activity, context DFD and Level 1 DFD","data_source":"diagrams/*.puml; diagrams/*.mmd","run_id":run_dir.name,"sample_count":"not applicable","units":"architecture","scope":"Verified from code"},
      {"artifact_id":"Figure 4.1-1","artifact_type":"figure","title":"Accepted dataset class distribution","data_source":"tables/class_distribution.csv","run_id":run_dir.name,"sample_count":"4,080","units":"rows","scope":"Verified from code"},
      {"artifact_id":"Figure 4.1-2","artifact_type":"figure","title":"Chronological train/test distribution","data_source":"tables/class_distribution.csv; tables/dataset_summary.csv","run_id":run_dir.name,"sample_count":"4,080","units":"rows","scope":"Verified from code"},
      {"artifact_id":"Figure 4.1-3","artifact_type":"screenshot","title":"Flask defender system monitor","data_source":"screenshots/01_system_monitor.png; logs/live_run.json","run_id":run_dir.name,"sample_count":"125 events","units":"application state","scope":"Fresh live measurement"},
      {"artifact_id":"Figure 4.3-1","artifact_type":"figure","title":"Primary model metrics by evaluation scope","data_source":"tables/primary_model_metrics.csv","run_id":run_dir.name,"sample_count":"tabular 816; LSTM audit three seeds","units":"rates","scope":"Explicitly labelled mixed evaluation scopes"},
      {"artifact_id":"Figure 4.3-2","artifact_type":"figure","title":"LSTM legacy versus source-group-isolated audit","data_source":"tables/lstm_evaluation_scope_summary.csv; tables/lstm_group_isolated_runs.csv","run_id":run_dir.name,"sample_count":"legacy 816; audit three seeds","units":"rates","scope":"Legacy reproduction and fresh robustness audit"},
      {"artifact_id":"Figures 4.3-3 to 4.3-8","artifact_type":"figure","title":"Confusion matrices, per-class, FPR/FNR, ROC and PR","data_source":"confusion_raw.csv; confusion_normalized.csv; per_class_metrics.csv; binary_metrics.csv; curves.csv","run_id":run_dir.name,"sample_count":"816 per evaluated model","units":"counts/rates/area","scope":"Fresh offline measurement"},
      {"artifact_id":"Figure 4.3-9","artifact_type":"figure","title":"Local Decision Tree SHAP explanation","data_source":"tables/shap_example.csv","run_id":run_dir.name,"sample_count":"one held-out event","units":"SHAP contribution","scope":"Fresh offline measurement"},
      {"artifact_id":"Figure 4.3-10","artifact_type":"figure","title":"Global Decision Tree SHAP importance","data_source":"tables/shap_global.csv","run_id":run_dir.name,"sample_count":"first 256 held-out rows","units":"mean absolute SHAP","scope":"Fresh offline measurement"},
      {"artifact_id":"Figure 4.3-11","artifact_type":"figure","title":"CPU saved-model inference latency","data_source":"tables/model_latency.csv","run_id":run_dir.name,"sample_count":"816 per batch; 12 repetitions","units":"milliseconds","scope":"Fresh offline measurement"},
      {"artifact_id":"Figure 4.3-12","artifact_type":"figure","title":"Recorded legacy LSTM training history","data_source":"tables/lstm_training_history.csv; saved lstm_metrics.json","run_id":run_dir.name,"sample_count":"50 epochs","units":"loss/accuracy","scope":"Historical evidence"},
      {"artifact_id":"Figures 4.3-13 to 4.3-14","artifact_type":"figure","title":"Live event flow and pipeline latency distribution","data_source":"tables/live_timeline.csv; tables/live_latency.csv","run_id":run_dir.name,"sample_count":"125 processed events","units":"events per second/milliseconds","scope":"Fresh live measurement"},
    ]; write_csv(run_dir/"report_artifact_metadata.csv",artifact_metadata)
    # Evidence index is generated last, then refreshed after manifest.
    env=read_json(run_dir/"environment.json") if (run_dir/"environment.json").exists() else {}
    offline=read_json(run_dir/"logs"/"offline_run.json") if (run_dir/"logs"/"offline_run.json").exists() else {}
    live=read_json(run_dir/"logs"/"live_run.json") if (run_dir/"logs"/"live_run.json").exists() else {}
    evaluator=offline.get("verified_evaluator",{})
    data_contract=evaluator.get("data_contract",{})
    training=read_json(MODEL_DIR/"training_manifest.json")
    dataset_manifest=read_json(DATASET_MANIFEST)
    preprocessing=read_json(MODEL_ROOT/"preprocessing_manifest.json")
    lstm_robustness=read_json(run_dir/"lstm_robustness"/"aggregate_summary.json")
    manifest={
      "run_id":run_dir.name,
      "generated_at_utc":utc_now(),
      "timestamps":{"offline_generated_at_utc":offline.get("generated_at_utc"),"live_started_at_utc":live.get("started_at_utc"),"live_ended_at_utc":live.get("ended_at_utc")},
      "repository":{"branch":command_output(["git","branch","--show-current"]),"commit":command_output(["git","rev-parse","HEAD"]),"working_tree_state":command_output(["git","status","--short"]).splitlines()},
      "commands":{"inspect":f"{PYTHON} scripts/report_evidence.py inspect --run-dir {run_dir}","offline":f"{PYTHON} scripts/report_evidence.py offline --run-dir {run_dir}","live":f"{PYTHON} scripts/report_evidence.py live --run-dir {run_dir}","render":f"{PYTHON} scripts/report_evidence.py render --run-dir {run_dir}","all_offline":f"{PYTHON} scripts/report_evidence.py all-offline","lstm_audit_seed_42":f"{PYTHON} scripts/audit_lstm_generalization.py --seed 42","lstm_audit_seed_43":f"{PYTHON} scripts/audit_lstm_generalization.py --seed 43","lstm_audit_seed_44":f"{PYTHON} scripts/audit_lstm_generalization.py --seed 44"},
      "runtime_versions":{"python":env.get("python"),"node":env.get("node"),"npm":env.get("npm"),"packages":env.get("packages",{}),"browser":live.get("dashboard_screenshot",{}).get("method")},
      "dataset":{"path":str(DATASET_PATH.relative_to(ROOT)),"dataset_version":dataset_manifest.get("dataset_version"),"sha256":sha256(DATASET_PATH),"manifest_sha256":sha256(DATASET_MANIFEST),"raw_events":dataset_manifest.get("total_events"),"accepted_events":dataset_manifest.get("accepted_events"),"rejected_events":dataset_manifest.get("rejected_events"),"duplicate_events":dataset_manifest.get("duplicate_events")},
      "protected_artifact_hashes":evaluator.get("protected_artifact_hashes",{}),
      "split":{"strategy":preprocessing.get("split",{}).get("strategy"),"train_rows":data_contract.get("tabular_test_rows") and preprocessing.get("split",{}).get("train_rows"),"validation_rows":0,"test_rows":data_contract.get("tabular_test_rows"),"train_end_utc":preprocessing.get("split",{}).get("train_end_utc"),"test_start_utc":preprocessing.get("split",{}).get("test_start_utc"),"sequence_length":data_contract.get("sequence_length"),"preprocessor_fit_scope":data_contract.get("preprocessor_fit_scope")},
      "seeds":{"traditional_models_random_state":training.get("configuration",{}).get("random_state"),"active_lstm_random_state":"unverified in saved artifact; training script default is 42 but invocation is not recorded","lstm_robustness_audit":[42,43,44],"evaluation":"deterministic saved-artifact inference plus separately labelled audit fitting"},
      "evaluation_settings":{"kind":offline.get("evaluation_kind"),"test_rows":data_contract.get("tabular_test_rows"),"classes":data_contract.get("classes"),"encoded_features":data_contract.get("encoded_features"),"timing_warmup_runs":2,"timing_repetitions":12,"timing_batch_size":data_contract.get("tabular_test_rows"),"artifact_loading_included":False},
      "live_demo_settings":{"kind":live.get("kind"),"ports":live.get("ports"),"events_captured":live.get("events_captured"),"events_processed":live.get("events_processed"),"processing_failures":len(live.get("processing_failures",[])),"storage":live.get("storage"),"event_collector_enabled":live.get("event_collector_enabled"),"external_notifications_enabled":live.get("external_notifications_enabled"),"host_firewall_changed":live.get("host_firewall_changed")},
      "evidence_scope":{"offline":"fresh execution of protected saved models on the original held-out arrays","lstm_robustness":"three source-IP-hash group-isolated candidate fits with training-only preprocessing and validation-loss checkpointing","live":"bounded localhost services with isolated files","historical":"saved legacy LSTM training history and manifests"},
      "lstm_robustness":{"runs":lstm_robustness.get("runs"),"seeds":lstm_robustness.get("seeds"),"accuracy":lstm_robustness.get("accuracy"),"macro_f1":lstm_robustness.get("macro_f1"),"source_group_overlap":"zero in every run","legacy_source_overlap":"791/816 test rows (96.94%)","legacy_template_overlap":"816/816 test rows","candidate_bundle":"lstm_robustness/20260907_candidate_bundle_seed42","active_model_modified":False,"candidate_promoted":False},
      "model_fit_called":{"protected_saved_model_evaluation":False,"lstm_robustness_audit_candidates":True},
      "original_data_models_logs_database_modified":False
    }
    write_json(run_dir/"run_manifest.json",manifest)
    dataset_row=read_csv(run_dir/"tables"/"dataset_summary.csv")[0]
    metric_rows={row["model"]:row for row in read_csv(run_dir/"tables"/"model_metrics.csv")}
    prediction_checks={}
    for model in ("decision_tree","random_forest","lstm_classifier"):
        rows=read_csv(run_dir/"predictions"/f"{model}_predictions.csv")
        computed=sum(row["true_label"]==row["predicted_label"] for row in rows)/len(rows)
        reported=float(metric_rows[model]["accuracy"])
        prediction_checks[model]={"rows":len(rows),"computed_accuracy":computed,"reported_accuracy":reported,"matches":abs(computed-reported)<1e-12}
    confusion_totals={}
    for row in read_csv(run_dir/"tables"/"confusion_raw.csv"):
        confusion_totals[row["model"]]=confusion_totals.get(row["model"],0)+int(row["count"])
    support_totals={}
    for row in read_csv(run_dir/"tables"/"per_class_metrics.csv"):
        support_totals[row["model"]]=support_totals.get(row["model"],0)+int(float(row["support"]))
    binary_totals={row["model"]:sum(int(row[key]) for key in ("tn","fp","fn","tp")) for row in read_csv(run_dir/"tables"/"binary_metrics.csv")}
    live_scenarios=read_csv(run_dir/"tables"/"live_scenarios.csv") if (run_dir/"tables"/"live_scenarios.csv").exists() else []
    live_timeline=read_csv(run_dir/"tables"/"live_timeline.csv") if (run_dir/"tables"/"live_timeline.csv").exists() else []
    robust_rows=read_csv(run_dir/"tables"/"lstm_group_isolated_runs.csv")
    robust_summary=read_json(run_dir/"lstm_robustness"/"aggregate_summary.json")
    robust_audits=[read_json(path) for path in sorted((run_dir/"lstm_robustness").glob("20260907_group_isolated*/audit_results.json"))]
    robust_accuracy=[float(row["test_accuracy"]) for row in robust_rows]
    robust_macro_f1=[float(row["test_macro_f1"]) for row in robust_rows]
    robust_group_overlap_zero=all(audit["group_isolated_split"]["test"]["group_overlap"]==0 and audit["group_isolated_split"]["validation_within_outer_train"]["group_overlap"]==0 for audit in robust_audits)
    integrity={
      "generated_at_utc":utc_now(),
      "run_id":run_dir.name,
      "checks":{
        "dataset_raw_equals_accepted_plus_rejected":int(dataset_row["raw"])==int(dataset_row["accepted"])+int(dataset_row["rejected"]),
        "dataset_accepted_equals_train_plus_validation_plus_test":int(dataset_row["accepted"])==int(dataset_row["train"])+int(dataset_row["validation"])+int(dataset_row["test"]),
        "prediction_metrics_recomputed":prediction_checks,
        "confusion_matrix_totals":confusion_totals,
        "confusion_totals_equal_816":all(value==816 for value in confusion_totals.values()),
        "per_class_support_totals":support_totals,
        "per_class_support_totals_equal_816":all(value==816 for value in support_totals.values()),
        "binary_confusion_totals":binary_totals,
        "binary_totals_equal_816":all(value==816 for value in binary_totals.values()),
        "live_scenario_totals":{"captured":sum(int(row["events_captured"]) for row in live_scenarios),"processed":sum(int(row["events_processed"]) for row in live_scenarios)},
        "live_timeline_totals":{"captured":sum(int(row["captured"]) for row in live_timeline),"processed":sum(int(row["processed"]) for row in live_timeline)},
        "live_totals_match_manifest":bool(live_scenarios) and sum(int(row["events_captured"]) for row in live_scenarios)==live.get("events_captured") and sum(int(row["events_processed"]) for row in live_scenarios)==live.get("events_processed") and sum(int(row["captured"]) for row in live_timeline)==live.get("events_captured") and sum(int(row["processed"]) for row in live_timeline)==live.get("events_processed"),
        "lstm_robustness_three_runs":len(robust_rows)==3 and len(robust_audits)==3,
        "lstm_robustness_source_group_overlap_zero":robust_group_overlap_zero,
        "lstm_robustness_accuracy_mean_matches":abs(sum(robust_accuracy)/len(robust_accuracy)-float(robust_summary["accuracy"]["mean"]))<1e-12,
        "lstm_robustness_macro_f1_mean_matches":abs(sum(robust_macro_f1)/len(robust_macro_f1)-float(robust_summary["macro_f1"]["mean"]))<1e-12,
        "lstm_robustness_active_model_unchanged":all(audit.get("active_model_modified") is False for audit in robust_audits),
      }
    }
    integrity["all_passed"]=all([
      integrity["checks"]["dataset_raw_equals_accepted_plus_rejected"],
      integrity["checks"]["dataset_accepted_equals_train_plus_validation_plus_test"],
      all(item["matches"] and item["rows"]==816 for item in prediction_checks.values()),
      integrity["checks"]["confusion_totals_equal_816"],
      integrity["checks"]["per_class_support_totals_equal_816"],
      integrity["checks"]["binary_totals_equal_816"],
      integrity["checks"]["live_totals_match_manifest"],
      integrity["checks"]["lstm_robustness_three_runs"],
      integrity["checks"]["lstm_robustness_source_group_overlap_zero"],
      integrity["checks"]["lstm_robustness_accuracy_mean_matches"],
      integrity["checks"]["lstm_robustness_macro_f1_mean_matches"],
      integrity["checks"]["lstm_robustness_active_model_unchanged"],
    ])
    write_json(run_dir/"logs"/"integrity_checks.json",integrity)
    index=[]
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file() and p.name!="evidence_index.csv"):
        rel=path.relative_to(run_dir).as_posix(); status="generated_and_verified"
        evidence_label="Verified from code"; source="repository inspection and generated report evidence"
        if rel.startswith(("offline_evaluation/","predictions/","tables/","figures/")):
            evidence_label="Fresh offline measurement"; source="protected saved models and original held-out arrays"
        if rel.startswith(("tables/live_","figures/live_","samples/live_")) or rel in ("logs/live_run.json","screenshots/01_system_monitor.png"):
            evidence_label="Fresh live measurement"; source="bounded isolated localhost run"
        if "lstm_training_history" in rel:
            evidence_label="Historical evidence"; source="saved LSTM training artifact"
        if rel.startswith("lstm_robustness/") or "lstm_group_isolated" in rel or "lstm_evaluation_scope" in rel:
            evidence_label="Fresh robustness audit"; source="source-IP-hash group-isolated LSTM evaluation"
        if rel.endswith("manual_screenshot_checklist.csv"):
            evidence_label="Pending/unverified"; source="manual capture checklist"
        index.append({"claim_or_item":Path(rel).stem.replace("_"," "),"artifact":rel,"source":source,"evidence_label":evidence_label,"run_id":run_dir.name,"sha256":sha256(path),"bytes":path.stat().st_size,"status":status})
    write_csv(run_dir/"evidence_index.csv",index)
    readme=f"""# Verified report evidence

Latest run: `{run_dir.name}`

Commands (from repository root):

```powershell
& data/runtime/python312/python.exe scripts/report_evidence.py inspect --run-dir \"{run_dir}\"
& data/runtime/python312/python.exe scripts/report_evidence.py offline --run-dir \"{run_dir}\"
& data/runtime/python312/python.exe scripts/report_evidence.py live --run-dir \"{run_dir}\"
& data/runtime/python312/python.exe scripts/report_evidence.py render --run-dir \"{run_dir}\"
& data/runtime/python312/python.exe scripts/report_evidence.py all-offline
& data/runtime/python312/python.exe scripts/audit_lstm_generalization.py --seed 42
& data/runtime/python312/python.exe scripts/audit_lstm_generalization.py --seed 43
& data/runtime/python312/python.exe scripts/audit_lstm_generalization.py --seed 44
```

`offline` runs inference only and verifies protected hashes. The separate LSTM audit uses source-IP-hash group-isolated train/validation/test partitions, training-only preprocessing and best-validation-loss checkpoint selection; it does not promote the candidate. `live` uses alternate localhost ports, isolated run files, disabled backend delivery and disabled external notifications. `render` builds every chart from CSV, stages the LSTM audit evidence, generates editable/rendered diagrams, Markdown, DOCX, traceability files and a sanitized ZIP.
"""; (REPORT_ROOT/"README.md").write_text(readme,encoding="utf-8")
    zip_path=REPORT_ROOT/f"verified_report_evidence_{run_dir.name}.zip"
    with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        archive.write(REPORT_ROOT/"README.md",arcname="report_evidence/README.md")
        archive.write(ROOT/"scripts"/"report_evidence.py",arcname="scripts/report_evidence.py")
        archive.write(ROOT/"scripts"/"audit_lstm_generalization.py",arcname="scripts/audit_lstm_generalization.py")
        for path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
            # Exclude any unexpected secret-bearing files by name.
            lowered=path.name.lower()
            rel=path.relative_to(run_dir).as_posix()
            if (
                any(token in lowered for token in (".token","secret","credential","honeypot.db"))
                or rel=="samples/live_events.jsonl"
                or rel.startswith(("docx_render/","docx_render_final/","docx_render_qa/"))
            ):
                continue
            archive.write(path,arcname=f"report_evidence/runs/{run_dir.name}/{rel}")


def render_mode(run_dir: Path) -> None:
    stage_lstm_robustness(run_dir); render_figures(run_dir); render_diagrams(run_dir); impl,results=build_markdown(run_dir); build_docx(run_dir,impl,results); finalize(run_dir)


def main() -> None:
    if hasattr(sys.stdout,"reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8",errors="replace")
    if hasattr(sys.stderr,"reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8",errors="replace")
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter); parser.add_argument("mode",choices=("inspect","offline","live","render","all-offline","all")); parser.add_argument("--run-dir",type=str); args=parser.parse_args(); run_dir=resolve_run(args.run_dir)
    if args.mode in ("inspect","all-offline","all"): inspect_mode(run_dir)
    if args.mode in ("offline","all-offline","all"): offline_mode(run_dir)
    if args.mode in ("live","all"): live_mode(run_dir)
    if args.mode in ("render","all-offline","all"): render_mode(run_dir)
    print(json.dumps({"status":"complete","mode":args.mode,"run_dir":str(run_dir)},indent=2))


if __name__=="__main__": main()
