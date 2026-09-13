from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# ============================================================
# MODEL PERFORMANCE DATA
# These values come from your evaluate_models.py output
# ============================================================

models = [
    "Decision Tree",
    "Random Forest",
    "LSTM Classifier",
    "Isolation Forest"
]

accuracy = [
    0.9831,
    0.9789,
    0.9803,
    0.9913
]

macro_f1 = [
    0.9696,
    0.9669,
    0.9715,
    0.9804
]

normal_fpr = [
    0.0112,
    0.0000,
    0.0000,
    0.0000
]

median_ms = [
    0.5047,
    64.5733,
    23.8242,
    84.2869
]

# ============================================================
# OUTPUT DIRECTORY
# ============================================================

PROJECT_ROOT = Path(r"D:\honeypot_v2")
OUTPUT_DIR = PROJECT_ROOT / "data" / "ml_ready" / "evaluation" / "graphs"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print(f"[GRAPH] Output directory: {OUTPUT_DIR}")

# ============================================================
# 1. ACCURACY COMPARISON
# ============================================================

plt.figure(figsize=(10, 6))

bars = plt.bar(models, accuracy)

plt.title("Model Accuracy Comparison")
plt.ylabel("Accuracy")
plt.xlabel("Model")
plt.ylim(0.95, 1.0)

plt.grid(axis="y", linestyle="--", alpha=0.4)

for bar, value in zip(bars, accuracy):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.0005,
        f"{value:.4f}",
        ha="center",
        va="bottom"
    )

plt.tight_layout()

accuracy_path = OUTPUT_DIR / "accuracy_comparison.png"
plt.savefig(accuracy_path, dpi=300)
plt.close()

print(f"[GRAPH] Saved: {accuracy_path}")

# ============================================================
# 2. MACRO F1 SCORE COMPARISON
# ============================================================

plt.figure(figsize=(10, 6))

bars = plt.bar(models, macro_f1)

plt.title("Model Macro F1-Score Comparison")
plt.ylabel("Macro F1-Score")
plt.xlabel("Model")
plt.ylim(0.94, 1.0)

plt.grid(axis="y", linestyle="--", alpha=0.4)

for bar, value in zip(bars, macro_f1):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.0005,
        f"{value:.4f}",
        ha="center",
        va="bottom"
    )

plt.tight_layout()

f1_path = OUTPUT_DIR / "macro_f1_comparison.png"
plt.savefig(f1_path, dpi=300)
plt.close()

print(f"[GRAPH] Saved: {f1_path}")

# ============================================================
# 3. FALSE POSITIVE RATE COMPARISON
# ============================================================

plt.figure(figsize=(10, 6))

bars = plt.bar(models, normal_fpr)

plt.title("Normal Traffic False Positive Rate")
plt.ylabel("False Positive Rate")
plt.xlabel("Model")

plt.grid(axis="y", linestyle="--", alpha=0.4)

for bar, value in zip(bars, normal_fpr):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.0002,
        f"{value:.4f}",
        ha="center",
        va="bottom"
    )

plt.tight_layout()

fpr_path = OUTPUT_DIR / "false_positive_rate.png"
plt.savefig(fpr_path, dpi=300)
plt.close()

print(f"[GRAPH] Saved: {fpr_path}")

# ============================================================
# 4. MEDIAN INFERENCE TIME
# ============================================================

plt.figure(figsize=(10, 6))

bars = plt.bar(models, median_ms)

plt.title("Median Model Inference Time")
plt.ylabel("Median Inference Time (ms)")
plt.xlabel("Model")

plt.grid(axis="y", linestyle="--", alpha=0.4)

for bar, value in zip(bars, median_ms):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 1,
        f"{value:.2f} ms",
        ha="center",
        va="bottom"
    )

plt.tight_layout()

latency_path = OUTPUT_DIR / "inference_time.png"
plt.savefig(latency_path, dpi=300)
plt.close()

print(f"[GRAPH] Saved: {latency_path}")

# ============================================================
# 5. ACCURACY + F1 COMBINED GRAPH
# ============================================================

x = np.arange(len(models))
width = 0.35

plt.figure(figsize=(11, 6))

bars1 = plt.bar(
    x - width / 2,
    accuracy,
    width,
    label="Accuracy"
)

bars2 = plt.bar(
    x + width / 2,
    macro_f1,
    width,
    label="Macro F1"
)

plt.title("Accuracy and Macro F1-Score Comparison")
plt.ylabel("Score")
plt.xlabel("Model")
plt.xticks(x, models)
plt.ylim(0.94, 1.0)

plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.4)

for bars in [bars1, bars2]:
    for bar in bars:
        value = bar.get_height()

        plt.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.0004,
            f"{value:.4f}",
            ha="center",
            va="bottom",
            fontsize=9
        )

plt.tight_layout()

combined_path = OUTPUT_DIR / "accuracy_vs_f1.png"
plt.savefig(combined_path, dpi=300)
plt.close()

print(f"[GRAPH] Saved: {combined_path}")

# ============================================================
# 6. PERFORMANCE SUMMARY GRAPH
# ============================================================

# Normalize latency so it can be visually compared with
# accuracy/F1 without letting the large millisecond values
# dominate the graph.

latency_normalized = 1 - (
    np.array(median_ms) / max(median_ms)
)

x = np.arange(len(models))
width = 0.25

plt.figure(figsize=(12, 7))

plt.bar(
    x - width,
    accuracy,
    width,
    label="Accuracy"
)

plt.bar(
    x,
    macro_f1,
    width,
    label="Macro F1"
)

plt.bar(
    x + width,
    latency_normalized,
    width,
    label="Latency Score"
)

plt.title("Overall Model Performance Comparison")
plt.ylabel("Performance Score")
plt.xlabel("Model")
plt.xticks(x, models)
plt.ylim(0.0, 1.05)

plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.4)

plt.tight_layout()

summary_path = OUTPUT_DIR / "overall_performance.png"
plt.savefig(summary_path, dpi=300)
plt.close()

print(f"[GRAPH] Saved: {summary_path}")

# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n==============================================")
print("GRAPH GENERATION COMPLETE")
print("==============================================")

print(f"Accuracy graph      : {accuracy_path}")
print(f"Macro F1 graph      : {f1_path}")
print(f"False positive graph: {fpr_path}")
print(f"Inference time graph: {latency_path}")
print(f"Accuracy vs F1      : {combined_path}")
print(f"Overall performance : {summary_path}")

print("\nBest accuracy:")
best_accuracy_idx = np.argmax(accuracy)
print(
    f"  {models[best_accuracy_idx]} "
    f"({accuracy[best_accuracy_idx]:.4f})"
)

print("\nBest Macro F1:")
best_f1_idx = np.argmax(macro_f1)
print(
    f"  {models[best_f1_idx]} "
    f"({macro_f1[best_f1_idx]:.4f})"
)

print("\nFastest inference:")
fastest_idx = np.argmin(median_ms)
print(
    f"  {models[fastest_idx]} "
    f"({median_ms[fastest_idx]:.4f} ms)"
)

print("==============================================")