from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(r"D:\honeypot_v2")

DATA_DIR = PROJECT_ROOT / "data"

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "ml_ready"
    / "evaluation"
    / "graphs"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

# Evaluate after every N training samples.
#
# 1  = every single data point, VERY SLOW
# 10 = every 10 data points
# 20 = every 20 data points
#
# Recommended:
EVALUATE_EVERY = 20


# ============================================================
# FIND DATASET
# ============================================================

print("==============================================")
print("MODEL TRAINING DATA-POINT CURVES")
print("==============================================")

csv_files = list(DATA_DIR.rglob("*.csv"))

if not csv_files:
    raise FileNotFoundError(
        f"No CSV files found inside:\n{DATA_DIR}"
    )


print("\nAvailable CSV files:\n")

for i, file in enumerate(csv_files, start=1):
    print(f"[{i}] {file}")


# Prefer ML-related datasets

preferred = []

for file in csv_files:

    name = file.name.lower()

    if any(
        word in name
        for word in [
            "dataset",
            "train",
            "processed",
            "feature",
            "ml_ready"
        ]
    ):
        preferred.append(file)


if len(preferred) > 0:

    # Choose largest preferred CSV
    DATA_FILE = max(
        preferred,
        key=lambda x: x.stat().st_size
    )

else:

    DATA_FILE = max(
        csv_files,
        key=lambda x: x.stat().st_size
    )


print("\n[INFO] Dataset selected:")
print(DATA_FILE)


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(DATA_FILE)

print(
    f"\n[INFO] Rows: {len(df)}"
)

print(
    f"[INFO] Columns: {len(df.columns)}"
)


# ============================================================
# FIND TARGET COLUMN
# ============================================================

possible_targets = [
    "label",
    "target",
    "class",
    "attack_type",
    "attack",
    "category",
    "y"
]

target_column = None

for column in possible_targets:

    if column in df.columns:

        target_column = column
        break


if target_column is None:

    # Look for low-cardinality columns

    candidates = []

    for column in df.columns:

        unique = df[column].nunique()

        if unique <= 20:

            candidates.append(
                (column, unique)
            )

    if not candidates:

        raise ValueError(
            "Could not identify target column."
        )

    print("\nPossible target columns:")

    for column, count in candidates:

        print(
            f"  {column}: {count} classes"
        )

    target_column = candidates[-1][0]


print(
    f"\n[INFO] Target column: {target_column}"
)


# ============================================================
# PREPARE X AND Y
# ============================================================

X = df.drop(
    columns=[target_column]
)

y = df[target_column]


# Only numeric features

X = X.select_dtypes(
    include=[np.number]
)


X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0)


print(
    f"[INFO] Features: {X.shape[1]}"
)

print(
    f"[INFO] Classes: {y.nunique()}"
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y
)


# Reset indexes

X_train = X_train.reset_index(drop=True)
y_train = y_train.reset_index(drop=True)

X_test = X_test.reset_index(drop=True)
y_test = y_test.reset_index(drop=True)


# ============================================================
# SHUFFLE TRAINING DATA
# ============================================================

rng = np.random.RandomState(
    RANDOM_STATE
)

order = rng.permutation(
    len(X_train)
)

X_train = X_train.iloc[
    order
].reset_index(drop=True)

y_train = y_train.iloc[
    order
].reset_index(drop=True)


print(
    f"\n[INFO] Training samples: {len(X_train)}"
)

print(
    f"[INFO] Testing samples: {len(X_test)}"
)


# ============================================================
# DATA POINTS
# ============================================================

# Start with enough samples to contain
# all classes.

min_samples = max(
    50,
    y_train.nunique() * 10
)

data_points = list(
    range(
        min_samples,
        len(X_train) + 1,
        EVALUATE_EVERY
    )
)

# Always include final training point

if data_points[-1] != len(X_train):

    data_points.append(
        len(X_train)
    )


print(
    f"\n[INFO] Evaluation points:"
    f" {len(data_points)}"
)

print(
    f"[INFO] Evaluating every:"
    f" {EVALUATE_EVERY} samples"
)


# ============================================================
# RESULTS
# ============================================================

results = {

    "Decision Tree": {
        "samples": [],
        "accuracy": [],
        "f1": []
    },

    "Random Forest": {
        "samples": [],
        "accuracy": [],
        "f1": []
    },

    "Isolation Forest": {
        "samples": [],
        "accuracy": [],
        "f1": []
    }
}


# ============================================================
# DECISION TREE
# ============================================================

print("\n==============================================")
print("DECISION TREE")
print("==============================================")


for n in data_points:

    print(
        f"[Decision Tree] "
        f"Training samples: {n}"
    )

    X_current = X_train.iloc[:n]
    y_current = y_train.iloc[:n]

    model = DecisionTreeClassifier(
        random_state=RANDOM_STATE
    )

    model.fit(
        X_current,
        y_current
    )

    predictions = model.predict(
        X_test
    )

    acc = accuracy_score(
        y_test,
        predictions
    )

    f1 = f1_score(
        y_test,
        predictions,
        average="macro"
    )

    results[
        "Decision Tree"
    ]["samples"].append(n)

    results[
        "Decision Tree"
    ]["accuracy"].append(acc)

    results[
        "Decision Tree"
    ]["f1"].append(f1)


# ============================================================
# RANDOM FOREST
# ============================================================

print("\n==============================================")
print("RANDOM FOREST")
print("==============================================")


for n in data_points:

    print(
        f"[Random Forest] "
        f"Training samples: {n}"
    )

    X_current = X_train.iloc[:n]
    y_current = y_train.iloc[:n]

    model = RandomForestClassifier(
        n_estimators=50,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    model.fit(
        X_current,
        y_current
    )

    predictions = model.predict(
        X_test
    )

    acc = accuracy_score(
        y_test,
        predictions
    )

    f1 = f1_score(
        y_test,
        predictions,
        average="macro"
    )

    results[
        "Random Forest"
    ]["samples"].append(n)

    results[
        "Random Forest"
    ]["accuracy"].append(acc)

    results[
        "Random Forest"
    ]["f1"].append(f1)


# ============================================================
# ISOLATION FOREST
# ============================================================

print("\n==============================================")
print("ISOLATION FOREST")
print("==============================================")


normal_candidates = [
    "normal",
    "Normal",
    "NORMAL",
    "benign",
    "Benign",
    "BENIGN"
]

normal_class = None

for candidate in normal_candidates:

    if candidate in y.unique():

        normal_class = candidate
        break


if normal_class is None:

    print(
        "[WARNING] Could not identify normal class."
    )

    print(
        "[WARNING] Isolation Forest skipped."
    )

else:

    for n in data_points:

        print(
            f"[Isolation Forest] "
            f"Training samples: {n}"
        )

        X_current = X_train.iloc[:n]

        model = IsolationForest(
            n_estimators=50,
            random_state=RANDOM_STATE,
            contamination="auto",
            n_jobs=-1
        )

        model.fit(
            X_current
        )

        raw_predictions = model.predict(
            X_test
        )

        predictions = np.where(
            raw_predictions == 1,
            normal_class,
            "anomaly"
        )

        y_test_binary = np.where(
            y_test == normal_class,
            normal_class,
            "anomaly"
        )

        acc = accuracy_score(
            y_test_binary,
            predictions
        )

        f1 = f1_score(
            y_test_binary,
            predictions,
            average="macro"
        )

        results[
            "Isolation Forest"
        ]["samples"].append(n)

        results[
            "Isolation Forest"
        ]["accuracy"].append(acc)

        results[
            "Isolation Forest"
        ]["f1"].append(f1)


# ============================================================
# SAVE NUMERIC RESULTS
# ============================================================

rows = []

for model_name in results:

    for i in range(
        len(results[model_name]["samples"])
    ):

        rows.append({

            "model":
                model_name,

            "training_samples":
                results[model_name]["samples"][i],

            "accuracy":
                results[model_name]["accuracy"][i],

            "f1":
                results[model_name]["f1"][i]
        })


results_df = pd.DataFrame(
    rows
)


csv_path = (
    OUTPUT_DIR
    / "training_data_point_results.csv"
)

results_df.to_csv(
    csv_path,
    index=False
)


# ============================================================
# GRAPH 1
# ACCURACY VS NUMBER OF DATA POINTS
# ============================================================

plt.figure(
    figsize=(14, 8)
)

for model_name in results:

    samples = results[
        model_name
    ]["samples"]

    accuracy = results[
        model_name
    ]["accuracy"]

    if len(samples) == 0:
        continue

    plt.plot(
        samples,
        accuracy,
        linewidth=2,
        label=model_name
    )


plt.title(
    "Model Accuracy During Training",
    fontsize=17,
    fontweight="bold"
)

plt.xlabel(
    "Number of Training Data Points"
)

plt.ylabel(
    "Accuracy"
)

plt.ylim(
    0,
    1.05
)

plt.grid(
    True,
    linestyle="--",
    alpha=0.5
)

plt.legend()

plt.tight_layout()


accuracy_path = (
    OUTPUT_DIR
    / "accuracy_vs_training_data_points.png"
)

plt.savefig(
    accuracy_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# GRAPH 2
# F1 VS NUMBER OF DATA POINTS
# ============================================================

plt.figure(
    figsize=(14, 8)
)

for model_name in results:

    samples = results[
        model_name
    ]["samples"]

    f1 = results[
        model_name
    ]["f1"]

    if len(samples) == 0:
        continue

    plt.plot(
        samples,
        f1,
        linewidth=2,
        label=model_name
    )


plt.title(
    "Model F1 Score During Training",
    fontsize=17,
    fontweight="bold"
)

plt.xlabel(
    "Number of Training Data Points"
)

plt.ylabel(
    "Macro F1 Score"
)

plt.ylim(
    0,
    1.05
)

plt.grid(
    True,
    linestyle="--",
    alpha=0.5
)

plt.legend()

plt.tight_layout()


f1_path = (
    OUTPUT_DIR
    / "f1_vs_training_data_points.png"
)

plt.savefig(
    f1_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# GRAPH 3
# ACCURACY + F1 FOR ALL MODELS
# ============================================================

for model_name in results:

    samples = results[
        model_name
    ]["samples"]

    accuracy = results[
        model_name
    ]["accuracy"]

    f1 = results[
        model_name
    ]["f1"]

    if len(samples) == 0:
        continue

    plt.figure(
        figsize=(14, 8)
    )

    plt.plot(
        samples,
        accuracy,
        linewidth=2,
        label="Accuracy"
    )

    plt.plot(
        samples,
        f1,
        linewidth=2,
        label="F1 Score"
    )

    plt.title(
        f"{model_name} Training Performance",
        fontsize=17,
        fontweight="bold"
    )

    plt.xlabel(
        "Number of Training Data Points"
    )

    plt.ylabel(
        "Performance Score"
    )

    plt.ylim(
        0,
        1.05
    )

    plt.grid(
        True,
        linestyle="--",
        alpha=0.5
    )

    plt.legend()

    plt.tight_layout()

    filename = (
        model_name
        .lower()
        .replace(" ", "_")
        + "_data_point_curve.png"
    )

    path = (
        OUTPUT_DIR
        / filename
    )

    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


# ============================================================
# FINISHED
# ============================================================

print("\n==============================================")
print("TRAINING DATA-POINT GRAPHS COMPLETE")
print("==============================================")

print("\nDataset:")
print(DATA_FILE)

print("\nGraphs:")

print(
    accuracy_path
)

print(
    f1_path
)

print("\nResults:")
print(
    csv_path
)

print("\n==============================================")