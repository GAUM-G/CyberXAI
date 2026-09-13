# lstmevaluation.py
#
# LSTM training evaluation
# Creates:
#   1. LSTM accuracy vs epoch
#   2. LSTM F1 score vs epoch
#   3. LSTM accuracy + F1 combined graph
#
# Output:
# D:\honeypot_v2\data\ml_ready\evaluation\lstm_graphs\

import os
import random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, f1_score

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import Callback


# ============================================================
# SETTINGS
# ============================================================

PROJECT_ROOT = r"D:\honeypot_v2"

DATA_DIR = os.path.join(
    PROJECT_ROOT,
    "data"
)

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "data",
    "ml_ready",
    "evaluation",
    "lstm_graphs"
)

EPOCHS = 20
BATCH_SIZE = 32
TEST_SIZE = 0.20
RANDOM_STATE = 42


# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# REPRODUCIBILITY
# ============================================================

random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)
tf.random.set_seed(RANDOM_STATE)


# ============================================================
# FIND DATASET
# ============================================================

def find_dataset():

    csv_files = []

    for root, dirs, files in os.walk(DATA_DIR):

        # Ignore generated/evaluation folders
        dirs[:] = [
            d for d in dirs
            if d not in ["evaluation", "graphs", "lstm_graphs"]
        ]

        for file in files:

            if file.lower().endswith(".csv"):

                path = os.path.join(root, file)

                # Ignore evaluation results
                if "evaluation" not in path.lower():
                    csv_files.append(path)

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV dataset found inside:\n{DATA_DIR}\n\n"
            "Please place your dataset CSV inside the data folder."
        )

    # Prefer common dataset names
    preferred_names = [
        "dataset.csv",
        "ml_dataset.csv",
        "training_data.csv",
        "train.csv",
        "data.csv"
    ]

    for preferred in preferred_names:

        for path in csv_files:

            if os.path.basename(path).lower() == preferred:
                return path

    # Otherwise use largest CSV
    csv_files.sort(
        key=lambda x: os.path.getsize(x),
        reverse=True
    )

    return csv_files[0]


# ============================================================
# FIND TARGET COLUMN
# ============================================================

def find_target_column(df):

    possible_targets = [
        "label",
        "target",
        "class",
        "attack_type",
        "attack",
        "category",
        "y"
    ]

    lower_columns = {
        column.lower(): column
        for column in df.columns
    }

    for target in possible_targets:

        if target in lower_columns:
            return lower_columns[target]

    # Try columns containing useful words
    for column in df.columns:

        name = column.lower()

        if any(
            word in name
            for word in [
                "label",
                "target",
                "class",
                "attack"
            ]
        ):
            return column

    # Last resort: use last column
    print(
        "[WARNING] Target column was not detected."
    )

    print(
        f"[WARNING] Using last column: {df.columns[-1]}"
    )

    return df.columns[-1]


# ============================================================
# F1 CALLBACK
# ============================================================

class F1Callback(Callback):

    def __init__(self, X_val, y_val):

        super().__init__()

        self.X_val = X_val
        self.y_val = y_val

        self.f1_scores = []

    def on_epoch_end(self, epoch, logs=None):

        predictions = self.model.predict(
            self.X_val,
            verbose=0
        )

        predictions = np.argmax(
            predictions,
            axis=1
        )

        f1 = f1_score(
            self.y_val,
            predictions,
            average="macro",
            zero_division=0
        )

        self.f1_scores.append(f1)

        print(
            f" - val_macro_f1: {f1:.4f}"
        )


# ============================================================
# LOAD DATA
# ============================================================

print()
print("=" * 60)
print("LSTM EVALUATION")
print("=" * 60)

dataset_path = find_dataset()

print()
print(f"[DATA] Dataset: {dataset_path}")

df = pd.read_csv(dataset_path)

print(
    f"[DATA] Rows: {len(df)}"
)

print(
    f"[DATA] Columns: {len(df.columns)}"
)


# ============================================================
# CLEAN DATA
# ============================================================

df = df.replace(
    [np.inf, -np.inf],
    np.nan
)

df = df.dropna()

print(
    f"[DATA] Rows after cleaning: {len(df)}"
)


# ============================================================
# TARGET
# ============================================================

target_column = find_target_column(df)

print(
    f"[DATA] Target column: {target_column}"
)

y_raw = df[target_column]

X = df.drop(
    columns=[target_column]
)


# ============================================================
# KEEP NUMERIC FEATURES
# ============================================================

numeric_columns = X.select_dtypes(
    include=[np.number]
).columns

X = X[numeric_columns]

if X.shape[1] == 0:

    raise ValueError(
        "No numeric feature columns were found."
    )

print(
    f"[DATA] Numeric features: {X.shape[1]}"
)


# ============================================================
# ENCODE TARGET
# ============================================================

label_encoder = LabelEncoder()

y = label_encoder.fit_transform(
    y_raw.astype(str)
)

num_classes = len(
    label_encoder.classes_
)

print(
    f"[DATA] Classes: {num_classes}"
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)


# ============================================================
# SCALE FEATURES
# ============================================================

scaler = StandardScaler()

X_train = scaler.fit_transform(
    X_train
)

X_test = scaler.transform(
    X_test
)


# ============================================================
# LSTM INPUT SHAPE
#
# LSTM expects:
# samples, timesteps, features
#
# We treat each row as one timestep.
# ============================================================

X_train = X_train.reshape(
    X_train.shape[0],
    1,
    X_train.shape[1]
)

X_test = X_test.reshape(
    X_test.shape[0],
    1,
    X_test.shape[1]
)


print(
    f"[DATA] Training samples: {X_train.shape[0]}"
)

print(
    f"[DATA] Testing samples: {X_test.shape[0]}"
)

print(
    f"[DATA] LSTM input shape: {X_train.shape[1:]}"
)


# ============================================================
# BUILD LSTM
# ============================================================

model = Sequential([

    LSTM(
        64,
        input_shape=(
            X_train.shape[1],
            X_train.shape[2]
        ),
        return_sequences=False
    ),

    Dropout(0.30),

    Dense(
        32,
        activation="relu"
    ),

    Dropout(0.20),

    Dense(
        num_classes,
        activation="softmax"
    )
])


model.compile(
    optimizer="adam",
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)


print()
print("[MODEL] LSTM model created")
print()


# ============================================================
# F1 CALLBACK
# ============================================================

f1_callback = F1Callback(
    X_test,
    y_test
)


# ============================================================
# TRAIN
# ============================================================

history = model.fit(

    X_train,
    y_train,

    validation_data=(
        X_test,
        y_test
    ),

    epochs=EPOCHS,

    batch_size=BATCH_SIZE,

    callbacks=[
        f1_callback
    ],

    verbose=1
)


# ============================================================
# FINAL TEST PREDICTION
# ============================================================

predictions = model.predict(
    X_test,
    verbose=0
)

predictions = np.argmax(
    predictions,
    axis=1
)


# ============================================================
# FINAL METRICS
# ============================================================

test_accuracy = accuracy_score(
    y_test,
    predictions
)

test_f1 = f1_score(
    y_test,
    predictions,
    average="macro",
    zero_division=0
)


print()
print("=" * 60)
print("FINAL LSTM RESULTS")
print("=" * 60)

print(
    f"Test Accuracy : {test_accuracy:.4f}"
)

print(
    f"Test Macro F1 : {test_f1:.4f}"
)

print("=" * 60)


# ============================================================
# SAVE TRAINING HISTORY
# ============================================================

results = pd.DataFrame({

    "epoch": range(
        1,
        EPOCHS + 1
    ),

    "training_accuracy":
        history.history["accuracy"],

    "validation_accuracy":
        history.history["val_accuracy"],

    "training_loss":
        history.history["loss"],

    "validation_loss":
        history.history["val_loss"],

    "validation_macro_f1":
        f1_callback.f1_scores
})


history_file = os.path.join(
    OUTPUT_DIR,
    "lstm_training_history.csv"
)

results.to_csv(
    history_file,
    index=False
)


# ============================================================
# GRAPH 1
# ACCURACY
# ============================================================

plt.figure(
    figsize=(10, 6)
)

plt.plot(
    results["epoch"],
    results["training_accuracy"],
    marker="o",
    label="Training Accuracy"
)

plt.plot(
    results["epoch"],
    results["validation_accuracy"],
    marker="o",
    label="Validation Accuracy"
)

plt.xlabel(
    "Epoch"
)

plt.ylabel(
    "Accuracy"
)

plt.title(
    "LSTM Training and Validation Accuracy"
)

plt.legend()

plt.grid(
    True,
    alpha=0.3
)

plt.tight_layout()

accuracy_graph = os.path.join(
    OUTPUT_DIR,
    "lstm_accuracy_vs_epoch.png"
)

plt.savefig(
    accuracy_graph,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# GRAPH 2
# F1 SCORE
# ============================================================

plt.figure(
    figsize=(10, 6)
)

plt.plot(
    results["epoch"],
    results["validation_macro_f1"],
    marker="o",
    label="Validation Macro F1"
)

plt.xlabel(
    "Epoch"
)

plt.ylabel(
    "Macro F1"
)

plt.title(
    "LSTM Macro F1 Score During Training"
)

plt.legend()

plt.grid(
    True,
    alpha=0.3
)

plt.tight_layout()

f1_graph = os.path.join(
    OUTPUT_DIR,
    "lstm_f1_vs_epoch.png"
)

plt.savefig(
    f1_graph,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# GRAPH 3
# ACCURACY + F1
# ============================================================

plt.figure(
    figsize=(10, 6)
)

plt.plot(
    results["epoch"],
    results["validation_accuracy"],
    marker="o",
    label="Validation Accuracy"
)

plt.plot(
    results["epoch"],
    results["validation_macro_f1"],
    marker="o",
    label="Validation Macro F1"
)

plt.xlabel(
    "Epoch"
)

plt.ylabel(
    "Score"
)

plt.title(
    "LSTM Accuracy and F1 Score During Training"
)

plt.legend()

plt.grid(
    True,
    alpha=0.3
)

plt.tight_layout()

combined_graph = os.path.join(
    OUTPUT_DIR,
    "lstm_accuracy_f1_vs_epoch.png"
)

plt.savefig(
    combined_graph,
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# SAVE MODEL
# ============================================================

model_file = os.path.join(
    OUTPUT_DIR,
    "lstm_evaluation_model.keras"
)

model.save(
    model_file
)


# ============================================================
# FINISHED
# ============================================================

print()
print("=" * 60)
print("FILES CREATED")
print("=" * 60)

print(
    f"Accuracy graph : {accuracy_graph}"
)

print(
    f"F1 graph       : {f1_graph}"
)

print(
    f"Combined graph : {combined_graph}"
)

print(
    f"History CSV    : {history_file}"
)

print(
    f"Model          : {model_file}"
)

print("=" * 60)