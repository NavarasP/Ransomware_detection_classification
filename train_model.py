"""Train a RandomForest ransomware detector and persist artifacts.

This script downloads the Kaggle dataset, cleans columns to match the
expected feature order, trains a RandomForest model, reports metrics, and
writes the trained model + metadata under `artifacts/`.

Usage (from repo root):
    python train_model.py

Note: Kaggle API credentials must be available for `kagglehub` to fetch
`amdj3dax/ransomware-detection-data-set`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import kagglehub
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from feature_extractor import FEATURE_COLUMNS

# Silence Pylance unknown-member/var noise from third-party stubs
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

ARTIFACT_DIR = Path("artifacts")
MODEL_PATH = ARTIFACT_DIR / "random_forest_model.joblib"
META_PATH = ARTIFACT_DIR / "feature_metadata.json"
DATASET_ID = "amdj3dax/ransomware-detection-data-set"


def _find_csv(download_dir: Path) -> Path:
    candidates = list(download_dir.rglob("data_file.csv"))
    if not candidates:
        candidates = list(download_dir.rglob("*.csv"))
    if not candidates:
        raise FileNotFoundError("Could not locate a CSV in the downloaded dataset")
    return candidates[0]


def load_dataset() -> pd.DataFrame:
    """Download and return the cleaned dataset as a DataFrame."""
    download_path = Path(kagglehub.dataset_download(DATASET_ID))
    csv_path = _find_csv(download_path)
    df = pd.read_csv(csv_path)

    # Drop non-feature identifiers if present
    df = df.drop(columns=[c for c in ["FileName", "md5Hash"] if c in df.columns], errors="ignore")

    if "Benign" not in df.columns:
        raise ValueError("Label column 'Benign' not found in dataset")

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing expected feature columns: {missing}")

    # Restrict and coerce types
    df = df[FEATURE_COLUMNS + ["Benign"]]
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df["Benign"] = pd.to_numeric(df["Benign"], errors="coerce").fillna(0).astype(int)
    return df


def split_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    X = df[FEATURE_COLUMNS]
    y = df["Benign"]
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=42,
    )
    return X_train, X_test, y_train, y_test


def train_model(X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=64,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def evaluate(model: RandomForestClassifier, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    report = classification_report(y_test, preds, output_dict=True, zero_division=0)
    return {"accuracy": acc, "classification_report": report}


def cross_validate(model: RandomForestClassifier, X: pd.DataFrame, y: pd.Series) -> float:
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    return float(np.mean(scores))


def persist_artifacts(model: RandomForestClassifier, meta: Dict[str, Any]) -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    META_PATH.write_text(json.dumps(meta, indent=2))


def main() -> None:
    print("Downloading and loading dataset via kagglehub...")
    df = load_dataset()
    print(f"Loaded dataset with shape {df.shape}")

    X_train, X_test, y_train, y_test = split_data(df)
    model = train_model(X_train, y_train)

    print("Running 5-fold CV on full data (accuracy)...")
    cv_acc = cross_validate(model, df[FEATURE_COLUMNS], df["Benign"])
    print(f"CV accuracy (mean): {cv_acc:.4f}")

    print("Evaluating on hold-out set...")
    test_metrics = evaluate(model, X_test, y_test)
    print(f"Test accuracy: {test_metrics['accuracy']:.4f}")

    meta = {
        "feature_columns": FEATURE_COLUMNS,
        "label": "Benign",
        "cv_accuracy": cv_acc,
        "test_accuracy": test_metrics["accuracy"],
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "model_type": "RandomForestClassifier",
        "model_params": {
            "n_estimators": 64,
            "random_state": 42,
            "class_weight": "balanced",
        },
    }

    persist_artifacts(model, meta)
    print(f"Artifacts saved to {ARTIFACT_DIR.resolve()}")
    print("Done.")


if __name__ == "__main__":
    main()
