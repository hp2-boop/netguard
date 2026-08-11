"""
ml/train_model.py

Trains an IsolationForest anomaly detector on NORMAL IoT traffic only
(unsupervised novelty detection -- the standard approach for anomaly
detection, since attack traffic is rare/unlabeled in the real world).

Run:
    python3 -m ml.train_model

Produces:
    models/isolation_forest.joblib
    models/scaler.joblib
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from traffic.synthetic_generator import generate_training_dataset
from traffic.feature_extraction import extract_features, features_to_vector

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


def build_training_matrix(n_windows: int = 400, window_seconds: float = 10.0):
    dataset = generate_training_dataset(n_windows=n_windows, window_seconds=window_seconds)
    rows = []
    for entry in dataset:
        features = extract_features(entry["packets"], entry["window_seconds"])
        rows.append(features_to_vector(features))
    return np.array(rows)


def train_and_save(n_windows: int = 400):
    print(f"[train_model] Generating {n_windows} synthetic normal-traffic windows...")
    X = build_training_matrix(n_windows=n_windows)
    print(f"[train_model] Training matrix shape: {X.shape}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,   # assume ~5% of "normal" windows might be borderline/noisy
        random_state=42,
    )
    model.fit(X_scaled)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, "isolation_forest.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    print(f"[train_model] Saved model + scaler to {MODEL_DIR}/")

    return model, scaler


if __name__ == "__main__":
    train_and_save()
