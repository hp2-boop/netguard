"""
ml/detector.py

Loads the trained IsolationForest + scaler and exposes a simple
score_window() function: takes raw packets for one device/window, returns
an anomaly score (0-1, higher = more anomalous) and a boolean is_anomaly.
"""

import os
import joblib
import numpy as np

from traffic.feature_extraction import extract_features, features_to_vector

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")


class AnomalyDetector:
    def __init__(self):
        if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)):
            raise FileNotFoundError(
                "Model not found. Run `python3 -m ml.train_model` first to train and save it."
            )
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)

    def score_window(self, packets: list, window_seconds: float, known_destinations: set = None):
        features = extract_features(packets, window_seconds, known_destinations)
        vector = np.array([features_to_vector(features)])
        vector_scaled = self.scaler.transform(vector)

        # decision_function: higher = more normal, lower/negative = more anomalous.
        raw_score = self.model.decision_function(vector_scaled)[0]
        prediction = self.model.predict(vector_scaled)[0]  # 1 = normal, -1 = anomaly

        # Normalize raw_score (~ -0.5 to 0.5 typically) into a 0-1 "anomaly score"
        # where higher = more anomalous, clipped for readability in reports.
        anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))

        return {
            "features": features,
            "anomaly_score": round(anomaly_score, 3),
            "is_anomaly": bool(prediction == -1),
        }
