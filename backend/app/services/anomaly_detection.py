
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for authentication activity.

    The initial model uses synthetic normal-behaviour data.
    It is a demonstration baseline, not a production-trained model.
    """

    MODEL_VERSION = "sentinel-isolation-forest-v1"

    FEATURE_NAMES = [
        "failed_logins_10m",
        "total_events_10m",
        "unique_usernames_10m",
        "failure_ratio",
        "events_per_minute",
    ]

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
        )
        self.is_trained = False

    def train(self):
        """Train using generated examples of normal login behaviour."""

        rng = np.random.default_rng(42)
        sample_count = 2000

        total_events = rng.poisson(
            lam=3,
            size=sample_count
        )

        failed_logins = np.array([
            rng.binomial(int(total), 0.15)
            for total in total_events
        ])

        unique_usernames = np.array([
            rng.integers(1, max(2, int(total) + 1))
            if total > 0 else 0
            for total in total_events
        ])

        failure_ratio = np.divide(
            failed_logins,
            total_events,
            out=np.zeros(sample_count, dtype=float),
            where=total_events != 0,
        )

        events_per_minute = total_events / 10.0

        training_data = np.column_stack([
            failed_logins,
            total_events,
            unique_usernames,
            failure_ratio,
            events_per_minute,
        ])

        self.model.fit(training_data)
        self.is_trained = True

    def analyze(self, metrics: dict) -> dict:
        """Analyse login activity and return an anomaly assessment."""

        if not self.is_trained:
            self.train()

        failed = max(0, int(metrics.get("failed_logins_10m", 0)))
        total = max(0, int(metrics.get("total_events_10m", 0)))
        usernames = max(0, int(metrics.get("unique_usernames_10m", 0)))

        if total == 0:
            failure_ratio = 0.0
        else:
            failure_ratio = min(1.0, failed / total)

        events_per_minute = total / 10.0

        features = np.array([[
            failed,
            total,
            usernames,
            failure_ratio,
            events_per_minute,
        ]])

        prediction = int(self.model.predict(features)[0])
        decision_value = float(
            self.model.decision_function(features)[0]
        )

        is_anomaly = prediction == -1

        # This is an illustrative risk score, not a probability.
        anomaly_score = -decision_value
        risk_score = int(
            max(0, min(100, round(50 + anomaly_score * 100)))
        )

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "risk_score": risk_score,
            "detection_method": "ISOLATION_FOREST",
            "model_version": self.MODEL_VERSION,
            "features": {
                "failed_logins_10m": failed,
                "total_events_10m": total,
                "unique_usernames_10m": usernames,
                "failure_ratio": round(failure_ratio, 3),
                "events_per_minute": round(events_per_minute, 3),
            },
        }


# Shared detector instance
anomaly_detector = AnomalyDetector()
