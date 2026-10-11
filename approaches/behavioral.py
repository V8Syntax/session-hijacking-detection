import time
import numpy as np
from sklearn.ensemble import IsolationForest

class BehavioralDetector:
    def __init__(self):
        self.model = self._train_baseline()

    def _train_baseline(self):
        # Generate baseline normal human browsing behavior
        # Normal interaction: inter-arrival interval 2.0s - 5.0s, payload 200 - 500 bytes
        np.random.seed(42)
        normal_deltas = np.random.normal(loc=3.5, scale=0.7, size=(300, 1))
        normal_payloads = np.random.normal(loc=350, scale=40, size=(300, 1))
        x_train = np.hstack([normal_deltas, normal_payloads])

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(x_train)
        return model

    def evaluate(self, delta_t: float, payload_size: int):
        start_time = time.perf_counter()

        sample = np.array([[delta_t, payload_size]])
        prediction = self.model.predict(sample)[0]  # 1 = normal, -1 = anomaly
        raw_score = self.model.score_samples(sample)[0]

        # Normalize decision function score into a 0.0 - 1.0 risk percentage
        risk_score = float(np.clip(1.0 - (raw_score + 0.6) / 0.5, 0.0, 1.0))
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        is_anomaly = (risk_score >= 0.65) or (prediction == -1)

        indicators = []
        if delta_t < 0.5:
            indicators.append("Unnaturally rapid request rate (Automated Replay / Bot Script)")
        elif delta_t > 7.0:
            indicators.append("Atypical session dwell time delay")

        if payload_size > 800 or payload_size < 100:
            indicators.append("Payload size deviates significantly from standard interaction baseline")

        return {
            "status": "ANOMALY DETECTED" if is_anomaly else "NORMAL PATTERN",
            "is_anomaly": is_anomaly,
            "risk_score_pct": risk_score * 100,
            "indicators": indicators,
            "latency_ms": latency_ms,
            "action": "Trigger Step-Up MFA / Re-Auth" if is_anomaly else "Allow Request"
        }