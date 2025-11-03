# detection/ml_detector.py

import joblib
import numpy as np
import os
import re
import pandas as pd
# Load trained model
model_path = os.path.join("models", "anomaly_model.pkl")
if os.path.exists(model_path):
    model = joblib.load(model_path)
else:
    model = None
    print("[ML Detector] Warning: Model not found.")

def extract_features(packet_size, protocol):
    return pd.DataFrame([{"packet_size": packet_size, "protocol": protocol}])

def is_anomalous(packet_size, protocol):
    if model is None:
        return False
    features = extract_features(packet_size, protocol)
    prediction = model.predict(features)
    return prediction[0] == -1  # Isolation Forest: -1 = anomaly

# Payload-based signature matching using known malicious patterns
known_signatures = [
    re.compile(rb"malicious"),              # Generic keyword
    re.compile(rb"\x90\x90\x90"),           # NOP sled (buffer overflow)
    re.compile(rb"DROP\s+TABLE", re.IGNORECASE),  # SQL Injection
    re.compile(rb"<script>.*?</script>", re.IGNORECASE),  # XSS pattern
]

def match_signature(payload_bytes):
    for signature in known_signatures:
        if signature.search(payload_bytes):
            return True
    return False
