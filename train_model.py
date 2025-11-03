# train_model.py

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

# Load or generate dummy training data (you can replace with real stats)
X_train = pd.DataFrame([
    {"packet_size": 66, "protocol": 6},
    {"packet_size": 77, "protocol": 6},
    {"packet_size": 101, "protocol": 6},
    {"packet_size": 302, "protocol": 6},
    {"packet_size": 150, "protocol": 17},
    {"packet_size": 200, "protocol": 17},
    {"packet_size": 90, "protocol": 1},
])

# Train Isolation Forest with correct feature names
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)

# Save model
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/anomaly_model.pkl")

print("✅ Anomaly detection model trained and saved to models/anomaly_model.pkl")