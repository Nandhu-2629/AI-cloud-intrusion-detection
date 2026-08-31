import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier


# Training data
# Features:
# [network_traffic, failed_logins, port_activity]

X = np.array([
    [500, 0, 0],
    [700, 1, 1],
    [900, 0, 1],
    [1100, 2, 1],
    [1200, 1, 2],

    [1300, 4, 3],
    [1400, 5, 4],
    [1500, 4, 5],
    [1550, 6, 4],
    [1600, 5, 6],

    [1700, 8, 7],
    [1750, 9, 8],
    [1800, 10, 9],
    [1900, 9, 10],
    [2000, 10, 10]
])


# Labels
# 0 = Normal
# 1 = Suspicious
# 2 = Malicious

y = np.array([
    0, 0, 0, 0, 0,
    1, 1, 1, 1, 1,
    2, 2, 2, 2, 2
])


# Create Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train the model
model.fit(X, y)


# Save trained model
joblib.dump(model, "intrusion_model.pkl")

print("ML model trained successfully!")
print("Model saved as intrusion_model.pkl")