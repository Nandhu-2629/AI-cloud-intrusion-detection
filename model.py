import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


MODEL_FILE = "intrusion_model.pkl"


# NSL-KDD column names
columns = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack", "difficulty"
]


def train_model():

    print("Loading NSL-KDD dataset...")

    data = pd.read_csv(
        "KDDTrain+.txt",
        names=columns
    )

    # Convert attack labels into three categories
    def classify_attack(attack):

        if attack == "normal":
            return "Normal"

        elif attack in [
            "neptune", "smurf", "pod", "teardrop",
            "back", "land", "apache2", "udpstorm",
            "processtable", "mailbomb"
        ]:
            return "Malicious"

        else:
            return "Suspicious"


    data["label"] = data["attack"].apply(classify_attack)


    # Select useful numerical network features
    features = [
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "num_failed_logins",
        "num_compromised",
        "serror_rate",
        "rerror_rate",
        "same_srv_rate"
    ]


    X = data[features]
    y = data["label"]


    # Convert labels to numbers
    encoder = LabelEncoder()

    y = encoder.fit_transform(y)


    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )


    # Random Forest ML model
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )


    print("Training Random Forest model...")

    model.fit(X_train, y_train)


    # Test model
    predictions = model.predict(X_test)


    # Calculate actual performance
    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )


    # Save model and encoder
    joblib.dump(
        {
            "model": model,
            "encoder": encoder,
            "features": features
        },
        MODEL_FILE
    )


    print("Model trained successfully!")

    print("Accuracy:", round(accuracy * 100, 2), "%")
    print("Precision:", round(precision * 100, 2), "%")
    print("Recall:", round(recall * 100, 2), "%")
    print("F1 Score:", round(f1 * 100, 2), "%")


return model, encoder, features, accuracy, precision, recall, f1

# Train model when application starts
model, encoder, features, accuracy, precision, recall, f1 = train_model()

def detect_intrusion(
    traffic,
    failed_logins,
    port_activity
):

    # Convert dashboard inputs into model features
    sample = pd.DataFrame([{

        "src_bytes": traffic,

        "dst_bytes": traffic // 2,

        "count": traffic // 100,

        "srv_count": traffic // 120,

        "num_failed_logins": failed_logins,

        "num_compromised": port_activity,

        "serror_rate": port_activity / 10,

        "rerror_rate": failed_logins / 10,

        "same_srv_rate": 1 - (port_activity / 20)

    }])


    prediction = model.predict(sample)[0]

    probabilities = model.predict_proba(sample)[0]

    confidence = round(
        max(probabilities) * 100,
        2
    )


    prediction_label = encoder.inverse_transform(
        [prediction]
    )[0]


       if prediction_label == "Malicious":
        risk = "HIGH"

    elif prediction_label == "Suspicious":
        risk = "MEDIUM"

    else:
        risk = "LOW"

    return {
        "prediction": prediction_label,
        "risk": risk,
        "confidence": confidence,
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2)
    }
