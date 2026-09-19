import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)


MODEL_FILE = "intrusion_model.pkl"


# ==================================================
# NSL-KDD COLUMN NAMES
# ==================================================

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


# ==================================================
# TRAIN MODEL
# ==================================================

def train_model():

    print("Loading NSL-KDD dataset...")

    dataset_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "KDDTrain+.txt"
    )

    print("Dataset path:", dataset_path)

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            "KDDTrain+.txt not found!"
        )

    data = pd.read_csv(
        dataset_path,
        names=columns,
        header=None
    )

    print("Dataset shape:", data.shape)

    if data.empty:
        raise ValueError(
            "KDDTrain+.txt was found but contains no data."
        )


    # ==================================================
    # CLASSIFY ATTACKS
    # ==================================================

    def classify_attack(attack):

        if attack == "normal":

            return "Normal"

        elif attack in [
            "neptune",
            "smurf",
            "pod",
            "teardrop",
            "back",
            "land",
            "apache2",
            "udpstorm",
            "processtable",
            "mailbomb"
        ]:

            return "Malicious"

        else:

            return "Suspicious"


    data["label"] = data["attack"].apply(
        classify_attack
    )


    # ==================================================
    # FEATURES USED BY RANDOM FOREST
    # ==================================================

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


    # ==================================================
    # ENCODE LABELS
    # ==================================================

    encoder = LabelEncoder()

    y = encoder.fit_transform(y)


    # ==================================================
    # TRAIN / TEST SPLIT
    # ==================================================

    X_train, X_test, y_train, y_test = train_test_split(

        X,
        y,

        test_size=0.20,

        random_state=42,

        stratify=y
    )


    # ==================================================
    # RANDOM FOREST
    # ==================================================

    model = RandomForestClassifier(

        n_estimators=100,

        random_state=42,

        n_jobs=-1
    )


    print(
        "Training Random Forest model..."
    )


    model.fit(
        X_train,
        y_train
    )


    # ==================================================
    # MODEL EVALUATION
    # ==================================================

    predictions = model.predict(
        X_test
    )


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


    # ==================================================
    # SAVE MODEL
    # ==================================================

    joblib.dump(

        {
            "model": model,
            "encoder": encoder,
            "features": features
        },
        MODEL_FILE
    )


    print(
        "Model trained successfully!"
    )

    print(
        "Accuracy:",
        round(accuracy * 100, 2),
        "%"
    )

    print(
        "Precision:",
        round(precision * 100, 2),
        "%"
    )

    print(
        "Recall:",
        round(recall * 100, 2),
        "%"
    )

    print(
        "F1 Score:",
        round(f1 * 100, 2),
        "%"
    )


    return (

        model,
        encoder,
        features,

        accuracy,
        precision,
        recall,
        f1

    )


# ==================================================
# TRAIN MODEL WHEN APPLICATION STARTS
# ==================================================

(
    model,
    encoder,
    features,
    accuracy,
    precision,
    recall,
    f1

) = train_model()


# ==================================================
# INTRUSION DETECTION
# ==================================================

def detect_intrusion(

    src_bytes,
    dst_bytes,
    count,
    srv_count,
    num_failed_logins,
    num_compromised,
    serror_rate,
    rerror_rate,
    same_srv_rate

):

    # ==================================================
    # CREATE SAMPLE USING REAL FEATURES
    # ==================================================

    sample = pd.DataFrame([{

        "src_bytes": src_bytes,

        "dst_bytes": dst_bytes,

        "count": count,

        "srv_count": srv_count,

        "num_failed_logins": num_failed_logins,

        "num_compromised": num_compromised,

        "serror_rate": serror_rate,

        "rerror_rate": rerror_rate,

        "same_srv_rate": same_srv_rate

    }])


    # ==================================================
    # RANDOM FOREST PREDICTION
    # ==================================================

    prediction = model.predict(
        sample
    )[0]


    # ==================================================
    # MODEL PROBABILITY
    # ==================================================

    probabilities = model.predict_proba(
        sample
    )[0]


    model_confidence = round(

        max(probabilities) * 100,

        2

    )


    # ==================================================
    # CONVERT ML LABEL
    # ==================================================

    prediction_label = encoder.inverse_transform(

        [prediction]

    )[0]


    # ==================================================
    # STRONG REAL-TIME SECURITY INDICATORS
    # ==================================================

    strong_suspicious_activity = False

    detection_reason = "Random Forest classification"


    # --------------------------------------------------
    # BRUTE FORCE INDICATOR
    # --------------------------------------------------

    if num_failed_logins >= 7:

        strong_suspicious_activity = True

        detection_reason = (
            "Multiple failed login attempts detected"
        )


    # --------------------------------------------------
    # PORT / RESOURCE SCANNING INDICATOR
    # --------------------------------------------------

    elif num_compromised >= 7:

        strong_suspicious_activity = True

        detection_reason = (
            "High suspicious port/resource activity detected"
        )


    # --------------------------------------------------
    # HIGH REQUEST RATE INDICATOR
    # --------------------------------------------------

    elif count >= 100:

        strong_suspicious_activity = True

        detection_reason = (
            "Abnormally high request activity detected"
        )


    # ==================================================
    # HYBRID SECURITY DECISION
    # ==================================================

    # If Random Forest says Normal but the live
    # application shows a strong attack indicator,
    # do not allow the final security classification
    # to remain Normal.

    if (

        prediction_label == "Normal"

        and strong_suspicious_activity

    ):

        prediction_label = "Suspicious"


    # ==================================================
    # RISK LEVEL
    # ==================================================

    if prediction_label == "Malicious":

        risk = "HIGH"

    elif prediction_label == "Suspicious":

        risk = "MEDIUM"

    else:

        risk = "LOW"


    # ==================================================
    # FINAL CONFIDENCE
    # ==================================================

    confidence = model_confidence


    # ==================================================
    # RETURN RESULT
    # ==================================================

    return {

        "prediction": prediction_label,

        "risk": risk,

        "confidence": confidence,

        "accuracy": round(
            accuracy * 100,
            2
        ),

        "precision": round(
            precision * 100,
            2
        ),

        "recall": round(
            recall * 100,
            2
        ),

        "f1": round(
            f1 * 100,
            2
        ),

        "detection_reason": detection_reason

    }
