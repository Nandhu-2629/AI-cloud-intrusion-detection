from flask import Flask, jsonify, send_from_directory
import random
import os

from model import detect_intrusion


app = Flask(__name__, static_folder=".")


@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/scan")
def scan():

    # Simulated cloud network data
    traffic = random.randint(1000, 2000)
    failed_logins = random.randint(0, 10)
    port_activity = random.randint(0, 10)


    # AI / ML prediction
    result = detect_intrusion(
        traffic,
        failed_logins,
        port_activity
    )


    # Determine attack type
    if failed_logins >= 7:

        attack = "Brute Force Attack"

    elif port_activity >= 7:

        attack = "Port Scanning"

    elif traffic >= 1700:

        attack = "DDoS Traffic"

    elif result["prediction"] == "Suspicious":

        attack = "Suspicious Network Activity"

    else:

        attack = "Normal Network Activity"


    # Security response
    if result["risk"] == "HIGH":

        action = (
            "Block suspicious traffic and investigate "
            "affected cloud resources."
        )

    elif result["risk"] == "MEDIUM":

        action = (
            "Monitor suspicious activity and review "
            "cloud security logs."
        )

    else:

        action = (
            "Continue monitoring the cloud environment."
        )


    return jsonify({

    "traffic": traffic,

    "threats": (
        1 if result["prediction"] != "Normal" else 0
    ),

    "attack": attack,

    "prediction": result["prediction"],

    "risk": result["risk"],

    "confidence": result["confidence"],

    "accuracy": result["accuracy"],

    "precision": result["precision"],

    "recall": result["recall"],

    "f1": result["f1"],

    "action": action

})


if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 7860)
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
    