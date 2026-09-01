from flask import Flask, jsonify, send_from_directory
import random
import os
import psycopg2

from model import detect_intrusion


app = Flask(__name__, static_folder=".")


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():

    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise Exception("DATABASE_URL is not configured")

    if "sslmode=" not in database_url:
        database_url += "?sslmode=require"

    return psycopg2.connect(database_url)


# ==================================================
# CREATE DATABASE TABLE
# ==================================================

def initialize_database():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (

            id SERIAL PRIMARY KEY,

            traffic INTEGER,

            failed_logins INTEGER,

            port_activity INTEGER,

            attack VARCHAR(100),

            prediction VARCHAR(50),

            risk VARCHAR(20),

            confidence FLOAT,

            accuracy FLOAT,

            precision_score FLOAT,

            recall FLOAT,

            f1_score FLOAT,

            action TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    connection.commit()

    cursor.close()
    connection.close()

    print("PostgreSQL database initialized successfully!")


# ==================================================
# HOME PAGE
# ==================================================

@app.route("/")
def home():

    return send_from_directory(
        ".",
        "index.html"
    )


# ==================================================
# CSS
# ==================================================

@app.route("/style.css")
def style():

    return send_from_directory(
        ".",
        "style.css"
    )


# ==================================================
# AI SECURITY SCAN
# ==================================================

# AI SECURITY SCAN
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

    # Convert ML values to normal Python floats
    confidence = float(result["confidence"])
    accuracy = float(result["accuracy"])
    precision = float(result["precision"])
    recall = float(result["recall"])
    f1 = float(result["f1"])

    # SAVE RESULT TO POSTGRESQL
    database_status = "Database save failed"

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        sql = """
            INSERT INTO scan_results (
                traffic,
                failed_logins,
                port_activity,
                attack,
                prediction,
                risk,
                confidence,
                accuracy,
                precision_score,
                recall,
                f1_score,
                action
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """

        values = (
            int(traffic),
            int(failed_logins),
            int(port_activity),
            str(attack),
            str(result["prediction"]),
            str(result["risk"]),
            confidence,
            accuracy,
            precision,
            recall,
            f1,
            str(action)
        )

        cursor.execute(sql, values)

        connection.commit()

        cursor.close()
        connection.close()

        database_status = "Saved to PostgreSQL"

        print("SCAN RESULT SAVED SUCCESSFULLY")

    except Exception as error:

        print("DATABASE ERROR:", repr(error))

        database_status = "Database save failed: " + str(error)

    # SEND RESULT TO DASHBOARD
    return jsonify({

        "traffic": traffic,

        "failed_logins": failed_logins,

        "port_activity": port_activity,

        "threats": (
            1 if result["prediction"] != "Normal" else 0
        ),

        "attack": attack,

        "prediction": result["prediction"],

        "risk": result["risk"],

        "confidence": confidence,

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1,

        "action": action,

        "database": database_status

    })

# ==================================================
# VIEW SCAN HISTORY
# ==================================================

@app.route("/history")
def history():

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                traffic,
                failed_logins,
                port_activity,
                attack,
                prediction,
                risk,
                confidence,
                created_at

            FROM scan_results

            ORDER BY created_at DESC

            LIMIT 20
        """)

        rows = cursor.fetchall()

        cursor.close()

        connection.close()


        results = []


        for row in rows:

            results.append({

                "id": row[0],

                "traffic": row[1],

                "failed_logins": row[2],

                "port_activity": row[3],

                "attack": row[4],

                "prediction": row[5],

                "risk": row[6],

                "confidence": row[7],

                "created_at": str(row[8])

            })


        return jsonify(results)


    except Exception as error:

        print(
            "HISTORY DATABASE ERROR:",
            repr(error)
        )

        return jsonify({

            "error": str(error)

        }), 500


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    try:

        initialize_database()

    except Exception as error:

        print(
            "Database initialization error:",
            repr(error)
        )


    port = int(
        os.environ.get(
            "PORT",
            7860
        )
    )


    app.run(

        host="0.0.0.0",

        port=port

    )
