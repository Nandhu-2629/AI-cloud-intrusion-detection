from flask import Flask, jsonify, send_from_directory, render_template_string
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

    return psycopg2.connect(database_url)


# ==================================================
# INITIALIZE DATABASE
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

@app.route("/scan")
def scan():

    traffic = random.randint(1000, 2000)

    failed_logins = random.randint(0, 10)

    port_activity = random.randint(0, 10)


    # AI prediction

    result = detect_intrusion(
        traffic,
        failed_logins,
        port_activity
    )


    # Determine attack

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


    # ==================================================
    # SAVE RESULT TO POSTGRESQL
    # ==================================================

    database_status = "Database save failed"

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO scan_results
            (
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
            VALUES
            (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
        """, (

            traffic,

            failed_logins,

            port_activity,

            attack,

            result["prediction"],

            result["risk"],

            result["confidence"],

            result["accuracy"],

            result["precision"],

            result["recall"],

            result["f1"],

            action
        ))


        connection.commit()

        database_status = "Saved to PostgreSQL"

        print("Scan result saved successfully!")


    except Exception as error:

        print("DATABASE INSERT ERROR:", error)

        if connection:
            connection.rollback()


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


    # ==================================================
    # RETURN SCAN RESULT
    # ==================================================

    return jsonify({

        "traffic": traffic,

        "failed_logins": failed_logins,

        "port_activity": port_activity,

        "threats":
            1 if result["prediction"] != "Normal" else 0,

        "attack": attack,

        "prediction": result["prediction"],

        "risk": result["risk"],

        "confidence": result["confidence"],

        "accuracy": result["accuracy"],

        "precision": result["precision"],

        "recall": result["recall"],

        "f1": result["f1"],

        "action": action,

        "database": database_status
    })


# ==================================================
# HISTORY API
# ==================================================

@app.route("/api/history")
def api_history():

    connection = None
    cursor = None

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

        print("HISTORY ERROR:", error)

        return jsonify({
            "error": str(error)
        }), 500


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ==================================================
# HISTORY WEB PAGE
# ==================================================

@app.route("/history")
def history():

    connection = None
    cursor = None

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


        return render_template_string("""

        <!DOCTYPE html>

        <html>

        <head>

            <title>Cloud IDS - Scan History</title>

            <style>

                body {
                    background: #071426;
                    color: white;
                    font-family: Arial, sans-serif;
                    padding: 30px;
                }

                h1 {
                    text-align: center;
                    color: #2196f3;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 30px;
                    background: #0d2038;
                }

                th, td {
                    padding: 12px;
                    border: 1px solid #23496d;
                    text-align: center;
                }

                th {
                    background: #12365c;
                    color: #4db8ff;
                }

                tr:hover {
                    background: #142d4b;
                }

                .high {
                    color: #ff4444;
                    font-weight: bold;
                }

                .medium {
                    color: #ffc107;
                    font-weight: bold;
                }

                .low {
                    color: #00ff88;
                    font-weight: bold;
                }

                .back {
                    display: block;
                    width: 180px;
                    margin: 25px auto;
                    padding: 12px;
                    background: #2196f3;
                    color: white;
                    text-align: center;
                    text-decoration: none;
                    border-radius: 6px;
                }

            </style>

        </head>


        <body>

            <h1>Cloud Intrusion Detection - Scan History</h1>

            <a class="back" href="/">
                ← Back to Dashboard
            </a>


            <table>

                <tr>

                    <th>ID</th>

                    <th>Traffic</th>

                    <th>Failed Logins</th>

                    <th>Port Activity</th>

                    <th>Attack</th>

                    <th>Prediction</th>

                    <th>Risk</th>

                    <th>Confidence</th>

                    <th>Time</th>

                </tr>


                {% for row in rows %}

                <tr>

                    <td>{{ row[0] }}</td>

                    <td>{{ row[1] }}</td>

                    <td>{{ row[2] }}</td>

                    <td>{{ row[3] }}</td>

                    <td>{{ row[4] }}</td>

                    <td>{{ row[5] }}</td>

                    <td class="{{ row[6]|lower }}">
                        {{ row[6] }}
                    </td>

                    <td>{{ row[7] }}%</td>

                    <td>{{ row[8] }}</td>

                </tr>

                {% endfor %}


            </table>


            {% if not rows %}

                <p style="text-align:center;">
                    No scan records available yet.
                </p>

            {% endif %}

        </body>

        </html>

        """, rows=rows)


    except Exception as error:

        print("HISTORY PAGE ERROR:", error)

        return f"""
        <h2>Database Error</h2>
        <p>{error}</p>
        """


    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    try:

        initialize_database()

    except Exception as error:

        print(
            "Database initialization error:",
            error
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
