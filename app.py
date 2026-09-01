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

@app.route("/scan")
def scan():

    # Simulated cloud network data

    traffic = random.randint(
        1000,
        2000
    )

    failed_logins = random.randint(
        0,
        10
    )

    port_activity = random.randint(
        0,
        10
    )


    # AI / ML prediction

    result = detect_intrusion(
        traffic,
        failed_logins,
        port_activity
    )


    # ==================================================
    # DETERMINE ATTACK TYPE
    # ==================================================

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


    # ==================================================
    # SECURITY RESPONSE
    # ==================================================

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
    # CONVERT ML VALUES TO PYTHON FLOAT
    # ==================================================

    confidence = float(result["confidence"])
    accuracy = float(result["accuracy"])
    precision = float(result["precision"])
    recall = float(result["recall"])
    f1 = float(result["f1"])


    # ==================================================
    # SAVE RESULT TO POSTGRESQL
    # ==================================================

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

                %s,

                %s,

                %s,

                %s,

                %s,

                %s,

                %s,

                %s,

                %s,

                %s,

                %s,

                %s

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


        cursor.execute(
            sql,
            values
        )


        connection.commit()


        cursor.close()

        connection.close()


        database_status = "Saved to PostgreSQL"


        print(
            "SCAN RESULT SAVED SUCCESSFULLY"
        )


    except Exception as error:

        print(
            "DATABASE ERROR:",
            repr(error)
        )

        database_status = (
            "Database save failed: "
            + str(error)
        )


    # ==================================================
    # SEND RESULT
    # ==================================================

    return jsonify({

        "traffic": traffic,

        "failed_logins": failed_logins,

        "port_activity": port_activity,

        "threats": (
            1
            if result["prediction"] != "Normal"
            else 0
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
# SCAN HISTORY
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


        # ------------------------------------------
        # CREATE TABLE ROWS
        # ------------------------------------------

        table_rows = ""


        for row in rows:

            risk_class = str(
                row[6]
            ).lower()


            table_rows += f"""
            <tr>

                <td>{row[0]}</td>

                <td>{row[1]}</td>

                <td>{row[2]}</td>

                <td>{row[3]}</td>

                <td>{row[4]}</td>

                <td>{row[5]}</td>

                <td class="risk-{risk_class}">
                    {row[6]}
                </td>

                <td>{float(row[7]):.2f}%</td>

                <td>{row[8]}</td>

            </tr>
            """


        # ------------------------------------------
        # IF NO RECORDS
        # ------------------------------------------

        if not rows:

            table_rows = """
            <tr>

                <td colspan="9">
                    No scan records available yet.
                </td>

            </tr>
            """


        # ------------------------------------------
        # HISTORY PAGE
        # ------------------------------------------

        html = f"""
        <!DOCTYPE html>

        <html lang="en">

        <head>

            <meta charset="UTF-8">

            <meta
                name="viewport"
                content="width=device-width,
                initial-scale=1.0"
            >

            <title>
                Cloud Intrusion Detection - Scan History
            </title>


            <style>

                * {{
                    box-sizing: border-box;
                }}


                body {{

                    margin: 0;

                    padding: 30px;

                    background: #061426;

                    color: #ffffff;

                    font-family:
                        Arial,
                        Helvetica,
                        sans-serif;

                }}


                .container {{

                    max-width: 1400px;

                    margin: auto;

                }}


                h1 {{

                    text-align: center;

                    color: #2495ff;

                    margin-bottom: 25px;

                }}


                .back-button {{

                    display: block;

                    width: fit-content;

                    margin: 0 auto 30px auto;

                    padding: 12px 24px;

                    background: #2495ff;

                    color: white;

                    text-decoration: none;

                    border-radius: 7px;

                    font-weight: bold;

                }}


                .back-button:hover {{

                    background: #147ddd;

                }}


                .table-container {{

                    width: 100%;

                    overflow-x: auto;

                    background: #0c1d33;

                    border: 1px solid #24527a;

                    border-radius: 10px;

                    padding: 10px;

                }}


                table {{

                    width: 100%;

                    border-collapse: collapse;

                    min-width: 1050px;

                }}


                th {{

                    background: #12375d;

                    color: #38a1ff;

                    padding: 15px 12px;

                    border: 1px solid #24527a;

                    text-align: center;

                    white-space: nowrap;

                }}


                td {{

                    padding: 13px 12px;

                    border: 1px solid #1d3d5d;

                    text-align: center;

                    white-space: nowrap;

                }}


                tr:nth-child(even) {{

                    background: #0a192b;

                }}


                tr:hover {{

                    background: #102b47;

                }}


                .risk-high {{

                    color: #ff5252;

                    font-weight: bold;

                }}


                .risk-medium {{

                    color: #ffc107;

                    font-weight: bold;

                }}


                .risk-low {{

                    color: #35e58a;

                    font-weight: bold;

                }}


                .empty {{

                    padding: 30px;

                    text-align: center;

                }}

            </style>

        </head>


        <body>

            <div class="container">

                <h1>
                    Cloud Intrusion Detection - Scan History
                </h1>


                <a
                    href="/"
                    class="back-button"
                >
                    ← Back to Dashboard
                </a>


                <div class="table-container">

                    <table>

                        <thead>

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

                        </thead>


                        <tbody>

                            {table_rows}

                        </tbody>

                    </table>

                </div>

            </div>

        </body>

        </html>
        """


        return html


    except Exception as error:

        print(
            "History database error:",
            repr(error)
        )


        return f"""
        <h2>
            Database Error
        </h2>

        <p>
            {str(error)}
        </p>
        """, 500


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
