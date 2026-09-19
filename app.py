from flask import Flask, jsonify, send_from_directory, request
import os
import time
from collections import defaultdict
import psycopg2

from model import detect_intrusion


app = Flask(
    __name__,
    static_folder="."
)


# ==================================================
# REAL TRAFFIC MONITOR
# ==================================================

traffic_logs = []

request_counts = defaultdict(int)

failed_request_counts = defaultdict(int)

def is_internal_monitoring_path(path):
    return path in [
        "/traffic",
        "/traffic-logs",
        "/scan",
        "/history",
        "/style.css",
        "/favicon.ico"
    ]

# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():

    database_url = os.environ.get(
        "DATABASE_URL"
    )

    if not database_url:

        raise Exception(
            "DATABASE_URL is not configured"
        )

    if "sslmode=" not in database_url:

        separator = "&" if "?" in database_url else "?"

        database_url += (
            separator +
            "sslmode=require"
        )

    return psycopg2.connect(
        database_url
    )


# ==================================================
# CREATE DATABASE TABLES
# ==================================================

def initialize_database():

    connection = get_db_connection()

    cursor = connection.cursor()


    # ----------------------------------------------
    # SCAN RESULTS
    # ----------------------------------------------

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


    # ----------------------------------------------
    # REAL TRAFFIC LOGS
    # ----------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (

            id SERIAL PRIMARY KEY,

            source_ip VARCHAR(100),

            method VARCHAR(20),

            path TEXT,

            user_agent TEXT,

            request_size INTEGER,

            response_status INTEGER,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    connection.commit()

    cursor.close()

    connection.close()


    print(
        "PostgreSQL database initialized successfully!"
    )


# ==================================================
# RECORD REAL REQUEST
# ==================================================

@app.before_request
def save_request(response):

    try:

    # Ignore internal dashboard/API requests
    # so they are not counted as user/network traffic.

    if is_internal_monitoring_path(request.path):
        return

    source_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )

    if source_ip and "," in source_ip:
        source_ip = source_ip.split(",")[0].strip()

    method = request.method
    path = request.path

    user_agent = request.headers.get(
        "User-Agent",
        "Unknown"
    )

    request_size = request.content_length or 0

    # Count request
    request_counts[source_ip] += 1

    # Count failed login-like requests
    if path in [
        "/login",
        "/admin",
        "/wp-login.php"
    ]:
        failed_request_counts[source_ip] += 1

    # Store request in memory
    traffic_logs.append({

        "source_ip": source_ip,

        "method": method,

        "path": path,

        "user_agent": user_agent,

        "request_size": request_size,

        "timestamp": time.time()

    })

    # Keep only the latest 1000 requests
    if len(traffic_logs) > 1000:
        del traffic_logs[:-1000]
   

# ==================================================
# RECORD RESPONSE STATUS
# ==================================================

@app.after_request
def save_request(response):

    try:
        if is_internal_monitoring_path(request.path):
            return response
        source_ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        )

        if source_ip and "," in source_ip:

            source_ip = (
                source_ip
                .split(",")[0]
                .strip()
            )


        # Save actual request to PostgreSQL

        connection = get_db_connection()

        cursor = connection.cursor()


        cursor.execute("""

            INSERT INTO traffic_logs (

                source_ip,

                method,

                path,

                user_agent,

                request_size,

                response_status

            )

            VALUES (%s, %s, %s, %s, %s, %s)

        """, (

            source_ip,

            request.method,

            request.path,

            request.headers.get(
                "User-Agent",
                "Unknown"
            ),

            request.content_length or 0,

            response.status_code

        ))


        connection.commit()

        cursor.close()

        connection.close()


    except Exception as error:

        print(
            "Traffic logging error:",
            repr(error)
        )


    return response


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
# REAL TRAFFIC STATISTICS
# ==================================================

def calculate_traffic_features():

    current_time = time.time()

    # ----------------------------------------------
    # Consider the last 60 seconds
    # ----------------------------------------------

    recent_logs = [

        log

        for log in traffic_logs

        if current_time - log["timestamp"] <= 60

    ]


    # ----------------------------------------------
    # Basic traffic
    # ----------------------------------------------

    traffic = sum(

        max(
            1,
            log["request_size"]
        )

        for log in recent_logs

    )


    # Avoid zero traffic

    if traffic <= 0:

        traffic = len(recent_logs)


    # ----------------------------------------------
    # Number of requests
    # ----------------------------------------------

    count = len(
        recent_logs
    )


    # ----------------------------------------------
    # Unique source IPs
    # ----------------------------------------------

    unique_ips = len({

        log["source_ip"]

        for log in recent_logs

    })


    # ----------------------------------------------
    # Failed login-like requests
    # ----------------------------------------------

    failed_logins = sum(

        1

        for log in recent_logs

        if log["path"] in [

            "/login",
            "/admin",
            "/wp-login.php"

        ]

    )


    # ----------------------------------------------
    # Suspicious path activity
    # ----------------------------------------------

    suspicious_paths = [

        "/admin",
        "/login",
        "/wp-login.php",
        "/.env",
        "/config",
        "/phpmyadmin",
        "/shell",
        "/cmd"

    ]


    port_activity = sum(

        1

        for log in recent_logs

        if any(

            suspicious in log["path"].lower()

            for suspicious in suspicious_paths

        )

    )


    # ----------------------------------------------
    # Bytes
    # ----------------------------------------------

    src_bytes = traffic

    dst_bytes = traffic // 2


    # ----------------------------------------------
    # Request count
    # ----------------------------------------------

    srv_count = max(
        1,
        count
    )


    # ----------------------------------------------
    # Compromised indicator
    # ----------------------------------------------

    num_compromised = min(

        10,

        port_activity

    )


    # ----------------------------------------------
    # Server error rate
    # ----------------------------------------------

    error_count = sum(

        1

        for log in recent_logs

        if log.get(
            "status",
            200
        ) >= 500

    )


    if count > 0:

        serror_rate = (
            error_count / count
        )

    else:

        serror_rate = 0.0


    # ----------------------------------------------
    # Request error rate
    # ----------------------------------------------

    if count > 0:

        rerror_rate = (
            failed_logins / count
        )

    else:

        rerror_rate = 0.0


    # Keep values in model range

    serror_rate = min(
        1.0,
        serror_rate
    )

    rerror_rate = min(
        1.0,
        rerror_rate
    )


    # ----------------------------------------------
    # Same service rate
    # ----------------------------------------------

    if count <= 1:

        same_srv_rate = 1.0

    else:

        same_srv_rate = (
            max(
                1,
                count - port_activity
            )
            / count
        )


    same_srv_rate = max(
        0.0,
        min(
            1.0,
            same_srv_rate
        )
    )


    return {

        "traffic": int(traffic),

        "failed_logins": int(
            failed_logins
        ),

        "port_activity": int(
            port_activity
        ),

        "src_bytes": int(
            src_bytes
        ),

        "dst_bytes": int(
            dst_bytes
        ),

        "count": int(
            count
        ),

        "srv_count": int(
            srv_count
        ),

        "num_failed_logins": int(
            failed_logins
        ),

        "num_compromised": int(
            num_compromised
        ),

        "serror_rate": float(
            serror_rate
        ),

        "rerror_rate": float(
            rerror_rate
        ),

        "same_srv_rate": float(
            same_srv_rate
        )

    }


# ==================================================
# AI SECURITY SCAN
# ==================================================

@app.route("/scan")
def scan():

    # ----------------------------------------------
    # Get REAL traffic features
    # ----------------------------------------------

    features = calculate_traffic_features()


    # ----------------------------------------------
    # AI / ML prediction
    # ----------------------------------------------

    result = detect_intrusion(

        features["src_bytes"],

        features["dst_bytes"],

        features["count"],

        features["srv_count"],

        features["num_failed_logins"],

        features["num_compromised"],

        features["serror_rate"],

        features["rerror_rate"],

        features["same_srv_rate"]

    )


    # ==================================================
    # DETERMINE ATTACK TYPE
    # ==================================================

    if features["failed_logins"] >= 7:

        attack = (
            "Brute Force Attack"
        )

    elif features["port_activity"] >= 7:

        attack = (
            "Port Scanning"
        )

    elif features["count"] >= 100:

        attack = (
            "High Traffic Activity"
        )

    elif result["prediction"] == "Suspicious":

        attack = (
            "Suspicious Network Activity"
        )

    elif result["prediction"] == "Malicious":

        attack = (
            "Malicious Network Activity"
        )

    else:

        attack = (
            "Normal Network Activity"
        )


    # ==================================================
    # SECURITY RESPONSE
    # ==================================================

    if result["risk"] == "HIGH":

        action = (

            "Block suspicious traffic and "
            "investigate affected cloud resources."

        )

    elif result["risk"] == "MEDIUM":

        action = (

            "Monitor suspicious activity and "
            "review cloud security logs."

        )

    else:

        action = (

            "Continue monitoring the cloud environment."

        )


    # ==================================================
    # CONVERT ML VALUES
    # ==================================================

    confidence = float(
        result["confidence"]
    )

    accuracy = float(
        result["accuracy"]
    )

    precision = float(
        result["precision"]
    )

    recall = float(
        result["recall"]
    )

    f1 = float(
        result["f1"]
    )


    # ==================================================
    # SAVE RESULT
    # ==================================================

    database_status = (
        "Database save failed"
    )


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

            int(
                features["traffic"]
            ),

            int(
                features["failed_logins"]
            ),

            int(
                features["port_activity"]
            ),

            str(attack),

            str(
                result["prediction"]
            ),

            str(
                result["risk"]
            ),

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


        database_status = (
            "Saved to PostgreSQL"
        )


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
    # SEND RESULT TO DASHBOARD
    # ==================================================

    return jsonify({

        "traffic":
            features["traffic"],

        "failed_logins":
            features["failed_logins"],

        "port_activity":
            features["port_activity"],

        "threats": (

            1

            if result["prediction"] != "Normal"

            else 0

        ),

        "attack":
            attack,

        "prediction":
            result["prediction"],

        "risk":
            result["risk"],

        "confidence":
            confidence,

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "action":
            action,

        "database":
            database_status,

        "traffic_source":
            "Real application traffic"

    })


# ==================================================
# TRAFFIC API
# ==================================================

@app.route("/traffic")
def traffic():

    features = calculate_traffic_features()

    return jsonify(features)


# ==================================================
# TIMEZONE HELPER
# ==================================================

def format_india_time(created_at):
    # PostgreSQL is storing the current timestamp in UTC.
    # Convert it to India Standard Time (UTC + 5:30) for the dashboard.
    if created_at is None:
        return ""

    from datetime import timedelta

    return (
        created_at + timedelta(hours=5, minutes=30)
    ).strftime("%H:%M:%S")


# ==================================================
# REAL TRAFFIC LOGS API
# ==================================================

@app.route("/traffic-logs")
def traffic_logs_api():

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                created_at,
                source_ip,
                method,
                path,
                response_status
            FROM traffic_logs
            ORDER BY created_at DESC
            LIMIT 10
        """)

        rows = cursor.fetchall()

        cursor.close()
        connection.close()

        logs = []

        for row in rows:

            created_at = row[0]
            source_ip = row[1]
            method = row[2]
            path = row[3]
            response_status = row[4]

            # Determine activity status
            if response_status >= 500:
                status = "Threat"

            elif response_status >= 400:
                status = "Suspicious"

            elif path in [
                "/admin",
                "/login",
                "/wp-login.php",
                "/.env",
                "/phpmyadmin",
                "/config",
                "/shell",
                "/cmd"
            ]:
                status = "Suspicious"

            else:
                status = "Normal"

            logs.append({

                "time": format_india_time(
                    created_at
                ),

                "ip": source_ip,

                "method": method,

                "path": path,

                "status": status,

                "response": response_status

            })

        return jsonify(logs)

    except Exception as error:

        print(
            "Traffic logs error:",
            repr(error)
        )

        return jsonify({
            "error": str(error)
        }), 500


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

                <td>
                    {float(row[7]):.2f}%
                </td>

                <td>{format_india_time(row[8])}</td>

            </tr>

            """


        if not rows:

            table_rows = """

            <tr>

                <td colspan="9">

                    No scan records available yet.

                </td>

            </tr>

            """


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

            </style>

        </head>


        <body>

            <div class="container">

                <h1>
                    Cloud Intrusion Detection -
                    Scan History
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
