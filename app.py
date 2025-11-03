from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
import pandas as pd
import threading
import os
from packet_sniffer import start_sniffer

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a secure key for session management

# Global variable for the dynamic threshold
anomaly_threshold = 1500

# Ensure the data directory and file exist
os.makedirs("data", exist_ok=True)
if not os.path.exists("data/traffic_data.csv"):
    with open("data/traffic_data.csv", "w") as f:
        f.write("timestamp,src_ip,dst_ip,protocol,packet_size\n")


@app.route('/')
def index():
    """Redirect to login or dashboard based on session."""
    app.logger.debug(f"Index route accessed. Session content: {session}")  # Debugging log
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    app.logger.debug(f"Login route accessed. Session content: {session}")  # Debugging log
    if "user" in session:
        return redirect(url_for("dashboard"))  # Redirect if already logged in

    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate credentials
        if username == "admin" and password == "password":  # Replace with secure validation
            session["user"] = username
            app.logger.debug(f"User {username} logged in successfully.")  # Debugging log
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Username or Password"
            app.logger.debug("Invalid login attempt.")  # Debugging log

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Log the user out and clear the session."""
    app.logger.debug(f"Logout route accessed. Clearing session: {session}")  # Debugging log
    session.clear()  # Completely clear session
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """Display the dashboard if the user is logged in."""
    app.logger.debug(f"Dashboard route accessed. Session content: {session}")  # Debugging log
    if "user" not in session:  # Ensure the user is logged in
        app.logger.debug("Unauthorized access to dashboard. Redirecting to login.")  # Debugging log
        return redirect(url_for("login"))
    return render_template('index.html')


@app.route('/get_packets')
def get_packets():
    """Fetch the latest packets from the CSV file."""
    data = pd.read_csv(
        "data/traffic_data.csv",
        skiprows=1,
        header=None,
        names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "country", "city", "latitude", "longitude"],
        dtype={
            "timestamp": float,
            "src_ip": str,
            "dst_ip": str,
            "protocol": str,
            "packet_size": float,
            "country": str,
            "city": str,
            "latitude": str,
            "longitude": str
        },
        low_memory=False
    )
    return data.tail(20).to_json(orient='records')


@app.route('/get_alerts')
def get_alerts():
    """Fetch alerts from alerts.csv and return structured alert data."""
    try:
        data = pd.read_csv(
            "data/alerts.csv",
            header=None,
            names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "alert", "country", "city", "latitude", "longitude"],
            dtype={
                "timestamp": str,
                "src_ip": str,
                "dst_ip": str,
                "protocol": str,
                "packet_size": str,
                "alert": str,
                "country": str,
                "city": str,
                "latitude": str,
                "longitude": str
            },
            low_memory=False
        )
        data["packet_size"] = pd.to_numeric(data["packet_size"], errors='coerce')
        data["timestamp"] = pd.to_numeric(data["timestamp"], errors='coerce')
        data = data.dropna(subset=["alert", "timestamp", "src_ip", "dst_ip", "packet_size"])
        data = data[data["alert"].astype(str).str.len() > 0]
        alerts = [
            f"{row['alert']} from {row['src_ip']} -> {row['dst_ip']} ({row['country']}, {row['city']})"
            for _, row in data.tail(20).iterrows()
        ]
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/set_threshold', methods=['POST'])
def set_threshold():
    """Set a new anomaly detection threshold."""
    global anomaly_threshold
    threshold = request.json.get("threshold")
    if threshold:
        anomaly_threshold = int(threshold)
        app.logger.debug(f"Threshold updated to: {anomaly_threshold}")  # Debugging log
        return jsonify({"status": "success", "threshold": anomaly_threshold})
    return jsonify({"status": "error", "message": "Invalid threshold value"}), 400



@app.route('/get_threshold')
def get_threshold():
    """Return the current anomaly detection threshold."""
    return jsonify({"threshold": anomaly_threshold})

def detect_anomalies(data):
    """Detect anomalies based on the dynamic threshold."""
    global anomaly_threshold
    alerts = []
    for _, row in data.iterrows():
        if row['packet_size'] > anomaly_threshold:
            alerts.append(f"Large packet detected: {row['src_ip']} -> {row['dst_ip']} (Size: {row['packet_size']})")
    return alerts


# Export routes
@app.route('/export_traffic_data')
def export_traffic_data():
    """Allow downloading the traffic CSV file."""
    return send_file("data/traffic_data.csv", as_attachment=True)

@app.route('/export_alerts')
def export_alerts():
    """Allow downloading the alerts CSV file."""
    return send_file("data/alerts.csv", as_attachment=True)

@app.route('/get_threat_stats')
def get_threat_stats():
    """Return a count of different types of alerts for threat statistics."""
    try:
        df = pd.read_csv(
            "data/alerts.csv",
            header=None,
            names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "alert", "country", "city", "latitude", "longitude"]
        )
        threat_counts = df["alert"].value_counts().to_dict()
        return jsonify(threat_counts)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/get_recent_anomalies')
def get_recent_anomalies():
    """Return the most recent 5 anomalies."""
    try:
        df = pd.read_csv(
            "data/alerts.csv",
            header=None,
            names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "alert", "country", "city", "latitude", "longitude"]
        )
        df = df.dropna(subset=["alert", "timestamp", "src_ip", "dst_ip"])
        df = df.fillna("")  # Replace NaN with empty string
        return jsonify(df.tail(5).to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/get_geo_data')
def get_geo_data():
    """Return unique GeoIP data points for mapping."""
    try:
        df = pd.read_csv(
            "data/alerts.csv",
            header=None,
            names=[
                "timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "alert",
                "country", "city", "latitude", "longitude"
            ],
            dtype={
                "timestamp": str,
                "src_ip": str,
                "dst_ip": str,
                "protocol": str,
                "packet_size": str,
                "alert": str,
                "country": str,
                "city": str,
                "latitude": str,
                "longitude": str
            },
            low_memory=False
        )
        df["latitude"] = pd.to_numeric(df["latitude"], errors='coerce')
        df["longitude"] = pd.to_numeric(df["longitude"], errors='coerce')
        df = df.dropna(subset=["latitude", "longitude", "src_ip"])
        df = df[df["latitude"].between(-90, 90) & df["longitude"].between(-180, 180)]
        df["country"] = df["country"].fillna("N/A")
        df["city"] = df["city"].fillna("N/A")
        geo_points = df[["country", "city", "src_ip", "latitude", "longitude"]].drop_duplicates().to_dict(orient='records')
        return jsonify(geo_points)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/get_threat_info')
def get_threat_info():
    """Return detailed threat information for visualization."""
    try:
        df = pd.read_csv(
            "data/alerts.csv",
            header=None,
            names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "alert", "country", "city", "latitude", "longitude"]
        )
        df = df.dropna(subset=["alert"])
        threat_info = df.groupby("alert").agg({
            "src_ip": "nunique",
            "dst_ip": "nunique",
            "packet_size": "mean"
        }).reset_index()
        threat_info.columns = ["alert", "unique_src_ips", "unique_dst_ips", "avg_packet_size"]
        return jsonify(threat_info.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/get_threat_distribution_data')
def get_threat_distribution_data():
    """Return threat distribution data for pie charts or similar visualizations."""
    try:
        df = pd.read_csv(
            "data/alerts.csv",
            header=None,
            names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_size", "alert", "country", "city", "latitude", "longitude"]
        )
        threat_counts = df["alert"].value_counts()
        distribution = {
            "labels": threat_counts.index.tolist(),
            "values": threat_counts.values.tolist()
        }
        return jsonify(distribution)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/map')
def map_page():
    return render_template('map.html')


# New route for threat_distribution page
@app.route('/threat-distribution')
def threat_distribution():
    return render_template('threat_distribution.html')
if __name__ == "__main__":
    # Start the packet sniffer in a separate thread
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    # Run the Flask application
    app.run(debug=True)