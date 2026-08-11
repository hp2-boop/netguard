import csv
import io

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from traffic.synthetic_generator import generate_demo_batch
from pipeline import get_detector, run_batch
from storage import alert_store
from forensics.generate_report import generate_report_for_alert


app = Flask(__name__)


# Initialize the detection model when the application starts.
# This prevents the first user request from having to wait for model loading.
get_detector()


@app.route("/")
def dashboard():
    """Display the main monitoring dashboard."""

    statistics = alert_store.get_stats()

    by_type = statistics.get("by_type", {})
    statistics["suspicious_ports_count"] = (
        by_type.get("brute_force_login", 0)
        + by_type.get("c2_communication", 0)
    )

    alerts = alert_store.get_all_alerts(limit=25)

    return render_template(
        "dashboard.html",
        stats=statistics,
        alerts=alerts,
    )


@app.route("/simulate", methods=["POST"])
def simulate():
    """Generate simulated network traffic and process it."""

    normal_count = int(request.form.get("n_normal", 15))
    attack_count = int(request.form.get("n_attacks", 3))

    traffic_batch = generate_demo_batch(
        n_normal=normal_count,
        n_attacks=attack_count,
    )

    run_batch(traffic_batch)

    return redirect(url_for("dashboard"))


@app.route("/alerts")
def alerts_json():
    """Return the latest alerts as JSON."""

    alerts = alert_store.get_all_alerts(limit=200)
    return jsonify(alerts)


@app.route("/alerts/<alert_id>")
def alert_detail(alert_id):
    """Show detailed information about a specific alert."""

    alert = alert_store.get_alert(alert_id)

    if alert is None:
        return "Alert not found", 404

    return render_template(
        "alert_detail.html",
        alert=alert,
    )


@app.route("/alerts/<alert_id>/report")
def alert_report(alert_id):
    """Generate or download the incident report for an alert."""

    alert = alert_store.get_alert(alert_id)

    if alert is None:
        return "Alert not found", 404

    if alert.get("report_generated"):
        report_file = alert["report_path"]
    else:
        report = generate_report_for_alert(alert)

        alert_store.mark_report_generated(
            alert_id,
            report["output_path"],
            report["report_hash"],
        )

        report_file = report["output_path"]

    return send_file(
        report_file,
        as_attachment=True,
        download_name=f"{alert_id}_incident_report.pdf",
    )


@app.route("/export/csv")
def export_csv():
    """Export stored security alerts as a CSV file."""

    alerts = alert_store.get_all_alerts(limit=1000)

    csv_buffer = io.StringIO()
    csv_writer = csv.writer(csv_buffer)

    csv_writer.writerow([
        "alert_id",
        "detected_timestamp",
        "device_id",
        "ip_address",
        "alert_type",
        "attck_technique",
        "attck_tactic",
        "severity",
        "anomaly_score",
    ])

    for alert in alerts:
        device = alert["device"]
        attack = alert["attack_info"]

        csv_writer.writerow([
            alert["alert_id"],
            alert["detected_timestamp"],
            device["device_id"],
            device["ip_address"],
            alert["alert_type"],
            attack["technique_id"],
            attack["tactic"],
            alert["severity_label"],
            alert["anomaly_score"],
        ])

    csv_buffer.seek(0)

    return app.response_class(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; filename=netguard_alerts_export.csv"
            )
        },
    )


@app.route("/logs")
def logs():
    """Display recent system and security logs."""

    recent_logs = alert_store.get_recent_logs(limit=50)

    return render_template(
        "logs.html",
        logs=recent_logs,
    )


if __name__ == "__main__":
    app.run(
        debug=False,
        use_reloader=False,
        host="0.0.0.0",
        port=5002,
    )