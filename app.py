"""
app.py

NetGuard IoT -- web dashboard for the anomaly detection + forensics pipeline.

Routes:
    GET  /                       Dashboard: stats + recent alerts
    POST /simulate               Runs a synthetic detection batch (demo button)
    GET  /alerts                 JSON list of all alerts
    GET  /alerts/<alert_id>      Alert detail page
    GET  /alerts/<alert_id>/report   Generates (if needed) and downloads the PDF report
    GET  /logs                   Recent raw traffic-window logs (audit trail)

Run:
    python3 app.py
    -> open http://127.0.0.1:5000

To point at a real MongoDB Atlas cluster instead of the in-memory fallback:
    export MONGO_URI="mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/"
    python3 app.py
"""

from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for

from traffic.synthetic_generator import generate_demo_batch
from pipeline import run_batch, get_detector
from storage import alert_store
from forensics.generate_report import generate_report_for_alert

app = Flask(__name__)

# Warm up the model once at startup so the first request isn't slow.
get_detector()


@app.route("/")
def dashboard():
    stats = alert_store.get_stats()
    stats["suspicious_ports_count"] = (
        stats["by_type"].get("brute_force_login", 0) + stats["by_type"].get("c2_communication", 0) + stats["by_type"].get("signature_suspicious_port", 0)
    )
    alerts = alert_store.get_all_alerts(limit=25)
    mitigations = alert_store.get_mitigations(limit=10)
    blocked_ips = alert_store.get_blocked_ips()
    return render_template("dashboard.html", stats=stats, alerts=alerts, mitigations=mitigations, blocked_ips=blocked_ips)


@app.route("/simulate", methods=["POST"])
def simulate():
    n_normal = int(request.form.get("n_normal", 15))
    n_attacks = int(request.form.get("n_attacks", 3))
    batch = generate_demo_batch(n_normal=n_normal, n_attacks=n_attacks)
    new_alert_ids = run_batch(batch)
    return redirect(url_for("dashboard"))


@app.route("/unblock/<ip>", methods=["POST"])
def unblock(ip):
    alert_store.remove_blocked_ip(ip)
    return redirect(url_for("dashboard"))


@app.route("/alerts")
def alerts_json():
    return jsonify(alert_store.get_all_alerts(limit=200))


@app.route("/alerts/<alert_id>")
def alert_detail(alert_id):
    alert = alert_store.get_alert(alert_id)
    if not alert:
        return "Alert not found", 404
    mitigations = alert_store.get_mitigations_for_alert(alert_id)
    return render_template("alert_detail.html", alert=alert, mitigations=mitigations)


@app.route("/alerts/<alert_id>/report")
def alert_report(alert_id):
    alert = alert_store.get_alert(alert_id)
    if not alert:
        return "Alert not found", 404

    if not alert.get("report_generated"):
        result = generate_report_for_alert(alert)
        alert_store.mark_report_generated(alert_id, result["output_path"], result["report_hash"])
        report_path = result["output_path"]
    else:
        report_path = alert["report_path"]

    return send_file(report_path, as_attachment=True, download_name=f"{alert_id}_incident_report.pdf")


@app.route("/export/csv")
def export_csv():
    import csv
    import io

    alerts = alert_store.get_all_alerts(limit=1000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["alert_id", "detected_timestamp", "device_id", "ip_address", "alert_type",
                      "attck_technique", "attck_tactic", "severity", "anomaly_score"])
    for a in alerts:
        writer.writerow([
            a["alert_id"], a["detected_timestamp"], a["device"]["device_id"], a["device"]["ip_address"],
            a["alert_type"], a["attack_info"]["technique_id"], a["attack_info"]["tactic"],
            a["severity_label"], a["anomaly_score"],
        ])

    buf.seek(0)
    return app.response_class(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netguard_alerts_export.csv"},
    )


@app.route("/logs")
def logs():
    recent_logs = alert_store.get_recent_logs(limit=50)
    return render_template("logs.html", logs=recent_logs)


if __name__ == "__main__":
    app.run(debug=False, use_reloader=False, host="0.0.0.0", port=5003)
