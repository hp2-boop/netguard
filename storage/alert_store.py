"""
storage/alert_store.py

Handles storage and retrieval of anomaly alerts and raw traffic-window
logs in MongoDB (or the mongomock in-memory fallback -- see
storage/mongo_client.py).

Collections:
    alerts        -- one document per detected anomaly (flagged windows)
    traffic_logs  -- one document per analyzed traffic window (normal + anomalous),
                     for audit trail / "what did the detector actually see"
"""

import time
import uuid
from datetime import datetime, timezone

from storage.mongo_client import get_database

_db, _mode = get_database()
_alerts = _db["alerts"]
_logs = _db["traffic_logs"]
_mitigations = _db["mitigations"]
_blocked_ips = _db["blocked_ips"]


def storage_mode() -> str:
    """Returns 'real' if connected to an actual MongoDB server, 'mock' otherwise."""
    return _mode


def _new_id(prefix: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def insert_traffic_log(device: dict, features: dict, anomaly_score: float, is_anomaly: bool, window_seconds: float):
    """Logs every analyzed window (not just anomalies) -- gives you a full audit trail in Mongo."""
    doc = {
        "log_id": _new_id("LOG"),
        "timestamp": datetime.now(timezone.utc),
        "device": device,
        "features": features,
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "window_seconds": window_seconds,
    }
    _logs.insert_one(doc)
    return doc["log_id"]


def insert_alert(device: dict, features: dict, anomaly_score: float, alert_type: str,
                  attack_info: dict, severity_label: str, severity_score: float,
                  timeline: list, evidence: dict):
    """Stores a full alert document -- this is what the report generator later reads from."""
    doc = {
        "alert_id": _new_id("ALERT"),
        "detected_timestamp": datetime.now(timezone.utc),
        "device": device,
        "alert_type": alert_type,
        "anomaly_score": anomaly_score,
        "detection_features": features,
        "attack_info": attack_info,
        "severity_label": severity_label,
        "severity_score": severity_score,
        "timeline": timeline,
        "evidence": evidence,
        "report_generated": False,
        "report_path": None,
        "report_hash": None,
    }
    _alerts.insert_one(doc)
    return doc["alert_id"]


def get_all_alerts(limit: int = 100):
    return list(_alerts.find({}, {"_id": 0}).sort("detected_timestamp", -1).limit(limit))


def get_alert(alert_id: str):
    return _alerts.find_one({"alert_id": alert_id}, {"_id": 0})


def mark_report_generated(alert_id: str, report_path: str, report_hash: str):
    _alerts.update_one(
        {"alert_id": alert_id},
        {"$set": {"report_generated": True, "report_path": report_path, "report_hash": report_hash}},
    )


def get_recent_logs(limit: int = 50):
    return list(_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))


def insert_mitigation(mitigation_record: dict):
    _mitigations.insert_one(mitigation_record)


def get_mitigations(limit: int = 50):
    return list(_mitigations.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))


def get_mitigations_for_alert(alert_id: str):
    return list(_mitigations.find({"alert_id": alert_id}, {"_id": 0}).sort("timestamp", -1))


def add_blocked_ip(ip: str, reason: str):
    _blocked_ips.update_one(
        {"ip": ip},
        {"$set": {"ip": ip, "reason": reason, "timestamp": datetime.now(timezone.utc)}},
        upsert=True
    )


def remove_blocked_ip(ip: str):
    _blocked_ips.delete_one({"ip": ip})


def get_blocked_ips():
    return list(_blocked_ips.find({}, {"_id": 0}).sort("timestamp", -1))


def is_ip_blocked(ip: str) -> bool:
    return _blocked_ips.find_one({"ip": ip}) is not None


def get_stats():
    total_logs = _logs.count_documents({})
    total_alerts = _alerts.count_documents({})
    by_severity = {}
    for sev in ["Critical", "High", "Medium", "Low"]:
        by_severity[sev] = _alerts.count_documents({"severity_label": sev})

    by_type = {}
    for t in ["port_scan", "ddos_traffic", "brute_force_login", "c2_communication", "unclassified_anomaly"]:
        by_type[t] = _alerts.count_documents({"alert_type": t})

    # Cumulative alert count over the session, ordered by detection time --
    # feeds the "Alert Volume" line chart on the dashboard.
    all_alerts_asc = list(_alerts.find({}, {"_id": 0, "detected_timestamp": 1}).sort("detected_timestamp", 1))
    timeline_series = []
    running_total = 0
    for a in all_alerts_asc:
        running_total += 1
        ts = a["detected_timestamp"]
        ts_str = ts.strftime("%H:%M:%S") if isinstance(ts, datetime) else str(ts)
        timeline_series.append({"time": ts_str, "count": running_total})

    return {
        "total_windows_analyzed": total_logs,
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "by_type": by_type,
        "timeline_series": timeline_series,
        "storage_mode": _mode,
    }
