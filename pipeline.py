"""
pipeline.py

The core orchestrator: takes one traffic window (device + packets), runs
it through the ML anomaly detector, and if flagged:
  1. Classifies the attack type (rule_classifier)
  2. Maps it to a MITRE ATT&CK technique (attack_mapping.json)
  3. Computes a combined severity score
  4. Builds a simple timeline + mock evidence record (pcap hash placeholder --
     wire this to your real pcap-saving code in a live deployment)
  5. Stores the alert in MongoDB (storage/alert_store.py)

Every analyzed window (anomalous or not) is also logged to the
traffic_logs collection for a full audit trail.
"""

import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from ml.detector import AnomalyDetector
from intelligence.rule_classifier import classify_attack_type
from intelligence.signature_ids import evaluate_window_signatures
from ips.prevention import execute_mitigation
from storage import alert_store

ATTACK_MAP_PATH = Path(__file__).parent / "intelligence" / "attack_mapping.json"
with open(ATTACK_MAP_PATH) as f:
    ATTACK_MAP = json.load(f)

_detector = None


def get_detector():
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


def _map_to_attack(alert_type: str) -> dict:
    if alert_type in ATTACK_MAP:
        return ATTACK_MAP[alert_type]
    return {
        "technique_id": "N/A",
        "technique_name": "Unclassified Behavior",
        "tactic": "Unknown",
        "description": ("This anomaly does not match any known rule pattern. "
                         "Manual analyst review recommended."),
        "recommended_actions": ["Escalate to human analyst for manual classification"],
        "severity_weight": 0.5,
    }


def _compute_severity(anomaly_score: float, attack_weight: float):
    combined = (anomaly_score * 0.6) + (attack_weight * 0.4)
    if combined >= 0.8:
        return "Critical", combined
    elif combined >= 0.6:
        return "High", combined
    elif combined >= 0.4:
        return "Medium", combined
    return "Low", combined


def _build_timeline(device: dict, packets: list, alert_type: str):
    if not packets:
        return []
    first_t = datetime.fromtimestamp(packets[0]["timestamp"], tz=timezone.utc)
    last_t = datetime.fromtimestamp(packets[-1]["timestamp"], tz=timezone.utc)
    return [
        {"time": first_t.isoformat(), "event": f"First packet observed from {device['device_id']}"},
        {"time": last_t.isoformat(), "event": f"Traffic window closed ({len(packets)} packets analyzed)"},
        {"time": datetime.now(timezone.utc).isoformat(),
         "event": f"Anomaly detector flagged window as '{alert_type}'"},
    ]


def _build_evidence(alert_id: str, packets: list):
    """
    In a real deployment, this is where you'd save the actual pcap segment
    to disk/cloud storage and hash the real file. Here we hash a
    deterministic summary of the packet list as a stand-in "evidence
    fingerprint" so the demo still produces a real, verifiable SHA-256.
    """
    summary = json.dumps(packets, sort_keys=True, default=str).encode()
    fingerprint = hashlib.sha256(summary).hexdigest()
    return {
        "pcap_file": f"evidence/{alert_id}_capture.pcap",
        "pcap_sha256": fingerprint,
        "chain_of_custody_id": f"COC-{alert_id}",
        "captured_by": "NetGuard AutoForensicAgent v1.0",
    }


def process_window(device: dict, packets: list, window_seconds: float, known_destinations: set = None):
    """
    Runs the full pipeline on one traffic window. Always logs the window;
    only creates an alert + report data if the ML model or signature IDS flags it.

    Returns the alert_id if an alert was created, else None.
    """
    # 0. Check IPS Blocklist
    device_ip = device.get("ip_address")
    if alert_store.is_ip_blocked(device_ip):
        # Device is quarantined, drop entire window silently (or log as blocked)
        return None
        
    filtered_packets = []
    for p in packets:
        if alert_store.is_ip_blocked(p["src_ip"]) or alert_store.is_ip_blocked(p["dst_ip"]):
            continue
        filtered_packets.append(p)
        
    if not filtered_packets:
        # All traffic in this window was blocked
        return None
        
    packets = filtered_packets

    # 1. Run Signature-Based IDS
    sig_result = evaluate_window_signatures(packets)
    
    if sig_result["signature_matched"]:
        alert_type = sig_result["alert_type"]
        attack_info = _map_to_attack(alert_type)
        severity_label, severity_score = _compute_severity(1.0, attack_info["severity_weight"])
        
        alert_store.insert_traffic_log(
            device=device,
            features={"signature_match": True, "description": sig_result["description"]},
            anomaly_score=1.0,
            is_anomaly=True,
            window_seconds=window_seconds,
        )
        
        timeline = _build_timeline(device, packets, alert_type)
        alert_id = alert_store.insert_alert(
            device=device,
            features={"signature_match": True, "description": sig_result["description"]},
            anomaly_score=1.0,
            alert_type=alert_type,
            attack_info=attack_info,
            severity_label=severity_label,
            severity_score=severity_score,
            timeline=timeline,
            evidence={},
        )
        evidence = _build_evidence(alert_id, packets)
        alert_store._alerts.update_one({"alert_id": alert_id}, {"$set": {"evidence": evidence}})
        
        # IPS Mitigation
        mitigation_record = execute_mitigation(alert_id, device, alert_type, severity_label, packets)
        alert_store.insert_mitigation(mitigation_record)
        
        return alert_id

    # 2. Run Anomaly-Based IDS (ML)
    detector = get_detector()
    result = detector.score_window(packets, window_seconds, known_destinations)

    alert_store.insert_traffic_log(
        device=device,
        features=result["features"],
        anomaly_score=result["anomaly_score"],
        is_anomaly=result["is_anomaly"],
        window_seconds=window_seconds,
    )

    if not result["is_anomaly"]:
        return None

    alert_type = classify_attack_type(result["features"])
    attack_info = _map_to_attack(alert_type)
    severity_label, severity_score = _compute_severity(result["anomaly_score"], attack_info["severity_weight"])

    # alert_id is generated inside insert_alert; build timeline/evidence with a
    # temp reference first, then patch once we have the real ID.
    timeline = _build_timeline(device, packets, alert_type)

    alert_id = alert_store.insert_alert(
        device=device,
        features=result["features"],
        anomaly_score=result["anomaly_score"],
        alert_type=alert_type,
        attack_info=attack_info,
        severity_label=severity_label,
        severity_score=severity_score,
        timeline=timeline,
        evidence={},  # placeholder, patched below
    )

    evidence = _build_evidence(alert_id, packets)
    alert_store._alerts.update_one({"alert_id": alert_id}, {"$set": {"evidence": evidence}})

    # IPS Mitigation
    mitigation_record = execute_mitigation(alert_id, device, alert_type, severity_label, packets)
    alert_store.insert_mitigation(mitigation_record)

    return alert_id


def run_batch(batch):
    """
    Runs process_window over a list of {"device", "packets", "window_seconds"}
    entries (as produced by traffic/synthetic_generator.generate_demo_batch(),
    traffic/pcap_reader.read_pcap_windows(), or traffic/live_capture.py).

    Returns list of alert_ids created (skips windows that weren't anomalous).
    """
    created_alerts = []
    for entry in batch:
        alert_id = process_window(entry["device"], entry["packets"], entry["window_seconds"])
        if alert_id:
            created_alerts.append(alert_id)
    return created_alerts
