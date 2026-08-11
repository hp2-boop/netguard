"""
ips/prevention.py

Simulated Intrusion Prevention System (IPS).
When an attack is detected (either via signature or ML anomaly), this module
determines the appropriate mitigation action (e.g., blocking an IP, quarantining
a device) and records the action. In a live environment, these could be swapped
with actual shell commands (e.g., iptables, network switch API calls).
"""
import datetime
from datetime import timezone
from storage import alert_store

def execute_mitigation(alert_id: str, device: dict, alert_type: str, severity_label: str, packets: list) -> dict:
    """
    Determines and executes (simulates) a mitigation action based on the alert.
    Returns a mitigation record dict.
    """
    timestamp = datetime.datetime.now(timezone.utc).isoformat()
    mitigation_action = ""
    target = ""
    
    device_ip = device.get("ip_address")
    offending_ip = None

    if packets:
        # Try to find the external IP
        for p in packets:
            if p["src_ip"] != device_ip:
                offending_ip = p["src_ip"]
                break
            elif p["dst_ip"] != device_ip:
                offending_ip = p["dst_ip"]
                break

    # Simple logic mapping alert types / severities to mitigation actions
    if alert_type == "signature_blacklisted_ip":
        mitigation_action = "BLOCK_IP"
        target = offending_ip if offending_ip else "Remote Malicious IP"
        if offending_ip:
            alert_store.add_blocked_ip(offending_ip, "Signature Blacklisted IP")
    elif alert_type == "brute_force_login":
        mitigation_action = "BLOCK_SOURCE_IP"
        target = offending_ip if offending_ip else "Attacking IP"
        if offending_ip:
            alert_store.add_blocked_ip(offending_ip, "Brute Force Login Source")
    elif alert_type in ["ddos_traffic", "c2_communication"] or severity_label == "Critical":
        mitigation_action = "QUARANTINE_DEVICE"
        target = device["device_id"]
        # Also block the device's IP to quarantine it
        alert_store.add_blocked_ip(device_ip, f"Quarantine Device: {alert_type}")
        if alert_type == "c2_communication" and offending_ip:
            # Also block the C2 server
            alert_store.add_blocked_ip(offending_ip, "C2 Server")
    elif severity_label == "High":
        mitigation_action = "QUARANTINE_DEVICE"
        target = device["device_id"]
        alert_store.add_blocked_ip(device_ip, "High Severity Quarantine")
    else:
        mitigation_action = "MONITOR_ONLY"
        target = device["device_id"]

    mitigation_record = {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "device_id": device["device_id"],
        "action": mitigation_action,
        "target": target,
        "status": "SUCCESS" if mitigation_action != "MONITOR_ONLY" else "N/A",
        "description": f"IPS automated action: {mitigation_action} on {target} due to {alert_type}"
    }
    
    return mitigation_record
