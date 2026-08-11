"""
intelligence/signature_ids.py

A lightweight Signature-Based Intrusion Detection System (IDS).
This runs *before* the ML anomaly detection pipeline to quickly flag
known malicious indicators (IoCs) such as bad IPs, specific malicious ports,
or deterministic attack patterns.
"""

KNOWN_BAD_IPS = {
    "198.51.100.33": "Known Ransomware C2 Server",
    "203.0.113.10": "Malicious Botnet Node",
}

KNOWN_BAD_PORTS = {
    4444: "Metasploit default listener",
    6667: "IRC (often used for legacy botnets)",
}

def evaluate_window_signatures(packets: list) -> dict:
    """
    Checks a list of packets against known signatures.
    Returns a dict with {"signature_matched": bool, "alert_type": str, "description": str}
    """
    for pkt in packets:
        # Check source IP against known bad IPs (Inbound attack)
        if pkt["src_ip"] in KNOWN_BAD_IPS:
            return {
                "signature_matched": True,
                "alert_type": "signature_blacklisted_ip",
                "description": f"Traffic from known bad IP: {pkt['src_ip']} ({KNOWN_BAD_IPS[pkt['src_ip']]})"
            }
            
        # Check dest IP against known bad IPs (Outbound C2 beaconing)
        if pkt["dst_ip"] in KNOWN_BAD_IPS:
            return {
                "signature_matched": True,
                "alert_type": "signature_blacklisted_ip",
                "description": f"Traffic to known bad IP: {pkt['dst_ip']} ({KNOWN_BAD_IPS[pkt['dst_ip']]})"
            }

        # Check for suspicious ports
        if pkt["dst_port"] in KNOWN_BAD_PORTS:
            return {
                "signature_matched": True,
                "alert_type": "signature_suspicious_port",
                "description": f"Traffic to suspicious port {pkt['dst_port']} ({KNOWN_BAD_PORTS[pkt['dst_port']]})"
            }
            
    return {
        "signature_matched": False,
        "alert_type": None,
        "description": ""
    }
