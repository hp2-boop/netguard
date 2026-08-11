"""
traffic/synthetic_generator.py

Generates synthetic per-device packet windows that mimic realistic IoT
traffic: normal periodic behavior (sensors, cameras phoning home) plus
injected attack patterns (port scan, DDoS/botnet flood, brute-force login,
C2 beaconing). Used for:
  - Training the IsolationForest model on "normal" behavior
  - Driving the live demo / simulation button in the web dashboard

This exists because the sandbox this was built in has no live network
interface to sniff real traffic from. For real deployments, use
traffic/live_capture.py (real interface + scapy) or traffic/pcap_reader.py
(analyze a captured .pcap file) instead -- both produce the same packet
record format consumed here.
"""

import random
import time

DEVICES = [
    {"device_id": "IOT-CAM-014", "ip_address": "192.168.1.47", "mac_address": "3C:EF:8C:11:9A:02",
     "device_type": "IP Camera", "vendor": "Hikvision", "first_seen": "2026-05-02T08:12:00Z"},
    {"device_id": "IOT-PLUG-002", "ip_address": "192.168.1.22", "mac_address": "5C:CF:7F:22:4B:19",
     "device_type": "Smart Plug", "vendor": "TP-Link", "first_seen": "2026-04-18T14:30:00Z"},
    {"device_id": "IOT-SENSOR-031", "ip_address": "192.168.1.63", "mac_address": "78:11:DC:09:E3:5A",
     "device_type": "Temp Sensor", "vendor": "Xiaomi", "first_seen": "2026-06-01T09:45:00Z"},
    {"device_id": "IOT-HUB-001", "ip_address": "192.168.1.10", "mac_address": "A0:D0:5C:44:7B:2E",
     "device_type": "Smart Hub", "vendor": "Samsung SmartThings", "first_seen": "2026-03-22T11:00:00Z"},
]

NORMAL_CLOUD_IPS = ["52.94.10.3", "34.201.55.9", "13.107.42.14"]
NORMAL_PORTS = [443, 8883, 80]  # HTTPS, MQTT over TLS, HTTP


def _make_packet(t, src_ip, dst_ip, dst_port, protocol, size, flags="", auth_failed=False):
    return {
        "timestamp": t,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": size,
        "flags": flags,
        "auth_failed": auth_failed,
    }


def generate_normal_window(device: dict, window_start: float, window_seconds: float = 10.0) -> list:
    """Low, regular traffic to 1-2 known cloud endpoints -- typical IoT 'phone home' behavior."""
    packets = []
    n_packets = random.randint(3, 8)
    dst = random.choice(NORMAL_CLOUD_IPS)
    port = random.choice(NORMAL_PORTS)
    for i in range(n_packets):
        t = window_start + random.uniform(0, window_seconds)
        packets.append(_make_packet(
            t, device["ip_address"], dst, port,
            protocol="TCP" if port != 8883 or True else "UDP",
            size=random.randint(60, 300),
            flags=random.choice(["A", "PA", ""]),
        ))
    return packets


def generate_port_scan_window(device: dict, window_start: float, window_seconds: float = 10.0) -> list:
    """Attacker (or compromised peer) scanning many ports on this device / from this device."""
    packets = []
    n_packets = random.randint(80, 200)
    target = "192.168.1." + str(random.randint(2, 254))
    for i in range(n_packets):
        t = window_start + random.uniform(0, window_seconds)
        packets.append(_make_packet(
            t, device["ip_address"], target, random.randint(1, 65535),
            protocol="TCP", size=random.randint(40, 60), flags="S",
        ))
    return packets


def generate_ddos_window(device: dict, window_start: float, window_seconds: float = 10.0) -> list:
    """Compromised device flooding many external destinations -- Mirai-style UDP flood."""
    packets = []
    n_packets = random.randint(2000, 5000)
    for i in range(n_packets):
        t = window_start + random.uniform(0, window_seconds)
        dst = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        packets.append(_make_packet(
            t, device["ip_address"], dst, random.randint(1024, 65535),
            protocol="UDP", size=random.randint(40, 80),
        ))
    return packets


def generate_brute_force_window(device: dict, window_start: float, window_seconds: float = 10.0) -> list:
    """Repeated failed login attempts against the device's management interface."""
    packets = []
    n_packets = random.randint(30, 60)
    attacker = f"185.220.{random.randint(1,255)}.{random.randint(1,254)}"
    for i in range(n_packets):
        t = window_start + random.uniform(0, window_seconds)
        packets.append(_make_packet(
            t, attacker, device["ip_address"], 22,
            protocol="TCP", size=random.randint(60, 120), flags="PA",
            auth_failed=True,
        ))
    return packets


def generate_c2_beacon_window(device: dict, window_start: float, window_seconds: float = 10.0) -> list:
    """Device compromised and beaconing to a suspicious external IP with unusual regularity."""
    packets = []
    n_packets = random.randint(10, 20)
    c2_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for i in range(n_packets):
        t = window_start + i * (window_seconds / n_packets)
        packets.append(_make_packet(
            t, device["ip_address"], c2_ip, random.choice([4444, 8080, 6667]),
            protocol="TCP", size=random.randint(100, 500), flags="PA",
        ))
    return packets


def generate_signature_attack_window(device: dict, window_start: float, window_seconds: float = 10.0) -> list:
    """Generates traffic that will be instantly caught by the Signature IDS."""
    packets = []
    n_packets = random.randint(5, 10)
    # 50% chance of known bad IP, 50% chance of known bad port
    if random.random() > 0.5:
        target_ip = random.choice(["198.51.100.33", "203.0.113.10"])
        port = random.randint(1024, 65535)
    else:
        target_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        port = random.choice([4444, 6667])
        
    for i in range(n_packets):
        t = window_start + random.uniform(0, window_seconds)
        packets.append(_make_packet(
            t, device["ip_address"], target_ip, port,
            protocol="TCP", size=random.randint(100, 500), flags="PA",
        ))
    return packets


ATTACK_GENERATORS = {
    "port_scan": generate_port_scan_window,
    "ddos_traffic": generate_ddos_window,
    "brute_force_login": generate_brute_force_window,
    "c2_communication": generate_c2_beacon_window,
    "signature_attack": generate_signature_attack_window,
}


def generate_training_dataset(n_windows: int = 300, window_seconds: float = 10.0):
    """Pure normal-traffic windows across all devices, for training the IsolationForest baseline."""
    dataset = []
    t = time.time() - n_windows * window_seconds
    for i in range(n_windows):
        device = random.choice(DEVICES)
        packets = generate_normal_window(device, t, window_seconds)
        dataset.append({"device": device, "packets": packets, "window_seconds": window_seconds,
                         "true_label": "normal"})
        t += window_seconds
    return dataset


def generate_demo_batch(n_normal: int = 15, n_attacks: int = 3, window_seconds: float = 10.0):
    """
    Mixed batch simulating a short monitoring session: mostly normal windows,
    with a few injected attacks of random type -- this is what the dashboard's
    'Run Detection Simulation' button triggers.
    """
    batch = []
    t = time.time()

    for i in range(n_normal):
        device = random.choice(DEVICES)
        packets = generate_normal_window(device, t, window_seconds)
        batch.append({"device": device, "packets": packets, "window_seconds": window_seconds,
                       "true_label": "normal"})
        t += window_seconds

    attack_types = list(ATTACK_GENERATORS.keys())
    for i in range(n_attacks):
        device = random.choice(DEVICES)
        attack_type = random.choice(attack_types)
        packets = ATTACK_GENERATORS[attack_type](device, t, window_seconds)
        batch.append({"device": device, "packets": packets, "window_seconds": window_seconds,
                       "true_label": attack_type})
        t += window_seconds

    random.shuffle(batch)
    return batch
