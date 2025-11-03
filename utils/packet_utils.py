# utils/packet_utils.py

from collections import defaultdict
import time
import re

# For frequency tracking
packet_history = defaultdict(list)

# Signature database (simple regex patterns)
signature_db = [
    re.compile(r'malware'),
    re.compile(r'exploit'),
    re.compile(r'(cmd\.exe|/bin/bash)'),
    re.compile(r'(base64|eval\()')
]

def detect_dos(ip, current_time, window=5, threshold=20):
    """Detects potential DoS by tracking frequency of packets."""
    packet_history[ip].append(current_time)
    packet_history[ip] = [t for t in packet_history[ip] if current_time - t < window]
    return len(packet_history[ip]) > threshold

def detect_port_scan(ip_ports, threshold=10):
    """Detects potential port scanning from IP trying many ports."""
    return len(ip_ports) > threshold

def detect_unusual_protocol(proto):
    common_protocols = {6, 17}  # TCP, UDP
    return proto not in common_protocols

def match_signature(payload):
    for pattern in signature_db:
        if pattern.search(payload):
            return True
    return False