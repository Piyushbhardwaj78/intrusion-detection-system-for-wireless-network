import subprocess
from utils.geoip_lookup import lookup_ip
from scapy.all import sniff, IP, Raw
import csv
import time
import os
from utils.packet_utils import detect_dos, detect_port_scan, detect_unusual_protocol
from detection.ml_detector import is_anomalous, match_signature
from collections import defaultdict

ip_port_map = defaultdict(set)

# Function to log packets
def log_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        timestamp = time.time()

        geo_info = lookup_ip(src_ip)
        country = geo_info.get('country', 'Unknown')
        city = geo_info.get('city', 'Unknown')
        latitude = geo_info.get('latitude')
        longitude = geo_info.get('longitude')

        ip_port_map[src_ip].add(protocol)

        alerts = []
        if detect_dos(src_ip, timestamp):
            alerts.append("DoS behavior detected")
        if detect_port_scan(ip_port_map[src_ip]):
            alerts.append("Port scanning detected")
        if detect_unusual_protocol(protocol):
            alerts.append("Unusual protocol detected")
        if is_anomalous(packet_size, protocol):
            alerts.append("ML-based anomaly detected")

        # Signature-based payload detection
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if match_signature(payload):
                alerts.append("Signature-based attack detected")

        os.makedirs("data", exist_ok=True)
        with open('data/traffic_data.csv', 'a') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, protocol, packet_size, country, city, latitude, longitude])
        print(f"Logged packet: {src_ip} -> {dst_ip}, Protocol: {protocol}, Size: {packet_size}, Location: {city}, {country}")

        if alerts:
            with open('data/alerts.csv', 'a') as f:
                writer = csv.writer(f)
                for alert in alerts:
                    writer.writerow([timestamp, src_ip, dst_ip, protocol, packet_size, alert, country, city, latitude, longitude])
            print(f"ALERTS: {alerts}")
            for alert in alerts:
                if "anomaly" in alert.lower() or "attack" in alert.lower():
                    print(f"🚫 [SIMULATED BLOCK] Would block IP: {src_ip} (skipping actual block on macOS)")
                    break

# replace the old start_sniffer function with this
from scapy.all import sniff, get_if_list

def start_sniffer(interface: str | None = None):
    """
    Start packet sniffer.
    If `interface` is None, the function will print available interfaces and
    automatically pick a sensible default (Wi-Fi or Ethernet if present).
    """
    print("Starting packet sniffer...")

    # Get available interfaces
    available = get_if_list()
    print("Available interfaces:", available)

    # If user didn't pass an interface, pick a good default
    if not interface:
        # prefer common Windows names
        for preferred_name in ("Wi-Fi", "Ethernet", "Wireless Network Connection", "wlan0", "eth0"):
            if preferred_name in available:
                interface = preferred_name
                break

        # otherwise pick the first non-loopback interface
        if not interface:
            for ifc in available:
                if "loop" not in ifc.lower() and not ifc.lower().startswith("lo"):
                    interface = ifc
                    break

        # fallback to first interface if nothing else
        if not interface and available:
            interface = available[0]

    print(f"Using interface: {interface!r} (change in code if this is wrong)")

    # Try to start sniffing and give useful error messages
    try:
        sniff(iface=interface, prn=log_packet, store=False)
    except ValueError as e:
        print("Error: Interface not found or invalid:", e)
        print("Double-check available interfaces above and set `interface` explicitly.")
    except PermissionError:
        print("PermissionError: You may need to run the script as Administrator (Windows) / root (Linux).")
    except Exception as e:
        print("Unexpected error starting sniffer:", e)
