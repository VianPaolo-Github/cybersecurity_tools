import argparse
import json
import re
import socket
import struct
import sys
from datetime import datetime

# Known initial TTL mappings
TTL_MAP = {
    64: "Linux / Android / macOS / iOS",
    128: "Windows",
    255: "Cisco / Network Hardware"
}

# Common MAC OUI prefixes (First 3 bytes)
OUI_MAP = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "3C:22:FB": "Apple",
    "00:1A:11": "Google"
}

device_database = {}

def estimate_initial_ttl(ttl):
    """Estimates the original TTL prior to network hop decrements."""
    if ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 255

def get_mac_oui(mac_str):
    """Extracts manufacturer OUI from a MAC address string."""
    prefix = mac_str.upper()[:8]
    return OUI_MAP.get(prefix, "Unknown Manufacturer")

def parse_user_agent(payload):
    """Parses user-agent string from HTTP GET/POST payload."""
    try:
        text = payload.decode('utf-8', errors='ignore')
        for line in text.split('\r\n'):
            if line.lower().startswith("user-agent:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None

def update_device_profile(ip, ttl, window_size, user_agent=None, mac=None):
    """Aggregates fingerprint data into an active device record."""
    if ip not in device_database:
        device_database[ip] = {
            "first_seen": datetime.now().isoformat(),
            "estimated_os": "Unknown",
            "ttl_observed": ttl,
            "tcp_window": window_size,
            "mac_address": mac or "N/A",
            "hardware_vendor": "Unknown",
            "user_agents": []
        }

    record = device_database[ip]
    est_ttl = estimate_initial_ttl(ttl)
    record["estimated_os"] = TTL_MAP.get(est_ttl, "Unknown OS")
    record["ttl_observed"] = ttl
    record["tcp_window"] = window_size

    if mac:
        record["mac_address"] = mac
        record["hardware_vendor"] = get_mac_oui(mac)

    if user_agent and user_agent not in record["user_agents"]:
        record["user_agents"].append(user_agent)

    print(f"[PROFILE UPDATED] IP: {ip} | OS Hint: {record['estimated_os']} | Vendor: {record['hardware_vendor']}")

def unpack_ipv4_header(data):
    version_header_len = data[0]
    header_length = (version_header_len & 15) * 4
    ttl, proto, src_bytes, dst_bytes = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = socket.inet_ntoa(src_bytes)
    dst_ip = socket.inet_ntoa(dst_bytes)
    return ttl, proto, src_ip, dst_ip, data[header_length:]

def unpack_tcp_header(data):
    src_port, dst_port, seq, ack, offset_reserved_flags, window_size = struct.unpack('! H H L L H H', data[:16])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dst_port, window_size, data[offset:]

def start_passive_fingerprinter(interface_ip):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((interface_ip, 0))
    except PermissionError:
        print("[!] PERMISSION ERROR: Run as Administrator / root.")
        sys.exit(1)

    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if sys.platform == "win32":
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Passive Device Profiler Running on {interface_ip}...\n")

    try:
        while True:
            raw_data, _ = conn.recvfrom(65535)
            if len(raw_data) >= 20:
                ttl, proto, src_ip, dst_ip, tcp_raw = unpack_ipv4_header(raw_data)

                if proto == 6 and len(tcp_raw) >= 16:
                    src_port, dst_port, window_size, payload = unpack_tcp_header(tcp_raw)
                    ua = parse_user_agent(payload) if payload else None
                    update_device_profile(src_ip, ttl, window_size, user_agent=ua)

    except KeyboardInterrupt:
        print("\n[*] Stopping Profiler. Exporting Device Inventory...")
        with open("device_inventory.json", "w") as f:
            json.dumps(device_database, f, indent=4)
        print("[*] Device profiles saved to 'device_inventory.json'.")

if __name__ == "__main__":
    active_ip = socket.gethostbyname(socket.gethostname())
    start_passive_fingerprinter(active_ip)