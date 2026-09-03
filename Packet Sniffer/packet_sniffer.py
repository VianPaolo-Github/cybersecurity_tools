import argparse
import json
import socket
import struct
import sys
from datetime import datetime

'''
!!!!!HOW TO USE!!!!!
RUN AS ADMINISTRATOR!!!

EXAMPLES:
FILTER BY PORT 80: python packet_sniffer.py --port 80

FILTER BY SPECIFIC IP ADDRESS: python packet_sniffer.py --ip [target_ip_here]

FILTER PORT 443 AND SAVE LOGS TO FILE: python packet_sniffer.py --port 443 --log capture.json

'''



# Protocol service lookup dictionary
KNOWN_SERVICES = {
    80: "HTTP",
    443: "HTTPS/TLS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}

def get_active_internet_ip():
    """Finds the specific local IP address used to reach the internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
    except Exception:
        active_ip = "127.0.0.1"
    finally:
        s.close()
    return active_ip

def unpack_ipv4_header(data):
    """Unpacks raw IPv4 packet header."""
    version_header_len = data[0]
    header_length = (version_header_len & 15) * 4
    ttl, proto, src_bytes, dst_bytes = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = socket.inet_ntoa(src_bytes)
    dst_ip = socket.inet_ntoa(dst_bytes)
    return proto, src_ip, dst_ip, data[header_length:]

def unpack_tcp_header(data):
    """Unpacks raw TCP segment header."""
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    return src_port, dst_port, flags, data[offset:]

def parse_tcp_flags(flags):
    """Decodes raw TCP flag bitmask into human-readable labels."""
    flag_list = []
    if flags & 0x002: flag_list.append("SYN")
    if flags & 0x010: flag_list.append("ACK")
    if flags & 0x008: flag_list.append("PSH")
    if flags & 0x001: flag_list.append("FIN")
    if flags & 0x004: flag_list.append("RST")
    if flags & 0x020: flag_list.append("URG")
    return ",".join(flag_list) if flag_list else "NONE"

def get_service_name(src_port, dst_port):
    """Maps source or destination port to known network service."""
    return KNOWN_SERVICES.get(src_port) or KNOWN_SERVICES.get(dst_port) or "TCP"

def parse_http_payload(payload):
    """Extracts cleartext HTTP request line, Host header, or response status."""
    try:
        text = payload.decode('utf-8', errors='ignore')
        lines = text.split('\r\n')
        first_line = lines[0]
        
        methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")
        if any(first_line.startswith(m) for m in methods):
            host = "Unknown"
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
            return f"[HTTP Request] {first_line} | Host: {host}"
        elif first_line.startswith("HTTP/"):
            return f"[HTTP Response] {first_line}"
    except Exception:
        pass
    return None

def parse_tls_sni(payload):
    """Extracts Server Name Indication (SNI) domain from TLS Client Hello packets."""
    if len(payload) < 43:
        return None
    if payload[0] == 0x16 and payload[5] == 0x01:
        try:
            idx = 43
            if idx >= len(payload): return None
            session_id_len = payload[idx]
            idx += 1 + session_id_len
            
            cipher_len = struct.unpack('!H', payload[idx:idx+2])[0]
            idx += 2 + cipher_len
            
            comp_len = payload[idx]
            idx += 1 + comp_len
            
            ext_len = struct.unpack('!H', payload[idx:idx+2])[0]
            idx += 2
            
            ext_end = idx + ext_len
            while idx + 4 <= ext_end and idx <= len(payload) - 4:
                ext_type, e_len = struct.unpack('!HH', payload[idx:idx+4])
                idx += 4
                if ext_type == 0:  # SNI Extension ID
                    server_name_len = struct.unpack('!H', payload[idx+3:idx+5])[0]
                    sni = payload[idx+5:idx+5+server_name_len].decode('ascii', errors='ignore')
                    return f"[TLS SNI] Requested Domain: {sni}"
                idx += e_len
        except Exception:
            pass
    return None

def log_to_file(filepath, record):
    """Appends structured packet log entry to a JSON Lines file."""
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        print("file saved as:", filepath)

def start_windows_raw_sniffer(filter_port=None, filter_ip=None, log_file=None):
    target_ip = get_active_internet_ip()
    print(f"[*] Auto-detected active internet interface IP: {target_ip}")
    if filter_port:
        print(f"[*] Port Filter: {filter_port}")
    if filter_ip:
        print(f"[*] IP Filter: {filter_ip}")
    if log_file:
        print(f"[*] Output Logging: Enabled -> {log_file}")

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((target_ip, 0))
    except PermissionError:
        print("\n[!] PERMISSION ERROR: Run VS Code / PowerShell as Administrator!!!")
        sys.exit(1)

    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Enhanced Sniffer Active on {target_ip}. Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, _ = conn.recvfrom(65535)
            if len(raw_data) >= 20:
                proto, src_ip, dst_ip, tcp_raw = unpack_ipv4_header(raw_data)
                
                # Apply IP Filter if specified (matches source or destination)
                if filter_ip and (src_ip != filter_ip and dst_ip != filter_ip):
                    continue

                if proto == 6 and len(tcp_raw) >= 14:
                    src_port, dst_port, flags, payload = unpack_tcp_header(tcp_raw)
                    
                    # Apply Port Filter if specified (matches source or destination port)
                    if filter_port and (src_port != filter_port and dst_port != filter_port):
                        continue

                    flag_str = parse_tcp_flags(flags)
                    service = get_service_name(src_port, dst_port)
                    
                    http_info = parse_http_payload(payload) if payload else None
                    tls_info = parse_tls_sni(payload) if payload else None
                    app_layer_data = http_info or tls_info or ""

                    log_msg = f"[{service}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: [{flag_str}] | Payload: {len(payload)}B"
                    if app_layer_data:
                        log_msg += f"\n    └─ {app_layer_data}"
                    
                    print(log_msg)

                    # Log structured record to file
                    if log_file:
                        record = {
                            "timestamp": datetime.now().isoformat(),
                            "protocol": service,
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "flags": flag_str,
                            "payload_size": len(payload),
                            "app_data": app_layer_data
                        }
                        log_to_file(log_file, record)

                elif proto == 17 and not filter_port and not filter_ip:
                    print(f"[UDP/DNS] {src_ip} -> {dst_ip} | Length: {len(tcp_raw)}B")
                elif proto == 1 and not filter_port and not filter_ip:
                    print(f"[ICMP/Ping] {src_ip} -> {dst_ip}")

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Windows Raw Socket Sniffer")
    parser.add_argument("-p", "--port", type=int, help="Filter traffic by port (e.g., 80 or 443)")
    parser.add_argument("-i", "--ip", type=str, help="Filter traffic by target IP address")
    parser.add_argument("-l", "--log", type=str, help="Save JSON logs to file (e.g., capture.json)")
    
    args = parser.parse_args()
    start_windows_raw_sniffer(filter_port=args.port, filter_ip=args.ip, log_file=args.log)