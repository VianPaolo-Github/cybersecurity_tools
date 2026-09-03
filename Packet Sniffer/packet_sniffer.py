import socket
import struct
import sys

def get_active_internet_ip():
    """Finds the specific local IP address used to reach the internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connects to public DNS (does not send packets) to find active interface
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
    except Exception:
        active_ip = "127.0.0.1"
    finally:
        s.close()
    return active_ip

def unpack_ipv4_header(data):
    version_header_len = data[0]
    header_length = (version_header_len & 15) * 4
    ttl, proto, src_bytes, dst_bytes = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = socket.inet_ntoa(src_bytes)
    dst_ip = socket.inet_ntoa(dst_bytes)
    return proto, src_ip, dst_ip, data[header_length:]

def unpack_tcp_header(data):
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    return src_port, dst_port, flags, data[offset:]

def start_windows_raw_sniffer():
    target_ip = get_active_internet_ip()
    print(f"[*] Auto-detected active internet interface IP: {target_ip}")

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((target_ip, 0))
    except PermissionError:
        print("\n[!] PERMISSION ERROR: Run VS Code / PowerShell as Administrator.")
        sys.exit(1)

    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Sniffer Active on {target_ip}. Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, _ = conn.recvfrom(65535)
            if len(raw_data) >= 20:
                proto, src_ip, dst_ip, tcp_raw = unpack_ipv4_header(raw_data)
                
                # Protocol 6 = TCP, Protocol 17 = UDP, Protocol 1 = ICMP
                if proto == 6 and len(tcp_raw) >= 14:
                    src_port, dst_port, flags, payload = unpack_tcp_header(tcp_raw)
                    print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Flags: {bin(flags)} | Payload: {len(payload)}B")
                elif proto == 17:
                    print(f"[UDP] {src_ip} -> {dst_ip} | Length: {len(tcp_raw)}B")
                elif proto == 1:
                    print(f"[ICMP/Ping] {src_ip} -> {dst_ip}")

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()

if __name__ == "__main__":
    start_windows_raw_sniffer()