# Creator: proxy082
# license: MIT
import sys

# Pre-execution library check to prevent crashing
try:
    from scapy.all import sniff, DNS, DNSQR, IP
except ImportError:
    print("[!] Error: Scapy library is not installed.")
    print("[!] Please run: pip install scapy")
    sys.exit(1)


# Common DNS Record Types Mapping
RECORD_TYPES = {
    1: "A (IPv4)",
    28: "AAAA (IPv6)",
    15: "MX (Mail)",
    16: "TXT (Text)",
    5: "CNAME (Alias)",
    12: "PTR (Reverse Lookup)",
    2: "NS (Nameserver)",
}


def process_packet(packet):
    """Processes captured UDP packets and extracts DNS query information."""
    # Check if the packet has a DNS layer and is a Request (qr == 0)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        src_ip = packet[IP].src if packet.haslayer(IP) else "Local Machine"

        # Verify DNS Query Record exists
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype_num = packet[DNSQR].qtype
            qtype_str = RECORD_TYPES.get(qtype_num, f"Type {qtype_num}")

            print(f"[+] Client: {src_ip:<15} | Type: {qtype_str:<12} | Domain: {qname}")


def main():
    print("=" * 70)
    print("                   LIVE DNS MONITORING STARTED                   ")
    print("=" * 70)
    print("Listening for outbound/inbound DNS queries on UDP Port 53...")
    print("Press Ctrl+C to stop.\n")

    try:
        # Filter for UDP traffic on port 53 (DNS)
        sniff(filter="udp port 53", store=False, prn=process_packet)
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
    except PermissionError:
        print("\n[!] Permission Denied: Packet sniffing requires Administrator / Root rights.")
        print("    - Windows: Open CMD as Administrator.")
        print("    - Linux/macOS: Run with 'sudo python script_name.py'.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")


if __name__ == "__main__":
    main()