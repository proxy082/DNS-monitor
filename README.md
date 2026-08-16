# DNS-monitor

A simple python program that works using <a href="https://en.wikipedia.org/wiki/Scapy">Scapy</a> to live-sniff DNS queries (UDP port 53) and prints client IP, query type and domain name.

## Features
- Captures DNS requests on UDP port 53
- Prints:
  - Client (source IP)
  - DNS record type (A, AAAA, MX, TXT, CNAME, PTR, NS, etc.)
  - Queried domain name
- Runs until you stop it (Ctrl+C)

# Requirements
- Python 3.x
- Scapy
### Install dependency

Run:

```bash
pip install scapy
```
### Update python 

Run:
```bash
python --version
pip --upgrade
```
