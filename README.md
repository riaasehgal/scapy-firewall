# Scapy Stateful Firewall

A Python-based stateful firewall using **Scapy** for packet sniffing and detection of SYN floods and port scans. Designed for educational and experimental purposes.

---

## Features

- Stateful packet inspection using TCP flags
- Detects **SYN flood attacks** and **port scans**
- Blocks malicious IPs for a configurable duration
- Trusted IPs and SSH traffic are ignored
- Hot-reloading of attack signatures from `signatures.py`

---

## Installation

1. Clone the repository:
```
git clone https://github.com/riaasehgal/scapy-firewall.git
cd scapy-firewall
```
2. Install dependencies (requires Python 3):
``` pip install scapy ```

## Configuration
1. signatures.py — configure thresholds for SYN flood, port scan, and block duration.
2. state_table.py — tracks connections and blocked IPs.
3. DRY_RUN — in firewall.py, set to False to actually block IPs using iptables.

## Usage 
Run the firewall:
``` sudo python3 firewall.py ```
In dry run mode, it prints alerts without blocking IPs. In active mode, it blocks IPs via iptables.

## Example Output
```
[*] Scapy Stateful Firewall Started
[ALERT] SYN flood detected from 192.168.208.137
[ALERT] Port scan detected from 192.168.208.137
[BLOCK] 192.168.208.137 for 120s
```

## Screenshots 
<img width="1147" height="236" alt="image" src="https://github.com/user-attachments/assets/2714ebf0-afcc-48d7-89e9-7cc6a7d03df6" />


## Notes
1. Run as root for blocking IPs (`sudo python3 firewall.py`)
2. Test carefully on a VM or isolated network to avoid accidental network disruption.
