#!/usr/bin/env python3
from scapy.all import *
import time
import subprocess
import socket

import state_table as st
import signatures as sig
from logger import info, alert
from reloader import reload_if_changed

DRY_RUN = True #only change to False if not test environment
INTERFACE = "ens33"

def get_my_ip():
    """Finds the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

MY_IP = get_my_ip()
info(f"[*] Firewall protecting IP: {MY_IP}")

def block_ip(ip):
    if ip in st.blocked_ips:
        return

    unblock_time = time.time() + sig.BLOCK_TIME
    st.blocked_ips[ip] = unblock_time

    alert(f"[BLOCK] {ip} for {sig.BLOCK_TIME}s")

    if not DRY_RUN:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=False
        )

def unblock_expired():
    now = time.time()
    for ip in list(st.blocked_ips.keys()):
        if now > st.blocked_ips[ip]:
            info(f"[UNBLOCK] {ip}")
            if not DRY_RUN:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=False
                )
            del st.blocked_ips[ip]

def packet_handler(pkt):
    reload_if_changed()
    unblock_expired()

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    src = pkt[IP].src
    if src in st.blocked_ips:
        return

    dst = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    flags = pkt[TCP].flags
   
    if src == MY_IP:
        return
        
    if dst != MY_IP:
        return

    if src in sig.TRUSTED_IPS or dport == 22 or sport == 22:
        return

    now = time.time()

    if flags == "S":
        st.syn_counter[src].append(now)
        st.syn_counter[src] = st.cleanup(st.syn_counter[src], now, sig.TIME_WINDOW)

        if sig.is_syn_flood(st.syn_counter[src]):
            alert(f"[ALERT] SYN flood detected from {src}")
            block_ip(src)
        st.port_counter[src].add(dport)
        if sig.is_port_scan(st.port_counter[src]):
            alert(f"[ALERT] Port scan detected from {src}")
            block_ip(src)

    if src not in st.blocked_ips:
        info(pkt.summary())

if __name__ == "__main__":
    info(f"[*] Scapy Stateful Firewall Started on {INTERFACE}")
    sniff(iface=INTERFACE, filter="tcp", prn=packet_handler, store=0)