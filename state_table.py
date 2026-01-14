from collections import defaultdict
import time

syn_counter = defaultdict(list)      
port_counter = defaultdict(set)      
blocked_ips = {}                    

def cleanup(counter, now, window):
    return [t for t in counter if now - t <= window]
