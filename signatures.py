# thresholds
SYN_FLOOD_THRESHOLD = 1
PORT_SCAN_THRESHOLD = 1
TIME_WINDOW = 10
BLOCK_TIME = 120  

TRUSTED_IPS = {
    "127.0.0.1",
    "192.168.208.1"
}

def is_syn_flood(syn_list):
    return len(syn_list) > SYN_FLOOD_THRESHOLD

def is_port_scan(port_set):
    return len(port_set) > PORT_SCAN_THRESHOLD
