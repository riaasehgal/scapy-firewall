import os
import time
import importlib
import signatures

last_mtime = os.path.getmtime("signatures.py")

def reload_if_changed():
    global last_mtime
    current_mtime = os.path.getmtime("signatures.py")

    if current_mtime != last_mtime:
        importlib.reload(signatures)
        last_mtime = current_mtime
        print("[*] Reloaded signatures.py")
