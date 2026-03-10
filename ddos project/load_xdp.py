#!/usr/bin/python3
from bcc import BPF  # type: ignore
import time
import sys

# Validate arguments
device = sys.argv[1] if len(sys.argv) > 1 else "eth0"

print(f"[*] Compiling and loading XDP program on interface {device}...")

# Load the eBPF program from the C file
b = BPF(src_file="xdp_filter.c")

# Retrieve the function to be attached as an XDP program
in_fn = b.load_func("drop_ddos", BPF.XDP)

# Attach to the network interface using XDP
# 0 represents default flags (often Generic XDP/SKB mode if driver mode is unsupported natively)
try:
    b.attach_xdp(device, in_fn, 0)
    print(f"[+] Successfully attached XDP program to {device}.")
    print("\n[*] Active Defenses:")
    print("    - Dropping ALL ICMP Traffic (Ping flood defense)")
    print("    - Dropping ALL UDP Traffic (UDP flood defense)")
    print("    - Dropping TCP SYN to Port 80 (TCP SYN flood defense)")
    print("\n[*] Waiting for packets... Press Ctrl+C to exit and detach the program.")

    while True:
        try:
            # Poll the statistics from the BPF Hash Map named "protocol_drops"
            drop_map = b.get_table("protocol_drops")
            if len(drop_map) > 0:
                print("\n[!] Dropped Packet Statistics:")
                for key, value in drop_map.items():
                    # Map IP protocol number to human readable string
                    proto = "ICMP" if key.value == 1 else "TCP" if key.value == 6 else "UDP" if key.value == 17 else f"Protocol {key.value}"
                    print(f"    => {proto}: {value.value} packets dropped")
            time.sleep(2)
        except KeyboardInterrupt:
            break

finally:
    # Always cleanly detach the XDP program on exit mapping sure not to leave the NIC locked
    print(f"\n[*] Detaching XDP program from {device}...")
    try:
        b.remove_xdp(device, 0)
        print("[+] XDP program removed successfully. Normal traffic resumed.")
    except Exception as e:
        print(f"[-] Failed to detach XDP program: {e}")
