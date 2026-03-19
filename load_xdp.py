#!/usr/bin/env python3
"""
load_xdp.py - Standalone CLI loader for the XDP DDoS filter.

Usage:
    sudo python3 load_xdp.py [interface]

Example:
    sudo python3 load_xdp.py eth0
"""
import sys
import os
import time

# Ensure the script's directory is on the import path for sibling modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xdp_manager import XDPFilter  # pyre-ignore[21]

if __name__ == "__main__":
    device = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    
    print(f"[*] Starting XDP DDoS Filter on '{device}'...")
    xdp = XDPFilter(device, src_file="xdp_filter.c")
    
    if not xdp.start():
        sys.exit(1)
        
    try:
        print("\n[*] Active Defenses:")
        print("    - ICMP:  Dropping ALL ICMP traffic (ping flood defense)")
        print("    - TCP:   SYN flood rate-limiting (auto-blacklist after 100 SYN/100ms)")
        print("    - Ports: Dynamic port blocking via blocked_ports map")
        print("    - IPs:   Dynamic IP blocking via blocked_ips map")
        print("\n[*] Waiting for packets... Press Ctrl+C to exit.\n")
        
        while True:
            stats = xdp.get_stats()
            
            # Dropped packets
            drops = stats.get("drops", {})
            if drops:
                print("[!] Dropped Packets:")
                for proto, count in drops.items():
                    print(f"    => {proto}: {count} dropped")
            
            # Ingress (allowed)
            ingress = stats.get("ingress", {})
            if ingress:
                print("[+] Allowed Ingress:")
                for proto, count in ingress.items():
                    print(f"    => {proto}: {count} passed")

            # Egress
            egress = stats.get("egress", {})
            if egress:
                print("[^] Egress:")
                for proto, count in egress.items():
                    print(f"    => {proto}: {count} sent")

            # Auto-blacklisted IPs
            blacklist = xdp.get_blacklist()
            active_bl = {ip: info for ip, info in blacklist.items() if info["active"]}
            if active_bl:
                print("[X] Auto-Blacklisted IPs:")
                for ip, info in active_bl.items():
                    print(f"    => {ip} (expires in {info['remaining_seconds']}s)")

            # Manual rules
            rules = xdp.get_blocked_rules()
            if rules["ips"]:
                print(f"[R] Blocked IPs:   {', '.join(rules['ips'])}")
            if rules["ports"]:
                print(f"[R] Blocked Ports: {', '.join(str(p) for p in rules['ports'])}")

            if drops or ingress or egress or active_bl:
                print("---")

            time.sleep(2)
            
    except KeyboardInterrupt:
        pass
    finally:
        xdp.stop()