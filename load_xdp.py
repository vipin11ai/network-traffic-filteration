import sys
from xdp_manager import XDPFilter
import time

if __name__ == "__main__":
    device = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    
    print(f"[*] Starting XDP Filter standalone on {device}...")
    xdp = XDPFilter(device, src_file="xdp_filter.c")
    
    if not xdp.start():
        sys.exit(1)
        
    try:
        print("\n[*] Active Defenses:")
        print("    - Dropping ALL ICMP Traffic (Ping flood defense)")
        print("    - Dropping ALL UDP Traffic (UDP flood defense)")
        print("    - Dropping TCP SYN to Port 80 (TCP SYN flood defense)")
        print("\n[*] Waiting for packets... Press Ctrl+C to exit and detach the program.")
        
        while True:
            stats = xdp.get_stats()
            if stats:
                print("\n[!] Dropped Packet Statistics:")
                for proto, count in stats.items():
                    print(f"    => {proto}: {count} packets dropped")
            time.sleep(2)
            
    except KeyboardInterrupt:
        pass
    finally:
        xdp.stop()
