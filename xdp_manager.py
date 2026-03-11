import time
import os
try:
    from bcc import BPF  # type: ignore
except ImportError:
    BPF = None

class XDPFilter:
    def __init__(self, device="eth0", src_file="xdp_filter.c"):
        self.device = device
        self.src_file = src_file
        self.bpf = None
        self.is_running = False
        
        # Determine the absolute path of the C file relative to this script
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.src_path = os.path.join(self.base_dir, self.src_file)

    def start(self):
        """Compiles and loads the XDP program onto the interface."""
        if BPF is None:
            print("[-] Error: 'bcc' module is not available. Please install 'python3-bpfcc'.")
            return False

        if self.is_running:
            return True

        if not os.path.exists(self.src_path):
            print(f"[-] Error: Source file {self.src_path} not found.")
            return False

        try:
            self.bpf = BPF(src_file=self.src_path)
            
            # Attach XDP for Ingress filtering
            in_fn = self.bpf.load_func("drop_ddos", BPF.XDP)
            # 0 represents default flags
            self.bpf.attach_xdp(self.device, in_fn, 0)
            
            # Attach TC for Egress monitoring
            out_fn = self.bpf.load_func("monitor_egress", BPF.SCHED_CLS)
            # Create a qdisc for a hook point if it doesn't exist
            os.system(f"tc qdisc add dev {self.device} clsact >/dev/null 2>&1")
            # Attach the TC program to the egress hook
            fd = out_fn.fd
            os.system(f"tc filter add dev {self.device} egress bpf da fd {fd} >/dev/null 2>&1")

            self.is_running = True
            print(f"[+] Successfully attached XDP (Ingress) and TC (Egress) programs to {self.device}.")
            return True
        except Exception as e:
            print(f"[-] Failed to attach BPF programs: {e}")
            self.bpf = None
            self.is_running = False
            return False

    def stop(self):
        """Detaches the XDP and TC programs cleanly."""
        if not self.is_running or self.bpf is None:
            return True
            
        print(f"\n[*] Detaching BPF programs from {self.device}...")
        try:
            # Detach XDP
            self.bpf.remove_xdp(self.device, 0)
            
            # Detach TC (flush the clsact qdisc rules)
            os.system(f"tc qdisc del dev {self.device} clsact >/dev/null 2>&1")
            
            print("[+] BPF programs removed successfully. Normal traffic resumed.")
            self.is_running = False
            return True
        except Exception as e:
            print(f"[-] Failed to detach BPF programs: {e}")
            self.bpf = None
            return False

    def get_stats(self):
        """Polls the BPF maps and returns human-readable stats for drops, ingress, and egress."""
        if not self.is_running or self.bpf is None:
            return {"drops": {}, "ingress": {}, "egress": {}}

        try:
            drop_map = self.bpf.get_table("protocol_drops")
            ingress_map = self.bpf.get_table("protocol_ingress")
            egress_map = self.bpf.get_table("protocol_egress")
            
            stats = {"drops": {}, "ingress": {}, "egress": {}}
            
            def read_map(bpf_map, target_dict):
                if len(bpf_map) > 0:
                    for key, value in bpf_map.items():
                        proto_val = key.value
                        proto_name = "ICMP" if proto_val == 1 else \
                                     "TCP"  if proto_val == 6 else \
                                     "UDP"  if proto_val == 17 else \
                                     f"Protocol {proto_val}"
                        target_dict[proto_name] = value.value
                        
            read_map(drop_map, stats["drops"])
            read_map(ingress_map, stats["ingress"])
            read_map(egress_map, stats["egress"])
            
            return stats
        except Exception as e:
            # Table might fail to read if BPF context is lost
            return {"drops": {}, "ingress": {}, "egress": {}}
