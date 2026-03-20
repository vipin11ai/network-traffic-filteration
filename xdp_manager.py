import time
import os
import ipaddress
import struct
from typing import Any

try:
    from bcc import BPF  # type: ignore
except ImportError:
    BPF = None

class XDPFilter:
    def __init__(self, device: str = "eth0", src_file: str = "xdp_filter.c") -> None:
        self.device = device
        self.src_file = src_file
        self.bpf: Any = None
        self.is_running = False
        
        # State for PPS calculation
        self._last_stats: dict = {"drops": {}, "ingress": {}, "egress": {}}
        self._last_time: float = 0.0
        self._pps: dict = {"drops": {}, "ingress": {}, "egress": {}}
        
        # Determine the absolute path of the C file relative to this script
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.src_path = os.path.join(self.base_dir, self.src_file)

    def start(self) -> bool:
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
            compat_header = os.path.join(self.base_dir, "bcc_compat.h")
            cflags = [
                "-Wno-unknown-warning-option", 
                "-Wno-duplicate-decl-specifier", 
                "-Wno-gnu-variable-sized-type-not-at-end",
                "-include", compat_header
            ]
            self.bpf = BPF(src_file=self.src_path, cflags=cflags)
                        # Attach XDP for Ingress filtering
            in_fn = self.bpf.load_func("drop_ddos", BPF.XDP)
            self.bpf.attach_xdp(self.device, in_fn, 0)
            
            # Attach TC for Egress monitoring
            out_fn = self.bpf.load_func("monitor_egress", BPF.SCHED_CLS)
            os.system(f"tc qdisc add dev {self.device} clsact >/dev/null 2>&1")
            fd = out_fn.fd
            os.system(f"tc filter add dev {self.device} egress bpf da fd {fd} >/dev/null 2>&1")

            self.is_running = True
            print(f"[+] Successfully attached XDP (Ingress) and TC (Egress) programs to {self.device}.")
            return True
        except Exception as e:
            error_msg = f"[-] Failed to attach BPF programs: {e}"
            print(error_msg)
            try:
                with open(os.path.join(self.base_dir, "xdp_error.log"), "w") as f:
                    f.write(str(e))
            except:
                pass
            self.bpf = None
            self.is_running = False
            return False

    def stop(self) -> bool:
        """Detaches the XDP and TC programs cleanly."""
        if not self.is_running or self.bpf is None:
            return True
            
        print(f"\n[*] Detaching BPF programs from {self.device}...")
        try:
            self.bpf.remove_xdp(self.device, 0)
            os.system(f"tc qdisc del dev {self.device} clsact >/dev/null 2>&1")
            
            print("[+] BPF programs removed successfully. Normal traffic resumed.")
            self.is_running = False
            return True
        except Exception as e:
            print(f"[-] Failed to detach BPF programs: {e}")
            self.bpf = None
            return False

    # ==================== Dynamic Rule Management ====================

    def block_ip(self, ip_str: str) -> bool:
        """Adds an IP address to the blocked_ips map."""
        if not self.is_running or self.bpf is None:
            return False
        try:
            ip_int = struct.unpack("I", ipaddress.IPv4Address(ip_str).packed)[0]
            tbl = self.bpf.get_table("blocked_ips")
            tbl[tbl.Key(ip_int)] = tbl.Leaf(0)
            print(f"[+] Blocked IP: {ip_str}")
            return True
        except Exception as e:
            print(f"[-] Failed to block IP {ip_str}: {e}")
            return False

    def unblock_ip(self, ip_str: str) -> bool:
        """Removes an IP address from the blocked_ips map."""
        if not self.is_running or self.bpf is None:
            return False
        try:
            ip_int = struct.unpack("I", ipaddress.IPv4Address(ip_str).packed)[0]
            tbl = self.bpf.get_table("blocked_ips")
            del tbl[tbl.Key(ip_int)]
            print(f"[+] Unblocked IP: {ip_str}")
            return True
        except Exception as e:
            print(f"[-] Failed to unblock IP {ip_str}: {e}")
            return False

    def block_port(self, port: int) -> bool:
        """Adds a port to the blocked_ports map."""
        if not self.is_running or self.bpf is None:
            return False
        try:
            port = int(port)
            tbl = self.bpf.get_table("blocked_ports")
            tbl[tbl.Key(port)] = tbl.Leaf(0)
            print(f"[+] Blocked Port: {port}")
            return True
        except Exception as e:
            print(f"[-] Failed to block port {port}: {e}")
            return False

    def unblock_port(self, port: int) -> bool:
        """Removes a port from the blocked_ports map."""
        if not self.is_running or self.bpf is None:
            return False
        try:
            port = int(port)
            tbl = self.bpf.get_table("blocked_ports")
            del tbl[tbl.Key(port)]
            print(f"[+] Unblocked Port: {port}")
            return True
        except Exception as e:
            print(f"[-] Failed to unblock port {port}: {e}")
            return False

    # ==================== Stats & Visibility ====================

    def get_blocked_rules(self) -> dict:
        """Returns the current list of manually blocked IPs and Ports."""
        if not self.is_running or self.bpf is None:
            return {"ips": [], "ports": []}
        
        ips = []
        for key in self.bpf["blocked_ips"].keys():
            ips.append(str(ipaddress.IPv4Address(struct.pack("I", key.value))))
            
        ports = [key.value for key in self.bpf["blocked_ports"].keys()]
        
        return {"ips": ips, "ports": ports}

    def get_blacklist(self) -> dict:
        """Returns auto-blacklisted IPs from rate limiting with remaining block time."""
        if not self.is_running or self.bpf is None:
            return {}
        
        try:
            now_ns = time.time_ns()
            bl_map = self.bpf.get_table("blacklist_map")
            result = {}
            for key, value in bl_map.items():
                ip_str = str(ipaddress.IPv4Address(struct.pack("I", key.value)))
                blocked_until = value.blocked_until
                remaining_s = max(0, (blocked_until - now_ns) / 1e9)
                result[ip_str] = {
                    "remaining_seconds": round(remaining_s, 1),
                    "active": remaining_s > 0
                }
            return result
        except Exception as e:
            print(f"[-] Error reading blacklist: {e}")
            return {}

    def get_stats(self) -> dict:
        """Polls all BPF maps and returns stats for drops, ingress, egress, and rules."""
        if not self.is_running or self.bpf is None:
            return {"drops": {}, "ingress": {}, "egress": {}, "blocked_ips": {}, "blocked_ports": {}}

        try:
            drop_map = self.bpf.get_table("protocol_drops")
            ingress_map = self.bpf.get_table("protocol_ingress")
            egress_map = self.bpf.get_table("protocol_egress")
            blocked_ips_map = self.bpf.get_table("blocked_ips")
            blocked_ports_map = self.bpf.get_table("blocked_ports")
            
            stats = {"drops": {}, "ingress": {}, "egress": {}, "blocked_ips": {}, "blocked_ports": {}}
            
            def _proto_name(val: int) -> str:
                return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(val, f"Protocol {val}")

            def read_proto_map(bpf_map: Any, target_dict: dict) -> None:
                for key, value in bpf_map.items():
                    target_dict[_proto_name(key.value)] = value.value
            
            def read_ip_map(bpf_map: Any, target_dict: dict) -> None:
                for key, value in bpf_map.items():
                    ip_str = str(ipaddress.IPv4Address(struct.pack("I", key.value)))
                    target_dict[ip_str] = value.value

            def read_port_map(bpf_map: Any, target_dict: dict) -> None:
                for key, value in bpf_map.items():
                    target_dict[str(key.value)] = value.value
                        
            read_proto_map(drop_map, stats["drops"])
            read_proto_map(ingress_map, stats["ingress"])
            read_proto_map(egress_map, stats["egress"])
            read_ip_map(blocked_ips_map, stats["blocked_ips"])
            read_port_map(blocked_ports_map, stats["blocked_ports"])
            
            # --- PPS Calculation ---
            now = time.time()
            dt = now - self._last_time
            if self._last_time > 0 and dt > 0:
                for category in ("drops", "ingress", "egress"):
                    for proto, current_count in stats[category].items():
                        last_count = self._last_stats[category].get(proto, 0)
                        rate = max(0, (current_count - last_count) / dt)
                        self._pps[category][proto] = int(rate)
            
            self._last_stats = {
                "drops": dict(stats["drops"]),
                "ingress": dict(stats["ingress"]),
                "egress": dict(stats["egress"])
            }
            self._last_time = now
            
            stats["pps"] = self._pps
            return stats
        except Exception as e:
            print(f"[-] Error reading stats: {e}")
            return {"drops": {}, "ingress": {}, "egress": {}, "blocked_ips": {}, "blocked_ports": {}, "pps": {"drops": {}, "ingress": {}, "egress": {}}}

    def get_top_ips(self, limit: int = 5) -> list:
        """Returns the top talkers by packet count."""
        if not self.is_running or self.bpf is None:
            return []
            
        try:
            ip_map = self.bpf.get_table("ip_packet_counts")
            counts = {}
            for key, value in ip_map.items():
                ip_str = str(ipaddress.IPv4Address(struct.pack("I", key.value)))
                counts[ip_str] = value.value
                
            # Sort by count descending and take top 'limit'
            sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:limit]  # pyre-ignore[16]
        except Exception as e:
            print(f"[-] Error reading ip_packet_counts: {e}")
            return []

    def get_attack_status(self) -> str:
        """Infers current attack status based on PPS drop rates."""
        drop_pps = self._pps.get("drops", {})
        
        tcp_drops = drop_pps.get("TCP", 0)
        icmp_drops = drop_pps.get("ICMP", 0)
        udp_drops = drop_pps.get("UDP", 0)
        
        if tcp_drops > 1000:
            return "UNDER ATTACK (TCP SYN Flood)"
        elif icmp_drops > 50:
            return "UNDER ATTACK (ICMP Ping Flood)"
        elif udp_drops > 1000:
            return "UNDER ATTACK (UDP Flood)"
        elif sum(drop_pps.values()) > 500:
            return "UNDER ATTACK (Distributed Flood)"
            
        return "NORMAL"