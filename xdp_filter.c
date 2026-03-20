// clang-diagnostic: This file is a BCC (BPF Compiler Collection) program.
// It uses BCC-specific includes (uapi/linux/*), macros (BPF_HASH), and
// method-call syntax (.lookup(), .update()) that are NOT standard C.
// IDE/clang errors in this file are expected and do not affect BCC compilation.
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#ifndef KBUILD_MODNAME
/* 
 * IDE Compatibility Layer:
 * This block is ONLY for the IDE's benefit. It mocks BCC-specific syntax 
 * that would otherwise cause syntax errors in common C analyzers.
 */
#include <linux/types.h>
#include <linux/bpf.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

#define BPF_HASH(name, key_type, leaf_type) \
    struct { \
        leaf_type* (*lookup)(key_type*); \
        int (*update)(key_type*, leaf_type*); \
        int (*delete)(key_type*); \
    } name

#define BPF_ARRAY(name, leaf_type, size) \
    struct { \
        leaf_type* (*lookup)(int*); \
        int (*update)(int*, leaf_type*); \
    } name

/* Mock Kernel Helpers */
static inline u64 bpf_ktime_get_ns() { return 0; }

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#define XDP_DROP 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#endif

#define htons(x) (x)
#define ntohs(x) (x)

#endif /* KBUILD_MODNAME */

/* ===================== CONFIG ===================== */

// Max SYN packets allowed per IP in time window
#define THRESHOLD 100

// Time window = 100ms (faster detection of bursts)
#define TIME_WINDOW_NS 100000000

// Blacklist duration = 10 seconds
#define BLACKLIST_TIME_NS 10000000000ULL

/* ===================== STRUCTS ===================== */

struct rate_limit_entry {
    u64 last_update;
    u32 packet_count;
};

struct blacklist_entry {
    u64 blocked_until;
};

/* ===================== MAPS ===================== */

// Original maps needed by xdp_manager.py
BPF_HASH(protocol_drops, u32, u64);
BPF_HASH(blocked_ips, u32, u64);
BPF_HASH(blocked_ports, u16, u64);
BPF_HASH(protocol_ingress, u32, u64);
BPF_HASH(protocol_egress, u32, u64);

// Advanced maps for rate limiting and blacklisting
BPF_HASH(rate_limit_map, u32, struct rate_limit_entry);
BPF_HASH(blacklist_map, u32, struct blacklist_entry);

// Attacker Intelligence: Global count of packets per source IP
BPF_HASH(ip_packet_counts, u32, u64);

/* ===================== MAIN XDP FUNCTION ===================== */

int drop_ddos(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; 

    // Only process IPv4 packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS; 

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    u32 src_ip = ip->saddr;
    u32 protocol = ip->protocol;
    u32 ihl = ip->ihl * 4;

    // Safety check for IP header length (handles IP options)
    if ((void *)ip + ihl > data_end)
        return XDP_PASS;

    u64 now = bpf_ktime_get_ns();

    // --- Threat Intelligence: Record all incoming packets per IP ---
    u64 *count = ip_packet_counts.lookup(&src_ip);
    u64 new_count = 1;
    if (count) new_count = *count + 1;
    ip_packet_counts.update(&src_ip, &new_count);

    // --- Dynamic Rule Check: Blocked IPs (PRIORITY 1) ---
    u64 *ip_drop_count = blocked_ips.lookup(&src_ip);
    if (ip_drop_count) {
        u64 cur_val = *ip_drop_count + 1;
        blocked_ips.update(&src_ip, &cur_val);
        
        u64 *proto_drop_count = protocol_drops.lookup(&protocol);
        u64 proto_val = 1;
        if (proto_drop_count) proto_val = *proto_drop_count + 1;
        protocol_drops.update(&protocol, &proto_val);
        return XDP_DROP;
    }

    // --- Advanced Blacklist Check ---
    struct blacklist_entry *bl = blacklist_map.lookup(&src_ip);
    if (bl && now < bl->blocked_until) {
        u64 *proto_drop_count = protocol_drops.lookup(&protocol);
        u64 proto_val = 1;
        if (proto_drop_count) proto_val = *proto_drop_count + 1;
        protocol_drops.update(&protocol, &proto_val);
        return XDP_DROP;
    }

    // --- Dynamic Rule Check: Blocked Ports (PRIORITY 2) ---
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        u16 dest_port = 0;
        if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ihl;
            if ((void *)(udp + 1) <= data_end) {
                dest_port = ntohs(udp->dest);
            }
        } else {
            struct tcphdr *tcp = (void *)ip + ihl;
            if ((void *)(tcp + 1) <= data_end) {
                dest_port = ntohs(tcp->dest);
            }
        }

        if (dest_port > 0) {
            u64 *port_drop_count = blocked_ports.lookup(&dest_port);
            if (port_drop_count) {
                u64 cur_val = *port_drop_count + 1;
                blocked_ports.update(&dest_port, &cur_val);
                
                u64 *proto_drop_count = protocol_drops.lookup(&protocol);
                u64 proto_val = 1;
                if (proto_drop_count) proto_val = *proto_drop_count + 1;
                protocol_drops.update(&protocol, &proto_val);
                return XDP_DROP;
            }
        }
    }

    // --- Policy Rules (PRIORITY 3) ---
    
    // Policy: Drop all ICMP to prevent Ping Floods
    if (protocol == IPPROTO_ICMP) {
        u64 *val = protocol_drops.lookup(&protocol);
        u64 cur_val = 1;
        if (val) cur_val = *val + 1;
        protocol_drops.update(&protocol, &cur_val);
        return XDP_DROP;
    }

    // Policy: SYN Flood Detection and Rate Limiting
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) <= data_end) {
            // Check for valid SYN (SYN set, ACK not set)
            if (tcp->syn && !tcp->ack) {
                // Rate limiting logic
                struct rate_limit_entry *entry = rate_limit_map.lookup(&src_ip);
                if (entry) {
                    if (now - entry->last_update < TIME_WINDOW_NS) {
                        entry->packet_count++;
                        if (entry->packet_count > THRESHOLD) {
                            // Move to blacklist
                            struct blacklist_entry new_bl = { .blocked_until = now + BLACKLIST_TIME_NS };
                            blacklist_map.update(&src_ip, &new_bl);
                            
                            u64 *val = protocol_drops.lookup(&protocol);
                            u64 cur_val = 1;
                            if (val) cur_val = *val + 1;
                            protocol_drops.update(&protocol, &cur_val);
                            return XDP_DROP;
                        }
                    } else {
                        entry->last_update = now;
                        entry->packet_count = 1;
                    }
                } else {
                    struct rate_limit_entry new_entry = { .last_update = now, .packet_count = 1 };
                    rate_limit_map.update(&src_ip, &new_entry);
                }
            }
        }
    }

    // Record incoming allowed packet
    u64 *val = protocol_ingress.lookup(&protocol);
    u64 cur_val = 1;
    if (val) cur_val = *val + 1;
    protocol_ingress.update(&protocol, &cur_val);

    return XDP_PASS; 
}

// Intercepts outgoing packets at the Traffic Control (TC) layer
int monitor_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0; 

    if (eth->h_proto != htons(ETH_P_IP))
        return 0; 

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    u32 ihl = ip->ihl * 4;
    if ((void *)ip + ihl > data_end)
        return 0;

    u32 protocol = ip->protocol;

    // Record outgoing packet
    u64 *val = protocol_egress.lookup(&protocol);
    u64 cur_val = 1;
    if (val) cur_val = *val + 1;
    protocol_egress.update(&protocol, &cur_val);

    return 0; 
}