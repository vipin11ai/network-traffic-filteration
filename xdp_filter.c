#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// BPF Map to count dropped packets per IP protocol (e.g., TCP, UDP, ICMP)
BPF_HASH(protocol_drops, u32, u64);

// BPF Map to count incoming (passed) packets per IP protocol
BPF_HASH(protocol_ingress, u32, u64);

// BPF Map to count outgoing (egress) packets per IP protocol
BPF_HASH(protocol_egress, u32, u64);

int drop_ddos(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS; // Packet too short to be valid, let the networking stack handle it

    // Only process IPv4 packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS; 

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;
        
    u32 protocol = ip->protocol;

    // RULE 1: Drop all ICMP (Ping Flood Defense against `hping3 --icmp`)
    if (protocol == IPPROTO_ICMP) {
        u64 *val = protocol_drops.lookup(&protocol);
        u64 cur_val = 1;
        if (val) {
            cur_val = *val + 1;
        }
        protocol_drops.update(&protocol, &cur_val);
        return XDP_DROP;
    }

    // RULE 2: Drop all UDP (UDP Flood Defense against `hping3 --udp`)
    // Warning: Drops all UDP. In production, you'd allow specific ports like DNS (53)
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
            
        u64 *val = protocol_drops.lookup(&protocol);
        u64 cur_val = 1;
        if (val) {
            cur_val = *val + 1;
        }
        protocol_drops.update(&protocol, &cur_val);
        return XDP_DROP;
    }

    // RULE 3: Basic TCP SYN Flood Defense against `hping3 -S`
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
            
        // If it's a TCP SYN packet (no ACK flag) targeting a vulnerable port (e.g., 80)
        // This is a naive check; advanced setups use BPF SYN Cookies or rate limit per Source IP.
        if (tcp->syn && !tcp->ack && tcp->dest == htons(80)) {
            u64 *val = protocol_drops.lookup(&protocol);
            u64 cur_val = 1;
            if (val) {
                cur_val = *val + 1;
            }
            protocol_drops.update(&protocol, &cur_val);
            return XDP_DROP;
        }
    }

    // Record incoming allowed packet
    u64 *val = protocol_ingress.lookup(&protocol);
    u64 cur_val = 1;
    if (val) {
        cur_val = *val + 1;
    }
    protocol_ingress.update(&protocol, &cur_val);

    return XDP_PASS; // Allow all other benign traffic
}

// Intercepts outgoing packets at the Traffic Control (TC) layer
int monitor_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return 0; // TC_ACT_OK equivalent for bcc

    if (eth->h_proto != htons(ETH_P_IP))
        return 0; 

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return 0;

    u32 protocol = ip->protocol;

    // Record outgoing packet
    u64 *val = protocol_egress.lookup(&protocol);
    u64 cur_val = 1;
    if (val) {
        cur_val = *val + 1;
    }
    protocol_egress.update(&protocol, &cur_val);

    return 0; // Allow traffic to go out
}
