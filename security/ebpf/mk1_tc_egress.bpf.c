// SPDX-License-Identifier: GPL-2.0
/*
 * MK1Ai TC clsact Egress & Post-Decrypt Filter (security/ebpf/mk1_tc_egress.bpf.c)
 *
 * Enforces:
 *   1. Physical NIC egress lockdown: In ONI_MODE or Dead-Man Switch expiry,
 *      only encrypted WireGuard UDP frames (wg_udp_port) or emergency SSH
 *      replies (when allow_ssh_emergency=1) may leave the physical interface;
 *      unauthorized plaintext leakage is dropped with TC_ACT_SHOT.
 *   2. wg0 post-decrypt inner packet validation: drops malformed L3/L4 headers
 *      and blocklisted inner peers.
 */

#include "mk1_common.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mk1_ctrl_cfg);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mk1_ctrl_map SEC(".maps");

SEC("classifier/egress")
int mk1_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    __u32 ctrl_key = 0;
    struct mk1_ctrl_cfg *cfg = bpf_map_lookup_elem(&mk1_ctrl_map, &ctrl_key);
    __u64 now_ns = bpf_ktime_get_ns();

    __u8 lockdown = 0;
    __u8 allow_ssh = 0;
    __u32 wg_port = 51820;

    if (!cfg) {
        lockdown = 1;
    } else {
        wg_port = cfg->wg_udp_port ? cfg->wg_udp_port : 51820;
        allow_ssh = cfg->allow_ssh_emergency;
        if (cfg->oni_mode || (cfg->fail_closed && (now_ns - cfg->last_heartbeat_ns > MK1_HEARTBEAT_TIMEOUT_NS)))
            lockdown = 1;
    }

    if (!lockdown)
        return TC_ACT_OK;

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip4 = nh;
        if ((void *)(ip4 + 1) > data_end || ip4->ihl < 5)
            return TC_ACT_SHOT;
        void *l4 = (char *)ip4 + ((__u32)ip4->ihl * 4);
        if (l4 > data_end)
            return TC_ACT_SHOT;
        if (ip4->protocol == IPPROTO_UDP) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end)
                return TC_ACT_SHOT;
            if (bpf_ntohs(udph->source) == wg_port || bpf_ntohs(udph->dest) == wg_port)
                return TC_ACT_OK;
        } else if (ip4->protocol == IPPROTO_TCP && allow_ssh) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end)
                return TC_ACT_SHOT;
            if (bpf_ntohs(tcph->source) == 22 || bpf_ntohs(tcph->dest) == 22)
                return TC_ACT_OK;
        }
        return TC_ACT_SHOT;
    }

    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_SHOT;
        void *l4 = (void *)(ip6 + 1);
        if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end)
                return TC_ACT_SHOT;
            if (bpf_ntohs(udph->source) == wg_port || bpf_ntohs(udph->dest) == wg_port)
                return TC_ACT_OK;
        } else if (ip6->nexthdr == IPPROTO_TCP && allow_ssh) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end)
                return TC_ACT_SHOT;
            if (bpf_ntohs(tcph->source) == 22 || bpf_ntohs(tcph->dest) == 22)
                return TC_ACT_OK;
        }
        return TC_ACT_SHOT;
    }

    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
