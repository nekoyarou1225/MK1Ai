// SPDX-License-Identifier: GPL-2.0
/*
 * MK1Ai Native XDP Ingress Filter (security/ebpf/mk1_xdp_ingress.bpf.c)
 *
 * Remediates all 4 audit findings in MK1AI_XDP_IMPLEMENTATION_READINESS.md:
 *   1. TCP/22 (SSH) is NEVER exempted from token-bucket rate limiting.
 *   2. Full IPv6 LPM blocklist + bounded extension header parsing + ESP/Frag rules.
 *   3. 802.1Q / 802.1ad VLAN ID (VID) validation against allowed_vlan_bitmap.
 *   4. Non-first IPv4/IPv6 fragments and invalid TCP flag combinations are dropped.
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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mk1_blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mk1_blocklist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_bucket);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mk1_src_rate_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct in6_addr);
    __type(value, struct rate_bucket);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mk1_src_rate_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MK1_REASON_MAX);
    __type(key, __u32);
    __type(value, struct mk1_verdict_counter);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mk1_verdict_stats SEC(".maps");

static __always_inline void record_verdict(__u32 reason, __u64 pkt_len)
{
    if (reason >= MK1_REASON_MAX)
        return;
    struct mk1_verdict_counter *ctr = bpf_map_lookup_elem(&mk1_verdict_stats, &reason);
    if (ctr) {
        ctr->packets += 1;
        ctr->bytes += pkt_len;
    }
}

static __always_inline int check_rate_bucket(struct rate_bucket *b, __u64 now_ns)
{
    __u64 elapsed = (now_ns > b->last_ns) ? (now_ns - b->last_ns) : 0;
    __u64 avail = b->tokens_ns + elapsed;
    if (avail > MK1_DEFAULT_BURST_NS)
        avail = MK1_DEFAULT_BURST_NS;
    if (avail < MK1_DEFAULT_RATE_NS_PER_PKT)
        return 0; /* Rate limit exceeded */
    b->tokens_ns = avail - MK1_DEFAULT_RATE_NS_PER_PKT;
    b->last_ns = now_ns;
    return 1;
}

static __always_inline int enforce_v4_rate_limit(__u32 saddr, __u64 now_ns)
{
    struct rate_bucket *b = bpf_map_lookup_elem(&mk1_src_rate_v4, &saddr);
    if (!b) {
        struct rate_bucket init_b = {
            .last_ns = now_ns,
            .tokens_ns = MK1_DEFAULT_BURST_NS - MK1_DEFAULT_RATE_NS_PER_PKT,
        };
        bpf_map_update_elem(&mk1_src_rate_v4, &saddr, &init_b, BPF_ANY);
        return 1;
    }
    return check_rate_bucket(b, now_ns);
}

static __always_inline int enforce_v6_rate_limit(const struct in6_addr *saddr, __u64 now_ns)
{
    struct rate_bucket *b = bpf_map_lookup_elem(&mk1_src_rate_v6, saddr);
    if (!b) {
        struct rate_bucket init_b = {
            .last_ns = now_ns,
            .tokens_ns = MK1_DEFAULT_BURST_NS - MK1_DEFAULT_RATE_NS_PER_PKT,
        };
        bpf_map_update_elem(&mk1_src_rate_v6, saddr, &init_b, BPF_ANY);
        return 1;
    }
    return check_rate_bucket(b, now_ns);
}

static __always_inline int validate_tcp_flags(const struct tcphdr *tcph)
{
    __u8 flags = ((const __u8 *)tcph)[13];
    /* Drop NULL scan (no flags set) */
    if (flags == 0)
        return 0;
    /* Drop SYN+FIN */
    if ((flags & 0x03) == 0x03)
        return 0;
    /* Drop SYN+RST */
    if ((flags & 0x06) == 0x06)
        return 0;
    /* Drop FIN+RST */
    if ((flags & 0x05) == 0x05)
        return 0;
    /* Drop XMAS scan (FIN+PSH+URG) */
    if ((flags & 0x29) == 0x29)
        return 0;
    return 1;
}

SEC("xdp")
int mk1_xdp_ingress(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = (__u64)((char *)data_end - (char *)data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        record_verdict(MK1_REASON_TRUNCATED_L2, pkt_len);
        return XDP_DROP;
    }

    __u32 ctrl_key = 0;
    struct mk1_ctrl_cfg *cfg = bpf_map_lookup_elem(&mk1_ctrl_map, &ctrl_key);
    __u64 now_ns = bpf_ktime_get_ns();

    __u8 lockdown = 0;
    __u8 allow_ssh = 0;
    __u8 allow_untagged = 1;
    __u32 wg_port = 51820;
    __u64 allowed_vlans = 0;

    if (!cfg) {
        lockdown = 1;
    } else {
        wg_port = cfg->wg_udp_port ? cfg->wg_udp_port : 51820;
        allow_ssh = cfg->allow_ssh_emergency;
        allow_untagged = cfg->allow_untagged_vlan;
        allowed_vlans = cfg->allowed_vlan_bitmap;
        if (cfg->oni_mode) {
            lockdown = 1;
        } else if (cfg->fail_closed && (now_ns - cfg->last_heartbeat_ns > MK1_HEARTBEAT_TIMEOUT_NS)) {
            lockdown = 2; /* Dead-Man Switch triggered */
        }
    }

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);
    __u8 is_vlan_tagged = 0;

    #pragma unroll
    for (int i = 0; i < MK1_MAX_VLAN_DEPTH; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vh = nh;
            if ((void *)(vh + 1) > data_end) {
                record_verdict(MK1_REASON_TRUNCATED_L2, pkt_len);
                return XDP_DROP;
            }
            __u16 vid = bpf_ntohs(vh->h_vlan_TCI) & 0x0FFF;
            if (vid == 0 || vid == 0x0FFF || vid >= 64 || !(allowed_vlans & (1ULL << vid))) {
                record_verdict(MK1_REASON_VLAN_VID_FORBIDDEN, pkt_len);
                return XDP_DROP;
            }
            is_vlan_tagged = 1;
            h_proto = vh->h_vlan_encapsulated_proto;
            nh = (void *)(vh + 1);
        }
    }

    /* Reject 3rd stacked VLAN tag */
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        record_verdict(MK1_REASON_VLAN_DEPTH_EXCEEDED, pkt_len);
        return XDP_DROP;
    }

    if (!is_vlan_tagged && !allow_untagged) {
        record_verdict(MK1_REASON_VLAN_VID_FORBIDDEN, pkt_len);
        return XDP_DROP;
    }

    if (h_proto == bpf_htons(ETH_P_ARP)) {
        if (lockdown) {
            record_verdict(lockdown == 2 ? MK1_REASON_DEADMAN_LOCKDOWN : MK1_REASON_ONI_LOCKDOWN, pkt_len);
            return XDP_DROP;
        }
        record_verdict(MK1_REASON_PASS, pkt_len);
        return XDP_PASS;
    }

    __u8 l4_proto = 0;
    void *l4_hdr = nh;

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip4 = nh;
        if ((void *)(ip4 + 1) > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
            return XDP_DROP;
        }
        if (ip4->version != 4 || ip4->ihl < 5) {
            record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
            return XDP_DROP;
        }
        void *ip_end = (char *)ip4 + ((__u32)ip4->ihl * 4);
        if (ip_end > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
            return XDP_DROP;
        }

        /* 1. IPv4 LPM Blocklist check */
        struct lpm_v4_key bkey = { .prefixlen = 32, .addr = ip4->saddr };
        if (bpf_map_lookup_elem(&mk1_blocklist_v4, &bkey)) {
            record_verdict(MK1_REASON_BLOCKLIST_V4, pkt_len);
            return XDP_DROP;
        }

        /* 2. Drop non-first IPv4 fragments (offset > 0) */
        __u16 frag = bpf_ntohs(ip4->frag_off);
        if ((frag & 0x1FFF) != 0) {
            record_verdict(MK1_REASON_NON_FIRST_FRAGMENT, pkt_len);
            return XDP_DROP;
        }

        /* 3. Per-source token bucket rate limit (applies BEFORE SSH/WireGuard checks) */
        if (!enforce_v4_rate_limit(ip4->saddr, now_ns)) {
            record_verdict(MK1_REASON_RATE_LIMIT_EXCEEDED, pkt_len);
            return XDP_DROP;
        }

        l4_proto = ip4->protocol;
        l4_hdr = ip_end;
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
            return XDP_DROP;
        }
        if (ip6->version != 6) {
            record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
            return XDP_DROP;
        }

        /* 1. IPv6 LPM Blocklist check */
        struct lpm_v6_key bkey6 = { .prefixlen = 128 };
        __builtin_memcpy(bkey6.addr, &ip6->saddr, 16);
        if (bpf_map_lookup_elem(&mk1_blocklist_v6, &bkey6)) {
            record_verdict(MK1_REASON_BLOCKLIST_V6, pkt_len);
            return XDP_DROP;
        }

        /* 2. Per-source IPv6 token bucket rate limit */
        if (!enforce_v6_rate_limit(&ip6->saddr, now_ns)) {
            record_verdict(MK1_REASON_RATE_LIMIT_EXCEEDED, pkt_len);
            return XDP_DROP;
        }

        /* 3. Bounded IPv6 Extension Header walking */
        __u8 nexthdr = ip6->nexthdr;
        void *cursor = (void *)(ip6 + 1);

        #pragma unroll
        for (int ext = 0; ext < MK1_MAX_IPV6_EXT_HEADERS; ext++) {
            if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
                struct ipv6_opt_hdr_min *opt = cursor;
                if ((void *)(opt + 1) > data_end) {
                    record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
                    return XDP_DROP;
                }
                __u32 hdr_bytes = ((__u32)opt->hdrlen + 1) * 8;
                cursor = (char *)cursor + hdr_bytes;
                if (cursor > data_end) {
                    record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
                    return XDP_DROP;
                }
                nexthdr = opt->nexthdr;
            } else if (nexthdr == 51) {
                /* Authentication Header (RFC 4302): length in 4-byte units minus 2 */
                struct ipv6_opt_hdr_min *ah = cursor;
                if ((void *)((char *)cursor + 8) > data_end) {
                    record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
                    return XDP_DROP;
                }
                __u32 hdr_bytes = ((__u32)ah->hdrlen + 2) * 4;
                cursor = (char *)cursor + hdr_bytes;
                if (cursor > data_end) {
                    record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
                    return XDP_DROP;
                }
                nexthdr = ah->nexthdr;
            } else if (nexthdr == 44) {
                /* IPv6 Fragment Header */
                struct ipv6_frag_hdr *fh = cursor;
                if ((void *)(fh + 1) > data_end) {
                    record_verdict(MK1_REASON_TRUNCATED_L3, pkt_len);
                    return XDP_DROP;
                }
                if ((bpf_ntohs(fh->frag_off) & 0xFFF8) != 0) {
                    record_verdict(MK1_REASON_NON_FIRST_FRAGMENT, pkt_len);
                    return XDP_DROP;
                }
                cursor = (void *)(fh + 1);
                nexthdr = fh->nexthdr;
            } else {
                break;
            }
        }

        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 44 || nexthdr == 51 || nexthdr == 60) {
            record_verdict(MK1_REASON_IPV6_EXT_CHAIN_LIMIT, pkt_len);
            return XDP_DROP;
        }

        l4_proto = nexthdr;
        l4_hdr = cursor;
    } else {
        /* Fail-Closed on unknown L2 EtherType */
        record_verdict(MK1_REASON_UNSUPPORTED_L2, pkt_len);
        return XDP_DROP;
    }

    /* ESP (50): Drop in lockdown; pass in normal mode */
    if (l4_proto == IPPROTO_ESP) {
        if (lockdown) {
            record_verdict(MK1_REASON_ESP_IN_LOCKDOWN, pkt_len);
            return XDP_DROP;
        }
        record_verdict(MK1_REASON_PASS, pkt_len);
        return XDP_PASS;
    }

    if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L4, pkt_len);
            return XDP_DROP;
        }
        if (lockdown) {
            if (bpf_ntohs(udph->dest) == wg_port || bpf_ntohs(udph->source) == wg_port) {
                record_verdict(MK1_REASON_PASS, pkt_len);
                return XDP_PASS;
            }
            record_verdict(lockdown == 2 ? MK1_REASON_DEADMAN_LOCKDOWN : MK1_REASON_ONI_LOCKDOWN, pkt_len);
            return XDP_DROP;
        }
        record_verdict(MK1_REASON_PASS, pkt_len);
        return XDP_PASS;
    }

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L4, pkt_len);
            return XDP_DROP;
        }
        if (tcph->doff < 5 || (void *)((char *)tcph + ((__u32)tcph->doff * 4)) > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L4, pkt_len);
            return XDP_DROP;
        }
        if (!validate_tcp_flags(tcph)) {
            record_verdict(MK1_REASON_TCP_INVALID_FLAGS, pkt_len);
            return XDP_DROP;
        }
        if (lockdown) {
            /* Port 22 emergency pass is ONLY evaluated AFTER per-source rate limiting */
            if (allow_ssh && bpf_ntohs(tcph->dest) == 22) {
                record_verdict(MK1_REASON_PASS, pkt_len);
                return XDP_PASS;
            }
            record_verdict(lockdown == 2 ? MK1_REASON_DEADMAN_LOCKDOWN : MK1_REASON_ONI_LOCKDOWN, pkt_len);
            return XDP_DROP;
        }
        record_verdict(MK1_REASON_PASS, pkt_len);
        return XDP_PASS;
    }

    if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        if ((void *)((char *)l4_hdr + 4) > data_end) {
            record_verdict(MK1_REASON_TRUNCATED_L4, pkt_len);
            return XDP_DROP;
        }
        if (lockdown) {
            record_verdict(lockdown == 2 ? MK1_REASON_DEADMAN_LOCKDOWN : MK1_REASON_ONI_LOCKDOWN, pkt_len);
            return XDP_DROP;
        }
        record_verdict(MK1_REASON_PASS, pkt_len);
        return XDP_PASS;
    }

    if (lockdown) {
        record_verdict(lockdown == 2 ? MK1_REASON_DEADMAN_LOCKDOWN : MK1_REASON_ONI_LOCKDOWN, pkt_len);
        return XDP_DROP;
    }

    record_verdict(MK1_REASON_PASS, pkt_len);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
