/* SPDX-License-Identifier: GPL-2.0 */
/* MK1Ai Sovereign-Airgap Shared eBPF / XDP / TC Definitions */
#ifndef __MK1_COMMON_BPF_H
#define __MK1_COMMON_BPF_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/pkt_cls.h>

#define MK1_MAX_VLAN_DEPTH          2
#define MK1_MAX_IPV6_EXT_HEADERS    8
#define MK1_HEARTBEAT_TIMEOUT_NS    5000000000ULL /* 5 seconds Dead-Man Switch */
#define MK1_DEFAULT_RATE_NS_PER_PKT 1000000ULL    /* 1,000 pps steady state */
#define MK1_DEFAULT_BURST_NS        50000000ULL   /* 50 ms burst allowance */

#ifndef ETH_P_8021Q
#define ETH_P_8021Q  0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP    0x0806
#endif

/* Drop / Pass reason codes for mk1_verdict_stats per-CPU array */
enum mk1_verdict_reason {
    MK1_REASON_PASS                 = 0,
    MK1_REASON_TRUNCATED_L2         = 1,
    MK1_REASON_VLAN_DEPTH_EXCEEDED  = 2,
    MK1_REASON_VLAN_VID_FORBIDDEN   = 3,
    MK1_REASON_UNSUPPORTED_L2       = 4,
    MK1_REASON_DEADMAN_LOCKDOWN     = 5,
    MK1_REASON_ONI_LOCKDOWN         = 6,
    MK1_REASON_TRUNCATED_L3         = 7,
    MK1_REASON_BLOCKLIST_V4         = 8,
    MK1_REASON_BLOCKLIST_V6         = 9,
    MK1_REASON_NON_FIRST_FRAGMENT   = 10,
    MK1_REASON_IPV6_EXT_CHAIN_LIMIT = 11,
    MK1_REASON_ESP_IN_LOCKDOWN      = 12,
    MK1_REASON_RATE_LIMIT_EXCEEDED  = 13,
    MK1_REASON_TRUNCATED_L4         = 14,
    MK1_REASON_TCP_INVALID_FLAGS    = 15,
    MK1_REASON_TC_PLAINTEXT_LEAK    = 16,
    MK1_REASON_MAX                  = 32
};

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

struct ipv6_opt_hdr_min {
    __u8 nexthdr;
    __u8 hdrlen;
} __attribute__((packed));

struct ipv6_frag_hdr {
    __u8   nexthdr;
    __u8   reserved;
    __be16 frag_off;
    __be32 identification;
} __attribute__((packed));

struct mk1_ctrl_cfg {
    __u8  oni_mode;            /* 1 = ONI_MODE lockdown active */
    __u8  fail_closed;         /* 1 = Drop on heartbeat expiry or parse error */
    __u8  allow_ssh_emergency; /* 1 = Allow TCP/22 in lockdown AFTER rate-limit */
    __u8  allow_untagged_vlan; /* 1 = Allow untagged frames; 0 = Require allowed VID */
    __u32 wg_udp_port;         /* WireGuard UDP port in host byte order (e.g. 51820) */
    __u64 last_heartbeat_ns;   /* Monotonic timestamp of last user-space heartbeat */
    __u64 allowed_vlan_bitmap; /* Bitmask for VLAN IDs 0..63 (0 = reject if tagged) */
};

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

struct rate_bucket {
    __u64 last_ns;
    __u64 tokens_ns;
};

struct mk1_verdict_counter {
    __u64 packets;
    __u64 bytes;
};

#endif /* __MK1_COMMON_BPF_H */
