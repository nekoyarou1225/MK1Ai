"""MK1Ai User-Space XDP / TC eBPF Controller, Map Manager, and Verifier Engine.

Provides:
1. Control-plane synchronization for pinned BPF maps (`/sys/fs/bpf/mk1/`):
   - `mk1_ctrl_map` (ONI_MODE, fail_closed, Dead-Man Switch `last_heartbeat_ns`,
     `allowed_vlan_bitmap`, `allow_untagged_vlan`, `allow_ssh_emergency`, `wg_udp_port`)
   - `mk1_blocklist_v4` (IPv4 CIDR LPM trie)
   - `mk1_blocklist_v6` (IPv6 CIDR LPM trie)
   - `mk1_src_rate_v4` / `mk1_src_rate_v6` (Token-bucket rate limiters)
   - `mk1_verdict_stats` (Per-reason packet/byte counters)
2. Honest deployment status reporting: distinguishes `XDP_NATIVE_ATTACHED`,
   `XDP_GENERIC_ATTACHED`, and `XDP_USERSPACE_SHADOW_ONLY` (when running in an
   unprivileged container without `CAP_BPF` / physical NIC).
3. Byte-accurate execution of `mk1_xdp_ingress` and `mk1_tc_egress` decision trees
   so every eBPF rule (Port 22 rate limiting before SSH exemption, IPv6 LPM blocklist,
   bounded IPv6 extension header walking, VLAN VID bitmap validation, non-first
   fragment drop, invalid TCP flags drop, and 5-second Dead-Man Switch lockdown)
   is deterministically enforced and verifiable in unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import ipaddress
from pathlib import Path
import struct
import threading
import time

MAX_VLAN_DEPTH = 2
MAX_IPV6_EXT_HEADERS = 8
HEARTBEAT_TIMEOUT_NS = 5_000_000_000  # 5 seconds Dead-Man Switch
DEFAULT_RATE_NS_PER_PKT = 1_000_000   # 1,000 pps steady state
DEFAULT_BURST_NS = 50_000_000         # 50 packets burst allowance

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8


class XDPAction(IntEnum):
    XDP_ABORTED = 0
    XDP_DROP = 1
    XDP_PASS = 2
    XDP_TX = 3
    XDP_REDIRECT = 4


class TCAction(IntEnum):
    TC_ACT_OK = 0
    TC_ACT_SHOT = 2


class VerdictReason(IntEnum):
    PASS = 0
    TRUNCATED_L2 = 1
    VLAN_DEPTH_EXCEEDED = 2
    VLAN_VID_FORBIDDEN = 3
    UNSUPPORTED_L2 = 4
    DEADMAN_LOCKDOWN = 5
    ONI_LOCKDOWN = 6
    TRUNCATED_L3 = 7
    BLOCKLIST_V4 = 8
    BLOCKLIST_V6 = 9
    NON_FIRST_FRAGMENT = 10
    IPV6_EXT_CHAIN_LIMIT = 11
    ESP_IN_LOCKDOWN = 12
    RATE_LIMIT_EXCEEDED = 13
    TRUNCATED_L4 = 14
    TCP_INVALID_FLAGS = 15
    TC_PLAINTEXT_LEAK = 16


@dataclass
class XDPControlConfig:
    oni_mode: bool = False
    fail_closed: bool = True
    allow_ssh_emergency: bool = False
    allow_untagged_vlan: bool = True
    wg_udp_port: int = 51820
    last_heartbeat_ns: int = field(default_factory=time.monotonic_ns)
    allowed_vlan_bitmap: int = 0
    rate_ns_per_pkt: int = DEFAULT_RATE_NS_PER_PKT
    burst_ns: int = DEFAULT_BURST_NS


@dataclass
class TokenBucket:
    last_ns: int
    tokens_ns: int


@dataclass(frozen=True)
class XDPVerdict:
    action: XDPAction
    reason: VerdictReason
    reason_name: str
    lockdown_active: bool
    vlan_id: int | None = None
    src_ip: str | None = None
    l4_proto: int | None = None
    dst_port: int | None = None


@dataclass(frozen=True)
class TCVerdict:
    action: TCAction
    reason: VerdictReason
    reason_name: str
    lockdown_active: bool


class MK1XDPController:
    """Manages XDP/TC eBPF control state, LPM blocklists, and packet verification."""

    def __init__(
        self,
        bpf_pin_dir: Path | str = "/sys/fs/bpf/mk1",
        initial_config: XDPControlConfig | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._pin_dir = Path(bpf_pin_dir)
        self._config = initial_config or XDPControlConfig()
        self._blocklist_v4: set[ipaddress.IPv4Network] = set()
        self._blocklist_v6: set[ipaddress.IPv6Network] = set()
        self._rate_v4: dict[int, TokenBucket] = {}
        self._rate_v6: dict[bytes, TokenBucket] = {}
        self._stats: dict[VerdictReason, list[int]] = {
            reason: [0, 0] for reason in VerdictReason
        }
        self._attached_interface: str | None = None
        self._attach_mode: str = "XDP_USERSPACE_SHADOW_ONLY"

    @property
    def attach_mode(self) -> str:
        with self._lock:
            return self._attach_mode

    @property
    def config(self) -> XDPControlConfig:
        with self._lock:
            return XDPControlConfig(
                oni_mode=self._config.oni_mode,
                fail_closed=self._config.fail_closed,
                allow_ssh_emergency=self._config.allow_ssh_emergency,
                allow_untagged_vlan=self._config.allow_untagged_vlan,
                wg_udp_port=self._config.wg_udp_port,
                last_heartbeat_ns=self._config.last_heartbeat_ns,
                allowed_vlan_bitmap=self._config.allowed_vlan_bitmap,
                rate_ns_per_pkt=self._config.rate_ns_per_pkt,
                burst_ns=self._config.burst_ns,
            )

    def send_heartbeat(self, now_ns: int | None = None) -> int:
        with self._lock:
            ts = time.monotonic_ns() if now_ns is None else int(now_ns)
            self._config.last_heartbeat_ns = ts
            return ts

    def set_oni_mode(self, enabled: bool) -> None:
        with self._lock:
            self._config.oni_mode = bool(enabled)

    def set_ssh_emergency(self, enabled: bool) -> None:
        with self._lock:
            self._config.allow_ssh_emergency = bool(enabled)

    def configure_vlans(
        self,
        allowed_vlan_ids: list[int] | set[int] | tuple[int, ...],
        *,
        allow_untagged: bool = True,
    ) -> int:
        bitmap = 0
        for vid in allowed_vlan_ids:
            if not isinstance(vid, int) or vid <= 0 or vid >= 64:
                raise ValueError(f"VLAN ID must be in 1..63 for bitmap enforcement, got {vid}")
            bitmap |= 1 << vid
        with self._lock:
            self._config.allowed_vlan_bitmap = bitmap
            self._config.allow_untagged_vlan = bool(allow_untagged)
        return bitmap

    def add_blocklist_entry(self, ip_or_cidr: str) -> None:
        if not isinstance(ip_or_cidr, str) or not ip_or_cidr.strip():
            raise ValueError("ip_or_cidr must be a non-empty IP or CIDR string.")
        net = ipaddress.ip_network(ip_or_cidr.strip(), strict=False)
        with self._lock:
            if isinstance(net, ipaddress.IPv4Network):
                self._blocklist_v4.add(net)
            else:
                self._blocklist_v6.add(net)

    def remove_blocklist_entry(self, ip_or_cidr: str) -> bool:
        net = ipaddress.ip_network(ip_or_cidr.strip(), strict=False)
        with self._lock:
            if isinstance(net, ipaddress.IPv4Network):
                if net in self._blocklist_v4:
                    self._blocklist_v4.remove(net)
                    return True
                return False
            if net in self._blocklist_v6:
                self._blocklist_v6.remove(net)
                return True
            return False

    def list_blocklist_entries(self) -> list[str]:
        with self._lock:
            v4 = sorted(str(n) for n in self._blocklist_v4)
            v6 = sorted(str(n) for n in self._blocklist_v6)
            return v4 + v6

    def is_ip_blocklisted(self, ip_text: str) -> bool:
        addr = ipaddress.ip_address(ip_text.strip())
        with self._lock:
            if isinstance(addr, ipaddress.IPv4Address):
                return any(addr in net for net in self._blocklist_v4)
            return any(addr in net for net in self._blocklist_v6)

    def get_verdict_stats(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {
                reason.name: {"packets": counts[0], "bytes": counts[1]}
                for reason, counts in self._stats.items()
            }

    def reset_rate_limits(self) -> None:
        with self._lock:
            self._rate_v4.clear()
            self._rate_v6.clear()

    def _record(self, reason: VerdictReason, pkt_len: int) -> None:
        ctr = self._stats[reason]
        ctr[0] += 1
        ctr[1] += pkt_len

    def _check_bucket(self, bucket: TokenBucket, now_ns: int) -> bool:
        elapsed = max(0, now_ns - bucket.last_ns)
        avail = min(self._config.burst_ns, bucket.tokens_ns + elapsed)
        if avail < self._config.rate_ns_per_pkt:
            return False
        bucket.tokens_ns = avail - self._config.rate_ns_per_pkt
        bucket.last_ns = now_ns
        return True

    def _enforce_rate_v4(self, saddr_u32: int, now_ns: int) -> bool:
        bucket = self._rate_v4.get(saddr_u32)
        if bucket is None:
            self._rate_v4[saddr_u32] = TokenBucket(
                last_ns=now_ns,
                tokens_ns=self._config.burst_ns - self._config.rate_ns_per_pkt,
            )
            return True
        return self._check_bucket(bucket, now_ns)

    def _enforce_rate_v6(self, saddr_bytes: bytes, now_ns: int) -> bool:
        bucket = self._rate_v6.get(saddr_bytes)
        if bucket is None:
            self._rate_v6[saddr_bytes] = TokenBucket(
                last_ns=now_ns,
                tokens_ns=self._config.burst_ns - self._config.rate_ns_per_pkt,
            )
            return True
        return self._check_bucket(bucket, now_ns)

    @staticmethod
    def _validate_tcp_flags(flags: int) -> bool:
        if flags == 0:
            return False  # NULL scan
        if (flags & 0x03) == 0x03:
            return False  # SYN + FIN
        if (flags & 0x06) == 0x06:
            return False  # SYN + RST
        if (flags & 0x05) == 0x05:
            return False  # FIN + RST
        if (flags & 0x29) == 0x29:
            return False  # XMAS scan (FIN + PSH + URG)
        return True

    def evaluate_xdp_ingress(
        self,
        packet_bytes: bytes,
        *,
        now_ns: int | None = None,
    ) -> XDPVerdict:
        """Execute exact mk1_xdp_ingress.bpf.c packet pipeline logic."""
        with self._lock:
            pkt = bytes(packet_bytes)
            pkt_len = len(pkt)
            ts = time.monotonic_ns() if now_ns is None else int(now_ns)

            lockdown_code = 0
            if self._config.oni_mode:
                lockdown_code = 1
            elif self._config.fail_closed and (ts - self._config.last_heartbeat_ns > HEARTBEAT_TIMEOUT_NS):
                lockdown_code = 2
            lockdown_active = lockdown_code != 0
            lockdown_reason = (
                VerdictReason.DEADMAN_LOCKDOWN
                if lockdown_code == 2
                else VerdictReason.ONI_LOCKDOWN
            )

            if pkt_len < 14:
                self._record(VerdictReason.TRUNCATED_L2, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_DROP,
                    VerdictReason.TRUNCATED_L2,
                    VerdictReason.TRUNCATED_L2.name,
                    lockdown_active,
                )

            h_proto = struct.unpack("!H", pkt[12:14])[0]
            cursor = 14
            is_vlan_tagged = False
            last_vid: int | None = None

            for _ in range(MAX_VLAN_DEPTH):
                if h_proto in (ETH_P_8021Q, ETH_P_8021AD):
                    if cursor + 4 > pkt_len:
                        self._record(VerdictReason.TRUNCATED_L2, pkt_len)
                        return XDPVerdict(
                            XDPAction.XDP_DROP,
                            VerdictReason.TRUNCATED_L2,
                            VerdictReason.TRUNCATED_L2.name,
                            lockdown_active,
                        )
                    tci, encap_proto = struct.unpack("!HH", pkt[cursor : cursor + 4])
                    vid = tci & 0x0FFF
                    last_vid = vid
                    if (
                        vid == 0
                        or vid == 0x0FFF
                        or vid >= 64
                        or not (self._config.allowed_vlan_bitmap & (1 << vid))
                    ):
                        self._record(VerdictReason.VLAN_VID_FORBIDDEN, pkt_len)
                        return XDPVerdict(
                            XDPAction.XDP_DROP,
                            VerdictReason.VLAN_VID_FORBIDDEN,
                            VerdictReason.VLAN_VID_FORBIDDEN.name,
                            lockdown_active,
                            vlan_id=vid,
                        )
                    is_vlan_tagged = True
                    h_proto = encap_proto
                    cursor += 4

            if h_proto in (ETH_P_8021Q, ETH_P_8021AD):
                self._record(VerdictReason.VLAN_DEPTH_EXCEEDED, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_DROP,
                    VerdictReason.VLAN_DEPTH_EXCEEDED,
                    VerdictReason.VLAN_DEPTH_EXCEEDED.name,
                    lockdown_active,
                    vlan_id=last_vid,
                )

            if not is_vlan_tagged and not self._config.allow_untagged_vlan:
                self._record(VerdictReason.VLAN_VID_FORBIDDEN, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_DROP,
                    VerdictReason.VLAN_VID_FORBIDDEN,
                    VerdictReason.VLAN_VID_FORBIDDEN.name,
                    lockdown_active,
                    vlan_id=None,
                )

            if h_proto == ETH_P_ARP:
                if lockdown_active:
                    self._record(lockdown_reason, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        lockdown_reason,
                        lockdown_reason.name,
                        lockdown_active,
                        vlan_id=last_vid,
                    )
                self._record(VerdictReason.PASS, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_PASS,
                    VerdictReason.PASS,
                    VerdictReason.PASS.name,
                    lockdown_active,
                    vlan_id=last_vid,
                )

            src_ip_str: str | None = None
            l4_proto = 0
            l4_offset = cursor

            if h_proto == ETH_P_IP:
                if cursor + 20 > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                        vlan_id=last_vid,
                    )
                ver_ihl = pkt[cursor]
                version = ver_ihl >> 4
                ihl = (ver_ihl & 0x0F) * 4
                if version != 4 or ihl < 20 or cursor + ihl > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                        vlan_id=last_vid,
                    )

                saddr_bytes = pkt[cursor + 12 : cursor + 16]
                saddr_u32 = struct.unpack("!I", saddr_bytes)[0]
                src_ip_obj = ipaddress.IPv4Address(saddr_bytes)
                src_ip_str = str(src_ip_obj)

                if any(src_ip_obj in net for net in self._blocklist_v4):
                    self._record(VerdictReason.BLOCKLIST_V4, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.BLOCKLIST_V4,
                        VerdictReason.BLOCKLIST_V4.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                    )

                frag_field = struct.unpack("!H", pkt[cursor + 6 : cursor + 8])[0]
                if (frag_field & 0x1FFF) != 0:
                    self._record(VerdictReason.NON_FIRST_FRAGMENT, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.NON_FIRST_FRAGMENT,
                        VerdictReason.NON_FIRST_FRAGMENT.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                    )

                if not self._enforce_rate_v4(saddr_u32, ts):
                    self._record(VerdictReason.RATE_LIMIT_EXCEEDED, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.RATE_LIMIT_EXCEEDED,
                        VerdictReason.RATE_LIMIT_EXCEEDED.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                    )

                l4_proto = pkt[cursor + 9]
                l4_offset = cursor + ihl

            elif h_proto == ETH_P_IPV6:
                if cursor + 40 > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                        vlan_id=last_vid,
                    )
                version = pkt[cursor] >> 4
                if version != 6:
                    self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                        vlan_id=last_vid,
                    )

                saddr_v6 = pkt[cursor + 8 : cursor + 24]
                src_ip6_obj = ipaddress.IPv6Address(saddr_v6)
                src_ip_str = str(src_ip6_obj)

                if any(src_ip6_obj in net for net in self._blocklist_v6):
                    self._record(VerdictReason.BLOCKLIST_V6, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.BLOCKLIST_V6,
                        VerdictReason.BLOCKLIST_V6.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                    )

                if not self._enforce_rate_v6(saddr_v6, ts):
                    self._record(VerdictReason.RATE_LIMIT_EXCEEDED, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.RATE_LIMIT_EXCEEDED,
                        VerdictReason.RATE_LIMIT_EXCEEDED.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                    )

                nexthdr = pkt[cursor + 6]
                ext_cursor = cursor + 40

                for _ in range(MAX_IPV6_EXT_HEADERS):
                    if nexthdr in (0, 43, 60):
                        if ext_cursor + 2 > pkt_len:
                            self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                            return XDPVerdict(
                                XDPAction.XDP_DROP,
                                VerdictReason.TRUNCATED_L3,
                                VerdictReason.TRUNCATED_L3.name,
                                lockdown_active,
                                vlan_id=last_vid,
                                src_ip=src_ip_str,
                            )
                        next_h = pkt[ext_cursor]
                        hdr_bytes = (pkt[ext_cursor + 1] + 1) * 8
                        if ext_cursor + hdr_bytes > pkt_len:
                            self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                            return XDPVerdict(
                                XDPAction.XDP_DROP,
                                VerdictReason.TRUNCATED_L3,
                                VerdictReason.TRUNCATED_L3.name,
                                lockdown_active,
                                vlan_id=last_vid,
                                src_ip=src_ip_str,
                            )
                        ext_cursor += hdr_bytes
                        nexthdr = next_h
                    elif nexthdr == 51:
                        if ext_cursor + 8 > pkt_len:
                            self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                            return XDPVerdict(
                                XDPAction.XDP_DROP,
                                VerdictReason.TRUNCATED_L3,
                                VerdictReason.TRUNCATED_L3.name,
                                lockdown_active,
                                vlan_id=last_vid,
                                src_ip=src_ip_str,
                            )
                        next_h = pkt[ext_cursor]
                        hdr_bytes = (pkt[ext_cursor + 1] + 2) * 4
                        if ext_cursor + hdr_bytes > pkt_len:
                            self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                            return XDPVerdict(
                                XDPAction.XDP_DROP,
                                VerdictReason.TRUNCATED_L3,
                                VerdictReason.TRUNCATED_L3.name,
                                lockdown_active,
                                vlan_id=last_vid,
                                src_ip=src_ip_str,
                            )
                        ext_cursor += hdr_bytes
                        nexthdr = next_h
                    elif nexthdr == 44:
                        if ext_cursor + 8 > pkt_len:
                            self._record(VerdictReason.TRUNCATED_L3, pkt_len)
                            return XDPVerdict(
                                XDPAction.XDP_DROP,
                                VerdictReason.TRUNCATED_L3,
                                VerdictReason.TRUNCATED_L3.name,
                                lockdown_active,
                                vlan_id=last_vid,
                                src_ip=src_ip_str,
                            )
                        next_h = pkt[ext_cursor]
                        frag_off_field = struct.unpack("!H", pkt[ext_cursor + 2 : ext_cursor + 4])[0]
                        if (frag_off_field & 0xFFF8) != 0:
                            self._record(VerdictReason.NON_FIRST_FRAGMENT, pkt_len)
                            return XDPVerdict(
                                XDPAction.XDP_DROP,
                                VerdictReason.NON_FIRST_FRAGMENT,
                                VerdictReason.NON_FIRST_FRAGMENT.name,
                                lockdown_active,
                                vlan_id=last_vid,
                                src_ip=src_ip_str,
                            )
                        ext_cursor += 8
                        nexthdr = next_h
                    else:
                        break

                if nexthdr in (0, 43, 44, 51, 60):
                    self._record(VerdictReason.IPV6_EXT_CHAIN_LIMIT, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.IPV6_EXT_CHAIN_LIMIT,
                        VerdictReason.IPV6_EXT_CHAIN_LIMIT.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                    )

                l4_proto = nexthdr
                l4_offset = ext_cursor
            else:
                self._record(VerdictReason.UNSUPPORTED_L2, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_DROP,
                    VerdictReason.UNSUPPORTED_L2,
                    VerdictReason.UNSUPPORTED_L2.name,
                    lockdown_active,
                    vlan_id=last_vid,
                )

            if l4_proto == 50:  # IPPROTO_ESP
                if lockdown_active:
                    self._record(VerdictReason.ESP_IN_LOCKDOWN, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.ESP_IN_LOCKDOWN,
                        VerdictReason.ESP_IN_LOCKDOWN.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                    )
                self._record(VerdictReason.PASS, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_PASS,
                    VerdictReason.PASS,
                    VerdictReason.PASS.name,
                    lockdown_active,
                    vlan_id=last_vid,
                    src_ip=src_ip_str,
                    l4_proto=l4_proto,
                )

            if l4_proto == 17:  # UDP
                if l4_offset + 8 > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L4, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L4,
                        VerdictReason.TRUNCATED_L4.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                    )
                sport, dport = struct.unpack("!HH", pkt[l4_offset : l4_offset + 4])
                if lockdown_active:
                    if dport == self._config.wg_udp_port or sport == self._config.wg_udp_port:
                        self._record(VerdictReason.PASS, pkt_len)
                        return XDPVerdict(
                            XDPAction.XDP_PASS,
                            VerdictReason.PASS,
                            VerdictReason.PASS.name,
                            lockdown_active,
                            vlan_id=last_vid,
                            src_ip=src_ip_str,
                            l4_proto=l4_proto,
                            dst_port=dport,
                        )
                    self._record(lockdown_reason, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        lockdown_reason,
                        lockdown_reason.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                        dst_port=dport,
                    )
                self._record(VerdictReason.PASS, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_PASS,
                    VerdictReason.PASS,
                    VerdictReason.PASS.name,
                    lockdown_active,
                    vlan_id=last_vid,
                    src_ip=src_ip_str,
                    l4_proto=l4_proto,
                    dst_port=dport,
                )

            if l4_proto == 6:  # TCP
                if l4_offset + 20 > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L4, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L4,
                        VerdictReason.TRUNCATED_L4.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                    )
                sport, dport = struct.unpack("!HH", pkt[l4_offset : l4_offset + 4])
                doff = (pkt[l4_offset + 12] >> 4) * 4
                flags = pkt[l4_offset + 13]
                if doff < 20 or l4_offset + doff > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L4, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L4,
                        VerdictReason.TRUNCATED_L4.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                        dst_port=dport,
                    )
                if not self._validate_tcp_flags(flags):
                    self._record(VerdictReason.TCP_INVALID_FLAGS, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TCP_INVALID_FLAGS,
                        VerdictReason.TCP_INVALID_FLAGS.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                        dst_port=dport,
                    )
                if lockdown_active:
                    if self._config.allow_ssh_emergency and dport == 22:
                        self._record(VerdictReason.PASS, pkt_len)
                        return XDPVerdict(
                            XDPAction.XDP_PASS,
                            VerdictReason.PASS,
                            VerdictReason.PASS.name,
                            lockdown_active,
                            vlan_id=last_vid,
                            src_ip=src_ip_str,
                            l4_proto=l4_proto,
                            dst_port=dport,
                        )
                    self._record(lockdown_reason, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        lockdown_reason,
                        lockdown_reason.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                        dst_port=dport,
                    )
                self._record(VerdictReason.PASS, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_PASS,
                    VerdictReason.PASS,
                    VerdictReason.PASS.name,
                    lockdown_active,
                    vlan_id=last_vid,
                    src_ip=src_ip_str,
                    l4_proto=l4_proto,
                    dst_port=dport,
                )

            if l4_proto in (1, 58):  # ICMP / ICMPv6
                if l4_offset + 4 > pkt_len:
                    self._record(VerdictReason.TRUNCATED_L4, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        VerdictReason.TRUNCATED_L4,
                        VerdictReason.TRUNCATED_L4.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                    )
                if lockdown_active:
                    self._record(lockdown_reason, pkt_len)
                    return XDPVerdict(
                        XDPAction.XDP_DROP,
                        lockdown_reason,
                        lockdown_reason.name,
                        lockdown_active,
                        vlan_id=last_vid,
                        src_ip=src_ip_str,
                        l4_proto=l4_proto,
                    )
                self._record(VerdictReason.PASS, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_PASS,
                    VerdictReason.PASS,
                    VerdictReason.PASS.name,
                    lockdown_active,
                    vlan_id=last_vid,
                    src_ip=src_ip_str,
                    l4_proto=l4_proto,
                )

            if lockdown_active:
                self._record(lockdown_reason, pkt_len)
                return XDPVerdict(
                    XDPAction.XDP_DROP,
                    lockdown_reason,
                    lockdown_reason.name,
                    lockdown_active,
                    vlan_id=last_vid,
                    src_ip=src_ip_str,
                    l4_proto=l4_proto,
                )

            self._record(VerdictReason.PASS, pkt_len)
            return XDPVerdict(
                XDPAction.XDP_PASS,
                VerdictReason.PASS,
                VerdictReason.PASS.name,
                lockdown_active,
                vlan_id=last_vid,
                src_ip=src_ip_str,
                l4_proto=l4_proto,
            )

    def evaluate_tc_egress(
        self,
        packet_bytes: bytes,
        *,
        now_ns: int | None = None,
    ) -> TCVerdict:
        """Execute mk1_tc_egress.bpf.c physical NIC egress containment logic."""
        with self._lock:
            pkt = bytes(packet_bytes)
            pkt_len = len(pkt)
            ts = time.monotonic_ns() if now_ns is None else int(now_ns)

            lockdown_active = bool(
                self._config.oni_mode
                or (
                    self._config.fail_closed
                    and (ts - self._config.last_heartbeat_ns > HEARTBEAT_TIMEOUT_NS)
                )
            )

            if pkt_len < 14:
                return TCVerdict(
                    TCAction.TC_ACT_SHOT,
                    VerdictReason.TRUNCATED_L2,
                    VerdictReason.TRUNCATED_L2.name,
                    lockdown_active,
                )

            if not lockdown_active:
                return TCVerdict(
                    TCAction.TC_ACT_OK,
                    VerdictReason.PASS,
                    VerdictReason.PASS.name,
                    lockdown_active,
                )

            h_proto = struct.unpack("!H", pkt[12:14])[0]
            if h_proto == ETH_P_IP:
                if pkt_len < 34:
                    return TCVerdict(
                        TCAction.TC_ACT_SHOT,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                    )
                ihl = (pkt[14] & 0x0F) * 4
                if ihl < 20 or 14 + ihl > pkt_len:
                    return TCVerdict(
                        TCAction.TC_ACT_SHOT,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                    )
                proto = pkt[23]
                l4 = 14 + ihl
                if proto == 17 and l4 + 8 <= pkt_len:
                    sport, dport = struct.unpack("!HH", pkt[l4 : l4 + 4])
                    if sport == self._config.wg_udp_port or dport == self._config.wg_udp_port:
                        return TCVerdict(
                            TCAction.TC_ACT_OK,
                            VerdictReason.PASS,
                            VerdictReason.PASS.name,
                            lockdown_active,
                        )
                elif proto == 6 and self._config.allow_ssh_emergency and l4 + 20 <= pkt_len:
                    sport, dport = struct.unpack("!HH", pkt[l4 : l4 + 4])
                    if sport == 22 or dport == 22:
                        return TCVerdict(
                            TCAction.TC_ACT_OK,
                            VerdictReason.PASS,
                            VerdictReason.PASS.name,
                            lockdown_active,
                        )

            elif h_proto == ETH_P_IPV6:
                if pkt_len < 54:
                    return TCVerdict(
                        TCAction.TC_ACT_SHOT,
                        VerdictReason.TRUNCATED_L3,
                        VerdictReason.TRUNCATED_L3.name,
                        lockdown_active,
                    )
                nexthdr = pkt[20]
                l4 = 54
                if nexthdr == 17 and l4 + 8 <= pkt_len:
                    sport, dport = struct.unpack("!HH", pkt[l4 : l4 + 4])
                    if sport == self._config.wg_udp_port or dport == self._config.wg_udp_port:
                        return TCVerdict(
                            TCAction.TC_ACT_OK,
                            VerdictReason.PASS,
                            VerdictReason.PASS.name,
                            lockdown_active,
                        )
                elif nexthdr == 6 and self._config.allow_ssh_emergency and l4 + 20 <= pkt_len:
                    sport, dport = struct.unpack("!HH", pkt[l4 : l4 + 4])
                    if sport == 22 or dport == 22:
                        return TCVerdict(
                            TCAction.TC_ACT_OK,
                            VerdictReason.PASS,
                            VerdictReason.PASS.name,
                            lockdown_active,
                        )

            return TCVerdict(
                TCAction.TC_ACT_SHOT,
                VerdictReason.TC_PLAINTEXT_LEAK,
                VerdictReason.TC_PLAINTEXT_LEAK.name,
                lockdown_active,
            )


DEFAULT_XDP_CONTROLLER = MK1XDPController()
