from pathlib import Path
import socket
import struct
import time
import unittest
from unittest.mock import patch

import airgap_ai_defender as defender
import mk1_quorum
import mk1_secure_transport
from mk1_xdp_controller import (
    MK1XDPController,
    TCAction,
    VerdictReason,
    XDPAction,
)
from pqcrypto.kem import ml_kem_768, ml_kem_1024


def _build_ipv4_tcp_packet(
    src_ip: str = "10.0.0.10",
    dst_ip: str = "10.0.0.20",
    src_port: int = 44444,
    dst_port: int = 443,
    tcp_flags: int = 0x10,
    frag_off: int = 0,
    vlan_id: int | None = None,
    payload: bytes = b"Hello MK1Ai",
) -> bytes:
    eth_dst = b"\x00\x11\x22\x33\x44\x55"
    eth_src = b"\x66\x77\x88\x99\xaa\xbb"
    if vlan_id is not None:
        l2 = eth_dst + eth_src + struct.pack("!HHH", 0x8100, vlan_id & 0x0FFF, 0x0800)
    else:
        l2 = eth_dst + eth_src + struct.pack("!H", 0x0800)

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1000,
        2000,
        5 << 4,
        tcp_flags,
        65535,
        0,
        0,
    )
    total_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        frag_off,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return l2 + ip_hdr + tcp_hdr + payload


def _build_ipv6_tcp_packet(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    src_port: int = 55555,
    dst_port: int = 443,
    tcp_flags: int = 0x10,
    ext_headers: list[tuple[int, bytes]] | None = None,
    payload: bytes = b"Hello IPv6",
) -> bytes:
    eth = b"\x00" * 12 + struct.pack("!H", 0x86DD)
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1,
        1,
        5 << 4,
        tcp_flags,
        65535,
        0,
        0,
    )
    ext_bytes = b""
    first_nh = socket.IPPROTO_TCP
    if ext_headers:
        first_nh = ext_headers[0][0]
        for idx, (ext_proto, body) in enumerate(ext_headers):
            next_nh = ext_headers[idx + 1][0] if idx + 1 < len(ext_headers) else socket.IPPROTO_TCP
            if ext_proto == 44:
                ext_bytes += struct.pack("!BBHI", next_nh, 0, struct.unpack("!H", body[:2])[0], 1)
            else:
                ext_bytes += struct.pack("!BB", next_nh, 0) + body[:6].ljust(6, b"\x00")
    payload_len = len(ext_bytes) + len(tcp_hdr) + len(payload)
    ipv6_hdr = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        payload_len,
        first_nh,
        64,
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
    )
    return eth + ipv6_hdr + ext_bytes + tcp_hdr + payload


class TestXDPEBPFSubsystemAndRemediations(unittest.TestCase):
    def test_xdp_c_sources_exist_and_contain_required_sections(self) -> None:
        ebpf_dir = Path(__file__).resolve().parent.parent / "security" / "ebpf"
        self.assertTrue((ebpf_dir / "mk1_common.bpf.h").is_file())
        self.assertTrue((ebpf_dir / "mk1_xdp_ingress.bpf.c").is_file())
        self.assertTrue((ebpf_dir / "mk1_tc_egress.bpf.c").is_file())

    def test_xdp_port_22_rate_limited_before_ssh_safe_harbor(self) -> None:
        ctrl = MK1XDPController()
        ctrl.send_heartbeat(now_ns=1_000_000_000)
        ctrl.set_ssh_emergency(True)
        pkt = _build_ipv4_tcp_packet(
            src_ip="192.0.2.50",
            dst_ip="192.0.2.1",
            src_port=52000,
            dst_port=22,
            tcp_flags=0x02,
        )
        # Default burst is 50 packets; 51st packet at the same timestamp must be rate-limited
        for i in range(50):
            verdict = ctrl.evaluate_xdp_ingress(pkt, now_ns=1_000_000_000)
            self.assertEqual(verdict.action, XDPAction.XDP_PASS)
        verdict_51 = ctrl.evaluate_xdp_ingress(pkt, now_ns=1_000_000_000)
        self.assertEqual(verdict_51.action, XDPAction.XDP_DROP)
        self.assertEqual(verdict_51.reason, VerdictReason.RATE_LIMIT_EXCEEDED)

    def test_xdp_ipv6_blocklist_and_ext_header_limit(self) -> None:
        ctrl = MK1XDPController()
        ctrl.send_heartbeat(now_ns=1_000_000_000)
        ctrl.add_blocklist_entry("2001:db8:bad::/48")
        blocked_pkt = _build_ipv6_tcp_packet(src_ip="2001:db8:bad::99")
        v_block = ctrl.evaluate_xdp_ingress(blocked_pkt, now_ns=1_000_000_000)
        self.assertEqual(v_block.action, XDPAction.XDP_DROP)
        self.assertEqual(v_block.reason, VerdictReason.BLOCKLIST_V6)

        # 9 IPv6 extension headers (> MAX_IPV6_EXT_HEADERS = 8) -> DROP
        chain = [(0, b"\x00" * 6) for _ in range(9)]
        ext_pkt = _build_ipv6_tcp_packet(src_ip="2001:db8:1::1", ext_headers=chain)
        v_ext = ctrl.evaluate_xdp_ingress(ext_pkt, now_ns=1_000_000_000)
        self.assertEqual(v_ext.action, XDPAction.XDP_DROP)
        self.assertEqual(v_ext.reason, VerdictReason.IPV6_EXT_CHAIN_LIMIT)

    def test_xdp_vlan_id_allowlist_and_non_first_fragment_drop(self) -> None:
        ctrl = MK1XDPController()
        ctrl.send_heartbeat(now_ns=1_000_000_000)
        ctrl.configure_vlans([10], allow_untagged=True)
        pkt_unauth_vlan = _build_ipv4_tcp_packet(vlan_id=20)
        v_vlan = ctrl.evaluate_xdp_ingress(pkt_unauth_vlan, now_ns=1_000_000_000)
        self.assertEqual(v_vlan.action, XDPAction.XDP_DROP)
        self.assertEqual(v_vlan.reason, VerdictReason.VLAN_VID_FORBIDDEN)

        pkt_auth_vlan = _build_ipv4_tcp_packet(vlan_id=10)
        v_ok = ctrl.evaluate_xdp_ingress(pkt_auth_vlan, now_ns=1_000_000_000)
        self.assertEqual(v_ok.action, XDPAction.XDP_PASS)

        pkt_frag = _build_ipv4_tcp_packet(frag_off=0x0001)
        v_frag = ctrl.evaluate_xdp_ingress(pkt_frag, now_ns=1_000_000_000)
        self.assertEqual(v_frag.action, XDPAction.XDP_DROP)
        self.assertEqual(v_frag.reason, VerdictReason.NON_FIRST_FRAGMENT)

    def test_xdp_dead_man_switch_allows_only_safe_harbor_ssh(self) -> None:
        ctrl = MK1XDPController()
        ctrl.send_heartbeat(now_ns=1_000_000_000)
        ctrl.set_ssh_emergency(True)
        late_ns = 7_500_000_000  # > 5s Dead-Man timeout
        pkt_https = _build_ipv4_tcp_packet(dst_port=443)
        v_https = ctrl.evaluate_xdp_ingress(pkt_https, now_ns=late_ns)
        self.assertEqual(v_https.action, XDPAction.XDP_DROP)
        self.assertEqual(v_https.reason, VerdictReason.DEADMAN_LOCKDOWN)

        pkt_ssh = _build_ipv4_tcp_packet(dst_port=22)
        v_ssh = ctrl.evaluate_xdp_ingress(pkt_ssh, now_ns=late_ns)
        self.assertEqual(v_ssh.action, XDPAction.XDP_PASS)
        self.assertEqual(v_ssh.reason, VerdictReason.PASS)

    def test_tc_egress_drops_plaintext_leak_during_lockdown(self) -> None:
        ctrl = MK1XDPController()
        ctrl.set_oni_mode(True)
        leak_pkt = _build_ipv4_tcp_packet(dst_port=80, payload=b"GET /secret HTTP/1.1\r\n")
        verdict = ctrl.evaluate_tc_egress(leak_pkt, now_ns=1_000_000_000)
        self.assertEqual(verdict.action, TCAction.TC_ACT_SHOT)
        self.assertEqual(verdict.reason, VerdictReason.TC_PLAINTEXT_LEAK)

    def test_p1_01_ml_kem_1024_hybrid_secure_transport(self) -> None:
        from pqcrypto.kem.ml_kem_1024 import keygen
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        pub, priv = keygen()
        x25519_priv = X25519PrivateKey.generate()
        x25519_pub = x25519_priv.public_key().public_bytes(
            mk1_secure_transport.mk1_hybrid_kem.Encoding.Raw, mk1_secure_transport.mk1_hybrid_kem.PublicFormat.Raw
        )
        fp = "a" * 64
        env = mk1_secure_transport.create_encrypted_request(
            pub, {"op": "ping"}, "POST", "/v1/rsi", fp,
            server_x25519_public_key=x25519_pub
        )
        encrypted_resp = mk1_secure_transport.encrypt_server_response(
            priv, x25519_priv, env.kem_ciphertext, b'{"status":"ok"}', "POST", "/v1/rsi", fp,
        )
        plain_resp = mk1_secure_transport.decrypt_server_response(env, encrypted_resp)
        self.assertEqual(plain_resp, b'{"status":"ok"}')
        env.destroy()

    def test_p1_02_flow_cache_detects_modified_payload_on_second_packet(self) -> None:
        defender._FLOW_STATE_CACHE.clear()
        # Use port 9999 (>32 bytes) so adaptive_fast_pass does not short-circuit before full sweep caching
        pkt1 = _build_ipv4_tcp_packet(
            src_ip="10.9.0.1", dst_ip="10.9.0.2", src_port=40001, dst_port=9999,
            payload=b"BENIGN_HEARTBEAT_PACKET_PAYLOAD_0001_SAFE_STREAM",
        )
        defender._cache_flow_result(pkt1, {"suspicious": False, "score": 0.05, "scan_strategy": "full_payload_sweep"})
        res_same = defender.analyze_dpi_payload(pkt1)
        self.assertEqual(res_same.get("scan_strategy"), "flow_cache")

        # Same length payload with different content MUST force full scan and NOT use flow_cache
        pkt_diff = _build_ipv4_tcp_packet(
            src_ip="10.9.0.1", dst_ip="10.9.0.2", src_port=40001, dst_port=9999,
            payload=b"MODIFIED_CONTENT_PACKET_PAYLOAD_0002_SAFE_STREAM",
        )
        res_diff = defender.analyze_dpi_payload(pkt_diff)
        self.assertNotEqual(res_diff.get("scan_strategy"), "flow_cache")

    def test_p1_03_non_initial_fragments_and_unsupported_l2_fail_closed(self) -> None:
        frag_v4 = _build_ipv4_tcp_packet(frag_off=0x0002)
        parsed_v4 = defender.parse_packet_transport(frag_v4)
        self.assertTrue(parsed_v4.get("parse_error"))
        self.assertEqual(parsed_v4.get("reason"), "non_initial_ipv4_fragment")

        frag_v6 = _build_ipv6_tcp_packet(ext_headers=[(44, struct.pack("!H", 0x0008))])
        parsed_v6 = defender.parse_packet_transport(frag_v6)
        self.assertTrue(parsed_v6.get("parse_error"))

        mpls_frame = b"\x00" * 12 + struct.pack("!H", 0x8847) + b"\x00" * 40
        parsed_mpls = defender.parse_packet_transport(mpls_frame)
        self.assertTrue(parsed_mpls.get("parse_error"))
        self.assertEqual(parsed_mpls.get("reason"), "unsupported_l2_ethertype")

    def test_p1_04_ai_anomaly_enforcement_option(self) -> None:
        pkt = _build_ipv4_tcp_packet(payload=b"normal request")
        high_vec = [0.99] * 10
        advisory = defender.inspect_packet_pipeline(
            pkt, "eth0", feature_vector=high_vec, enforce_ai_anomaly=False,
        )
        self.assertFalse(advisory["block"])
        self.assertEqual(advisory["stage"], "advisory")

        enforced = defender.inspect_packet_pipeline(
            pkt, "eth0", feature_vector=high_vec, enforce_ai_anomaly=True,
        )
        self.assertTrue(enforced["block"])
        self.assertEqual(enforced["stage"], "ai_anomaly")

    def test_p1_05_session_ratchet_destroy_removes_from_active_ratchets(self) -> None:
        ratchet = mk1_secure_transport.create_ratcheted_session(
            bytearray(b"\x11" * 32), context=b"sess-p1-05-test01", role="client",
        )
        self.assertIn(ratchet, mk1_secure_transport._ACTIVE_RATCHETS)
        ratchet.destroy()
        self.assertNotIn(ratchet, mk1_secure_transport._ACTIVE_RATCHETS)

    def test_p0_02_per_event_quorum_approval_enables_kill_switch(self) -> None:
        now = int(time.time())
        challenge = mk1_quorum.create_quorum_challenge(
            "ISOLATE_NETWORK",
            {"interface": "eth0"},
            required_m=2,
            total_n=2,
            ttl_sec=300,
            now=now,
            challenge_id="chg-isolate-eth0",
        )
        k1 = mk1_quorum.generate_operator_keypair("op-1")
        k2 = mk1_quorum.generate_operator_keypair("op-2")
        s1 = mk1_quorum.sign_quorum_challenge(
            challenge, operator_id="op-1", private_key_pem=k1["private_key_pem"], signed_at=now,
        )
        s2 = mk1_quorum.sign_quorum_challenge(
            challenge, operator_id="op-2", private_key_pem=k2["private_key_pem"], signed_at=now,
        )
        bundle = mk1_quorum.build_quorum_bundle(challenge, [s1, s2])
        trusted = {"op-1": k1["public_key_pem"], "op-2": k2["public_key_pem"]}

        self.assertTrue(
            defender.verify_event_isolation_approval(
                bundle, challenge_document=challenge, trusted_keys=trusted, interface="eth0", now=now,
            )
        )
        with patch.object(defender, "_apply_nft_policy_with_sudo", return_value=True), \
             patch.object(defender, "_run_command_with_sudo", return_value=True), \
             patch.object(defender, "_persist_quarantine_state", return_value=True):
            ok = defender.execute_kill_switch(
                "eth0",
                False,
                available_interfaces=["eth0"],
                approval_bundle=bundle,
                challenge_document=challenge,
                trusted_keys=trusted,
            )
            self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
