import time
import unittest

import mk1_quorum
from mk1_qkd import (
    ETSIKMIClient,
    QKDAuditMonitor,
    QKDDeviceAdapter,
    QKDKeyLifecycleState,
    QKDKeyPurpose,
    QKDKeyRegistry,
    QKDLinkMetrics,
    QKDPolicyController,
    QKDSessionManager,
    QKDState,
    QKDTransportBridge,
    QKDTransportMode,
    QKDValidationError,
    validate_qkd_key_material,
    validate_qkd_zone_policy,
)


class TestQKDSubsystem(unittest.TestCase):
    def _make_high_entropy_key(self, seed: int = 0) -> bytes:
        return bytes((i * 73 + seed * 31 + 19) % 256 for i in range(32))

    def test_simulated_adapter_never_enters_qkd_ready(self) -> None:
        adapter = QKDDeviceAdapter(
            vendor_name="SIM-KME",
            kme_endpoint="https://kme.local",
            expected_kme_spki_sha256="a" * 64,
            is_simulated=True,
            hardware_present=True,
        )
        self.assertEqual(adapter.state, QKDState.QKD_SIMULATED)
        self.assertFalse(adapter.is_production_qkd_active)
        with self.assertRaises(PermissionError):
            adapter.connect_hardware_kme(
                presented_spki_sha256="a" * 64,
                metrics=QKDLinkMetrics(
                    qber=0.01,
                    sifted_key_rate_bps=50000.0,
                    optical_loss_db=3.0,
                    available_keys=100,
                ),
            )

    def test_real_hardware_adapter_transitions_through_states_and_qber_abort(self) -> None:
        spki_pin = "b" * 64
        adapter = QKDDeviceAdapter(
            vendor_name="TOSHIBA-QKD",
            kme_endpoint="https://kme.honmaru.internal",
            expected_kme_spki_sha256=spki_pin,
            is_simulated=False,
            hardware_present=True,
        )
        self.assertEqual(adapter.state, QKDState.QKD_CONNECTING)
        state_ready = adapter.connect_hardware_kme(
            presented_spki_sha256=spki_pin,
            metrics=QKDLinkMetrics(
                qber=0.012,
                sifted_key_rate_bps=120000.0,
                optical_loss_db=2.5,
                available_keys=64,
            ),
        )
        self.assertEqual(state_ready, QKDState.QKD_READY)
        self.assertTrue(adapter.is_production_qkd_active)

        # High QBER (>= 11%) triggers QKD_DEGRADED and disables production QKD
        state_degraded = adapter.connect_hardware_kme(
            presented_spki_sha256=spki_pin,
            metrics=QKDLinkMetrics(
                qber=0.14,
                sifted_key_rate_bps=120000.0,
                optical_loss_db=2.5,
                available_keys=64,
            ),
        )
        self.assertEqual(state_degraded, QKDState.QKD_DEGRADED)
        self.assertFalse(adapter.is_production_qkd_active)

    def test_9_zone_policy_prohibits_outer_zones_and_cross_zone_honmaru_import(self) -> None:
        for outer in ("OUTER_1", "OUTER_2", "OUTER_3", "OUTER_4"):
            with self.assertRaises(PermissionError):
                validate_qkd_zone_policy(outer)

        for allowed in ("INNER_1", "INNER_2", "INNER_3", "INNER_4", "HONMARU"):
            self.assertEqual(validate_qkd_zone_policy(allowed), allowed)

        reg = QKDKeyRegistry()
        now_ns = time.time_ns()
        key_id = "550e8400-e29b-41d4-a716-446655440000"
        reg.register_key(
            key_id=key_id,
            raw_key=self._make_high_entropy_key(1),
            source_kme_id="KME-INNER-1",
            target_kme_id="KME-INNER-2",
            zone_id="INNER_1",
            purpose=QKDKeyPurpose.TRANSPORT_HYBRID_COMBINER,
            issued_at_ns=now_ns,
            expires_at_ns=now_ns + 60_000_000_000,
            now_ns=now_ns,
        )
        with self.assertRaises(PermissionError):
            reg.reserve_key(
                key_id,
                requester_zone_id="HONMARU",
                expected_purpose=QKDKeyPurpose.TRANSPORT_HYBRID_COMBINER,
                now_ns=now_ns,
            )

    def test_key_registry_one_time_use_and_zeroization(self) -> None:
        audit = QKDAuditMonitor()
        reg = QKDKeyRegistry(audit_monitor=audit)
        now_ns = time.time_ns()
        key_id = "550e8400-e29b-41d4-a716-446655440001"
        raw_key = self._make_high_entropy_key(2)
        rec = reg.register_key(
            key_id=key_id,
            raw_key=raw_key,
            source_kme_id="KME-HONMARU-1",
            target_kme_id="KME-HONMARU-2",
            zone_id="HONMARU",
            purpose=QKDKeyPurpose.TRANSPORT_HYBRID_COMBINER,
            issued_at_ns=now_ns,
            expires_at_ns=now_ns + 60_000_000_000,
            now_ns=now_ns,
        )
        self.assertEqual(rec.state, QKDKeyLifecycleState.AVAILABLE)

        # Wrong purpose must be rejected
        with self.assertRaises(PermissionError):
            reg.consume_and_wipe(
                key_id,
                requester_zone_id="HONMARU",
                expected_purpose=QKDKeyPurpose.AUDIT_SEAL_MAC,
                now_ns=now_ns,
            )

        consumed = reg.consume_and_wipe(
            key_id,
            requester_zone_id="HONMARU",
            expected_purpose=QKDKeyPurpose.TRANSPORT_HYBRID_COMBINER,
            now_ns=now_ns,
        )
        self.assertEqual(bytes(consumed), raw_key)
        self.assertEqual(rec.state, QKDKeyLifecycleState.WIPED)
        self.assertEqual(bytes(rec.raw_key), b"\x00" * 32)

        # Second consumption attempt on same key_id must fail (One-Time Use)
        with self.assertRaises((KeyError, RuntimeError, PermissionError)):
            reg.consume_and_wipe(
                key_id,
                requester_zone_id="HONMARU",
                expected_purpose=QKDKeyPurpose.TRANSPORT_HYBRID_COMBINER,
                now_ns=now_ns,
            )
        self.assertTrue(audit.verify_chain())

    def test_etsi_kmi_client_and_session_manager_and_hybrid_transport_bridge(self) -> None:
        spki_pin = "c" * 64
        adapter = QKDDeviceAdapter(
            vendor_name="IDQ-QKD",
            kme_endpoint="https://kme.honmaru.internal",
            expected_kme_spki_sha256=spki_pin,
            is_simulated=False,
            hardware_present=True,
        )
        adapter.connect_hardware_kme(
            presented_spki_sha256=spki_pin,
            metrics=QKDLinkMetrics(
                qber=0.011,
                sifted_key_rate_bps=100000.0,
                optical_loss_db=2.0,
                available_keys=128,
            ),
        )
        kmi = ETSIKMIClient(adapter)
        init_reg = QKDKeyRegistry()
        resp_reg = QKDKeyRegistry()
        sess_mgr = QKDSessionManager(kmi, init_reg)

        now_ns = time.time_ns()
        sync_meta = sess_mgr.initiate_session_key(
            zone_id="HONMARU",
            purpose=QKDKeyPurpose.SESSION_RATCHET_ROOT_SEED,
            session_epoch=1,
            initiator_nonce=b"\x01" * 16,
            responder_nonce=b"\x02" * 16,
            now_ns=now_ns,
        )
        accepted_kid = sess_mgr.accept_session_key(
            sync_meta, responder_registry=resp_reg, now_ns=now_ns,
        )
        self.assertEqual(accepted_kid, sync_meta.key_id)

        bridge_init = QKDTransportBridge(init_reg)
        bridge_resp = QKDTransportBridge(resp_reg)
        ratchet_i, res_i = bridge_init.create_hybrid_session_ratchet(
            key_id=sync_meta.key_id,
            zone_id="HONMARU",
            ml_kem_shared_secret=b"\xAA" * 32,
            x25519_shared_secret=b"\xBB" * 32,
            context_transcript=sync_meta.transcript_binding_sha384,
            role="client",
            session_epoch=1,
            now_ns=now_ns,
        )
        ratchet_r, res_r = bridge_resp.create_hybrid_session_ratchet(
            key_id=sync_meta.key_id,
            zone_id="HONMARU",
            ml_kem_shared_secret=b"\xAA" * 32,
            x25519_shared_secret=b"\xBB" * 32,
            context_transcript=sync_meta.transcript_binding_sha384,
            role="server",
            session_epoch=1,
            now_ns=now_ns,
        )
        self.assertEqual(res_i.derived_key, res_r.derived_key)
        ct = ratchet_i.encrypt(b"Quantum-hybrid airgap frame", aad=b"honmaru")
        pt = ratchet_r.decrypt(ct, aad=b"honmaru")
        self.assertEqual(pt, b"Quantum-hybrid airgap frame")
        ratchet_i.destroy()
        ratchet_r.destroy()

    def test_policy_downgrade_requires_quorum_approval(self) -> None:
        adapter = QKDDeviceAdapter(is_simulated=False, hardware_present=False)
        policy = QKDPolicyController(
            adapter,
            initial_mode=QKDTransportMode.QKD_MANDATORY,
        )
        with self.assertRaises(PermissionError):
            policy.change_mode(QKDTransportMode.PQC_ONLY)

        now = int(time.time())
        challenge = mk1_quorum.create_quorum_challenge(
            "qkd_fallback_to_pqc_only",
            {"target_mode": "PQC_ONLY"},
            required_m=2,
            total_n=2,
            ttl_sec=300,
            now=now,
            challenge_id="chg-qkd-downgrade",
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

        new_mode = policy.change_mode(
            QKDTransportMode.PQC_ONLY,
            quorum_bundle=bundle,
            challenge_document=challenge,
            trusted_keys=trusted,
            now=now,
        )
        self.assertEqual(new_mode, QKDTransportMode.PQC_ONLY)

    def test_low_entropy_key_material_rejected(self) -> None:
        now_ns = time.time_ns()
        with self.assertRaises(QKDValidationError):
            validate_qkd_key_material(
                b"\x00" * 32,
                key_id="550e8400-e29b-41d4-a716-446655440000",
                issued_at_ns=now_ns,
                expires_at_ns=now_ns + 60_000_000_000,
                now_ns=now_ns,
            )


if __name__ == "__main__":
    unittest.main()
