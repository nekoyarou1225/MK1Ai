"""Unit tests for MK1Ai Offline License Verification, Anti-Rollback, Traffic Policer, and Developer Groups."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from mk1_license import (
    DeveloperGroupAdminEngine,
    DeveloperGroupPrivilegeError,
    LicenseRollbackError,
    LicenseVerificationError,
    MonotonicLicenseLedger,
    OfflineLicenseVerifier,
    PlanTier,
    SignedLicenseCRL,
    SignedLicenseToken,
    TIER_CATALOG,
    TrafficPolicer,
    compute_device_fingerprint,
    ed25519_public_key_from_seed,
    ed25519_sign,
    issue_signed_crl,
    issue_signed_license,
)


class LicensePlatformTest(unittest.TestCase):
    def setUp(self) -> None:
        self.authority_seed32 = b"\x11" * 32
        self.authority_pub32 = ed25519_public_key_from_seed(self.authority_seed32)
        self.device_fp = compute_device_fingerprint(
            machine_id="node-alpha-01",
            cpu_model="AMD-EPYC-9654",
            primary_mac="00:16:3e:aa:bb:cc",
            root_fs_uuid="f47ac10b-58cc-4372-a567-0e02b2c3d479",
        )
        self.verifier = OfflineLicenseVerifier(
            authority_public_key32=self.authority_pub32,
            local_device_fingerprint=self.device_fp,
        )

    def test_client_verifier_holds_no_private_key_and_verifies_ed25519_offline(self) -> None:
        self.assertFalse(self.verifier.has_private_key_material)
        token = issue_signed_license(
            SignedLicenseToken(
                license_id="LIC-PRO-001",
                customer_org="Sovereign Defense Corp",
                tier=PlanTier.PRO,
                device_fingerprint=self.device_fp,
                issued_at_utc=1_700_000_000,
                expires_at_utc=1_800_000_000,
                sequence_number=10,
            ),
            self.authority_seed32,
        )
        ent = self.verifier.evaluate_license(token, current_utc=1_750_000_000, strict=True)
        self.assertEqual(ent.tier, PlanTier.PRO)
        self.assertEqual(ent.max_honeypots, 4)
        self.assertTrue(ent.custom_os_allowed)
        self.assertFalse(ent.degraded_mode)
        self.assertTrue(ent.core_isolation_enabled)
        self.assertTrue(ent.attack_detection_enabled)
        self.assertTrue(ent.emergency_kill_switch_enabled)

    def test_tampered_or_expired_or_wrong_device_enters_safe_degraded_mode_preserving_core(self) -> None:
        valid_token = issue_signed_license(
            SignedLicenseToken(
                license_id="LIC-STD-002",
                customer_org="Org B",
                tier=PlanTier.STANDARD,
                device_fingerprint=self.device_fp,
                issued_at_utc=1_700_000_000,
                expires_at_utc=1_750_000_000,
                sequence_number=1,
            ),
            self.authority_seed32,
        )

        # 1. Expired license -> Safe Degraded Mode (Community/Basic limits, CORE 100% active)
        expired_ent = self.verifier.evaluate_license(valid_token, current_utc=1_760_000_000, strict=False)
        self.assertTrue(expired_ent.degraded_mode)
        self.assertEqual(expired_ent.tier, PlanTier.COMMUNITY_BASIC)
        self.assertEqual(expired_ent.max_honeypots, 1)
        self.assertTrue(expired_ent.core_isolation_enabled)
        self.assertTrue(expired_ent.attack_detection_enabled)
        self.assertTrue(expired_ent.emergency_kill_switch_enabled)
        self.assertTrue(expired_ent.emergency_control_plane_unlimited)

        # 2. Forged tier without authority signature -> rejected / degraded
        forged_token = SignedLicenseToken(
            license_id=valid_token.license_id,
            customer_org=valid_token.customer_org,
            tier=PlanTier.DEVELOPER_GROUP,
            device_fingerprint=self.device_fp,
            issued_at_utc=valid_token.issued_at_utc,
            expires_at_utc=valid_token.expires_at_utc,
            sequence_number=2,
            group_id="grp-1",
            signature_hex=valid_token.signature_hex,
        )
        with self.assertRaises(LicenseVerificationError):
            self.verifier.evaluate_license(forged_token, current_utc=1_720_000_000, strict=True)

        # 3. Hardware fingerprint mismatch -> rejected
        other_fp_token = issue_signed_license(
            SignedLicenseToken(
                license_id="LIC-OTHER-HW",
                customer_org="Org B",
                tier=PlanTier.PRO,
                device_fingerprint="a" * 64,
                issued_at_utc=1_700_000_000,
                expires_at_utc=1_800_000_000,
                sequence_number=3,
            ),
            self.authority_seed32,
        )
        with self.assertRaises(LicenseVerificationError):
            self.verifier.evaluate_license(other_fp_token, current_utc=1_720_000_000, strict=True)

    def test_clock_rollback_and_sequence_downgrade_and_crl_revocation_blocked(self) -> None:
        ledger = MonotonicLicenseLedger(max_clock_skew_sec=10)
        verifier = OfflineLicenseVerifier(
            authority_public_key32=self.authority_pub32,
            local_device_fingerprint=self.device_fp,
            ledger=ledger,
        )
        tok_seq5 = issue_signed_license(
            SignedLicenseToken(
                license_id="LIC-SEQ-5",
                customer_org="Org C",
                tier=PlanTier.PRO,
                device_fingerprint=self.device_fp,
                issued_at_utc=1_700_000_000,
                expires_at_utc=1_800_000_000,
                sequence_number=5,
            ),
            self.authority_seed32,
        )
        verifier.evaluate_license(tok_seq5, current_utc=1_750_000_000, strict=True)

        # System clock rolled back by 1 hour -> LicenseRollbackError
        with self.assertRaises(LicenseRollbackError):
            verifier.evaluate_license(tok_seq5, current_utc=1_750_000_000 - 3600, strict=True)

        # Old license sequence replay (seq=4 < 5) -> LicenseRollbackError
        tok_seq4 = issue_signed_license(
            SignedLicenseToken(
                license_id="LIC-SEQ-4",
                customer_org="Org C",
                tier=PlanTier.STANDARD,
                device_fingerprint=self.device_fp,
                issued_at_utc=1_700_000_000,
                expires_at_utc=1_800_000_000,
                sequence_number=4,
            ),
            self.authority_seed32,
        )
        with self.assertRaises(LicenseRollbackError):
            verifier.evaluate_license(tok_seq4, current_utc=1_750_000_100, strict=True)

        # Install signed CRL revoking LIC-SEQ-5
        crl = issue_signed_crl(
            SignedLicenseCRL(
                crl_sequence=1,
                issued_at_utc=1_750_000_200,
                revoked_license_ids=("LIC-SEQ-5",),
            ),
            self.authority_seed32,
        )
        verifier.install_crl(crl)
        with self.assertRaises(LicenseVerificationError):
            verifier.evaluate_license(tok_seq5, current_utc=1_750_000_300, strict=True)

    def test_traffic_policer_exempts_emergency_control_plane(self) -> None:
        basic_ent = TIER_CATALOG[PlanTier.COMMUNITY_BASIC]
        policer = TrafficPolicer(basic_ent)

        # Normal data-plane traffic exceeding 100 Mbps is throttled
        normal_res = policer.evaluate_traffic(
            observed_mbps=450.0,
            observed_pps=50_000,
            active_sessions=2_048,
            is_emergency_control_plane=False,
        )
        self.assertFalse(normal_res["allowed"])
        self.assertTrue(normal_res["throttled"])

        # Emergency control plane (kill switch / quarantine / alert IPC) is NEVER throttled
        emerg_res = policer.evaluate_traffic(
            observed_mbps=450.0,
            observed_pps=50_000,
            active_sessions=2_048,
            is_emergency_control_plane=True,
        )
        self.assertTrue(emerg_res["allowed"])
        self.assertFalse(emerg_res["throttled"])
        self.assertEqual(emerg_res["exempt_reason"], "EMERGENCY_CONTROL_PLANE_UNLIMITED")

    def test_developer_group_lifecycle_and_zero_trust_privilege_rejection(self) -> None:
        engine = DeveloperGroupAdminEngine(authority_public_key32=self.authority_pub32)
        dev_ent = TIER_CATALOG[PlanTier.DEVELOPER_GROUP]
        pro_ent = TIER_CATALOG[PlanTier.PRO]

        msg = b"MK1AI-DEV-GROUP-CREATE-v1|grp-sec-01|SecOps Core Team|alice|5"
        auth_sig = ed25519_sign(self.authority_seed32, msg).hex()

        # Self-asserted developer flag is rejected even with valid signature
        with self.assertRaises(DeveloperGroupPrivilegeError):
            engine.create_group(
                group_id="grp-sec-01",
                group_name="SecOps Core Team",
                owner_id="alice",
                max_seats=5,
                entitlements=dev_ent,
                authority_signature_hex=auth_sig,
                self_asserted_developer=True,
            )

        # Non-Developer-Group tier (Pro) cannot create a Developer Group
        with self.assertRaises(DeveloperGroupPrivilegeError):
            engine.create_group(
                group_id="grp-sec-01",
                group_name="SecOps Core Team",
                owner_id="alice",
                max_seats=5,
                entitlements=pro_ent,
                authority_signature_hex=auth_sig,
            )

        # Valid Developer Group creation and member addition/removal
        grp = engine.create_group(
            group_id="grp-sec-01",
            group_name="SecOps Core Team",
            owner_id="alice",
            max_seats=5,
            entitlements=dev_ent,
            authority_signature_hex=auth_sig,
        )
        self.assertIn("alice", grp.members)

        engine.add_member(
            group_id="grp-sec-01",
            actor_id="alice",
            member_id="bob",
            role="developer",
            device_fingerprint="b" * 64,
        )
        self.assertIn("bob", grp.members)

        # Non-admin member ("bob") cannot add another member
        with self.assertRaises(DeveloperGroupPrivilegeError):
            engine.add_member(
                group_id="grp-sec-01",
                actor_id="bob",
                member_id="mallory",
                role="admin",
                device_fingerprint="c" * 64,
            )

        engine.remove_member(group_id="grp-sec-01", actor_id="alice", member_id="bob")
        self.assertNotIn("bob", grp.members)
        self.assertTrue(engine.verify_audit_chain())

    def test_thunderhole_32_plans_kyc_biometric_hashes_and_watermark_traceability(self) -> None:
        from mk1_license import (
            THUNDERHOLE_PLAN_CATALOG,
            embed_audit_log_watermark,
            embed_packet_watermark,
            trace_leak_owner,
            validate_kyc_biometric_hashes,
        )

        # 1. Verify all 32 plans (4 categories x 8 sub-tiers) exist and enforce CORE invariants
        self.assertEqual(len(THUNDERHOLE_PLAN_CATALOG), 32)
        for code, ent in THUNDERHOLE_PLAN_CATALOG.items():
            self.assertTrue(ent.core_isolation_enabled, code)
            self.assertTrue(ent.attack_detection_enabled, code)
            self.assertTrue(ent.emergency_kill_switch_enabled, code)

        # 2. Reject 12-digit My Number and raw facial image data
        valid_kyc = "a" * 64
        valid_mesh = "b" * 64
        with self.assertRaisesRegex(LicenseVerificationError, "My Number"):
            validate_kyc_biometric_hashes(
                kyc_identity_hash="123456789012",
                biometric_3d_mesh_hash=valid_mesh,
                device_fingerprint=self.device_fp,
            )
        with self.assertRaisesRegex(LicenseVerificationError, "Raw image"):
            validate_kyc_biometric_hashes(
                kyc_identity_hash=valid_kyc,
                biometric_3d_mesh_hash=b"\x89PNG\r\n\x1a\nrawface",
                device_fingerprint=self.device_fp,
            )

        # 3. Issue RESEARCH.ULTRA_MAX 30-day offline trial with KYC + 3D mesh hash + watermark
        trial_token = issue_signed_license(
            SignedLicenseToken(
                license_id="TRIAL-RES-001",
                customer_org="AegisLab Trial User",
                tier=PlanTier.PRO,
                plan_code="RESEARCH.ULTRA_MAX",
                device_fingerprint=self.device_fp,
                issued_at_utc=1_700_000_000,
                expires_at_utc=1_700_000_000 + 30 * 86400,
                sequence_number=10,
                kyc_identity_hash=valid_kyc,
                biometric_3d_mesh_hash=valid_mesh,
                is_offline_trial=True,
            ),
            self.authority_seed32,
        )
        verifier = OfflineLicenseVerifier(
            authority_public_key32=self.authority_pub32,
            local_device_fingerprint=self.device_fp,
        )
        ent = verifier.evaluate_license(trial_token, current_utc=1_700_010_000, strict=True)
        self.assertEqual(ent.plan_code, "RESEARCH.ULTRA_MAX")
        self.assertTrue(ent.watermark_required)
        self.assertIsNotNone(ent.watermark_digest)

        # 4. Verify 100% owner reverse-traceability from leaked packet and audit log
        wm_pkt = embed_packet_watermark(b"THUNDERHOLE-TRIAL-PACKET", ent.watermark_digest or "")
        wm_log = embed_audit_log_watermark({"event": "trial_export"}, ent.watermark_digest or "")
        traced_pkt = trace_leak_owner(wm_pkt, [trial_token])
        traced_log = trace_leak_owner(wm_log, [trial_token])
        self.assertIsNotNone(traced_pkt)
        self.assertEqual(traced_pkt["license_id"], "TRIAL-RES-001")
        self.assertEqual(traced_pkt["kyc_identity_hash"], valid_kyc)
        self.assertEqual(traced_log["license_id"], "TRIAL-RES-001")

        # 5. Expiration degrades safely to GENERAL.PLUS with CORE 100% active
        expired_ent = verifier.evaluate_license(
            trial_token, current_utc=1_700_000_000 + 31 * 86400, strict=False,
        )
        self.assertTrue(expired_ent.degraded_mode)
        self.assertEqual(expired_ent.plan_code, "GENERAL.PLUS")
        self.assertTrue(expired_ent.core_isolation_enabled)


if __name__ == "__main__":
    unittest.main()

