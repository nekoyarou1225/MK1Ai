"""Unit tests for MK1Ai One-Tap Envelope Encryption, 9-Zone Key Isolation, and QKD/PQC Posture."""

from __future__ import annotations

import dataclasses
import unittest

from mk1_one_tap_crypto import (
    ALL_9_SECURITY_ZONES,
    CryptoPostureTracker,
    EnvelopeTamperError,
    NineZoneKeyVault,
    OneTapCryptoError,
    OneTapEnvelope,
    SecurityZone,
    ZoneIsolationViolationError,
    one_tap_decrypt,
    one_tap_encrypt,
)


class OneTapCryptoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = NineZoneKeyVault(root_seed32=b"\x42" * 32)

    def test_all_9_zones_derive_distinct_isolated_keys(self) -> None:
        self.assertEqual(len(ALL_9_SECURITY_ZONES), 9)
        seen_key_ids: set[str] = set()
        nonce = b"\x01" * 16
        for zone in ALL_9_SECURITY_ZONES:
            subkey, key_id, epoch = self.vault.derive_envelope_subkey(
                zone, caller_zone=zone, envelope_nonce=nonce
            )
            self.assertEqual(epoch, 1)
            self.assertNotIn(key_id, seen_key_ids)
            seen_key_ids.add(key_id)
            self.assertEqual(len(subkey), 32)

    def test_one_tap_encrypt_decrypt_roundtrip_and_cross_zone_isolation(self) -> None:
        secret_payload = b"CORE_TELEMETRY_SNAPSHOT:attack_blocked=true"
        aad = b"channel=core-internal-audit"
        env = one_tap_encrypt(
            self.vault,
            zone=SecurityZone.ZONE_CORE_MAIN,
            plaintext=secret_payload,
            aad=aad,
        )
        recovered = one_tap_decrypt(
            self.vault,
            caller_zone=SecurityZone.ZONE_CORE_MAIN,
            envelope=env,
            aad=aad,
        )
        self.assertEqual(recovered, secret_payload)

        # Every honeypot zone (1..8) MUST be rejected when attempting to decrypt ZONE_CORE_MAIN envelope
        for hp_zone in ALL_9_SECURITY_ZONES:
            if hp_zone == SecurityZone.ZONE_CORE_MAIN:
                continue
            with self.assertRaises(ZoneIsolationViolationError):
                one_tap_decrypt(
                    self.vault,
                    caller_zone=hp_zone,
                    envelope=env,
                    aad=aad,
                )

    def test_honeypot_compromise_key_destruction_does_not_affect_core_or_other_honeypots(self) -> None:
        env_hp1 = one_tap_encrypt(
            self.vault,
            zone=SecurityZone.ZONE_HONEYPOT_1,
            plaintext=b"hp1-decoy-log",
        )
        env_core = one_tap_encrypt(
            self.vault,
            zone=SecurityZone.ZONE_CORE_MAIN,
            plaintext=b"core-vital-secret",
        )

        # Simulate Honeypot 1 compromise -> destroy ZONE_HONEYPOT_1 key
        self.vault.destroy_zone_key(SecurityZone.ZONE_HONEYPOT_1)
        with self.assertRaises(OneTapCryptoError):
            one_tap_decrypt(
                self.vault,
                caller_zone=SecurityZone.ZONE_HONEYPOT_1,
                envelope=env_hp1,
            )

        # ZONE_CORE_MAIN remains 100% operational and unaffected
        self.assertEqual(
            one_tap_decrypt(
                self.vault,
                caller_zone=SecurityZone.ZONE_CORE_MAIN,
                envelope=env_core,
            ),
            b"core-vital-secret",
        )

    def test_tampered_ciphertext_aad_or_tag_fails_closed(self) -> None:
        env = one_tap_encrypt(
            self.vault,
            zone=SecurityZone.ZONE_HONEYPOT_2,
            plaintext=b"integrity-protected-message",
            aad=b"context-v1",
        )
        # Wrong AAD
        with self.assertRaises(EnvelopeTamperError):
            one_tap_decrypt(
                self.vault,
                caller_zone=SecurityZone.ZONE_HONEYPOT_2,
                envelope=env,
                aad=b"context-v2-tampered",
            )
        # Tampered tag
        bad_tag_env = dataclasses.replace(env, tag_hex="00" * 32)
        with self.assertRaises(EnvelopeTamperError):
            one_tap_decrypt(
                self.vault,
                caller_zone=SecurityZone.ZONE_HONEYPOT_2,
                envelope=bad_tag_env,
                aad=b"context-v1",
            )

    def test_crypto_posture_strictly_separates_qkd_from_pqc_and_ratchet(self) -> None:
        tracker = CryptoPostureTracker(
            qkd_kme_connected=False,
            qkd_authenticated_channel=False,
            pqc_ml_kem_768_available=False,
            classical_ed25519_available=True,
            symmetric_ratchet_active=True,
        )
        report = tracker.get_posture_report()
        self.assertEqual(report["qkd"]["status"], "QKD_UNAVAILABLE")
        self.assertFalse(report["qkd"]["conflated_with_pqc"])
        self.assertEqual(report["pqc"]["status"], "PQC_LIB_NOT_INSTALLED")
        self.assertEqual(report["classical_asymmetric"]["status"], "ACTIVE")
        self.assertEqual(report["symmetric_and_ratchet"]["one_tap_aead"], "ACTIVE_9ZONE_ISOLATED")


if __name__ == "__main__":
    unittest.main()
