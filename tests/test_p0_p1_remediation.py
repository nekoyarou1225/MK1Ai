import unittest
import math
import struct
import socket
import threading
from airgap_ai_defender import (
    inspect_packet_pipeline,
    toggle_oni_mode,
    ONI_MODE_is_active,
    extract_payload_bytes,
    parse_packet_transport,
    _matches_enforcement_signature,
    _marker_matches_in_context,
)
import mk1_secure_transport
import mk1_hybrid_kem

class TestP0P1Remediation(unittest.TestCase):

    def setUp(self):
        # Ensure ONI_MODE is disabled before each test
        toggle_oni_mode(False)

    def test_p0_1_1_dpi_fail_closed(self):
        # A packet with truncated IP header
        packet = b"\x00" * 14 + b"\x45\x00\x00\x10" # Truncated
        res = inspect_packet_pipeline(packet, "eth0")
        # Should block with stage 'parse_error' because parse_packet_transport returns parse_error=True
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "parse_error")

    def test_p0_1_3_oni_mode_sync(self):
        toggle_oni_mode(True)
        self.assertTrue(ONI_MODE_is_active())
        res = inspect_packet_pipeline(b"dummy", "eth0")
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "oni")
        
        toggle_oni_mode(False)
        self.assertFalse(ONI_MODE_is_active())

    def test_p1_2_1_vlan_parsing(self):
        # Ethernet (14B) + VLAN (4B) + Original EtherType (2B) + IPv4 (20B) + UDP (8B) + Payload
        vlan_packet = (
            b"\x00" * 12 + b"\x81\x00" + b"\x00\x01" + # TPID + TCI
            b"\x08\x00" + # Original EtherType (IPv4)
            b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x11\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01" + # IPv4
            b"\x12\x34\x12\x34\x00\x08\x00\x00" + # UDP
            b"HELLO" # Payload
        )
        payload = extract_payload_bytes(vlan_packet)
        self.assertEqual(payload, b"HELLO")

    def test_p1_2_2_signature_false_positives(self):
        # Benign filenames should NOT trigger signature match
        self.assertIsNone(_matches_enforcement_signature(b"powershell-guide.pdf"))
        self.assertIsNone(_matches_enforcement_signature(b"cmd.exe.md"))
        
        # Actual commands SHOULD trigger signature match
        self.assertIsNotNone(_matches_enforcement_signature(b"powershell -ExecutionPolicy Bypass"))
        self.assertIsNotNone(_matches_enforcement_signature(b"eval(payload)"))
        # But identifier 'my_eval' should NOT match
        self.assertFalse(_marker_matches_in_context(b"my_eval(", b"eval("))

    def test_p1_2_3_feature_validation(self):
        # Use a valid Ethernet + IPv4 packet to pass the parser phase
        valid_packet = (
            b"\x00" * 12 + b"\x08\x00" + # IPv4
            b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01" + # IP
            b"\x12\x34\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00" # TCP (offset 5=20B)
        )
        
        # Invalid length
        res = inspect_packet_pipeline(valid_packet, "eth0", feature_vector=[0.5] * 5)
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "feature_validation")
        
        # NaN value
        res = inspect_packet_pipeline(valid_packet, "eth0", feature_vector=[float('nan')] * 10)
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "feature_validation")
        
        # Out of range
        res = inspect_packet_pipeline(valid_packet, "eth0", feature_vector=[1.5] * 10)
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "feature_validation")

    def test_p1_2_4_secure_transport_unification(self):
        # Verify that SecureTransport uses ML-KEM-1024
        self.assertEqual(mk1_secure_transport.SUPPORTED_PQC_ALGORITHMS, ("ML-KEM-1024",))
        
        # Test creation of encrypted request with CORRECT size keys
        from pqcrypto.kem.ml_kem_1024 import keygen
        pub_key, _ = keygen()
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        x25519_pub = X25519PrivateKey.generate().public_key().public_bytes(
            mk1_hybrid_kem.Encoding.Raw, mk1_hybrid_kem.PublicFormat.Raw
        )
        envelope = mk1_secure_transport.create_encrypted_request(
            pub_key,
            {"test": "data"},
            "POST",
            "/api/test",
            "0" * 64,
            server_x25519_public_key=x25519_pub
        )
        self.assertIsNotNone(envelope.kem_ciphertext)
        self.assertEqual(len(envelope.kem_ciphertext), 32 + mk1_hybrid_kem.ML_KEM_1024_CIPHERTEXT_BYTES)

if __name__ == "__main__":
    unittest.main()
