"""Unit tests for MK1Ai Dynamic Honeypot Management, OS Catalog, and Atomic Reconfiguration."""

from __future__ import annotations

import dataclasses
import hashlib
import unittest

from mk1_honeypot import (
    CoreReservedFloor,
    HoneypotEngineError,
    HoneypotImageVerificationError,
    HoneypotManager,
    HoneypotNodeSpec,
    HoneypotPolicyViolationError,
    HoneypotResourceStarvationError,
    HoneypotSlotCost,
    HostResourceCapacity,
    OFFICIAL_OS_CATALOG,
    OSImageManifest,
    compute_effective_honeypot_limit,
    compute_hardware_honeypot_limit,
    sign_image_manifest,
)


class HoneypotLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog_key = b"mk1ai-test-catalog-verify-key-32"
        self.abundant_host = HostResourceCapacity(
            total_cpu_cores=16,
            total_ram_mib=16384,
            total_disk_gib=200,
            total_fd_budget=65536,
        )

    def _make_signed_image(
        self,
        *,
        image_id: str = "img-debian-12",
        os_family: str = "debian",
        os_version: str = "12",
        image_format: str = "qcow2",
        payload: bytes = b"QCOW2-DEBIAN-12-GOLDEN-IMAGE",
        is_custom: bool = False,
        sandbox_quarantine_passed: bool = True,
        prohibited_capabilities: tuple[str, ...] = (),
    ) -> tuple[OSImageManifest, bytes]:
        manifest = OSImageManifest(
            image_id=image_id,
            os_family=os_family,
            os_version=os_version,
            image_format=image_format,
            sha256_hex=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            is_custom=is_custom,
            sandbox_quarantine_passed=sandbox_quarantine_passed,
            prohibited_capabilities=prohibited_capabilities,
        )
        return sign_image_manifest(manifest, self.catalog_key), payload

    def test_effective_honeypot_limit_and_core_reserved_floor(self) -> None:
        # Host that barely meets CORE Reserved Floor (2 cores, 2048 MiB RAM) -> 0 honeypots allowed
        starved_host = HostResourceCapacity(
            total_cpu_cores=2,
            total_ram_mib=2048,
            total_disk_gib=20,
            total_fd_budget=4096,
        )
        self.assertEqual(compute_hardware_honeypot_limit(starved_host), 0)
        limits = compute_effective_honeypot_limit(
            license_limit=8,
            capacity=starved_host,
            admin_policy_limit=8,
        )
        self.assertEqual(limits["effective_limit"], 0)
        self.assertEqual(limits["hardware_limit"], 0)

        # Host with 4 CPU cores, 4096 MiB RAM -> 2 cores & 2048 MiB left -> 2 honeypots max by hardware
        mid_host = HostResourceCapacity(
            total_cpu_cores=4,
            total_ram_mib=4096,
            total_disk_gib=60,
            total_fd_budget=16384,
        )
        limits_mid = compute_effective_honeypot_limit(
            license_limit=8,
            capacity=mid_host,
            admin_policy_limit=6,
        )
        self.assertEqual(limits_mid["hardware_limit"], 2)
        self.assertEqual(limits_mid["effective_limit"], 2)

        # Admin policy tighter than hardware and license
        limits_admin = compute_effective_honeypot_limit(
            license_limit=8,
            capacity=self.abundant_host,
            admin_policy_limit=3,
        )
        self.assertEqual(limits_admin["effective_limit"], 3)

    def test_official_os_catalog_and_custom_os_quarantine_enforcement(self) -> None:
        for family in ("debian", "ubuntu-server", "rocky-linux", "almalinux", "fedora-server"):
            self.assertIn(family, OFFICIAL_OS_CATALOG)

        mgr = HoneypotManager(
            capacity=self.abundant_host,
            catalog_verify_key=self.catalog_key,
            license_limit=4,
            admin_policy_limit=4,
            allowed_os_families=("debian", "ubuntu-server", "rocky-linux", "almalinux", "fedora-server", "custom-os"),
            custom_os_allowed=True,
            auto_rebuild_allowed=True,
        )

        # Tampered SHA-256 image payload must fail closed
        manifest, blob = self._make_signed_image()
        spec = HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=manifest)
        with self.assertRaises(HoneypotImageVerificationError):
            mgr.reconfigure_topology([spec], {manifest.image_id: blob + b"tampered"})

        # Custom OS failing sandbox quarantine must be rejected
        bad_custom_manifest, custom_blob = self._make_signed_image(
            image_id="custom-bad",
            os_family="custom-os",
            os_version="1.0",
            payload=b"CUSTOM-IMAGE-UNSAFE",
            is_custom=True,
            sandbox_quarantine_passed=False,
        )
        bad_spec = HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=bad_custom_manifest)
        with self.assertRaises(HoneypotImageVerificationError):
            mgr.reconfigure_topology([bad_spec], {bad_custom_manifest.image_id: custom_blob})

        # Custom OS with prohibited host mount capability must be rejected
        cap_manifest, cap_blob = self._make_signed_image(
            image_id="custom-cap",
            os_family="custom-os",
            os_version="1.0",
            payload=b"CUSTOM-IMAGE-CAP",
            is_custom=True,
            sandbox_quarantine_passed=True,
            prohibited_capabilities=("CAP_SYS_ADMIN", "HOST_CORE_MOUNT"),
        )
        cap_spec = HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=cap_manifest)
        with self.assertRaises(HoneypotImageVerificationError):
            mgr.reconfigure_topology([cap_spec], {cap_manifest.image_id: cap_blob})

    def test_outer_and_inner_multi_layer_topology_and_atomic_rollback(self) -> None:
        mgr = HoneypotManager(
            capacity=self.abundant_host,
            catalog_verify_key=self.catalog_key,
            license_limit=4,
            admin_policy_limit=4,
            allowed_os_families=("debian", "ubuntu-server", "rocky-linux"),
            custom_os_allowed=False,
            auto_rebuild_allowed=True,
        )
        m_deb, b_deb = self._make_signed_image(image_id="deb12", os_family="debian", os_version="12")
        m_ubu, b_ubu = self._make_signed_image(image_id="ubu24", os_family="ubuntu-server", os_version="24.04", payload=b"UBUNTU-2404")
        m_rky, b_rky = self._make_signed_image(image_id="rky95", os_family="rocky-linux", os_version="9.5", payload=b"ROCKY-95")
        blobs = {"deb12": b_deb, "ubu24": b_ubu, "rky95": b_rky}

        initial_specs = [
            HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=m_deb),
            HoneypotNodeSpec(node_id="Inner-1", layer="inner", zone_index=2, manifest=m_ubu),
        ]
        result = mgr.reconfigure_topology(initial_specs, blobs)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(result["outer_count"], 1)
        self.assertEqual(result["inner_count"], 1)
        self.assertEqual(len(mgr.active_nodes), 2)

        # Inject mid-transaction failure at step 7 and verify atomic rollback preserves Outer-1 and Inner-1
        next_specs = [
            HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=m_deb),
            HoneypotNodeSpec(node_id="Outer-2", layer="outer", zone_index=3, manifest=m_rky),
            HoneypotNodeSpec(node_id="Inner-1", layer="inner", zone_index=2, manifest=m_ubu),
        ]
        with self.assertRaises(HoneypotEngineError):
            mgr.reconfigure_topology(next_specs, blobs, inject_step_failure=7)
        self.assertEqual(set(mgr.active_nodes.keys()), {"Outer-1", "Inner-1"})

        # Exceeding license limit (5 > 4) also rolls back cleanly
        over_specs = [
            HoneypotNodeSpec(node_id=f"Outer-{i}", layer="outer", zone_index=i, manifest=m_deb)
            for i in range(1, 6)
        ]
        with self.assertRaises(HoneypotPolicyViolationError):
            mgr.reconfigure_topology(over_specs, blobs)
        self.assertEqual(set(mgr.active_nodes.keys()), {"Outer-1", "Inner-1"})

    def test_any_scan_or_attack_in_any_active_honeypot_triggers_core_isolation(self) -> None:
        isolated_callbacks: list[tuple[str, dict]] = []
        mgr = HoneypotManager(
            capacity=self.abundant_host,
            catalog_verify_key=self.catalog_key,
            license_limit=4,
            admin_policy_limit=4,
            allowed_os_families=("debian", "ubuntu-server"),
            custom_os_allowed=False,
            auto_rebuild_allowed=True,
            on_core_emergency_isolate=lambda nid, rec: isolated_callbacks.append((nid, rec)),
        )
        m_deb, b_deb = self._make_signed_image(image_id="deb12", os_family="debian", os_version="12")
        specs = [
            HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=m_deb, auto_rebuild=True),
            HoneypotNodeSpec(node_id="Inner-1", layer="inner", zone_index=2, manifest=m_deb, auto_rebuild=True),
        ]
        mgr.reconfigure_topology(specs, {"deb12": b_deb})
        self.assertFalse(mgr.core_isolated)

        # Attack on Outer-1 immediately isolates CORE, captures forensic snapshot, and auto-rebuilds
        ev = mgr.report_honeypot_security_event(
            "Outer-1",
            event_type="SYN_PORT_SCAN",
            attacker_ip="198.51.100.77",
            detail="Aggressive port scan on decoy SSH/HTTP",
        )
        self.assertTrue(mgr.core_isolated)
        self.assertTrue(ev["core_isolated"])
        self.assertTrue(ev["forensic_snapshot_captured"])
        self.assertTrue(ev["auto_rebuilt"])
        self.assertEqual(ev["rebuild_count"], 1)
        self.assertEqual(len(isolated_callbacks), 1)
        self.assertEqual(len(mgr.active_nodes["Outer-1"].forensic_snapshots), 1)

    def test_signed_config_export_and_import_rejects_tampering(self) -> None:
        mgr = HoneypotManager(
            capacity=self.abundant_host,
            catalog_verify_key=self.catalog_key,
            license_limit=4,
            admin_policy_limit=4,
            allowed_os_families=("debian",),
            custom_os_allowed=False,
            auto_rebuild_allowed=True,
        )
        m_deb, b_deb = self._make_signed_image(image_id="deb12", os_family="debian", os_version="12")
        mgr.reconfigure_topology(
            [HoneypotNodeSpec(node_id="Outer-1", layer="outer", zone_index=1, manifest=m_deb)],
            {"deb12": b_deb},
        )
        backup_key = b"mk1ai-config-backup-signing-key!"
        bundle = mgr.export_signed_config(backup_key)

        # Tampered bundle is rejected
        tampered = bundle.replace(b'"Outer-1"', b'"Outer-2"')
        with self.assertRaises(HoneypotEngineError):
            mgr.import_signed_config(tampered, backup_key, {"deb12": b_deb})

        # Valid bundle restores cleanly into a fresh manager
        mgr2 = HoneypotManager(
            capacity=self.abundant_host,
            catalog_verify_key=self.catalog_key,
            license_limit=4,
            admin_policy_limit=4,
            allowed_os_families=("debian",),
            custom_os_allowed=False,
            auto_rebuild_allowed=True,
        )
        res = mgr2.import_signed_config(bundle, backup_key, {"deb12": b_deb})
        self.assertEqual(res["status"], "COMMITTED")
        self.assertIn("Outer-1", mgr2.active_nodes)

    def test_concentric_4_plus_4_shock_gas_ring_buffer_and_ai_safety_loop(self) -> None:
        from airgap_ai_defender import (
            MAX_SAFETY_LOOP_ITERATIONS,
            SafetyExecutionLoop,
            verify_10000_deterministic_cycles,
        )
        from mk1_honeypot import FixedRingBuffer
        import mk1_hybrid_kem
        import mk1_key_derivation
        import mk1_memory_guard

        # 1. FixedRingBuffer pre-allocated capacity never grows dynamically
        ring = FixedRingBuffer(capacity_bytes=128, max_records=4)
        for i in range(10):
            meta = ring.append_payload(f"SHOCK-GAS-PAYLOAD-{i:02d}".encode("ascii"))
            self.assertEqual(meta["capacity"], 128)
        self.assertEqual(ring.capacity_bytes, 128)
        self.assertEqual(ring.read_latest(), b"SHOCK-GAS-PAYLOAD-09")

        # 2. Outer honeypot contact seals airgap, records shock gas, and hands off 10-feature vector to AI
        mgr = HoneypotManager(
            capacity=self.abundant_host,
            catalog_verify_key=self.catalog_key,
            license_limit=8,
            admin_policy_limit=8,
            allowed_os_families=("debian",),
            custom_os_allowed=False,
            auto_rebuild_allowed=True,
        )
        m_deb, b_deb = self._make_signed_image(image_id="deb12", os_family="debian", os_version="12")
        # 5 outer honeypots (> MAX_OUTER_HONEYPOTS=4) is rejected even when total <= 8
        with self.assertRaisesRegex(HoneypotPolicyViolationError, "OUTER limit"):
            mgr.reconfigure_topology(
                [HoneypotNodeSpec(node_id=f"Outer-{i}", layer="outer", zone_index=i, manifest=m_deb) for i in range(1, 6)],
                {"deb12": b_deb},
            )

        # Valid 4 Outer + 4 Inner = 8 concentric topology succeeds
        concentric_specs = [
            HoneypotNodeSpec(node_id=f"Outer-{i}", layer="outer", zone_index=i, manifest=m_deb)
            for i in range(1, 5)
        ] + [
            HoneypotNodeSpec(node_id=f"Inner-{i}", layer="inner", zone_index=i + 4, manifest=m_deb)
            for i in range(1, 5)
        ]
        commit = mgr.reconfigure_topology(concentric_specs, {"deb12": b_deb})
        self.assertEqual(commit["outer_count"], 4)
        self.assertEqual(commit["inner_count"], 4)

        ev = mgr.report_honeypot_security_event(
            "Outer-1",
            event_type="EXPLOIT_PAYLOAD",
            attacker_ip="203.0.113.99",
            detail="Shellcode probe",
            attack_payload=b"GET /../../etc/shadow HTTP/1.1\r\n\r\n",
        )
        self.assertTrue(ev["airgap_sealed"])
        self.assertEqual(ev["quarantine_state"], "FAIL_CLOSED_BLOCK")
        self.assertEqual(ev["ai_handoff"]["action"], "FAIL_CLOSED_BLOCK")
        self.assertEqual(len(ev["ai_handoff"]["feature_vector"]), 10)

        # 3. SafetyExecutionLoop max 3 iterations & 10,000-cycle 0 FP / 0 FN verification
        self.assertEqual(MAX_SAFETY_LOOP_ITERATIONS, 3)
        with self.assertRaises(ValueError):
            SafetyExecutionLoop(max_iterations=4)
        timeout_res = SafetyExecutionLoop().evaluate(b"PING", simulate_timeout=True)
        self.assertEqual(timeout_res["action"], "FAIL_CLOSED_BLOCK")
        stats_10k = verify_10000_deterministic_cycles(10000)
        self.assertTrue(stats_10k["zero_fp_fn_verified"])
        self.assertEqual(stats_10k["false_positives"], 0)
        self.assertEqual(stats_10k["false_negatives"], 0)
        self.assertLessEqual(stats_10k["max_observed_iterations"], 3)

        # 4. SecureBuffer zeroization and production C-extension fail-closed check
        raw_secret = bytearray(b"0123456789abcdef0123456789abcdef")
        with mk1_memory_guard.SecureBuffer(raw_secret) as sbuf:
            self.assertEqual(raw_secret, bytearray(32))  # source wiped immediately
            self.assertEqual(len(sbuf), 32)
        self.assertTrue(sbuf.is_zeroized)
        with self.assertRaisesRegex(RuntimeError, "FAIL_CLOSED_BLOCK"):
            mk1_key_derivation.verify_crypto_provider_integrity(production_mode=True)
        with self.assertRaisesRegex(RuntimeError, "FAIL_CLOSED_BLOCK"):
            mk1_hybrid_kem.verify_crypto_provider_integrity(production_mode=True)


if __name__ == "__main__":
    unittest.main()

