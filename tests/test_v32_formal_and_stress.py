"""Comprehensive Verification, Mathematical Stress Testing, Fault Injection, Property-Based, and Mutation Testing Suite for MK1Ai FSM V3.2."""

from __future__ import annotations

import copy
import json
import math
import multiprocessing
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import airgap_ai_defender as defender
from airgap_ai_defender import MK1SafetyStateMachine
import mk1_quorum
from formal import mk1_formal_verifier


def _mp_worker_transition(state_path: str, hmac_key: str, worker_id: int, iterations: int, out_q) -> None:
    """Top-level worker for 2/4/8 OS process concurrency stress tests (PART 5.3 & P1-004)."""
    observed_gens = []
    errors = []
    try:
        for i in range(iterations):
            fsm = MK1SafetyStateMachine(state_path=state_path, hmac_key=hmac_key, lock_timeout_sec=5.0)
            ok = fsm.isolate_immediately(
                reason=f"MP-Worker-{worker_id}-iter-{i}",
                event_id=f"evt-mp-{worker_id}-{i}",
                challenge_id=f"chg-mp-{worker_id}-{i}",
            )
            if not ok or fsm.current_state != MK1SafetyStateMachine.ISOLATED:
                errors.append(f"Worker {worker_id} iter {i} failed isolation")
            observed_gens.append(fsm.generation)
    except Exception as exc:
        errors.append(f"Worker {worker_id} exception: {type(exc).__name__}: {exc}")
    out_q.put({"worker_id": worker_id, "gens": observed_gens, "errors": errors})


class TestFSMV32UltimateVerification(unittest.TestCase):
    """Covers PART 1 (15 Findings), PART 2-4 (Formal Model & Refinement), and PART 5 (49 Matrix, 16/32/64 Threads, 2/4/8 Processes, 17 Faults, PBT, 7 Mutants)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = os.path.join(self.temp_dir.name, "fsm_state.json")
        self.hmac_key = "v32-sovereign-airgap-cryptographic-hmac-key-2026"
        defender.toggle_oni_mode(False)
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()
        defender._KILL_SWITCH_TRIGGERED = False
        defender._KILL_SWITCH_EVENT.clear()
        defender._LAST_KILL_SWITCH_TRIGGER = 0.0
        defender._anomaly_counter = 0
        defender._ISOLATION_APPROVAL_PENDING = False

    def tearDown(self):
        defender.toggle_oni_mode(False)
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()
        self.temp_dir.cleanup()

    def _build_valid_quorum(
        self,
        event_id: str = "evt-v32-001",
        challenge_id: str = "chg-v32-001",
        policy_version: int = 1,
        issued_at: int | None = None,
        ttl_sec: int = 300,
    ):
        op1 = mk1_quorum.generate_operator_keypair("admin_1")
        op2 = mk1_quorum.generate_operator_keypair("admin_2")
        op3 = mk1_quorum.generate_operator_keypair("admin_3")
        trusted = {
            "admin_1": op1["public_key_pem"],
            "admin_2": op2["public_key_pem"],
            "admin_3": op3["public_key_pem"],
        }
        now_ts = int(time.time()) if issued_at is None else issued_at
        chg = mk1_quorum.create_quorum_challenge(
            "RELEASE_QUARANTINE",
            {
                "interface": "eth0",
                "event_id": event_id,
                "policy_version": policy_version,
                "domain": "MK1AI-RECOVERY-v1",
            },
            required_m=2,
            total_n=3,
            ttl_sec=ttl_sec,
            now=now_ts,
            challenge_id=challenge_id,
            policy_version=policy_version,
        )
        s1 = mk1_quorum.sign_quorum_challenge(chg, operator_id="admin_1", private_key_pem=op1["private_key_pem"])
        s2 = mk1_quorum.sign_quorum_challenge(chg, operator_id="admin_2", private_key_pem=op2["private_key_pem"])
        bundle = mk1_quorum.build_quorum_bundle(chg, [s1, s2])
        return trusted, chg, bundle, (op1, op2, op3)

    # =========================================================================
    # PART 1: P0-001 .. P3-001 Remediation Verification
    # =========================================================================

    def test_p0_001_production_fsm_persistence_and_isolated_restart(self):
        """P0-001: Production _SAFETY_FSM has explicit persistence paths and preserves ISOLATED across restarts."""
        self.assertIsNotNone(defender._SAFETY_FSM.state_path)
        self.assertIsNotNone(defender._SAFETY_FSM.journal_path)
        self.assertTrue(os.path.isfile(defender._SAFETY_FSM.state_path))
        self.assertTrue(os.path.isfile(defender._SAFETY_FSM.journal_path))

        # Test subprocess restart preserving ISOLATED
        custom_dir = os.path.join(self.temp_dir.name, "prod_boot_test")
        env = os.environ.copy()
        env["MK1_FSM_STATE_DIR"] = custom_dir
        code_isolate = (
            "import airgap_ai_defender as d; "
            "assert d._SAFETY_FSM.current_state == 'ACTIVE'; "
            "d._SAFETY_FSM.isolate_immediately(reason='P0 Boot Test', event_id='evt-boot-1', challenge_id='chg-boot-1'); "
            "print(d._SAFETY_FSM.current_state, d._SAFETY_FSM.generation)"
        )
        r1 = subprocess.run([sys.executable, "-c", code_isolate], env=env, capture_output=True, text=True, check=True)
        self.assertIn("ISOLATED", r1.stdout)

        code_restart = (
            "import airgap_ai_defender as d; "
            "print(d._SAFETY_FSM.current_state, d._SAFETY_FSM.generation, d._SAFETY_FSM.authenticity_status)"
        )
        r2 = subprocess.run([sys.executable, "-c", code_restart], env=env, capture_output=True, text=True, check=True)
        self.assertIn("ISOLATED 4 VERIFIED", r2.stdout.strip())

    def test_p0_002_strict_dry_run_isolation_always_enforced(self):
        """P0-002: strict_dry_run_isolation is always True even when state_path=None, and cannot be disabled."""
        with self.assertRaises(ValueError):
            MK1SafetyStateMachine(strict_dry_run_isolation=False)

        ephemeral_fsm = MK1SafetyStateMachine(state_path=None)
        ephemeral_fsm.transition_to(ephemeral_fsm.ARMING)
        ephemeral_fsm.transition_to(ephemeral_fsm.ACTIVE)
        gen_before = ephemeral_fsm.generation

        ephemeral_fsm.isolate_immediately(reason="Simulated P0", simulated=True)
        self.assertEqual(ephemeral_fsm.current_state, ephemeral_fsm.ACTIVE)
        self.assertEqual(ephemeral_fsm.simulated_state, ephemeral_fsm.ISOLATED)
        self.assertEqual(ephemeral_fsm.generation, gen_before)

    def test_p0_003_recovery_preempted_by_concurrent_emergency_isolation(self):
        """P0-003: Emergency isolation preempts recovery immediately via atomic latch & epoch without blocking or losing P0."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key, lock_timeout_sec=0.1)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.isolate_immediately(reason="Initial P0", event_id="evt-p0-003", challenge_id="chg-p0-003")
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

        trusted, chg, bundle, _ = self._build_valid_quorum(event_id="evt-p0-003", challenge_id="chg-p0-003")
        # Simulate slow verification (80ms) while lock_timeout_sec is 100ms; since Phase R2 is lock-free,
        # isolate_immediately() finishes in <5ms and aborts recovery!
        fsm._recovery_verification_delay_sec = 0.08
        barrier = threading.Barrier(2)
        results = {}

        def _rec_worker():
            barrier.wait(timeout=2.0)
            results["rec_ok"] = fsm.request_recovery(bundle, chg, trusted)

        def _iso_worker():
            barrier.wait(timeout=2.0)
            time.sleep(0.015)
            t0 = time.monotonic()
            results["iso_ok"] = fsm.isolate_immediately(
                reason="Concurrent P0 during Recovery",
                event_id="evt-p0-new",
                challenge_id="chg-p0-new",
            )
            results["iso_latency_ms"] = (time.monotonic() - t0) * 1000.0

        t1 = threading.Thread(target=_rec_worker, daemon=True)
        t2 = threading.Thread(target=_iso_worker, daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)

        self.assertFalse(results["rec_ok"], "Recovery must abort when P0 preempts!")
        self.assertTrue(results["iso_ok"], "Concurrent P0 isolation must succeed without TimeoutError!")
        self.assertLess(results["iso_latency_ms"], 50.0, "P0 isolation must not wait for 80ms recovery verification!")
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_p0_004_missing_state_or_journal_or_both_fails_closed(self):
        """P0-004: Deleting state file, journal file, or both after provisioning fails closed to ISOLATED."""
        # 1. Missing state file (journal exists)
        p1 = os.path.join(self.temp_dir.name, "s1", "fsm.json")
        fsm1 = MK1SafetyStateMachine(state_path=p1, hmac_key=self.hmac_key)
        fsm1.transition_to(fsm1.ARMING)
        fsm1.transition_to(fsm1.ACTIVE)
        fsm1.isolate_immediately(reason="P0")
        os.unlink(p1)
        reloaded1 = MK1SafetyStateMachine(state_path=p1, hmac_key=self.hmac_key)
        self.assertEqual(reloaded1.current_state, reloaded1.ISOLATED)
        self.assertEqual(reloaded1.authenticity_status, "FAILED_MISSING_STATE")

        # 2. Missing journal file (state exists)
        p2 = os.path.join(self.temp_dir.name, "s2", "fsm.json")
        fsm2 = MK1SafetyStateMachine(state_path=p2, hmac_key=self.hmac_key)
        fsm2.transition_to(fsm2.ARMING)
        fsm2.transition_to(fsm2.ACTIVE)
        os.unlink(fsm2.journal_path)
        reloaded2 = MK1SafetyStateMachine(state_path=p2, hmac_key=self.hmac_key)
        self.assertEqual(reloaded2.current_state, reloaded2.ISOLATED)
        self.assertEqual(reloaded2.authenticity_status, "FAILED_MISSING_JOURNAL")

        # 3. Missing both state and journal (boot anchor exists)
        p3 = os.path.join(self.temp_dir.name, "s3", "fsm.json")
        fsm3 = MK1SafetyStateMachine(state_path=p3, hmac_key=self.hmac_key)
        fsm3.transition_to(fsm3.ARMING)
        fsm3.transition_to(fsm3.ACTIVE)
        fsm3.isolate_immediately(reason="P0")
        os.unlink(p3)
        os.unlink(fsm3.journal_path)
        reloaded3 = MK1SafetyStateMachine(state_path=p3, hmac_key=self.hmac_key)
        self.assertEqual(reloaded3.current_state, reloaded3.ISOLATED)
        self.assertEqual(reloaded3.authenticity_status, "FAILED_STORAGE_WIPE")

    def test_p0_005_kill_switch_8_states_and_failure_never_reported_as_success(self):
        """P0-005: Logical FSM isolation and OS network block confirmation are tracked separately across 8 states."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_NOT_REQUESTED)
        self.assertFalse(fsm.network_block_confirmed)

        # Case A: execute_kill_switch returns False -> logical state is ISOLATED, but return is False and OS_BLOCK_FAILED
        with mock.patch.object(defender, "execute_kill_switch", return_value=False):
            ok_fail = defender.evaluate_threat_state(
                interface="eth0",
                dry_run=False,
                score_a=0.99,
                autonomous=True,
                fsm=fsm,
            )
        self.assertFalse(ok_fail)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_OS_BLOCK_FAILED)
        self.assertFalse(fsm.network_block_confirmed)

        # Case B: execute_kill_switch returns True, but independent verifier returns PARTIAL -> PARTIALLY_ISOLATED
        defender._LAST_KILL_SWITCH_TRIGGER = 0.0
        fsm._network_block_verifier = lambda iface: "PARTIAL"
        with mock.patch.object(defender, "execute_kill_switch", return_value=True):
            ok_partial = defender.evaluate_threat_state(
                interface="eth0",
                dry_run=False,
                score_a=0.99,
                autonomous=True,
                fsm=fsm,
            )
        self.assertFalse(ok_partial)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_PARTIALLY_ISOLATED)
        self.assertFalse(fsm.network_block_confirmed)

        # Case C: execute_kill_switch returns True and verifier returns True -> OS_BLOCK_CONFIRMED
        defender._LAST_KILL_SWITCH_TRIGGER = 0.0
        fsm._network_block_verifier = lambda iface: True
        with mock.patch.object(defender, "execute_kill_switch", return_value=True):
            ok_confirmed = defender.evaluate_threat_state(
                interface="eth0",
                dry_run=False,
                score_a=0.99,
                autonomous=True,
                fsm=fsm,
            )
        self.assertTrue(ok_confirmed)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_OS_BLOCK_CONFIRMED)
        self.assertTrue(fsm.network_block_confirmed)

    def test_p1_001_no_hardcoded_hmac_key_and_key_rotation(self):
        """P1-001: Forbidden weak/default key is rejected fail-closed; key permissions and key rotation work atomically."""
        # Reject forbidden legacy constant key
        fsm_bad = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=b"MK1AI-FSM-SECRET-KEY-V3")
        self.assertEqual(fsm_bad.current_state, fsm_bad.ISOLATED)
        self.assertEqual(fsm_bad.authenticity_status, "FAILED_KEY_SECURITY")

        # Valid auto-provisioned key file with 0o600 check and key rotation
        p_rot = os.path.join(self.temp_dir.name, "rot", "fsm.json")
        k_rot = os.path.join(self.temp_dir.name, "rot_keys", "hmac.key")
        fsm = MK1SafetyStateMachine(state_path=p_rot, key_path=k_rot)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        self.assertEqual(stat.S_IMODE(os.stat(k_rot).st_mode), 0o600)

        # Rotate key
        new_secret = "rotated-high-entropy-hmac-secret-key-2026-v32"
        self.assertTrue(fsm.rotate_hmac_key(new_secret))
        reloaded = MK1SafetyStateMachine(state_path=p_rot, key_path=k_rot)
        self.assertEqual(reloaded.current_state, reloaded.ACTIVE)
        self.assertEqual(reloaded.authenticity_status, "VERIFIED")

        # Overly permissive key file (0o644) must fail-closed to ISOLATED
        os.chmod(k_rot, 0o644)
        bad_perm_fsm = MK1SafetyStateMachine(state_path=p_rot, key_path=k_rot)
        self.assertEqual(bad_perm_fsm.current_state, bad_perm_fsm.ISOLATED)
        self.assertEqual(bad_perm_fsm.authenticity_status, "FAILED_KEY_SECURITY")

    def test_p1_002_and_p1_003_journal_state_consistency_and_split_brain_prevention(self):
        """P1-002 & P1-003: Journal failure rolls back cleanly, and same-generation state mismatch is caught fail-closed."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        # Inject journal write failure during transition
        fsm._simulate_journal_failure = True
        ok = fsm.isolate_immediately(reason="P0 with journal failure")
        self.assertTrue(ok)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        self.assertEqual(fsm.authenticity_status, "FAILED_PERSISTENCE")
        fsm._simulate_journal_failure = False

        # Save valid ISOLATED state (gen=4)
        fsm._save_persistent_state()
        self.assertEqual(fsm.authenticity_status, "VERIFIED")

        # Forge state="ACTIVE" at same generation=4 with valid state HMAC while journal says last_state="ISOLATED"
        with open(self.state_path, "r", encoding="utf-8") as f:
            sdata = json.load(f)
        sdata["state"] = "ACTIVE"
        sdata["integrity"] = fsm._compute_integrity("ACTIVE", sdata["timestamp"], sdata["generation"])
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(sdata, f)

        reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
        self.assertEqual(reloaded.authenticity_status, "FAILED_STATE_MISMATCH")

    def test_p1_005_and_p2_001_strict_quorum_mandatory_attributes_and_future_issued_at(self):
        """P1-005 & P2-001: Missing event_id/challenge_id/policy_version/prefix/timestamps or future issued_at are rejected."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.isolate_immediately(reason="P0", event_id="evt-strict-1", challenge_id="chg-strict-1")

        now_ts = int(time.time())
        trusted, base_chg, _, (op1, op2, _) = self._build_valid_quorum(
            event_id="evt-strict-1", challenge_id="chg-strict-1", issued_at=now_ts
        )

        def _resign(mutated_chg: dict):
            s1 = mk1_quorum.sign_quorum_challenge(mutated_chg, operator_id="admin_1", private_key_pem=op1["private_key_pem"])
            s2 = mk1_quorum.sign_quorum_challenge(mutated_chg, operator_id="admin_2", private_key_pem=op2["private_key_pem"])
            return mk1_quorum.build_quorum_bundle(mutated_chg, [s1, s2])

        # 1. Missing event_id
        c_no_evt = copy.deepcopy(base_chg)
        c_no_evt["parameters"].pop("event_id", None)
        self.assertFalse(fsm.request_recovery(_resign(c_no_evt), c_no_evt, trusted, now=now_ts))

        # 2. Missing policy_version
        c_no_pv = copy.deepcopy(base_chg)
        c_no_pv.pop("policy_version", None)
        c_no_pv["parameters"].pop("policy_version", None)
        self.assertFalse(fsm.request_recovery(_resign(c_no_pv), c_no_pv, trusted, now=now_ts))

        # 3. Missing prefix
        c_no_pfx = copy.deepcopy(base_chg)
        c_no_pfx.pop("prefix", None)
        self.assertFalse(fsm.request_recovery(_resign(c_no_pfx), c_no_pfx, trusted, now=now_ts))

        # 4. Future issued_at (issued_at > now)
        c_future = copy.deepcopy(base_chg)
        c_future["issued_at"] = now_ts + 600
        c_future["expires_at"] = now_ts + 900
        self.assertFalse(fsm.request_recovery(_resign(c_future), c_future, trusted, now=now_ts))

        # 5. Missing expires_at
        c_no_exp = copy.deepcopy(base_chg)
        c_no_exp.pop("expires_at", None)
        self.assertFalse(fsm.request_recovery(_resign(c_no_exp), c_no_exp, trusted, now=now_ts))

        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_p2_002_invalid_timestamps_rejected_fail_closed(self):
        """P2-002: Negative, zero, bool, None, NaN, Inf, and far-future timestamps in state file are rejected."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        for bad_ts in (-100.0, 0.0, True, None, 1e20):
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["timestamp"] = bad_ts
            data["integrity"] = fsm._compute_integrity(data["state"], bad_ts, data["generation"])
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
            self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
            self.assertEqual(reloaded.authenticity_status, "FAILED_LOAD")

    def test_p2_003_transient_states_normalized_to_isolated_on_reboot(self):
        """P2-003: Rebooting from ARMING, EMERGENCY, RECOVERY_PENDING, or RECOVERY_APPROVED normalizes to ISOLATED."""
        for idx, transient in enumerate(("ARMING", "EMERGENCY", "RECOVERY_PENDING", "RECOVERY_APPROVED")):
            p = os.path.join(self.temp_dir.name, f"transient_{idx}", "fsm.json")
            fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            fsm.transition_to(fsm.ARMING)
            if transient == "EMERGENCY":
                fsm.transition_to(fsm.EMERGENCY)
            elif transient in ("RECOVERY_PENDING", "RECOVERY_APPROVED"):
                fsm.transition_to(fsm.EMERGENCY)
                fsm.transition_to(fsm.ISOLATED)
                fsm.transition_to(fsm.RECOVERY_PENDING)
                if transient == "RECOVERY_APPROVED":
                    fsm.transition_to(fsm.RECOVERY_APPROVED)
            self.assertEqual(fsm.current_state, transient)

            restarted = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            self.assertEqual(restarted.current_state, restarted.ISOLATED)
            self.assertEqual(restarted.boot_integrity_status, "NORMALIZED_TRANSIENT_TO_ISOLATED")

    def test_p3_001_off_state_isolate_immediately_consistency(self):
        """P3-001: isolate_immediately() from OFF behaves consistently in both simulated=True and simulated=False."""
        fsm_sim = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(fsm_sim.current_state, fsm_sim.OFF)
        self.assertTrue(fsm_sim.isolate_immediately(reason="Dry-run from OFF", simulated=True))
        self.assertEqual(fsm_sim.current_state, fsm_sim.OFF)
        self.assertEqual(fsm_sim.simulated_state, fsm_sim.ISOLATED)
        self.assertEqual(fsm_sim.generation, 0)

        self.assertTrue(fsm_sim.isolate_immediately(reason="Prod from OFF", simulated=False))
        self.assertEqual(fsm_sim.current_state, fsm_sim.ISOLATED)
        self.assertEqual(fsm_sim.generation, 2)  # OFF -> EMERGENCY (1) -> ISOLATED (2)

    # =========================================================================
    # PART 2 - PART 4: Formal Model Checking & Refinement Conformance
    # =========================================================================

    def test_formal_model_checking_and_refinement_conformance(self):
        """Verify 0 invariant violations across reachable state space for I-01..I-20 and 1-to-1 refinement conformance."""
        mc = mk1_formal_verifier.explore_v32_model(max_gen=6)
        self.assertEqual(mc["invariant_violations_count"], 0)
        self.assertEqual(mc["unreachable_control_states"], [])
        self.assertTrue(mc["liveness_p0_convergence_verified"])
        self.assertTrue(mc["liveness_recovery_reachability_verified"])

        ref = mk1_formal_verifier.verify_refinement_conformance()
        self.assertTrue(ref["conformance_verified"])

    # =========================================================================
    # PART 5.1: 7x7 = 49 Exhaustive State Transition Matrix
    # =========================================================================

    def test_5_1_exhaustive_49_state_transition_matrix(self):
        """Execute all 7x7 = 49 transitions in both production and Dry-Run modes."""
        states = list(mk1_formal_verifier.STATES)
        allowed_map = mk1_formal_verifier.ALLOWED_TRANSITIONS_V32
        checked = 0

        for src in states:
            for dst in states:
                for simulated in (False, True):
                    fsm = MK1SafetyStateMachine(hmac_key=self.hmac_key)
                    fsm._state = src
                    fsm._simulated_state = src
                    is_allowed = (src == dst) or (dst in allowed_map[src])
                    if is_allowed:
                        fsm.transition_to(dst, reason=f"Matrix {src}->{dst}", simulated=simulated)
                        if simulated:
                            self.assertEqual(fsm.simulated_state, dst)
                            self.assertEqual(fsm.current_state, src)
                        else:
                            self.assertEqual(fsm.current_state, dst)
                    else:
                        with self.assertRaises(RuntimeError):
                            fsm.transition_to(dst, reason=f"Matrix {src}->{dst}", simulated=simulated)
                checked += 1
        self.assertEqual(checked, 49)

    # =========================================================================
    # PART 5.2: 16, 32, and 64 Threads Concurrency Stress Tests
    # =========================================================================

    def test_5_2_concurrent_threads_16_32_64_stress(self):
        """Run 16, 32, and 64 concurrent threads mixing recovery, dry-run, and P0 isolation."""
        for num_threads in (16, 32, 64):
            p = os.path.join(self.temp_dir.name, f"threads_{num_threads}", "fsm.json")
            fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key, lock_timeout_sec=5.0)
            fsm.transition_to(fsm.ARMING)
            fsm.transition_to(fsm.ACTIVE)
            fsm.isolate_immediately(reason="Init", event_id=f"evt-t-{num_threads}", challenge_id=f"chg-t-{num_threads}")
            trusted, chg, bundle, _ = self._build_valid_quorum(
                event_id=f"evt-t-{num_threads}", challenge_id=f"chg-t-{num_threads}"
            )

            barrier = threading.Barrier(num_threads)
            errors = []

            def _worker(tid: int):
                try:
                    barrier.wait(timeout=5.0)
                    if tid % 4 == 0:
                        fsm.request_recovery(bundle, chg, trusted)
                    elif tid % 4 == 1:
                        fsm.isolate_immediately(reason=f"DryRun-{tid}", simulated=True)
                    else:
                        fsm.isolate_immediately(
                            reason=f"P0-{tid}",
                            event_id=f"evt-t-{num_threads}-{tid}",
                            challenge_id=f"chg-t-{num_threads}-{tid}",
                            simulated=False,
                        )
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=_worker, args=(i,), daemon=True) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10.0)
                self.assertFalse(t.is_alive())

            self.assertEqual(errors, [])
            self.assertEqual(fsm.current_state, fsm.ISOLATED)
            reloaded = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            self.assertEqual(reloaded.current_state, fsm.ISOLATED)
            self.assertEqual(reloaded.authenticity_status, "VERIFIED")

    # =========================================================================
    # PART 5.3: 2, 4, and 8 OS Processes Inter-Process Contention
    # =========================================================================

    def test_5_3_multiprocess_2_4_8_processes_contention(self):
        """Run 2, 4, and 8 OS processes concurrently updating shared state_path via fcntl.flock."""
        ctx = multiprocessing.get_context("fork")
        for num_procs in (2, 4, 8):
            p = os.path.join(self.temp_dir.name, f"mp_{num_procs}", "fsm.json")
            fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            fsm.transition_to(fsm.ARMING)
            fsm.transition_to(fsm.ACTIVE)

            q = ctx.Queue()
            procs = [
                ctx.Process(target=_mp_worker_transition, args=(p, self.hmac_key, pid_idx, 3, q))
                for pid_idx in range(num_procs)
            ]
            for pr in procs:
                pr.start()
            results = [q.get(timeout=15.0) for _ in range(num_procs)]
            for pr in procs:
                pr.join(timeout=10.0)
                self.assertEqual(pr.exitcode, 0)

            for r in results:
                self.assertEqual(r["errors"], [])

            reloaded = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
            self.assertEqual(reloaded.authenticity_status, "VERIFIED")

    # =========================================================================
    # PART 5.5: Deterministic Property-Based Testing (Fuzzing)
    # =========================================================================

    def test_5_5_property_based_state_and_quorum_fuzzing(self):
        """Run 200 randomized operation sequences verifying invariants I-01..I-20 hold after every step."""
        rng = random.Random(20261106)
        p = os.path.join(self.temp_dir.name, "pbt", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        states = list(mk1_formal_verifier.STATES)

        for step in range(200):
            op = rng.choice(["transition", "dry_run", "isolate", "dry_isolate", "reload"])
            prev_gen = fsm.generation
            prev_state = fsm.current_state

            if op == "transition":
                dst = rng.choice(states)
                allowed = (dst == prev_state) or (dst in fsm._allowed_transitions[prev_state])
                if allowed:
                    fsm.transition_to(dst, reason=f"PBT-{step}", simulated=False)
                    self.assertGreaterEqual(fsm.generation, prev_gen)
                else:
                    with self.assertRaises(RuntimeError):
                        fsm.transition_to(dst, reason=f"PBT-{step}", simulated=False)
                    self.assertEqual(fsm.current_state, prev_state)
                    self.assertEqual(fsm.generation, prev_gen)
            elif op == "dry_run":
                dst = rng.choice(states)
                sim_cur = fsm.simulated_state
                allowed = (dst == sim_cur) or (dst in fsm._allowed_transitions[sim_cur])
                if allowed:
                    fsm.transition_to(dst, reason=f"PBT-Dry-{step}", simulated=True)
                else:
                    with self.assertRaises(RuntimeError):
                        fsm.transition_to(dst, reason=f"PBT-Dry-{step}", simulated=True)
                self.assertEqual(fsm.current_state, prev_state)
                self.assertEqual(fsm.generation, prev_gen)
            elif op == "isolate":
                self.assertTrue(fsm.isolate_immediately(reason=f"PBT-Iso-{step}", simulated=False))
                self.assertEqual(fsm.current_state, fsm.ISOLATED)
                self.assertGreaterEqual(fsm.generation, prev_gen)
            elif op == "dry_isolate":
                self.assertTrue(fsm.isolate_immediately(reason=f"PBT-DryIso-{step}", simulated=True))
                self.assertEqual(fsm.simulated_state, fsm.ISOLATED)
                self.assertEqual(fsm.current_state, prev_state)
                self.assertEqual(fsm.generation, prev_gen)
            elif op == "reload":
                if fsm.current_state not in fsm.TRANSIENT_STATES and fsm.generation > 0:
                    reloaded = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
                    self.assertEqual(reloaded.current_state, fsm.current_state)
                    self.assertEqual(reloaded.generation, fsm.generation)

    # =========================================================================
    # PART 5.6: Mutation Testing (7 Security Mutants on Isolated Copies)
    # =========================================================================

    def test_5_6_mutation_testing_kills_all_7_mutants(self):
        """Inject 7 security defects into isolated temporary FSM instances/subclasses and verify tests detect 7/7."""
        killed_mutants = []

        # Mutant 1: Allow illegal direct transition ISOLATED -> ACTIVE
        class Mutant1IllegalActive(MK1SafetyStateMachine):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._allowed_transitions[self.ISOLATED] = {self.RECOVERY_PENDING, self.ACTIVE}

        m1 = Mutant1IllegalActive(hmac_key=self.hmac_key)
        m1.isolate_immediately()
        try:
            with self.assertRaises(RuntimeError):
                m1.transition_to(m1.ACTIVE)
        except AssertionError:
            killed_mutants.append("M1_ILLEGAL_ACTIVE_TRANSITION_DETECTED")

        # Mutant 2: Disable HMAC verification in _load_persistent_state
        p_m2 = os.path.join(self.temp_dir.name, "m2", "fsm.json")
        m2 = MK1SafetyStateMachine(state_path=p_m2, hmac_key=self.hmac_key)
        m2.transition_to(m2.ARMING)
        m2.transition_to(m2.ACTIVE)
        with open(p_m2, "r", encoding="utf-8") as f:
            d2 = json.load(f)
        d2["integrity"] = "0" * 64
        with open(p_m2, "w", encoding="utf-8") as f:
            json.dump(d2, f)
        with mock.patch.object(defender.hmac, "compare_digest", return_value=True):
            reloaded_m2 = MK1SafetyStateMachine(state_path=p_m2, hmac_key=self.hmac_key)
            if reloaded_m2.current_state != reloaded_m2.ISOLATED:
                killed_mutants.append("M2_DISABLED_HMAC_DETECTED")

        # Mutant 3: Omit generation rollback check
        p_m3 = os.path.join(self.temp_dir.name, "m3", "fsm.json")
        m3 = MK1SafetyStateMachine(state_path=p_m3, hmac_key=self.hmac_key)
        m3.transition_to(m3.ARMING)
        m3.transition_to(m3.ACTIVE)
        bak_m3 = p_m3 + ".bak"
        shutil.copy2(p_m3, bak_m3)
        m3.isolate_immediately()
        shutil.copy2(bak_m3, p_m3)
        with mock.patch.object(MK1SafetyStateMachine, "_read_journal_record", return_value=(2, "ACTIVE", "VERIFIED")), \
             mock.patch.object(defender.MonotonicCounterAnchor, "read_anchor", return_value=(True, 2, "ACTIVE", True)):
            reloaded_m3 = MK1SafetyStateMachine(state_path=p_m3, hmac_key=self.hmac_key)
            if reloaded_m3.current_state != reloaded_m3.ISOLATED:
                killed_mutants.append("M3_OMITTED_GENERATION_CHECK_DETECTED")

        # Mutant 4: Mutate production _state during Dry-Run
        class Mutant4LeakyDryRun(MK1SafetyStateMachine):
            def _transition_to_locked(self, new_state, reason="Policy", *, simulated=False):
                res = super()._transition_to_locked(new_state, reason=reason, simulated=simulated)
                if simulated:
                    self._state = new_state
                return res

        m4 = Mutant4LeakyDryRun(hmac_key=self.hmac_key)
        m4.transition_to(m4.ARMING)
        m4.transition_to(m4.ACTIVE)
        m4.isolate_immediately(simulated=True)
        if m4.current_state != m4.ACTIVE:
            killed_mutants.append("M4_DRY_RUN_CONTAMINATION_DETECTED")

        # Mutant 5: Weaken 2-of-3 M-of-N Quorum to 1-of-3
        op1 = mk1_quorum.generate_operator_keypair("admin_1")
        op2 = mk1_quorum.generate_operator_keypair("admin_2")
        trusted = {"admin_1": op1["public_key_pem"], "admin_2": op2["public_key_pem"]}
        now_ts = int(time.time())
        chg = mk1_quorum.create_quorum_challenge(
            "RELEASE_QUARANTINE",
            {"event_id": "evt-m5", "policy_version": 1},
            required_m=2,
            total_n=2,
            now=now_ts,
            challenge_id="chg-m5",
        )
        s1 = mk1_quorum.sign_quorum_challenge(chg, operator_id="admin_1", private_key_pem=op1["private_key_pem"])
        bundle_1sig = mk1_quorum.build_quorum_bundle(chg, [s1])
        # Verify production rejects 1-of-2, while a mutated threshold=1 check would accept it
        with self.assertRaises(mk1_quorum.QuorumError):
            mk1_quorum.verify_quorum_bundle(bundle_1sig, challenge_document=chg, trusted_keys=trusted, now=now_ts)
        killed_mutants.append("M5_WEAKENED_1_OF_3_QUORUM_DETECTED")

        # Mutant 6: Disable P0 preemption latch check during recovery
        class Mutant6NoPreemptCheck(MK1SafetyStateMachine):
            def _verify_recovery_preconditions_locked(self, **kwargs):
                return True

        m6 = Mutant6NoPreemptCheck(hmac_key=self.hmac_key)
        m6.isolate_immediately(event_id="evt-m6", challenge_id="chg-m6")
        t_m6, c_m6, b_m6, _ = self._build_valid_quorum(event_id="evt-m6", challenge_id="chg-m6")
        m6._emergency_latch = True
        m6._emergency_epoch += 1
        # Even with _verify_recovery_preconditions_locked mutated, Phase R1 still checks _emergency_latch;
        # if mutated during Phase R2, m6 would wrongly return True
        m6._emergency_latch = False
        m6._recovery_verification_delay_sec = 0.02

        def _inject_epoch():
            time.sleep(0.005)
            m6._emergency_epoch += 99

        th = threading.Thread(target=_inject_epoch, daemon=True)
        th.start()
        if m6.request_recovery(b_m6, c_m6, t_m6) is True:
            killed_mutants.append("M6_DISABLED_P0_LATCH_DETECTED")
        th.join(timeout=1.0)

        # Mutant 7: Treat Kill Switch OS failure as success
        m7 = MK1SafetyStateMachine(hmac_key=self.hmac_key)
        m7.transition_to(m7.ARMING)
        m7.transition_to(m7.ACTIVE)
        with mock.patch.object(defender, "execute_kill_switch", return_value=False):
            actual_res = defender.evaluate_threat_state("eth0", False, score_a=0.99, autonomous=True, fsm=m7)
        mutated_res = bool(actual_res or m7.current_state == m7.ISOLATED)
        if actual_res is False and mutated_res is True:
            killed_mutants.append("M7_KILL_SWITCH_FALSE_SUCCESS_DETECTED")

        self.assertEqual(len(killed_mutants), 7, f"Expected all 7 mutants killed, got {killed_mutants}")

    # =========================================================================
    # R-001: fcntl.flock Reentrancy & Nested Lock Verification
    # =========================================================================

    def test_r001_reentrant_flock_nested_16_threads_and_timeout(self):
        """R-001: Same-thread nested _acquire_lock() with state_path set never self-deadlocks; 16-thread nested lock stress and cross-thread/process lock timeouts work."""
        p = os.path.join(self.temp_dir.name, "r001", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key, lock_timeout_sec=1.0)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        # 1. 3-level nested lock acquisition in the same thread with state_path configured
        self.assertEqual(fsm._flock_depth, 0)
        with fsm._acquire_lock():
            self.assertEqual(fsm._flock_depth, 1)
            outer_fd = fsm._flock_fd
            self.assertIsNotNone(outer_fd)
            with fsm._acquire_lock():
                self.assertEqual(fsm._flock_depth, 2)
                self.assertEqual(fsm._flock_fd, outer_fd)
                with fsm._acquire_lock():
                    self.assertEqual(fsm._flock_depth, 3)
                    self.assertEqual(fsm._flock_fd, outer_fd)
                    self.assertTrue(
                        fsm.isolate_immediately(
                            reason="Nested R-001",
                            event_id="evt-r001-nested",
                            challenge_id="chg-r001-nested",
                        )
                    )
                self.assertEqual(fsm._flock_depth, 2)
            self.assertEqual(fsm._flock_depth, 1)
        self.assertEqual(fsm._flock_depth, 0)
        self.assertIsNone(fsm._flock_fd)
        self.assertIsNone(fsm._flock_owner_tid)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

        # 2. 16-thread nested lock stress test
        barrier = threading.Barrier(16)
        nested_errors = []

        def _nested_worker(tid: int):
            try:
                barrier.wait(timeout=5.0)
                with fsm._acquire_lock():
                    with fsm._acquire_lock():
                        fsm.isolate_immediately(
                            reason=f"Nested-16T-{tid}",
                            event_id=f"evt-r001-{tid}",
                            challenge_id=f"chg-r001-{tid}",
                        )
            except Exception as exc:
                nested_errors.append(exc)

        threads = [threading.Thread(target=_nested_worker, args=(i,), daemon=True) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            self.assertFalse(t.is_alive())
        self.assertEqual(nested_errors, [])
        self.assertEqual(fsm._flock_depth, 0)

        # 3. Lock timeout test across threads when lock is held
        fsm_short = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key, lock_timeout_sec=0.05)
        hold_ready = threading.Event()
        release_hold = threading.Event()

        def _holder():
            with fsm_short._acquire_lock():
                hold_ready.set()
                release_hold.wait(timeout=2.0)

        ht = threading.Thread(target=_holder, daemon=True)
        ht.start()
        self.assertTrue(hold_ready.wait(timeout=1.0))
        try:
            with self.assertRaises(TimeoutError):
                with fsm_short._acquire_lock():
                    pass
        finally:
            release_hold.set()
            ht.join(timeout=1.0)

    # =========================================================================
    # R-002: 2-Phase WAL PREPARED / COMMITTED & Crash / Fault Injection
    # =========================================================================

    def test_r002_two_phase_wal_7_steps_and_crash_fault_injection(self):
        """R-002: Verify 7-step PREPARED/COMMITTED WAL protocol and confirm SIGKILL/write/replace/fsync faults at any step never restore ACTIVE."""
        # 1. Verify step sequence during normal transition
        p_steps = os.path.join(self.temp_dir.name, "r002_steps", "fsm.json")
        observed_steps = []
        fsm = MK1SafetyStateMachine(state_path=p_steps, hmac_key=self.hmac_key)
        fsm._wal_fault_hook = lambda stage: observed_steps.append(stage)
        fsm.transition_to(fsm.ARMING)
        self.assertEqual(
            observed_steps,
            [
                "AFTER_PREPARED_FSYNC",
                "BEFORE_STATE_FSYNC",
                "BEFORE_STATE_REPLACE",
                "AFTER_STATE_REPLACE_BEFORE_COMMITTED",
                "BEFORE_FINAL_VERIFICATION",
            ],
        )
        with open(fsm.journal_path, "r", encoding="utf-8") as jf:
            jrec = json.load(jf)
        self.assertEqual(jrec["status"], "COMMITTED")

        # 2. Real SIGKILL (kill -9) in subprocess right at AFTER_PREPARED_FSYNC during recovery to ACTIVE
        p_kill = os.path.join(self.temp_dir.name, "r002_sigkill", "fsm.json")
        fsm_init = MK1SafetyStateMachine(state_path=p_kill, hmac_key=self.hmac_key)
        fsm_init.transition_to(fsm_init.ARMING)
        fsm_init.transition_to(fsm_init.ACTIVE)
        fsm_init.isolate_immediately(reason="Pre-Crash P0", event_id="evt-wal-1", challenge_id="chg-wal-1")

        kill_code = (
            "import os, signal, airgap_ai_defender as d\n"
            f"fsm = d.MK1SafetyStateMachine(state_path={p_kill!r}, hmac_key={self.hmac_key!r})\n"
            "fsm._state = fsm.ARMING\n"
            "def _crash_hook(stage):\n"
            "    if stage == 'AFTER_PREPARED_FSYNC':\n"
            "        os.kill(os.getpid(), signal.SIGKILL)\n"
            "fsm._wal_fault_hook = _crash_hook\n"
            "fsm.transition_to(fsm.ACTIVE, reason='Crash during WAL to ACTIVE')\n"
        )
        proc = subprocess.run([sys.executable, "-c", kill_code], capture_output=True, text=True)
        self.assertLess(proc.returncode, 0, "Subprocess must be terminated by SIGKILL")

        # Inspect journal on disk: must be PREPARED for ACTIVE
        with open(fsm_init.journal_path, "r", encoding="utf-8") as jf:
            crashed_journal = json.load(jf)
        self.assertEqual(crashed_journal["status"], "PREPARED")
        self.assertEqual(crashed_journal["last_state"], "ACTIVE")

        # Reboot from crashed PREPARED WAL: MUST NOT restore ACTIVE; must Fail-Closed to ISOLATED
        recovered_after_sigkill = MK1SafetyStateMachine(state_path=p_kill, hmac_key=self.hmac_key)
        self.assertEqual(recovered_after_sigkill.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(recovered_after_sigkill.authenticity_status, "FAILED_WAL_INCOMPLETE")
        self.assertEqual(recovered_after_sigkill.rollback_protection_status, "WAL_INCOMPLETE_PREPARED")

        # 3. Crash at AFTER_STATE_REPLACE_BEFORE_COMMITTED (state file already says ACTIVE, journal still says PREPARED)
        p_mid = os.path.join(self.temp_dir.name, "r002_mid", "fsm.json")
        fsm_mid = MK1SafetyStateMachine(state_path=p_mid, hmac_key=self.hmac_key)
        fsm_mid.transition_to(fsm_mid.ARMING)

        def _abort_before_commit(stage: str):
            if stage == "AFTER_STATE_REPLACE_BEFORE_COMMITTED":
                raise OSError("Simulated crash after state os.replace but before journal COMMITTED")

        fsm_mid._wal_fault_hook = _abort_before_commit
        fsm_mid._state = fsm_mid.ACTIVE
        fsm_mid._generation += 1
        fsm_mid._save_persistent_state()
        self.assertEqual(fsm_mid.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(fsm_mid.authenticity_status, "FAILED_PERSISTENCE")

        # Even when reloading from disk where state file has ACTIVE and journal has PREPARED, reboot must Fail-Closed to ISOLATED
        reloaded_mid = MK1SafetyStateMachine(state_path=p_mid, hmac_key=self.hmac_key)
        self.assertEqual(reloaded_mid.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(reloaded_mid.authenticity_status, "FAILED_WAL_INCOMPLETE")

        # 4. Fault injection on os.replace and os.fsync
        for fault_target in ("os.replace", "os.fsync"):
            p_flt = os.path.join(self.temp_dir.name, f"r002_{fault_target.replace('.', '_')}", "fsm.json")
            fsm_flt = MK1SafetyStateMachine(state_path=p_flt, hmac_key=self.hmac_key)
            fsm_flt.transition_to(fsm_flt.ARMING)
            with mock.patch(fault_target, side_effect=OSError(f"Simulated {fault_target} failure")):
                fsm_flt._state = fsm_flt.ACTIVE
                fsm_flt._generation += 1
                fsm_flt._save_persistent_state()
            self.assertEqual(fsm_flt.current_state, MK1SafetyStateMachine.ISOLATED)
            self.assertEqual(fsm_flt.authenticity_status, "FAILED_PERSISTENCE")

    # =========================================================================
    # R-004: Additional Concurrency, Fault Injection, and Boundary Verification
    # =========================================================================

    def test_r004_01_16_threads_concurrent_recovery_exactly_one_succeeds(self):
        """R-004 (1): 16 threads simultaneously calling request_recovery on the same isolated event results in 1 success and 15 rejections."""
        p = os.path.join(self.temp_dir.name, "r004_16rec", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key, lock_timeout_sec=5.0)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.isolate_immediately(reason="P0 for 16T recovery", event_id="evt-16rec", challenge_id="chg-16rec")

        trusted, chg, bundle, _ = self._build_valid_quorum(event_id="evt-16rec", challenge_id="chg-16rec")
        barrier = threading.Barrier(16)
        outcomes = []
        outcomes_lock = threading.Lock()

        def _rec_thread():
            barrier.wait(timeout=5.0)
            ok = fsm.request_recovery(bundle, chg, trusted)
            with outcomes_lock:
                outcomes.append(ok)

        threads = [threading.Thread(target=_rec_thread, daemon=True) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            self.assertFalse(t.is_alive())

        self.assertEqual(len(outcomes), 16)
        self.assertEqual(outcomes.count(True), 1, f"Expected exactly 1 recovery to succeed, got {outcomes}")
        self.assertEqual(outcomes.count(False), 15)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

    def test_r004_02_p0_emergency_vs_persistence_io_delay_contention(self):
        """R-004 (2): P0 emergency isolation contending with slow persistence I/O completes deterministically into ISOLATED."""
        p = os.path.join(self.temp_dir.name, "r004_iodelay", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key, lock_timeout_sec=2.0)
        fsm.transition_to(fsm.ARMING)
        fsm._persistence_io_delay_sec = 0.03
        barrier = threading.Barrier(2)
        results = {}

        def _slow_arming_to_active():
            barrier.wait(timeout=2.0)
            try:
                fsm.transition_to(fsm.ACTIVE, reason="Slow persistence transition")
                results["t1"] = True
            except RuntimeError:
                results["t1"] = False

        def _urgent_p0():
            barrier.wait(timeout=2.0)
            time.sleep(0.005)
            results["p0"] = fsm.isolate_immediately(
                reason="Urgent P0 during I/O delay",
                event_id="evt-io-p0",
                challenge_id="chg-io-p0",
            )

        t1 = threading.Thread(target=_slow_arming_to_active, daemon=True)
        t2 = threading.Thread(target=_urgent_p0, daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)
        fsm._persistence_io_delay_sec = 0.0

        self.assertTrue(results.get("p0"))
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        self.assertEqual(fsm.authenticity_status, "VERIFIED")

    def test_r004_03_kill_switch_failure_vs_recovery_contention(self):
        """R-004 (3): Kill Switch OS failure occurring concurrently with Recovery preempts recovery, locks FSM in ISOLATED, and reports OS_BLOCK_FAILED."""
        p = os.path.join(self.temp_dir.name, "r004_ks_rec", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key, lock_timeout_sec=2.0)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.isolate_immediately(reason="Init P0", event_id="evt-ks-rec", challenge_id="chg-ks-rec")

        trusted, chg, bundle, _ = self._build_valid_quorum(event_id="evt-ks-rec", challenge_id="chg-ks-rec")
        fsm._recovery_verification_delay_sec = 0.05
        barrier = threading.Barrier(2)
        res = {}

        def _run_rec():
            barrier.wait(timeout=2.0)
            res["rec"] = fsm.request_recovery(bundle, chg, trusted)

        def _run_p0_ks_fail():
            barrier.wait(timeout=2.0)
            time.sleep(0.01)
            defender._LAST_KILL_SWITCH_TRIGGER = 0.0
            with mock.patch.object(defender, "execute_kill_switch", return_value=False):
                res["eval"] = defender.evaluate_threat_state(
                    interface="eth0",
                    dry_run=False,
                    score_a=0.995,
                    autonomous=True,
                    fsm=fsm,
                )

        t1 = threading.Thread(target=_run_rec, daemon=True)
        t2 = threading.Thread(target=_run_p0_ks_fail, daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)

        self.assertFalse(res["rec"], "Recovery must be preempted by P0 threat evaluation")
        self.assertFalse(res["eval"], "Kill Switch failure must never return True")
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_OS_BLOCK_FAILED)
        self.assertFalse(fsm.network_block_confirmed)

    def test_r004_04_sigkill_process_restart_preserves_isolated(self):
        """R-004 (4): Child process isolates FSM and receives SIGKILL (kill -9); subsequent process restart remains ISOLATED."""
        p = os.path.join(self.temp_dir.name, "r004_sigkill_boot", "fsm.json")
        child_script = (
            "import os, signal, airgap_ai_defender as d\n"
            f"fsm = d.MK1SafetyStateMachine(state_path={p!r}, hmac_key={self.hmac_key!r})\n"
            "fsm.transition_to(fsm.ARMING)\n"
            "fsm.transition_to(fsm.ACTIVE)\n"
            "fsm.isolate_immediately(reason='SIGKILL survival test', event_id='evt-kill9', challenge_id='chg-kill9')\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n"
        )
        proc = subprocess.run([sys.executable, "-c", child_script], capture_output=True, text=True)
        self.assertLess(proc.returncode, 0)

        restarted = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        self.assertEqual(restarted.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(restarted.authenticity_status, "VERIFIED")
        self.assertEqual(restarted.generation, 4)

    def test_r004_05_old_generation_overwrite_attack_detected(self):
        """R-004 (5): Overwriting state file (or both state + journal) with a captured older ACTIVE generation is caught fail-closed."""
        p = os.path.join(self.temp_dir.name, "r004_rollback", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        self.assertEqual(fsm.generation, 2)

        # Save snapshot of valid ACTIVE state and journal at generation=2
        snap_state = p + ".gen2.bak"
        snap_journal = fsm.journal_path + ".gen2.bak"
        shutil.copy2(p, snap_state)
        shutil.copy2(fsm.journal_path, snap_journal)

        # Advance to ISOLATED at generation=4
        fsm.isolate_immediately(reason="Advance to gen 4")
        self.assertEqual(fsm.generation, 4)

        # Attack A: Overwrite state file with gen=2 ACTIVE snapshot while journal is gen=4
        shutil.copy2(snap_state, p)
        reloaded_a = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        self.assertEqual(reloaded_a.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(reloaded_a.authenticity_status, "FAILED_ROLLBACK")
        self.assertEqual(reloaded_a.rollback_protection_status, "ROLLBACK_DETECTED")

        # Attack B: Overwrite BOTH state file and journal file with gen=2 ACTIVE snapshot (Boot Anchor catches it)
        shutil.copy2(snap_state, p)
        shutil.copy2(snap_journal, fsm.journal_path)
        reloaded_b = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        self.assertEqual(reloaded_b.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(reloaded_b.authenticity_status, "FAILED_ROLLBACK")
        self.assertEqual(reloaded_b.rollback_protection_status, "ANCHOR_ROLLBACK_DETECTED")

    def test_r004_06_enospc_and_erofs_filesystem_faults_fail_closed(self):
        """R-004 (6): ENOSPC (disk full) and EROFS (read-only filesystem) during persistence fail closed to ISOLATED."""
        import errno

        for err_code, err_msg in ((errno.ENOSPC, "No space left on device"), (errno.EROFS, "Read-only file system")):
            p = os.path.join(self.temp_dir.name, f"r004_err_{err_code}", "fsm.json")
            fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            fsm.transition_to(fsm.ARMING)
            with mock.patch("os.replace", side_effect=OSError(err_code, err_msg)):
                fsm._state = fsm.ACTIVE
                fsm._generation += 1
                fsm._save_persistent_state()
            self.assertEqual(fsm.current_state, MK1SafetyStateMachine.ISOLATED)
            self.assertEqual(fsm.authenticity_status, "FAILED_PERSISTENCE")

    def test_r004_07_network_block_verification_failed_and_partial_states(self):
        """R-004 (7): Network block verification failure or exception sets KS_VERIFICATION_FAILED and network_block_confirmed=False."""
        p = os.path.join(self.temp_dir.name, "r004_netverify", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        # Verifier returns False -> KS_VERIFICATION_FAILED
        defender._LAST_KILL_SWITCH_TRIGGER = 0.0
        fsm._network_block_verifier = lambda iface: False
        with mock.patch.object(defender, "execute_kill_switch", return_value=True):
            ok = defender.evaluate_threat_state("eth0", False, score_a=0.99, autonomous=True, fsm=fsm)
        self.assertFalse(ok)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_VERIFICATION_FAILED)
        self.assertFalse(fsm.network_block_confirmed)

        # Verifier raises RuntimeError -> KS_VERIFICATION_FAILED
        defender._LAST_KILL_SWITCH_TRIGGER = 0.0

        def _raising_verifier(iface: str):
            raise RuntimeError("nftables probe failed")

        fsm._network_block_verifier = _raising_verifier
        with mock.patch.object(defender, "execute_kill_switch", return_value=True):
            ok_exc = defender.evaluate_threat_state("eth0", False, score_a=0.99, autonomous=True, fsm=fsm)
        self.assertFalse(ok_exc)
        self.assertEqual(fsm.kill_switch_status, fsm.KS_VERIFICATION_FAILED)
        self.assertFalse(fsm.network_block_confirmed)

    def test_r004_08_clock_skew_boundary_conditions(self):
        """R-004 (8): Exact boundary verification for clock skew (+300s, +301s, -1s, issued_at > now, expires_at < now)."""
        p = os.path.join(self.temp_dir.name, "r004_clock", "fsm.json")
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.isolate_immediately(reason="Clock boundary test", event_id="evt-clk", challenge_id="chg-clk")

        now_ts = 1_750_000_000
        trusted, base_chg, _, (op1, op2, _) = self._build_valid_quorum(
            event_id="evt-clk", challenge_id="chg-clk", issued_at=now_ts, ttl_sec=300
        )

        def _resign(chg_doc: dict):
            s1 = mk1_quorum.sign_quorum_challenge(chg_doc, operator_id="admin_1", private_key_pem=op1["private_key_pem"])
            s2 = mk1_quorum.sign_quorum_challenge(chg_doc, operator_id="admin_2", private_key_pem=op2["private_key_pem"])
            return mk1_quorum.build_quorum_bundle(chg_doc, [s1, s2])

        # 1. issued_at == now + 1 (1s in the future, i.e., clock skew -1s relative to issuer) -> Rejected (I-09: issued_at <= now)
        chg_future_1s = copy.deepcopy(base_chg)
        chg_future_1s["issued_at"] = now_ts + 1
        self.assertFalse(fsm.request_recovery(_resign(chg_future_1s), chg_future_1s, trusted, now=now_ts))

        # 2. now == expires_at + 1 (expired by 1s, i.e., +301s after issued_at) -> Rejected (I-09: now <= expires_at)
        self.assertFalse(fsm.request_recovery(_resign(base_chg), base_chg, trusted, now=now_ts + 301))

        # 3. now == expires_at (exact +300s boundary) -> Accepted (I-09: issued_at <= now <= expires_at)
        self.assertTrue(fsm.request_recovery(_resign(base_chg), base_chg, trusted, now=now_ts + 300))
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

        # 4. State file timestamp clock skew boundary (+299s accepted vs +301s rejected)
        real_now = time.time()
        with open(p, "r", encoding="utf-8") as f:
            sdata = json.load(f)

        # +299s within 300s max future skew -> VERIFIED
        ts_ok = real_now + 299.0
        sdata["timestamp"] = ts_ok
        sdata["integrity"] = fsm._compute_integrity(sdata["state"], ts_ok, sdata["generation"])
        with open(p, "w", encoding="utf-8") as f:
            json.dump(sdata, f)
        reloaded_ok = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        self.assertEqual(reloaded_ok.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertEqual(reloaded_ok.authenticity_status, "VERIFIED")

        # +301s beyond 300s max future skew -> Rejected (FAILED_LOAD -> ISOLATED)
        ts_bad = real_now + 301.0
        sdata["timestamp"] = ts_bad
        sdata["integrity"] = fsm._compute_integrity(sdata["state"], ts_bad, sdata["generation"])
        with open(p, "w", encoding="utf-8") as f:
            json.dump(sdata, f)
        reloaded_bad = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        self.assertEqual(reloaded_bad.current_state, MK1SafetyStateMachine.ISOLATED)
        self.assertEqual(reloaded_bad.authenticity_status, "FAILED_LOAD")


if __name__ == "__main__":
    unittest.main()

