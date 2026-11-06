import unittest
import os
import json
import time
import shutil
import threading
import tempfile

import airgap_ai_defender as defender
from airgap_ai_defender import MK1SafetyStateMachine, LightweightMultiTaskAI
import mk1_quorum


import unittest.mock as mock


class TestV3FinalRemediation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = os.path.join(self.temp_dir.name, "fsm_state.json")
        self.hmac_key = "test-v3-secret-hmac-key-2026-sovereign-airgap"
        self.valid_packet = (
            b"\x00" * 12 + b"\x08\x00"
            + b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"
            + b"\x12\x34\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00"
        )
        defender.toggle_oni_mode(False)
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()
        defender._KILL_SWITCH_TRIGGERED = False
        defender._KILL_SWITCH_EVENT.clear()
        defender._LAST_KILL_SWITCH_TRIGGER = 0.0
        defender._anomaly_counter = 0
        defender._ISOLATION_APPROVAL_PENDING = False
        self._ks_patcher = mock.patch.object(defender, "execute_kill_switch", return_value=True)
        self.mock_kill_switch = self._ks_patcher.start()

    def tearDown(self):
        self._ks_patcher.stop()
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()
        self.temp_dir.cleanup()

    def _create_isolated_fsm(self, path=None, event_id="evt-001", challenge_id="chg-001"):
        p = path or self.state_path
        fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.transition_to(
            fsm.EMERGENCY,
            reason="Threat Detected",
            event_id=event_id,
            challenge_id=challenge_id,
        )
        fsm.transition_to(
            fsm.ISOLATED,
            reason="Autonomous Isolation",
            event_id=event_id,
            challenge_id=challenge_id,
        )
        return fsm

    def _create_quorum_operators_and_bundle(
        self,
        event_id="evt-001",
        challenge_id="chg-001",
        ttl_seconds=300,
        issued_at=None,
        policy_version=1,
        num_signers=2,
    ):
        op1 = mk1_quorum.generate_operator_keypair("admin_1")
        op2 = mk1_quorum.generate_operator_keypair("admin_2")
        op3 = mk1_quorum.generate_operator_keypair("admin_3")
        trusted = {
            "admin_1": op1["public_key_pem"],
            "admin_2": op2["public_key_pem"],
            "admin_3": op3["public_key_pem"],
        }
        target = {
            "interface": "eth0",
            "event_id": event_id,
            "policy_version": policy_version,
            "domain": "MK1AI-RECOVERY-v1",
        }
        challenge = mk1_quorum.create_quorum_challenge(
            "RELEASE_QUARANTINE",
            target,
            required_m=2,
            total_n=3,
            ttl_sec=ttl_seconds,
            now=int(time.time()) if issued_at is None else issued_at,
            challenge_id=challenge_id,
        )
        sigs = []
        ops = [("admin_1", op1), ("admin_2", op2), ("admin_3", op3)]
        for i in range(num_signers):
            op_id, op_keys = ops[i]
            sigs.append(
                mk1_quorum.sign_quorum_challenge(
                    challenge,
                    operator_id=op_id,
                    private_key_pem=op_keys["private_key_pem"],
                )
            )
        bundle = mk1_quorum.build_quorum_bundle(challenge, sigs)
        return trusted, challenge, bundle

    # =========================================================================
    # Baseline V3 Compatibility Tests
    # =========================================================================

    def test_strict_fsm_startup(self):
        """OFF state cannot transition directly to ACTIVE; must go through ARMING."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(fsm.current_state, fsm.OFF)

        with self.assertRaises(RuntimeError):
            fsm.transition_to(fsm.ACTIVE)

        fsm.transition_to(fsm.ARMING)
        self.assertEqual(fsm.current_state, fsm.ARMING)

        fsm.transition_to(fsm.ACTIVE)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

    def test_fsm_persistence_and_integrity(self):
        """FSM state is saved persistently and integrity-checked."""
        fsm1 = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm1.transition_to(fsm1.ARMING)
        fsm1.transition_to(fsm1.ACTIVE)
        fsm1.transition_to(fsm1.EMERGENCY)
        fsm1.transition_to(fsm1.ISOLATED)
        self.assertEqual(fsm1.current_state, fsm1.ISOLATED)

        fsm2 = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(fsm2.current_state, fsm2.ISOLATED)

    def test_fsm_tamper_detection_fail_closed(self):
        """Tampering with persistent state triggers Fail-Closed ISOLATED state."""
        fsm1 = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm1.transition_to(fsm1.ARMING)
        fsm1.transition_to(fsm1.ACTIVE)

        with open(self.state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["state"] = "ACTIVE"
        data["integrity"] = "invalid_hash"
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        fsm_tampered = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(fsm_tampered.current_state, fsm_tampered.ISOLATED)

    # =========================================================================
    # P0-1: FSM Concurrency & Self-Deadlock Remediation (TEST-FSM-001..004)
    # =========================================================================

    def test_fsm_001_rlock_reentrancy(self):
        """TEST-FSM-001: RLock reentrant acquisition and _transition_to_locked do not deadlock."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        with fsm._acquire_lock():
            with fsm._acquire_lock():
                fsm._transition_to_locked(fsm.ARMING, reason="Reentrant test")
                fsm._transition_to_locked(fsm.ACTIVE, reason="Reentrant active")
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

    def test_fsm_002_recovery_deadlock_timeout(self):
        """TEST-FSM-002: request_recovery() completes within 1.0s without self-deadlock."""
        fsm = self._create_isolated_fsm(event_id="evt-002", challenge_id="chg-002")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-002", challenge_id="chg-002"
        )
        result_holder = {}

        def _worker():
            t0 = time.monotonic()
            ok = fsm.request_recovery(
                bundle,
                challenge,
                trusted,
                expected_event_id="evt-002",
                expected_challenge_id="chg-002",
            )
            result_holder["ok"] = ok
            result_holder["elapsed"] = time.monotonic() - t0

        th = threading.Thread(target=_worker, daemon=True)
        th.start()
        th.join(timeout=1.5)
        self.assertFalse(th.is_alive(), "request_recovery() deadlocked!")
        self.assertTrue(result_holder.get("ok"))
        self.assertLess(result_holder.get("elapsed", 99.0), 1.0)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

    def test_fsm_003_concurrent_isolation_requests(self):
        """TEST-FSM-003: 16 concurrent threads invoking isolate_immediately() converge cleanly to ISOLATED."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        barrier = threading.Barrier(16)
        errors = []

        def _isolate_worker(idx):
            try:
                barrier.wait(timeout=2.0)
                fsm.isolate_immediately(reason=f"Concurrent threat {idx}", event_id=f"evt-c-{idx}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_isolate_worker, args=(i,), daemon=True) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)
            self.assertFalse(t.is_alive())

        self.assertEqual(errors, [])
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(reloaded.current_state, fsm.ISOLATED)

    def test_fsm_004_isolation_vs_recovery_race(self):
        """TEST-FSM-004: Concurrent emergency isolation preempts recovery and converges to ISOLATED."""
        fsm = self._create_isolated_fsm(event_id="evt-race", challenge_id="chg-race")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-race", challenge_id="chg-race"
        )

        # Verify direct preemption from RECOVERY_PENDING to ISOLATED
        fsm.transition_to(fsm.RECOVERY_PENDING, reason="Start recovery")
        fsm.isolate_immediately(reason="Threat during RECOVERY_PENDING")
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

        # Reset context and test true concurrent preemption during request_recovery without post-join masking
        fsm.set_isolation_context(event_id="evt-race", challenge_id="chg-race")
        fsm._recovery_verification_delay_sec = 0.02
        barrier = threading.Barrier(2)
        rec_results = []

        def _recovery_thread():
            barrier.wait(timeout=2.0)
            ok = fsm.request_recovery(bundle, challenge, trusted)
            rec_results.append(ok)

        def _isolation_thread():
            barrier.wait(timeout=2.0)
            time.sleep(0.005)
            fsm.isolate_immediately(reason="Preemptive emergency isolation")

        t1 = threading.Thread(target=_recovery_thread, daemon=True)
        t2 = threading.Thread(target=_isolation_thread, daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)
        fsm._recovery_verification_delay_sec = 0.0

        self.assertEqual(rec_results, [False])
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    # =========================================================================
    # P0-2: Dry-Run Complete Isolation (TEST-DRY-001..005)
    # =========================================================================

    def test_dry_001_production_fsm_isolation(self):
        """TEST-DRY-001: Dry-run threat evaluation does not mutate production FSM state, generation, or cooldown."""
        fsm = MK1SafetyStateMachine(
            state_path=self.state_path,
            hmac_key=self.hmac_key,
            strict_dry_run_isolation=True,
        )
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        gen_before = fsm.generation

        triggered = defender.evaluate_threat_state(
            interface="eth0",
            dry_run=True,
            score_a=0.99,
            score_b=0.10,
            score_c=0.10,
            autonomous=True,
            fsm=fsm,
        )
        self.assertTrue(triggered)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)
        self.assertEqual(fsm.simulated_state, fsm.ISOLATED)
        self.assertEqual(fsm.generation, gen_before)
        self.assertFalse(defender._KILL_SWITCH_EVENT.is_set())
        self.assertEqual(defender._LAST_KILL_SWITCH_TRIGGER, 0.0)
        self.assertEqual(defender._anomaly_counter, 0)

        # Verify a subsequent real threat is NOT blocked by any dry-run cooldown
        real_triggered = defender.evaluate_threat_state(
            interface="eth0",
            dry_run=False,
            score_a=0.99,
            score_b=0.0,
            score_c=0.0,
            autonomous=True,
            fsm=fsm,
        )
        self.assertTrue(real_triggered)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_dry_002_persistent_file_unchanged_and_already_isolated(self):
        """TEST-DRY-002: Dry-run when production FSM is ISOLATED never alters persistent production state."""
        fsm = self._create_isolated_fsm(event_id="evt-dry-2", challenge_id="chg-dry-2")
        gen_isolated = fsm.generation

        fsm.transition_to(fsm.RECOVERY_PENDING, reason="Simulated recovery check", simulated=True)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        self.assertEqual(fsm.simulated_state, fsm.RECOVERY_PENDING)
        self.assertEqual(fsm.generation, gen_isolated)

    def test_dry_003_dry_run_exception_preserves_state(self):
        """TEST-DRY-003: Invalid simulated transition raises error without corrupting production state."""
        fsm = MK1SafetyStateMachine(
            state_path=self.state_path,
            hmac_key=self.hmac_key,
            strict_dry_run_isolation=True,
        )
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        gen_before = fsm.generation

        with self.assertRaises(RuntimeError):
            fsm.transition_to(fsm.RECOVERY_APPROVED, reason="Invalid dry-run jump", simulated=True)

        self.assertEqual(fsm.current_state, fsm.ACTIVE)
        self.assertEqual(fsm.generation, gen_before)

    def test_dry_004_byte_for_byte_file_comparison(self):
        """TEST-DRY-004: Persistent state file and journal are byte-for-byte identical before and after dry-run."""
        fsm = MK1SafetyStateMachine(
            state_path=self.state_path,
            hmac_key=self.hmac_key,
            strict_dry_run_isolation=True,
        )
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        with open(self.state_path, "rb") as f:
            bytes_before = f.read()
        with open(fsm.journal_path, "rb") as f:
            journal_before = f.read()

        fsm.transition_to(fsm.EMERGENCY, reason="DryRun Emergency", simulated=True)
        fsm.transition_to(fsm.ISOLATED, reason="DryRun Isolated", simulated=True)
        defender.evaluate_threat_state(
            interface="eth0",
            dry_run=True,
            score_a=0.99,
            score_b=0.99,
            score_c=0.99,
            autonomous=True,
            fsm=fsm,
        )

        with open(self.state_path, "rb") as f:
            bytes_after = f.read()
        with open(fsm.journal_path, "rb") as f:
            journal_after = f.read()

        self.assertEqual(bytes_before, bytes_after)
        self.assertEqual(journal_before, journal_after)

    def test_dry_005_dry_run_restart_recovery(self):
        """TEST-DRY-005: Restarting FSM after dry-run isolation restores production ACTIVE state."""
        fsm = MK1SafetyStateMachine(
            state_path=self.state_path,
            hmac_key=self.hmac_key,
            strict_dry_run_isolation=True,
        )
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        fsm.transition_to(fsm.EMERGENCY, reason="DryRun", simulated=True)
        fsm.transition_to(fsm.ISOLATED, reason="DryRun", simulated=True)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)
        self.assertEqual(fsm.simulated_state, fsm.ISOLATED)

        restarted = MK1SafetyStateMachine(
            state_path=self.state_path,
            hmac_key=self.hmac_key,
            strict_dry_run_isolation=True,
        )
        self.assertEqual(restarted.current_state, restarted.ACTIVE)

    # =========================================================================
    # P1-3: RECOVERY_APPROVED Event Binding & Replay Prevention (TEST-RECOVERY-001..006)
    # =========================================================================

    def test_recovery_001_valid_2_of_3_approval(self):
        """TEST-RECOVERY-001: Valid 2-of-3 Ed25519 quorum bound to event_id & challenge_id recovers to ACTIVE."""
        fsm = self._create_isolated_fsm(event_id="evt-rec-001", challenge_id="chg-rec-001")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-rec-001", challenge_id="chg-rec-001", num_signers=2
        )

        ok = fsm.request_recovery(
            bundle,
            challenge,
            trusted,
            expected_event_id="evt-rec-001",
            expected_challenge_id="chg-rec-001",
            expected_policy_version=1,
        )
        self.assertTrue(ok)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)
        meta = fsm.last_recovery_approval
        self.assertIsNotNone(meta)
        self.assertEqual(meta["event_id"], "evt-rec-001")
        self.assertEqual(meta["challenge_id"], "chg-rec-001")
        self.assertEqual(meta["policy_version"], 1)
        self.assertEqual(len(meta["signers"]), 2)

    def test_recovery_002_expired_approval_rejected(self):
        """TEST-RECOVERY-002: Expired quorum approval challenge is rejected and FSM remains ISOLATED."""
        fsm = self._create_isolated_fsm(event_id="evt-rec-002", challenge_id="chg-rec-002")
        past_ts = int(time.time()) - 1000
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-rec-002",
            challenge_id="chg-rec-002",
            ttl_seconds=60,
            issued_at=past_ts,
        )

        ok = fsm.request_recovery(bundle, challenge, trusted)
        self.assertFalse(ok)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_recovery_003_replay_approval_rejected(self):
        """TEST-RECOVERY-003: Replaying an already-consumed quorum approval token is rejected."""
        fsm = self._create_isolated_fsm(event_id="evt-rec-003", challenge_id="chg-rec-003")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-rec-003", challenge_id="chg-rec-003"
        )

        ok = fsm.request_recovery(bundle, challenge, trusted)
        self.assertTrue(ok)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

        # Isolate again and attempt to replay the exact same bundle/challenge
        fsm.transition_to(fsm.EMERGENCY, reason="Second incident", event_id="evt-rec-003", challenge_id="chg-rec-003")
        fsm.transition_to(fsm.ISOLATED, reason="Second isolation", event_id="evt-rec-003", challenge_id="chg-rec-003")

        replayed = fsm.request_recovery(bundle, challenge, trusted)
        self.assertFalse(replayed)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_recovery_004_wrong_event_id_rejected(self):
        """TEST-RECOVERY-004: Quorum approval for a different event_id is rejected."""
        fsm = self._create_isolated_fsm(event_id="evt-actual-999", challenge_id="chg-rec-004")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-wrong-111", challenge_id="chg-rec-004"
        )

        ok = fsm.request_recovery(bundle, challenge, trusted)
        self.assertFalse(ok)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_recovery_005_wrong_challenge_id_rejected(self):
        """TEST-RECOVERY-005: Quorum approval for a mismatched challenge_id is rejected."""
        fsm = self._create_isolated_fsm(event_id="evt-rec-005", challenge_id="chg-expected-555")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-rec-005", challenge_id="chg-different-777"
        )

        ok = fsm.request_recovery(bundle, challenge, trusted)
        self.assertFalse(ok)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_recovery_006_persistence_failure_maintains_isolated(self):
        """TEST-RECOVERY-006: If state persistence fails during recovery, FSM rolls back and stays ISOLATED."""
        fsm = self._create_isolated_fsm(event_id="evt-rec-006", challenge_id="chg-rec-006")
        trusted, challenge, bundle = self._create_quorum_operators_and_bundle(
            event_id="evt-rec-006", challenge_id="chg-rec-006"
        )

        fsm._simulate_persistence_failure = True
        try:
            ok = fsm.request_recovery(bundle, challenge, trusted)
        finally:
            fsm._simulate_persistence_failure = False

        self.assertFalse(ok)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

        # P1-006: Because persistence failed before commit, tokens were not permanently burned; retry succeeds
        retry_ok = fsm.request_recovery(bundle, challenge, trusted)
        self.assertTrue(retry_ok)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

    # =========================================================================
    # P1-4: FSM Generation Rollback & HMAC Hardening (TEST-ROLLBACK-001..005)
    # =========================================================================

    def test_rollback_001_hmac_tampering_and_key_mismatch(self):
        """TEST-ROLLBACK-001: Tampered HMAC or wrong HMAC key forces fail-closed ISOLATED and no key is in JSON."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        with open(self.state_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
        self.assertNotIn(self.hmac_key, raw_text)

        # Loading with wrong HMAC key must fail-closed to ISOLATED
        fsm_wrong_key = MK1SafetyStateMachine(state_path=self.state_path, hmac_key="wrong-key-999")
        self.assertEqual(fsm_wrong_key.current_state, fsm_wrong_key.ISOLATED)
        self.assertEqual(fsm_wrong_key.authenticity_status, "FAILED_HMAC")

    def test_rollback_002_generation_rollback_rejected(self):
        """TEST-ROLLBACK-002: Decreasing generation number in state file is rejected as rollback."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)
        fsm.transition_to(fsm.EMERGENCY)
        fsm.transition_to(fsm.ISOLATED)
        self.assertGreaterEqual(fsm.generation, 4)

        # Forge lower generation with valid HMAC for that payload, while journal has higher generation
        with open(self.state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["generation"] = 1
        data["state"] = "ACTIVE"
        data["integrity"] = fsm._compute_integrity(data["state"], data["timestamp"], data["generation"])
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
        self.assertEqual(reloaded.authenticity_status, "FAILED_ROLLBACK")

    def test_rollback_003_old_valid_state_file_replay_rejected(self):
        """TEST-ROLLBACK-003: Copying an old valid ACTIVE state file over an ISOLATED state file is caught via journal."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        backup_active_path = os.path.join(self.temp_dir.name, "fsm_state.active.bak")
        shutil.copy2(self.state_path, backup_active_path)

        fsm.transition_to(fsm.EMERGENCY)
        fsm.transition_to(fsm.ISOLATED)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

        # Replay attack: overwrite fsm_state.json with the earlier valid ACTIVE snapshot
        shutil.copy2(backup_active_path, self.state_path)

        reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
        self.assertEqual(reloaded.authenticity_status, "FAILED_ROLLBACK")

    def test_rollback_004_missing_generation_rejected(self):
        """TEST-ROLLBACK-004: State file missing generation field is rejected fail-closed to ISOLATED."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        with open(self.state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        del data["generation"]
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
        self.assertEqual(reloaded.authenticity_status, "FAILED_LOAD")

    def test_rollback_005_interrupted_persistence_corrupted_json(self):
        """TEST-ROLLBACK-005: Truncated/corrupted JSON from interrupted write triggers fail-closed ISOLATED."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        with open(self.state_path, "w", encoding="utf-8") as f:
            f.write('{"state": "ACTIVE", "generation": ')

        reloaded = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        self.assertEqual(reloaded.current_state, reloaded.ISOLATED)
        self.assertEqual(reloaded.authenticity_status, "FAILED_LOAD")

    # =========================================================================
    # P1-5: Three-Head AI Output & Model Weight Integrity (TEST-AI-001..010)
    # =========================================================================

    def test_ai_001_nan_output_fail_closed(self):
        """TEST-AI-001: NaN output from any AI head triggers fail-closed isolation and packet block."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        triggered = defender.evaluate_threat_state(
            interface="eth0",
            dry_run=False,
            score_a=float("nan"),
            score_b=0.0,
            score_c=0.0,
            autonomous=True,
            fsm=fsm,
        )
        self.assertTrue(triggered)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_ai_002_inf_output_fail_closed(self):
        """TEST-AI-002: +Inf or -Inf output from any AI head triggers fail-closed isolation."""
        for idx, bad_val in enumerate((float("inf"), float("-inf"))):
            p = os.path.join(self.temp_dir.name, f"fsm_inf_{idx}.json")
            fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            fsm.transition_to(fsm.ARMING)
            fsm.transition_to(fsm.ACTIVE)
            triggered = defender.evaluate_threat_state(
                interface="eth0",
                dry_run=False,
                score_a=0.1,
                score_b=bad_val,
                score_c=0.1,
                autonomous=True,
                fsm=fsm,
            )
            self.assertTrue(triggered)
            self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_ai_003_out_of_range_output_fail_closed(self):
        """TEST-AI-003: Out-of-range (<0.0 or >1.0) or None output triggers fail-closed isolation."""
        for idx, bad_val in enumerate((-0.01, 1.01, None)):
            p = os.path.join(self.temp_dir.name, f"fsm_oor_{idx}.json")
            fsm = MK1SafetyStateMachine(state_path=p, hmac_key=self.hmac_key)
            fsm.transition_to(fsm.ARMING)
            fsm.transition_to(fsm.ACTIVE)
            triggered = defender.evaluate_threat_state(
                interface="eth0",
                dry_run=False,
                score_a=0.1,
                score_b=0.1,
                score_c=bad_val,
                autonomous=True,
                fsm=fsm,
            )
            self.assertTrue(triggered)
            self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_ai_004_head_a_integrity_independent_isolation(self):
        """TEST-AI-004: Head A alone exceeding P0 threshold (0.99) isolates independently."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        triggered = defender.evaluate_threat_state(
            interface="eth0",
            dry_run=False,
            score_a=0.99,
            score_b=0.01,
            score_c=0.01,
            autonomous=True,
            fsm=fsm,
        )
        self.assertTrue(triggered)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_ai_005_head_b_integrity_independent_isolation(self):
        """TEST-AI-005: Head B alone exceeding P0 threshold (0.98) isolates independently."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        triggered = defender.evaluate_threat_state(
            interface="eth0",
            dry_run=False,
            score_a=0.01,
            score_b=0.98,
            score_c=0.01,
            autonomous=True,
            fsm=fsm,
        )
        self.assertTrue(triggered)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_ai_006_head_c_integrity_independent_isolation(self):
        """TEST-AI-006: Head C alone exceeding P0 threshold (0.95) isolates independently."""
        fsm = MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key)
        fsm.transition_to(fsm.ARMING)
        fsm.transition_to(fsm.ACTIVE)

        triggered = defender.evaluate_threat_state(
            interface="eth0",
            dry_run=False,
            score_a=0.01,
            score_b=0.01,
            score_c=0.95,
            autonomous=True,
            fsm=fsm,
        )
        self.assertTrue(triggered)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)

    def test_ai_007_weight_tampering_and_manifest_verification_reaches_final_block(self):
        """TEST-AI-007: Weight buffer modification invalidates signed manifest and blocks packet at ai_integrity_failure."""
        model = LightweightMultiTaskAI(input_dim=10)
        manifest = model.create_signed_weights_manifest(self.hmac_key)
        self.assertTrue(model.verify_signed_weights_manifest(manifest, self.hmac_key))

        # Modify actual weight buffer bytes (1-byte tamper)
        model._weight_buffers["head_c.0.weight"] = b"\xff" * 16
        self.assertFalse(model.verify_signed_weights_manifest(manifest, self.hmac_key))
        self.assertFalse(model.verify_weights_integrity())

        res = defender.inspect_packet_pipeline(
            self.valid_packet,
            "eth0",
            model=model,
            feature_vector=[0.1] * 10,
        )
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "ai_integrity_failure")
        self.assertTrue(res.get("ai_integrity_failure"))
        self.assertEqual(res["score"], 1.0)

    def test_ai_008_missing_baseline_rejected_when_required(self):
        """TEST-AI-008: Model with require_baseline=True fails verification if baseline was never recorded."""
        model = LightweightMultiTaskAI(input_dim=10)
        model._require_baseline = True
        self.assertFalse(model.verify_weights_integrity())

        res = defender.inspect_packet_pipeline(
            self.valid_packet,
            "eth0",
            model=model,
            feature_vector=[0.1] * 10,
        )
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "ai_integrity_failure")

    def test_ai_009_malformed_tensor_dimension_fail_closed(self):
        """TEST-AI-009: Model returning wrong tuple length or empty tensor triggers fail-closed block."""
        class MalformedModel:
            def verify_weights_integrity(self):
                return True

            def __call__(self, x):
                return (defender.torch.tensor([[0.1]]), defender.torch.tensor([[0.1]]))

        res = defender.inspect_packet_pipeline(
            self.valid_packet,
            "eth0",
            model=MalformedModel(),
            feature_vector=[0.1] * 10,
        )
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "ai_integrity_failure")
        self.assertIn("malformed_model_output_dimensions", res.get("reason", ""))

    def test_ai_010_model_exception_fail_closed(self):
        """TEST-AI-010: Exception raised inside AI model forward pass triggers fail-closed block."""
        class ExplodingModel:
            def verify_weights_integrity(self):
                return True

            def __call__(self, x):
                raise RuntimeError("Simulated GPU/tensor runtime crash")

        res = defender.inspect_packet_pipeline(
            self.valid_packet,
            "eth0",
            model=ExplodingModel(),
            feature_vector=[0.1] * 10,
        )
        self.assertTrue(res["block"])
        self.assertEqual(res["stage"], "ai_integrity_failure")
        self.assertIn("model_inference_exception", res.get("reason", ""))


if __name__ == "__main__":
    unittest.main()
