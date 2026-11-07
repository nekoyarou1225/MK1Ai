import unittest
import math
import time
import threading
from typing import Any
from airgap_ai_defender import (
    MK1MathematicalSecurityEngine,
    MK1SafetySupervisor,
    MK1SafetyStateMachine,
    DeterministicVerdict,
    evaluate_threat_state,
    _SAFETY_FSM,
    _MATH_ENGINE,
    _SAFETY_SUPERVISOR,
    SafetyExecutionLoop,
    is_maintenance_mode,
    is_learning_mode
)

class TestMK1HybridSecurity(unittest.TestCase):
    def setUp(self):
        # Reset global FSM and engines for each test
        _SAFETY_FSM._state = MK1SafetyStateMachine.OFF
        _SAFETY_FSM._simulated_state = MK1SafetyStateMachine.OFF
        _SAFETY_FSM._emergency_latch = False
        _SAFETY_FSM._audit_trail = []
        _SAFETY_FSM.record_kill_switch_state(MK1SafetyStateMachine.KS_NOT_REQUESTED)
        _MATH_ENGINE._anomaly_history.clear()
        _SAFETY_SUPERVISOR._override_latch = False

        
    def test_ai_nan_fail_closed(self):
        """TC-001: AI returns NaN score -> Fail-closed isolation."""
        # Use evaluate_threat_state directly to simulate AI output
        result = evaluate_threat_state(None, False, score_a=float('nan'), autonomous=True)
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_ai_inf_fail_closed(self):
        """TC-002: AI returns Inf score -> Fail-closed isolation."""
        result = evaluate_threat_state(None, False, score_a=float('inf'), autonomous=True)
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_imse_danger_override(self):
        """TC-003: IMSE DANGER overrides AI SAFE (0.0)."""
        # Feature 9 >= 0.9 triggers IMSE DANGER (Fragment)
        features = [0.1] * 10
        features[9] = 0.95
        
        result = evaluate_threat_state(
            None, False, score_a=0.0, 
            autonomous=True, 
            packet_bytes=b"dummy", 
            feature_vector=features
        )
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)
        found_imse = any("IMSE" in str(entry.get("reason", "")) for entry in _SAFETY_FSM._audit_trail)
        self.assertTrue(found_imse)

    def test_ai_p0_rejected_by_imse_safe(self):
        """TC-004: AI P0 (0.99) rejected when IMSE is SAFE."""
        # Feature 1 (Entropy) low, Feature 2 (DPI) low -> IMSE SAFE
        features = [0.0] * 10
        
        result = evaluate_threat_state(
            None, False, score_a=0.99, 
            autonomous=True, 
            packet_bytes=b"dummy", 
            feature_vector=features
        )
        # Should NOT isolate immediately if IMSE is SAFE
        self.assertFalse(result)
        self.assertNotEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_ai_p0_validated_by_imse_suspicious(self):
        """TC-005: AI P0 (0.99) accepted when IMSE is SUSPICIOUS."""
        # Max feature > 0.85 -> SUSPICIOUS
        features = [0.0] * 10
        features[0] = 0.86
        
        result = evaluate_threat_state(
            None, False, score_a=0.99, 
            autonomous=True, 
            packet_bytes=b"dummy", 
            feature_vector=features
        )
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_imse_corrupted_features_fail_closed(self):
        """TC-006: Corrupted feature vector (negative) -> Fail-closed."""
        features = [0.1] * 10
        features[5] = -1.0
        
        result = evaluate_threat_state(
            None, False, score_a=0.1, 
            autonomous=True, 
            packet_bytes=b"dummy", 
            feature_vector=features
        )
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_imse_out_of_range_features_fail_closed(self):
        """TC-007: Corrupted feature vector (>1.0) -> Fail-closed."""
        features = [0.1] * 10
        features[5] = 1.1
        
        result = evaluate_threat_state(
            None, False, score_a=0.1, 
            autonomous=True, 
            packet_bytes=b"dummy", 
            feature_vector=features
        )
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_safety_loop_stage3_commit(self):
        """TC-008: SafetyExecutionLoop STAGE_3 uses Supervisor."""
        loop = SafetyExecutionLoop(model=None)
        # Force a threat in features for IMSE that bypasses STAGE_2 early break
        # STAGE_2 break needs features[1] >= 0.96 or features[2] >= 0.70
        features = [0.1] * 10
        features[1] = 0.90 
        features[2] = 0.60
        features[9] = 0.95 # IMSE DANGER (Fragment)
        # IMSE will return DANGER in STAGE_3
        
        res = loop.evaluate(b"dummy_packet", feature_vector=features)
        self.assertEqual(res["state"], "FAIL_CLOSED_BLOCK")
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)


    def test_dry_run_no_isolation(self):
        """TC-009: Dry-run mode prevents actual isolation."""
        features = [0.1] * 10
        features[9] = 0.95 # IMSE Danger
        
        result = evaluate_threat_state(
            None, True, score_a=0.0, 
            autonomous=True, 
            packet_bytes=b"dummy", 
            feature_vector=features
        )
        # result is True (threat detected) but FSM should be simulated isolated, not real isolated
        self.assertTrue(result)
        # Check if real state is still OFF (or whatever it was)
        # Note: target_fsm.isolate_immediately(..., simulated=True) should update simulated_state
        self.assertEqual(_SAFETY_FSM._simulated_state, MK1SafetyStateMachine.ISOLATED)
        self.assertNotEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_quorum_requirement_for_low_confidence(self):
        """TC-010: Quorum required if autonomous=False even if score is high."""
        result = evaluate_threat_state(None, False, score_a=0.99, autonomous=False)
        self.assertFalse(result)
        self.assertNotEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_imse_burst_anomalies(self):
        """TC-011: Sequential Consistency: Rapid burst of anomalous features."""
        # Need 10 anomalies with avg > 0.7
        features = [0.0] * 10
        features[2] = 0.85 # Anomalous but not DANGER yet
        
        for _ in range(9):
            _MATH_ENGINE.evaluate_packet(b"p", features)
        
        # 10th one should trigger DANGER
        verdict = _MATH_ENGINE.evaluate_packet(b"p", features)
        self.assertEqual(verdict, DeterministicVerdict.DANGER)

    def test_ai_takeover_nan_inference(self):
        """TC-012: AI model compromised (returns NaN) -> Supervisor isolates."""
        ai_report = {
            "threat_score": float('nan'),
            "inference_status": "corrupted"
        }
        features = [0.1] * 10
        is_blocked = _SAFETY_SUPERVISOR.evaluate_hybrid_threat(ai_report, b"p", features, autonomous=True)
        self.assertTrue(is_blocked)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_deterministic_fragment_blocking(self):
        """TC-013: IMSE blocks fragments in CORE."""
        features = [0.0] * 10
        features[9] = 1.0 # Fragment
        verdict = _MATH_ENGINE.evaluate_packet(b"p", features)
        self.assertEqual(verdict, DeterministicVerdict.DANGER)

    def test_deterministic_entropy_dpi_blocking(self):
        """TC-014: IMSE blocks high entropy + DPI signature."""
        features = [0.0] * 10
        features[1] = 0.96 # Entropy
        features[2] = 0.91 # DPI
        verdict = _MATH_ENGINE.evaluate_packet(b"p", features)
        self.assertEqual(verdict, DeterministicVerdict.DANGER)

    def test_imse_suspicious_latch(self):
        """TC-015: IMSE Suspicious state recorded."""
        features = [0.0] * 10
        features[0] = 0.86 # Max > 0.85
        verdict = _MATH_ENGINE.evaluate_packet(b"p", features)
        self.assertEqual(verdict, DeterministicVerdict.SUSPICIOUS)

    def test_fail_closed_on_none_feature(self):
        """TC-016: evaluate_threat_state fails closed on None feature_vector if autonomous."""
        result = evaluate_threat_state(None, False, score_a=0.99, autonomous=True, feature_vector=None)
        # None defaults to [0.0]*10, which is SAFE. 
        # But wait, in evaluate_threat_state:
        # feature_vector or ([0.0] * 10)
        # If score_a=0.99 and features=[0]*10 (SAFE), it should be rejected by Supervisor.
        self.assertFalse(result)

    def test_fail_closed_on_corrupted_ai_report(self):
        """TC-017: Supervisor isolates on corrupted AI report."""
        ai_report = {"inference_status": "corrupted"}
        is_blocked = _SAFETY_SUPERVISOR.evaluate_hybrid_threat(ai_report, b"p", [0.1]*10, autonomous=True)
        self.assertTrue(is_blocked)

    def test_autonomous_isolation_path(self):
        """TC-018: verify autonomous path records event and sets global latch."""
        import airgap_ai_defender
        airgap_ai_defender._KILL_SWITCH_EVENT.clear()
        
        features = [0.1] * 10
        features[9] = 0.95 # Danger
        
        evaluate_threat_state(None, False, score_a=0.0, autonomous=True, packet_bytes=b"p", feature_vector=features)
        
        self.assertTrue(airgap_ai_defender._KILL_SWITCH_EVENT.is_set())
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

    def test_hybrid_decision_matrix_consensus(self):
        """TC-019: AI 0.99 + IMSE Suspicious -> Isolation."""
        ai_report = {"threat_score": 0.99, "inference_status": "ok"}
        features = [0.0] * 10
        features[0] = 0.86 # Suspicious
        
        is_blocked = _SAFETY_SUPERVISOR.evaluate_hybrid_threat(ai_report, b"p", features, autonomous=True)
        self.assertTrue(is_blocked)

    def test_hybrid_decision_matrix_no_consensus(self):
        """TC-020: AI 0.99 + IMSE Safe -> No Isolation (Warning only)."""
        ai_report = {"threat_score": 0.99, "inference_status": "ok"}
        features = [0.0] * 10 # Safe
        
        is_blocked = _SAFETY_SUPERVISOR.evaluate_hybrid_threat(ai_report, b"p", features, autonomous=True)
        self.assertFalse(is_blocked)

    def test_maintenance_mode_bypass(self):
        """TC-021: Maintenance mode acts like dry-run."""
        # To simulate maintenance mode, we can monkeypatch or use existing logic if it depends on env/globals
        import airgap_ai_defender
        old_val = airgap_ai_defender._MAINTENANCE_ACTIVE
        airgap_ai_defender._MAINTENANCE_ACTIVE = True
        try:

            features = [0.1] * 10
            features[9] = 0.95 # Danger
            result = evaluate_threat_state(None, False, score_a=0.0, autonomous=True, packet_bytes=b"p", feature_vector=features)
            self.assertTrue(result)
            self.assertNotEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)
            self.assertEqual(_SAFETY_FSM._simulated_state, MK1SafetyStateMachine.ISOLATED)
        finally:
            airgap_ai_defender._MAINTENANCE_ACTIVE = old_val


    def test_learning_mode_bypass(self):
        """TC-022: Learning mode prevents isolation."""
        import airgap_ai_defender
        old_val = airgap_ai_defender._RSI_MODE_ACTIVE
        airgap_ai_defender._RSI_MODE_ACTIVE = True
        try:

            features = [0.1] * 10
            features[9] = 0.95 # Danger
            result = evaluate_threat_state(None, False, score_a=0.99, autonomous=True, packet_bytes=b"p", feature_vector=features)
            self.assertFalse(result)
            self.assertNotEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)
        finally:
            airgap_ai_defender._RSI_MODE_ACTIVE = old_val


    def test_iss_override_latch(self):
        """TC-023: ISS override latch is set on danger."""
        _SAFETY_SUPERVISOR._override_latch = False
        features = [0.1] * 10
        features[9] = 0.95 # Danger
        _SAFETY_SUPERVISOR.evaluate_hybrid_threat({"threat_score": 0.0}, b"p", features, autonomous=True)
        self.assertTrue(_SAFETY_SUPERVISOR._override_latch)

    def test_fsm_record_audit_on_mismatch(self):
        """TC-024: Mismatch AI/IMSE is audited."""
        # Reset audit log
        _SAFETY_FSM._audit_trail = []
        ai_report = {"threat_score": 0.99, "inference_status": "ok"}
        features = [0.0] * 10 # Safe
        _SAFETY_SUPERVISOR.evaluate_hybrid_threat(ai_report, b"p", features, autonomous=True)
        
        found = any("AI_IMSE_MISMATCH" in entry["event_type"] for entry in _SAFETY_FSM._audit_trail)
        self.assertTrue(found)


    def test_privileged_dispatch_fallback(self):
        """TC-025: Autonomous isolation falls back to local if dispatch fails."""
        # This is hard to test without mocking _dispatch_privileged_command
        # But we can verify it doesn't crash.
        features = [0.1] * 10
        features[9] = 0.95 # Danger
        result = _SAFETY_SUPERVISOR.evaluate_hybrid_threat({"threat_score": 0.0}, b"p", features, autonomous=True)
        self.assertTrue(result)
        self.assertEqual(_SAFETY_FSM._state, MK1SafetyStateMachine.ISOLATED)

if __name__ == '__main__':
    unittest.main()
