import unittest
import time
import airgap_ai_defender as defender
from airgap_ai_defender import MK1SafetyStateMachine, LightweightMultiTaskAI
import mk1_quorum

class TestV3Remediation(unittest.TestCase):

    def setUp(self):
        # Reset state before each test
        defender.toggle_oni_mode(False)
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()
        defender._KILL_SWITCH_TRIGGERED = False
        defender._anomaly_counter = 0
        defender._ISOLATION_APPROVAL_PENDING = False

    def tearDown(self):
        defender.toggle_oni_mode(False)
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()

    def test_v3_fsm_states(self):
        """Verify the presence of all 7 V3 states."""
        fsm = defender._SAFETY_FSM
        states = [fsm.OFF, fsm.ARMING, fsm.ACTIVE, fsm.EMERGENCY, fsm.ISOLATED, fsm.RECOVERY_PENDING, fsm.RECOVERY_APPROVED]
        self.assertEqual(len(set(states)), 7)

    def test_v3_transition_matrix(self):
        """Verify the FSM transition matrix enforcement."""
        fsm = MK1SafetyStateMachine() # New instance starts at OFF
        self.assertEqual(fsm.current_state, fsm.OFF)
        
        # OFF -> ARMING (Valid)
        fsm.transition_to(fsm.ARMING)
        self.assertEqual(fsm.current_state, fsm.ARMING)
        
        # ARMING -> ACTIVE (Valid)
        fsm.transition_to(fsm.ACTIVE)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)
        
        # ACTIVE -> EMERGENCY (Valid)
        fsm.transition_to(fsm.EMERGENCY)
        self.assertEqual(fsm.current_state, fsm.EMERGENCY)
        
        # EMERGENCY -> ISOLATED (Valid)
        fsm.transition_to(fsm.ISOLATED)
        self.assertEqual(fsm.current_state, fsm.ISOLATED)
        
        # ISOLATED -> RECOVERY_PENDING (Valid)
        fsm.transition_to(fsm.RECOVERY_PENDING)
        self.assertEqual(fsm.current_state, fsm.RECOVERY_PENDING)
        
        # RECOVERY_PENDING -> RECOVERY_APPROVED (Valid)
        fsm.transition_to(fsm.RECOVERY_APPROVED)
        self.assertEqual(fsm.current_state, fsm.RECOVERY_APPROVED)
        
        # RECOVERY_APPROVED -> ARMING (Valid)
        fsm.transition_to(fsm.ARMING)
        self.assertEqual(fsm.current_state, fsm.ARMING)

        # ARMING -> ACTIVE (Valid)
        fsm.transition_to(fsm.ACTIVE)
        self.assertEqual(fsm.current_state, fsm.ACTIVE)

    def test_invalid_transitions(self):
        """Verify that illegal transitions raise RuntimeError."""
        fsm = MK1SafetyStateMachine() # OFF
        with self.assertRaises(RuntimeError):
            fsm.transition_to(fsm.ISOLATED) # OFF -> ISOLATED is invalid
        with self.assertRaises(RuntimeError):
            fsm.transition_to(fsm.ACTIVE) # OFF -> ACTIVE (skipping ARMING) is now strictly forbidden

    def test_independent_head_a_trigger(self):
        """Head A alone should trigger autonomous isolation (simulated in dry_run without polluting production _state)."""
        # score_a >= 0.99 is P0
        defender.evaluate_threat_state(
            interface="eth0", 
            dry_run=True, 
            score_a=0.99, 
            autonomous=True
        )
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertEqual(defender._SAFETY_FSM.simulated_state, MK1SafetyStateMachine.ISOLATED)

    def test_independent_head_b_trigger(self):
        """Head B alone should trigger autonomous isolation (simulated in dry_run without polluting production _state)."""
        # score_b >= 0.98 is P0
        defender.evaluate_threat_state(
            interface="eth0", 
            dry_run=True, 
            score_b=0.98, 
            autonomous=True
        )
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertEqual(defender._SAFETY_FSM.simulated_state, MK1SafetyStateMachine.ISOLATED)

    def test_independent_head_c_trigger(self):
        """Head C alone should trigger autonomous isolation (simulated in dry_run without polluting production _state)."""
        # score_c >= 0.95 is P0
        defender.evaluate_threat_state(
            interface="eth0", 
            dry_run=True, 
            score_c=0.95, 
            autonomous=True
        )
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertEqual(defender._SAFETY_FSM.simulated_state, MK1SafetyStateMachine.ISOLATED)

    def test_recovery_gate_logic(self):
        """Restoration must pass through RECOVERY_APPROVED."""
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ISOLATED
        defender._SAFETY_FSM._save_persistent_state()
        
        # Mocking recovery call without approval
        success = defender._SAFETY_FSM.request_recovery(None, None, None)
        self.assertFalse(success)
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ISOLATED)

if __name__ == "__main__":
    unittest.main()
