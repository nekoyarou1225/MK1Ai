import unittest
import time
import airgap_ai_defender as defender
import mk1_quorum
from airgap_ai_defender import MK1SafetyStateMachine, LightweightMultiTaskAI

class TestV2Remediation(unittest.TestCase):

    def setUp(self):
        # Reset state before each test (V3 states)
        defender.toggle_oni_mode(False)
        # Use _state to bypass transition rules for setup if necessary, or use valid transitions
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()
        defender._KILL_SWITCH_TRIGGERED = False
        defender._anomaly_counter = 0
        defender._simulated_anomaly_counter = 0
        defender._ISOLATION_APPROVAL_PENDING = False

    def tearDown(self):
        defender.toggle_oni_mode(False)
        defender._SAFETY_FSM._state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._simulated_state = MK1SafetyStateMachine.ACTIVE
        defender._SAFETY_FSM._save_persistent_state()

    def test_fsm_basic_transitions(self):
        fsm = defender._SAFETY_FSM
        # We start at ACTIVE because of setUp
        self.assertEqual(fsm.current_state, MK1SafetyStateMachine.ACTIVE)
        
        # ACTIVE -> EMERGENCY (Valid V3)
        fsm.transition_to(MK1SafetyStateMachine.EMERGENCY, reason="Unit Test")
        self.assertEqual(fsm.current_state, MK1SafetyStateMachine.EMERGENCY)
        self.assertTrue(defender.ONI_MODE_is_active())
        
        # EMERGENCY -> ISOLATED (Valid V3)
        fsm.transition_to(MK1SafetyStateMachine.ISOLATED, reason="Unit Test")
        self.assertEqual(fsm.current_state, MK1SafetyStateMachine.ISOLATED)

    def test_autonomous_p0_isolation_logic(self):
        # High confidence P0 threat
        score_a = 0.995 
        
        # In V3.2 (P0-002 / Invariant I-06), dry_run=True isolates simulated_state
        # without contaminating production current_state.
        defender.evaluate_threat_state(
            interface="eth0", 
            dry_run=True, 
            score_a=score_a, 
            autonomous=True
        )
        
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertEqual(defender._SAFETY_FSM.simulated_state, MK1SafetyStateMachine.ISOLATED)

    def test_non_autonomous_requires_quorum(self):
        # High confidence threat but autonomous=False
        score_a = 0.995 
        
        # Under V3.2 Invariant I-06, dry_run=True does not mutate production _ISOLATION_APPROVAL_PENDING
        triggered_dry = defender.evaluate_threat_state(
            interface="eth0", 
            dry_run=True, 
            score_a=score_a, 
            autonomous=False
        )
        self.assertTrue(triggered_dry)
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertFalse(defender._ISOLATION_APPROVAL_PENDING)

        # Production dry_run=False with autonomous=False sets _ISOLATION_APPROVAL_PENDING=True without isolating
        triggered = defender.evaluate_threat_state(
            interface="eth0", 
            dry_run=False, 
            score_a=score_a, 
            autonomous=False
        )
        
        # triggered should be True (it detected threat and is waiting for approval)
        self.assertTrue(triggered)
        # Should stay in ACTIVE (not ISOLATED)
        self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ACTIVE)
        self.assertTrue(defender._ISOLATION_APPROVAL_PENDING)

    def test_quorum_domain_separation_prefixes(self):
        # Test ISOLATE_NETWORK prefix
        chg_isolate = mk1_quorum.create_quorum_challenge(operation="ISOLATE_NETWORK")
        self.assertEqual(chg_isolate.get("prefix"), "MK1AI-ISOLATE-v1")
        
        # Test RELEASE_QUARANTINE prefix
        chg_release = mk1_quorum.create_quorum_challenge(operation="RELEASE_QUARANTINE")
        self.assertEqual(chg_release.get("prefix"), "MK1AI-RECOVERY-v1")
        
    def test_multi_head_ai_output(self):
        # Just check that it returns 3 values
        model = LightweightMultiTaskAI(input_dim=10)
        torch_stub = defender.torch
        if hasattr(torch_stub, "tensor"):
            x = torch_stub.tensor([[0.5] * 10])
            outputs = model(x)
            self.assertEqual(len(outputs), 3)

if __name__ == "__main__":
    unittest.main()
