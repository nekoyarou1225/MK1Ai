# MK1Ai V3 Regression Test Plan
## Test Suite and Verification Protocol

**Target Test Files**: `tests/test_v3_remediation.py`, `tests/test_xdp_controller.py`, `tests/test_quorum.py`

### 1. Test Execution Command
```bash
python3 -m unittest discover -s tests
```

### 2. Test Coverage Matrix

| Category | Test Case | Target Function | Expected Result |
|---|---|---|---|
| **FSM** | `test_v3_fsm_states` | FSM state count | 7 states verified |
| **FSM** | `test_v3_transition_matrix` | Valid transitions | PASS |
| **FSM** | `test_invalid_transitions` | Illegal transitions | Raise `RuntimeError` |
| **AI** | `test_independent_head_a_trigger` | Head A isolation | `ISOLATED` state |
| **AI** | `test_independent_head_b_trigger` | Head B isolation | `ISOLATED` state |
| **AI** | `test_independent_head_c_trigger` | Head C isolation | `ISOLATED` state |
| **Quorum** | `test_recovery_gate_logic` | M-of-N verification | False without valid bundle |
| **XDP** | `test_xdp_ingress_lockdown` | Dead-man switch / ONI | `XDP_DROP` |

### 3. Acceptance Criteria
All existing and newly added unit tests must return `OK` without errors or warnings in the test runner output.
