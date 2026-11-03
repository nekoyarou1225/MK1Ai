# MK1Ai V3 Test Specification
## Verification Protocol for Final V3 Remediation

**Target**: `tests/test_v3_final.py`

### 1. Mandatory Passing Criteria (V3)
The system must pass all 14 criteria defined in the V3 Final Security Remediation brief.

### 2. Specific Test Suites

#### 2.1 FSM Strictness (Success Criterion 7)
- **ID**: `TEST_FSM_01_STRICT_STARTUP`
- **Method**: Instantiate `MK1SafetyStateMachine`. Attempt `transition_to(ACTIVE)` from `OFF`.
- **Expected**: `RuntimeError`.
- **ID**: `TEST_FSM_02_RECOVERY_ARMING`
- **Method**: In `RECOVERY_APPROVED`, attempt `transition_to(ACTIVE)`.
- **Expected**: `RuntimeError`. Must transition to `ARMING` first.

#### 2.2 FSM Persistence (Requirement 2.4)
- **ID**: `TEST_FSM_03_PERSISTENCE_LOAD`
- **Method**: Set state to `ISOLATED`. Call `_save_state()`. Manually re-instantiate FSM.
- **Expected**: `fsm.current_state == ISOLATED`.
- **ID**: `TEST_FSM_04_PERSISTENCE_TAMPER`
- **Method**: Manually corrupt the integrity hash in `fsm_state.json`.
- **Expected**: `fsm.current_state == ISOLATED` (Fail-Closed default).

#### 2.3 Head C Integrity (Success Criterion 3)
- **ID**: `TEST_HEADC_01_MODEL_TAMPER`
- **Method**: Temporarily modify a weight in `AbsoluteDefenseModel.shared_layer`.
- **Expected**: `score_c >= 0.95` during next inference.
- **ID**: `TEST_HEADC_02_ISOLATION_TRIGGER`
- **Method**: Trigger `score_c=1.0` in `inspect_packet_pipeline`.
- **Expected**: `evaluate_threat_state` transitions FSM to `ISOLATED`.

#### 2.4 M-of-N Quorum (Success Criterion 8)
- **ID**: `TEST_QUORUM_01_RECOVERY_RESTRICTED`
- **Method**: Attempt recovery with a challenge document for a different `event_id`.
- **Expected**: `QuorumError`.

### 3. Execution Protocol
1. Run `python3 -m unittest tests/test_v3_remediation.py`.
2. Run `python3 -m unittest tests/test_v3_final.py` (New).
3. Verify all 14 V3 passing criteria are marked `OK` in the test log.
