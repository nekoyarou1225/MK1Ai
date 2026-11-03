# MK1Ai V3 Remediation Diff Plan
## Proposed Engineering Changes for Final V3 Alignment

**Target Phase**: Phase 4 (Final Fixing & Verification)
**Objective**: Resolve the 3 P1 gaps identified in the V3 Audit.

### 1. FSM Integrity & Startup Sequence (Gap 3.1 & 3.2)
- **Target**: `airgap_ai_defender.py:MK1SafetyStateMachine`
- **Action**:
    - Remove `self.OFF: {self.ACTIVE}` from the allowed transitions.
    - Add `self.RECOVERY_APPROVED: {self.ARMING}`.
    - Remove `self.RECOVERY_APPROVED: {self.ACTIVE}`.
    - Update `request_recovery` to transition to `ARMING` instead of `ACTIVE`.
- **Outcome**: Strict compliance with Success Criterion 7 and Section 2.3.

### 2. FSM State Persistence (Gap 3.3)
- **Target**: `airgap_ai_defender.py:MK1SafetyStateMachine`
- **Action**:
    - Implement `_save_state()`: Writes JSON to `/.ai_data/fsm_state.json` with a SHA-256 integrity hash of `{state, timestamp}`.
    - Implement `_load_state()`: Reads during `__init__`. If hash mismatch or file missing (and not first run), default to `ISOLATED` (Fail-Closed).
    - Call `_save_state()` at the end of every `transition_to`.
- **Outcome**: Survivability across process restarts (Requirement 2.4).

### 3. Head C Model Integrity (Gap 3.2)
- **Target**: `airgap_ai_defender.py:AbsoluteDefenseModel` and `inspect_packet_pipeline`
- **Action**:
    - Implement `verify_weights_hash()`: Computes SHA-256 of all model parameters (shared + head_a).
    - In `AbsoluteDefenseModel.forward()`, if a global `INTEGRITY_CHECK_INTERVAL` is met, perform hash check.
    - If hash mismatch, set `score_c = 1.0` (Critical Integrity Failure).
    - Update `inspect_packet_pipeline` to use this `score_c` to trigger isolation.
- **Outcome**: Detection of model poisoning/tampering (Success Criterion 3).

### 4. Code Change Summary (Proposed Diff)

```python
# airgap_ai_defender.py (Conceptual Diff)

# 1. Strict Matrix
self._allowed_transitions = {
    self.OFF: {self.ARMING},
    self.RECOVERY_APPROVED: {self.ARMING, self.EMERGENCY},
    ...
}

# 2. Persistence
def _save_state(self):
    data = {"state": self._state, "ts": time.time()}
    data["sig"] = hmac.new(b"INTERNAL_KEY", json.dumps(data), hashlib.sha256).hexdigest()
    write_atomic("/.ai_data/fsm_state.json", data)

# 3. Head C Integrity
def verify_weights_hash(self):
    actual = hashlib.sha256(pickle.dumps(self.state_dict())).hexdigest()
    if actual != EXPECTED_MODEL_HASH:
        return 1.0 # High anomaly
    return 0.0
```

### 5. Verification Plan
- **Unit Test**: `test_v3_strict_fsm_startup` (Ensure `OFF->ACTIVE` fails).
- **Unit Test**: `test_v3_fsm_persistence` (Kill process, restart, verify state is preserved).
- **Unit Test**: `test_v3_model_tamper_detection` (Manually corrupt weight, verify Head C triggers isolation).
