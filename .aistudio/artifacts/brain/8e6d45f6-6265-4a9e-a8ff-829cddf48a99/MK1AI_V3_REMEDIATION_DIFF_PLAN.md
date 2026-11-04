# MK1Ai V3 Remediation Diff Plan
## Proposed Engineering Changes for FSM Strictness and Persistence

**Target Phase**: Phase 2 (Code Remediation upon User Approval)

### 1. Proposed Code Modifications (`airgap_ai_defender.py`)

#### 1.1 Enforce Strict FSM Startup
- **Target**: `MK1SafetyStateMachine.__init__` (around line 461).
- **Change**: Remove `{self.ACTIVE}` from `self._allowed_transitions[self.OFF]`.
- **Reason**: Force all startups to pass through `ARMING` to ensure integrity checks execute.

#### 1.2 Implement FSM State Persistence
- **Target**: `MK1SafetyStateMachine` class.
- **Change**: Add `_save_state()` and `_load_state()` methods storing JSON with HMAC integrity checks in `/.ai_data/fsm_state.json`.
- **Reason**: Prevent state loss across process restarts.

#### 1.3 Fix Recovery Transition Path
- **Target**: `MK1SafetyStateMachine.request_recovery` (line 512).
- **Change**: Change successful recovery target state from `ACTIVE` to `ARMING`.
- **Reason**: Ensure re-arming and re-verification occur after quarantine release.

### 2. Regression Risk
- Low. All changes strengthen invariant enforcement and do not alter network interfaces or packet parsing logic.
