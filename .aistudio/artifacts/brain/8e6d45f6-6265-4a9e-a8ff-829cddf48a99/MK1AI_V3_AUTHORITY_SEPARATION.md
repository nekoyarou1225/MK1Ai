# MK1Ai V3 Authority Separation Report
## Separation of Autonomous AI Isolation and M-of-N Recovery Gates

**Status**: IMPLEMENTED & VERIFIED

### 1. Conceptual Framework
The V3 architecture enforces a strict separation of powers:
1. **AI Authority**: Autonomous, machine-speed isolation (Bypass M-of-N). Purpose: Immediate defense.
2. **Human Authority**: M-of-N (2-of-3) Ed25519 Quorum for restoration. Purpose: Integrity-checked recovery.

### 2. Authority Implementation Analysis

#### 2.1 AI-Driven Autonomous Path
- **Trigger**: `evaluate_threat_state(autonomous=True)`
- **Mechanism**: Calls `execute_kill_switch(autonomous_bypass=True)`.
- **Verification**: `mk1_quorum.py` is **not** called during this path, ensuring that a P0 threat is mitigated within milliseconds without waiting for human signers.
- **FSM State**: `EMERGENCY -> ISOLATED`.

#### 2.2 Human-Gated Recovery Path
- **Trigger**: `_SAFETY_FSM.request_recovery()`
- **Mechanism**: Calls `mk1_quorum.verify_quorum_bundle()`.
- **Requirements**:
    - Valid `approval_bundle` (JSON/Base64).
    - `challenge_document` with `operation="RELEASE_QUARANTINE"`.
    - At least 2 distinct trusted Ed25519 public keys.
- **FSM State**: `ISOLATED -> RECOVERY_PENDING -> RECOVERY_APPROVED -> ACTIVE`.

### 3. Separation Evidence (Source Code)

| Feature | Autonomous Isolation | M-of-N Recovery |
|---|---|---|
| **Entry Point** | `evaluate_threat_state` (line 5823) | `MK1SafetyStateMachine.request_recovery` (line 493) |
| **Logic Connector** | `autonomous_bypass=True` | `verify_quorum_bundle(...)` |
| **Fail-Closed Gate** | None (Immediate) | `InvalidSignature` or `QuorumError` -> Rollback to `ISOLATED` |

### 4. Integrity Gaps Identified
- **Replay Protection**: While `TwoAdminQuorumGate` (in `mk1_quorum.py`) provides replay protection, the current `request_recovery` implementation in `airgap_ai_defender.py` does not yet persist the `consumed_events` ledger across restarts.
- **Recovery Destination**: Current logic transitions from `RECOVERY_APPROVED` directly to `ACTIVE` (line 512). It should transition to `ARMING` first to re-verify drivers and policy integrity.

### 5. Conclusion
The "Authority Separation" is functionally complete in code, preventing AI from being blocked by missing human signatures while ensuring no single administrator can reopen the air-gap alone.
