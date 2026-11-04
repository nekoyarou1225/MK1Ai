# MK1Ai V3 FSM Verification Report
## Formal State Transition Matrix & Security Audit

**Target Class**: `MK1SafetyStateMachine` (`airgap_ai_defender.py:433`)

### 1. State Transition Matrix

| Current State | Requested Target | Execution Condition | Required Privilege | Refusal Condition | Audit Log Message | Failure Behavior |
|---|---|---|---|---|---|---|
| `OFF` | `ARMING` | System Boot / Init | Root / Daemon | Already armed / Invalid state | `[FSM] 状態遷移: OFF -> ARMING` | Raise `RuntimeError` |
| `ARMING` | `ACTIVE` | Integrity Checks Passed | System Daemon | Checks failed / Unverified | `[FSM] 状態遷移: ARMING -> ACTIVE` | Raise `RuntimeError` |
| `ACTIVE` | `EMERGENCY` | P0 Threat (Any Head) | AI Defender Engine | None (Fail-Closed) | `[FSM] 状態遷移: ACTIVE -> EMERGENCY` | Immediate Lockdown |
| `EMERGENCY` | `ISOLATED` | Kill Switch Complete | Air-Gap Controller | Switch failure | `[FSM] 状態遷移: EMERGENCY -> ISOLATED` | Retain Emergency |
| `ISOLATED` | `RECOVERY_PENDING` | Admin Restoration Request | Operator Console | System not isolated | `[FSM] 状態遷移: ISOLATED -> RECOVERY_PENDING`| Refuse Request |
| `RECOVERY_PENDING` | `RECOVERY_APPROVED`| M-of-N Ed25519 Verified | 2 of 3 Admins | Invalid/Expired Signature | `[FSM] 状態遷移: PENDING -> APPROVED` | Rollback to ISOLATED |
| `RECOVERY_APPROVED` | `ARMING` | Post-Quorum Re-arm | System Daemon | Unverified integrity | `[FSM] 状態遷移: APPROVED -> ARMING` | Retain Approved |

### 2. Thread Safety & Concurrency
- `MK1SafetyStateMachine` uses `threading.Lock()` (`self._lock`) across all state reads and transitions.
- Concurrent P0 threat signals from multiple heads or simultaneous administrative requests will queue and execute atomically, preventing race conditions or split-brain FSM states.

### 3. Audit Findings & Compliance
- **Transition Strictness**: The code currently permits `OFF -> ACTIVE` for robust startup. To achieve 100% compliance with Section 2.3, this transition must be removed in Phase 2, enforcing `OFF -> ARMING -> ACTIVE`.
- **Persistence**: Currently volatile; needs atomic JSON disk writing to survive reboots.
