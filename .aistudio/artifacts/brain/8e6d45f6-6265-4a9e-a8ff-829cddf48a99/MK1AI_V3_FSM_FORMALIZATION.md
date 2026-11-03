# MK1Ai V3 FSM Formalization Report
## 7-State Safety Finite State Machine (FSM) Specification

**Status**: IMPLEMENTED (Audit Failed: Transition Violations Found)

### 1. V3 State Definitions

| State | Description | Integrity Level |
|---|---|---|
| **OFF** | Service stopped. No monitoring. | 0 |
| **ARMING** | Driver loading, Integrity checks, Policy sync. | 1 |
| **ACTIVE** | Normal Operation. 3-Head monitoring. | 2 |
| **EMERGENCY** | P0 detected. Kill Switch active. | 3 |
| **ISOLATED** | Air-Gap sealed. All paths blocked. | 4 |
| **RECOVERY_PENDING** | Recovery requested. Waiting for M-of-N. | 4 |
| **RECOVERY_APPROVED** | Quorum met. Preparing to restore. | 3 |

### 2. Valid Transition Matrix (Actual vs. Required)

| Source State | Target State | Implementation Status | Requirement Match |
|---|---|---|---|
| **OFF** | **ARMING** | VALID | YES |
| **OFF** | **ACTIVE** | VALID (Violation) | **NO (Bypass of ARMING)** |
| **ARMING** | **ACTIVE** | VALID | YES |
| **ACTIVE** | **EMERGENCY** | VALID | YES |
| **EMERGENCY** | **ISOLATED** | VALID | YES |
| **ISOLATED** | **RECOVERY_PENDING**| VALID | YES |
| **RECOVERY_PENDING**| **RECOVERY_APPROVED**| VALID | YES |
| **RECOVERY_APPROVED**| **ARMING** | **INVALID** | **YES (Required but missing)** |
| **RECOVERY_APPROVED**| **ACTIVE** | VALID | **NO (Should go via ARMING)** |

### 3. Verification Findings
- **Audit Issue #1**: `OFF -> ACTIVE` is explicitly allowed at line 461. This allows a "Quick Start" that skips the `ARMING` state's mandatory integrity checks (Success Criterion 7).
- **Audit Issue #2**: `RECOVERY_APPROVED -> ACTIVE` (line 467) bypasses `ARMING`. Recovery is a sensitive state and should re-trigger system arming to ensure no tampering occurred during isolation.

### 4. Transition Logic (e.g. Failure/Timeout)
The FSM is currently implemented as an in-memory `MK1SafetyStateMachine` class. 
- Any exception in `evaluate_threat_state` currently defaults to `FAIL_CLOSED` in the calling loop (SafetyExecutionLoop), but the FSM itself does not have a `FAIL_CLOSED` state; it relies on `EMERGENCY/ISOLATED`.

### 5. Remediation Plan
1. Revert `OFF -> ACTIVE` transition.
2. Update transition matrix to enforce `RECOVERY_APPROVED -> ARMING`.
3. Implement `_save_fsm_state()` to `/.ai_data/fsm_state.json`.
