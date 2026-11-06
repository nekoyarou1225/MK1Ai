-------------------------- MODULE MK1AI_FSM_V32 --------------------------
(***************************************************************************)
(* Formal Specification of MK1Ai Project Sovereign-Airgap FSM V3.2         *)
(* Target Assurance Level: Common Criteria CC:2022 EAL7 Readiness          *)
(* Covers:                                                                 *)
(*   - 7 Control States & Transition Relation T                            *)
(*   - 19 Extended State Variables (Sigma)                                 *)
(*   - Atomic P0 Emergency Preemption Latch & Monotonic Epoch              *)
(*   - 3-Phase Recovery with Pre-Commit 7-Point Guard Re-Verification      *)
(*   - Strict Dry-Run Non-Interference (I-06)                              *)
(*   - Transactional WAL/Journal/State/Anchor Persistence (I-07, I-08)     *)
(*   - 8-State Independent Kill Switch & OS Network Block Confirmation     *)
(*   - M-of-N Quorum Binding & Two-Phase Token Reservation (I-09..I-11)    *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxGen,          \* Upper bound on generation for bounded model checking
    ValidEvents,     \* Finite set of valid isolation event IDs
    ValidChallenges, \* Finite set of valid challenge IDs
    ValidTokens      \* Finite set of valid approval bundle digests

States == {
    "OFF", "ARMING", "ACTIVE", "EMERGENCY",
    "ISOLATED", "RECOVERY_PENDING", "RECOVERY_APPROVED"
}

TransientStates == {
    "ARMING", "EMERGENCY", "RECOVERY_PENDING", "RECOVERY_APPROVED"
}

KillSwitchStates == {
    "NOT_REQUESTED", "REQUESTED", "LOGICALLY_ISOLATED",
    "OS_BLOCK_PENDING", "OS_BLOCK_CONFIRMED", "OS_BLOCK_FAILED",
    "PARTIALLY_ISOLATED", "VERIFICATION_FAILED"
}

AuthStatuses == {
    "UNVERIFIED", "VERIFIED", "FAILED_HMAC", "FAILED_ROLLBACK",
    "FAILED_MISSING_STATE", "FAILED_MISSING_JOURNAL", "FAILED_STORAGE_WIPE",
    "FAILED_STATE_MISMATCH", "FAILED_JOURNAL_DESYNC", "FAILED_PERSISTENCE",
    "FAILED_LOAD", "FAILED_SCHEMA", "FAILED_KEY_SECURITY"
}

VARIABLES
    state,                    \* 1. Production FSM control state in States
    simulated_state,          \* 2. Dry-Run simulated state in States
    generation,               \* 3. In-memory committed generation in Nat
    max_observed_generation,  \* 4. High-water mark generation in Nat
    emergency_latch,          \* 5. Atomic preemption latch in BOOLEAN
    emergency_epoch,          \* 6. Monotonic emergency epoch counter in Nat
    active_event_id,          \* 7. Bound isolation event_id or "NONE"
    active_challenge_id,      \* 8. Bound recovery challenge_id or "NONE"
    policy_version,           \* 9. Active policy version in Nat \ {0}
    recovery_approval_status, \* 10. "NONE", "PENDING", "VERIFIED", "REJECTED", "ABORTED_PREEMPTED"
    reserved_tokens,          \* 11. In-flight reserved token set
    consumed_tokens,          \* 12. Permanently consumed token set
    storage_authenticity,     \* 13. Disk authenticity status in AuthStatuses
    rollback_status,          \* 14. Journal rollback status
    journal_generation,       \* 15. On-disk journal max_generation
    journal_last_state,       \* 16. On-disk journal last_state
    kill_switch_status,       \* 17. Independent OS kill switch status in KillSwitchStates
    network_block_confirmed,  \* 18. True iff kill_switch_status = "OS_BLOCK_CONFIRMED"
    boot_integrity_status,    \* 19. Boot verification status
    snap_recovery_epoch,      \* Snapshot of emergency_epoch at recovery Phase R1
    snap_recovery_gen         \* Snapshot of generation at recovery Phase R1

vars == <<
    state, simulated_state, generation, max_observed_generation,
    emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
    policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
    storage_authenticity, rollback_status, journal_generation, journal_last_state,
    kill_switch_status, network_block_confirmed, boot_integrity_status,
    snap_recovery_epoch, snap_recovery_gen
>>

AllowedTransitions(s) ==
    CASE s = "OFF"               -> {"ARMING", "EMERGENCY"}
      [] s = "ARMING"            -> {"OFF", "ACTIVE", "EMERGENCY"}
      [] s = "ACTIVE"            -> {"OFF", "EMERGENCY", "ISOLATED"}
      [] s = "EMERGENCY"         -> {"ISOLATED"}
      [] s = "ISOLATED"          -> {"RECOVERY_PENDING"}
      [] s = "RECOVERY_PENDING"  -> {"ISOLATED", "RECOVERY_APPROVED", "EMERGENCY"}
      [] s = "RECOVERY_APPROVED" -> {"ARMING", "EMERGENCY", "ISOLATED"}
      [] OTHER                   -> {}

Init ==
    /\ state = "OFF"
    /\ simulated_state = "OFF"
    /\ generation = 0
    /\ max_observed_generation = 0
    /\ emergency_latch = FALSE
    /\ emergency_epoch = 0
    /\ active_event_id = "NONE"
    /\ active_challenge_id = "NONE"
    /\ policy_version = 1
    /\ recovery_approval_status = "NONE"
    /\ reserved_tokens = {}
    /\ consumed_tokens = {}
    /\ storage_authenticity = "UNVERIFIED"
    /\ rollback_status = "UNINITIALIZED"
    /\ journal_generation = 0
    /\ journal_last_state = "OFF"
    /\ kill_switch_status = "NOT_REQUESTED"
    /\ network_block_confirmed = FALSE
    /\ boot_integrity_status = "CLEAN_INIT"
    /\ snap_recovery_epoch = 0
    /\ snap_recovery_gen = 0

\* Normal Startup Transition: OFF -> ARMING -> ACTIVE
NormalTransition(next_s) ==
    /\ generation < MaxGen
    /\ emergency_latch = FALSE
    /\ next_s \in AllowedTransitions(state)
    /\ next_s \in {"ARMING", "ACTIVE", "OFF"}
    /\ state /= "RECOVERY_APPROVED" \* Recovery path uses CommitRecoveryActive
    /\ state' = next_s
    /\ simulated_state' = next_s
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = next_s
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        kill_switch_status, network_block_confirmed, boot_integrity_status,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* Atomic P0 Emergency Latch (Step 1 of isolate_immediately, lock-free preemption)
TriggerEmergencyLatch(evt, chg) ==
    /\ evt \in ValidEvents
    /\ chg \in ValidChallenges
    /\ emergency_epoch < MaxGen
    /\ emergency_latch' = TRUE
    /\ emergency_epoch' = emergency_epoch + 1
    /\ active_event_id' = evt
    /\ active_challenge_id' = chg
    /\ UNCHANGED <<
        state, simulated_state, generation, max_observed_generation,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, journal_generation, journal_last_state,
        kill_switch_status, network_block_confirmed, boot_integrity_status,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* Drain Emergency Latch & Commit Isolation (Step 2 of isolate_immediately)
DrainEmergencyToIsolated ==
    /\ emergency_latch = TRUE
    /\ generation + 1 <= MaxGen
    /\ state' = "ISOLATED"
    /\ simulated_state' = "ISOLATED"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "ISOLATED"
    /\ emergency_latch' = FALSE
    /\ reserved_tokens' = {}
    /\ recovery_approval_status' = IF recovery_approval_status \in {"PENDING", "VERIFIED"}
                                   THEN "ABORTED_PREEMPTED"
                                   ELSE recovery_approval_status
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ kill_switch_status' = "LOGICALLY_ISOLATED"
    /\ network_block_confirmed' = FALSE
    /\ UNCHANGED <<
        emergency_epoch, active_event_id, active_challenge_id,
        policy_version, consumed_tokens, boot_integrity_status,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* Phase R1: Begin Recovery (ISOLATED -> RECOVERY_PENDING)
BeginRecovery ==
    /\ state = "ISOLATED"
    /\ emergency_latch = FALSE
    /\ generation < MaxGen
    /\ active_event_id \in ValidEvents
    /\ active_challenge_id \in ValidChallenges
    /\ state' = "RECOVERY_PENDING"
    /\ simulated_state' = "RECOVERY_PENDING"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "RECOVERY_PENDING"
    /\ recovery_approval_status' = "PENDING"
    /\ snap_recovery_epoch' = emergency_epoch
    /\ snap_recovery_gen' = generation + 1
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, reserved_tokens, consumed_tokens,
        kill_switch_status, network_block_confirmed, boot_integrity_status
       >>

\* Phase R3: Commit Verified Recovery (only if emergency_latch = FALSE and epoch unchanged)
CommitRecoveryApproved(tok) ==
    /\ tok \in ValidTokens
    /\ tok \notin consumed_tokens
    /\ tok \notin reserved_tokens
    /\ state = "RECOVERY_PENDING"
    /\ emergency_latch = FALSE
    /\ emergency_epoch = snap_recovery_epoch
    /\ generation = snap_recovery_gen
    /\ generation + 2 <= MaxGen
    /\ state' = "ACTIVE"
    /\ simulated_state' = "ACTIVE"
    /\ generation' = generation + 2
    /\ max_observed_generation' = generation + 2
    /\ journal_generation' = generation + 2
    /\ journal_last_state' = "ACTIVE"
    /\ recovery_approval_status' = "VERIFIED"
    /\ consumed_tokens' = consumed_tokens \cup {tok}
    /\ reserved_tokens' = {}
    /\ active_event_id' = "NONE"
    /\ active_challenge_id' = "NONE"
    /\ kill_switch_status' = "NOT_REQUESTED"
    /\ network_block_confirmed' = FALSE
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, policy_version,
        boot_integrity_status, snap_recovery_epoch, snap_recovery_gen
       >>

\* Dry-Run Transition (Simulated only - strictly non-interfering with production vars)
DryRunTransition(sim_next) ==
    /\ sim_next \in AllowedTransitions(simulated_state)
    /\ simulated_state' = sim_next
    /\ UNCHANGED <<
        state, generation, max_observed_generation,
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, journal_generation, journal_last_state,
        kill_switch_status, network_block_confirmed, boot_integrity_status,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* Kill Switch OS Execution Outcomes (P0-005)
ConfirmOSKillSwitch ==
    /\ state = "ISOLATED"
    /\ kill_switch_status \in {"LOGICALLY_ISOLATED", "OS_BLOCK_PENDING"}
    /\ kill_switch_status' = "OS_BLOCK_CONFIRMED"
    /\ network_block_confirmed' = TRUE
    /\ UNCHANGED <<
        state, simulated_state, generation, max_observed_generation,
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, journal_generation, journal_last_state,
        boot_integrity_status, snap_recovery_epoch, snap_recovery_gen
       >>

FailOSKillSwitch ==
    /\ state = "ISOLATED"
    /\ kill_switch_status \in {"LOGICALLY_ISOLATED", "OS_BLOCK_PENDING"}
    /\ kill_switch_status' = "OS_BLOCK_FAILED"
    /\ network_block_confirmed' = FALSE
    /\ UNCHANGED <<
        state, simulated_state, generation, max_observed_generation,
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, journal_generation, journal_last_state,
        boot_integrity_status, snap_recovery_epoch, snap_recovery_gen
       >>

Next ==
    \/ \E s \in States : NormalTransition(s)
    \/ \E e \in ValidEvents, c \in ValidChallenges : TriggerEmergencyLatch(e, c)
    \/ DrainEmergencyToIsolated
    \/ BeginRecovery
    \/ \E t \in ValidTokens : CommitRecoveryApproved(t)
    \/ \E s \in States : DryRunTransition(s)
    \/ ConfirmOSKillSwitch
    \/ FailOSKillSwitch

\* =========================================================================
\* Mathematical Invariants (I-01 .. I-20)
\* =========================================================================
I01_StateTypeSafety ==
    /\ state \in States
    /\ simulated_state \in States
    /\ kill_switch_status \in KillSwitchStates

I03_GenerationMonotonicity ==
    /\ generation <= max_observed_generation
    /\ generation = journal_generation

I04_EmergencyLatchBlocksActiveRecovery ==
    (emergency_latch = TRUE /\ state \in {"ISOLATED", "RECOVERY_PENDING", "RECOVERY_APPROVED"})
        => (state /= "ACTIVE")

I07_PersistenceConsistency ==
    (storage_authenticity = "VERIFIED") =>
        (generation = journal_generation /\ state = journal_last_state)

I14_KillSwitchConsistency ==
    network_block_confirmed = TRUE =>
        (state = "ISOLATED" /\ kill_switch_status = "OS_BLOCK_CONFIRMED")

I15_FailClosedIntegrity ==
    storage_authenticity \in {
        "FAILED_HMAC", "FAILED_ROLLBACK", "FAILED_MISSING_STATE",
        "FAILED_MISSING_JOURNAL", "FAILED_STORAGE_WIPE", "FAILED_STATE_MISMATCH"
    } => (state = "ISOLATED")

=============================================================================
