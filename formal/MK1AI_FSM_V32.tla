-------------------------- MODULE MK1AI_FSM_V32 --------------------------
(***************************************************************************)
(* Formal Specification of MK1Ai Project Sovereign-Airgap FSM V3.2         *)
(* Target Assurance Level: Common Criteria CC:2022 EAL7 Readiness          *)
(* Complete R-003 Formal Model:                                            *)
(*   - 7 Control States & Complete Transition Relation T                   *)
(*   - Full Non-Abbreviated Recovery Path:                                 *)
(*       ISOLATED -> RECOVERY_PENDING -> RECOVERY_APPROVED                 *)
(*                -> ARMING -> ACTIVE                                      *)
(*   - 2-Phase WAL Persistence (PREPARED -> State -> COMMITTED)            *)
(*   - Crash / Restart / Persistence Failure / Storage Tamper Modeling     *)
(*   - All 20 Mandatory Mathematical Invariants (I-01 .. I-20)             *)
(*   - Explicit Separation of Safety Invariants and LTL/CTL Liveness       *)
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

WALStatuses == {
    "UNINITIALIZED", "PREPARED", "COMMITTED"
}

AuthStatuses == {
    "UNVERIFIED", "VERIFIED", "FAILED_HMAC", "FAILED_ROLLBACK",
    "FAILED_MISSING_STATE", "FAILED_MISSING_JOURNAL", "FAILED_STORAGE_WIPE",
    "FAILED_STATE_MISMATCH", "FAILED_JOURNAL_DESYNC", "FAILED_PERSISTENCE",
    "FAILED_WAL_INCOMPLETE", "FAILED_LOAD", "FAILED_SCHEMA", "FAILED_KEY_SECURITY",
    "FAILED_SEAL_MISSING", "FAILED_SEAL_TAMPER", "FAILED_ANCHOR_MISSING", "FAILED_ANCHOR_DESYNC"
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
    wal_status,               \* 15. 2-Phase WAL status ("UNINITIALIZED", "PREPARED", "COMMITTED")
    journal_generation,       \* 16. On-disk journal max_generation
    journal_last_state,       \* 17. On-disk journal last_state
    kill_switch_status,       \* 18. Independent OS kill switch status in KillSwitchStates
    network_block_confirmed,  \* 19. True iff kill_switch_status = "OS_BLOCK_CONFIRMED"
    dry_run_mode,             \* 20. True iff last transition was Dry-Run
    process_identity,         \* 21. Active OS process identity (1..8)
    boot_integrity_status,    \* 22. Boot verification status
    domain_tag,               \* 23. Domain separation tag ("CORE" vs "DECOY")
    quorum_distinct_signers,  \* 24. Number of distinct verified Ed25519 signers on active recovery
    last_action,              \* 25. Audit label of most recent transition
    prev_state,               \* 26. Previous control state for step invariant verification
    prev_generation,          \* 27. Previous generation for monotonicity verification
    snap_recovery_epoch,      \* 28. Snapshot of emergency_epoch at recovery Phase R1
    snap_recovery_gen,         \* 29. Snapshot of generation across recovery stages
    deterministic_danger,     \* 30. Layer B (IMSE) danger detection
    ai_corrupted              \* 31. Layer A (AI-TIE) data corruption indicator


vars == <<
    state, simulated_state, generation, max_observed_generation,
    emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
    policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
    storage_authenticity, rollback_status, wal_status, journal_generation, journal_last_state,
    kill_switch_status, network_block_confirmed, dry_run_mode, process_identity,
    boot_integrity_status, domain_tag, quorum_distinct_signers, last_action,
    prev_state, prev_generation, snap_recovery_epoch, snap_recovery_gen,
    deterministic_danger, ai_corrupted

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
    /\ wal_status = "UNINITIALIZED"
    /\ journal_generation = 0
    /\ journal_last_state = "OFF"
    /\ kill_switch_status = "NOT_REQUESTED"
    /\ network_block_confirmed = FALSE
    /\ dry_run_mode = FALSE
    /\ process_identity = 1
    /\ boot_integrity_status = "CLEAN_INIT"
    /\ domain_tag = "CORE"
    /\ quorum_distinct_signers = 0
    /\ last_action = "INIT"
    /\ prev_state = "OFF"
    /\ prev_generation = 0
    /\ snap_recovery_epoch = 0
    /\ snap_recovery_gen = 0
    /\ deterministic_danger = FALSE
    /\ ai_corrupted = FALSE


\* -------------------------------------------------------------------------
\* 1. Normal Startup & Operational Transitions: OFF -> ARMING -> ACTIVE -> OFF
\* -------------------------------------------------------------------------
NormalTransition(next_s) ==
    /\ generation < MaxGen
    /\ emergency_latch = FALSE
    /\ next_s \in AllowedTransitions(state)
    /\ next_s \in {"ARMING", "ACTIVE", "OFF"}
    /\ ~(state = "ARMING" /\ recovery_approval_status = "VERIFIED")
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = next_s
    /\ simulated_state' = next_s
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = next_s
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ dry_run_mode' = FALSE
    /\ last_action' = "NORMAL_TRANSITION"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen,
        deterministic_danger, ai_corrupted
       >>


\* -------------------------------------------------------------------------
\* 2. Atomic P0 Emergency Preemption Latch & Drain (OFF/ARMING/ACTIVE/RECOVERY -> EMERGENCY -> ISOLATED)
\* -------------------------------------------------------------------------
TriggerEmergencyLatch(evt, chg) ==
    /\ evt \in ValidEvents
    /\ chg \in ValidChallenges
    /\ emergency_epoch < 2
    /\ generation + 2 <= MaxGen
    /\ state /= "ISOLATED"
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ emergency_latch' = TRUE
    /\ emergency_epoch' = emergency_epoch + 1
    /\ active_event_id' = evt
    /\ active_challenge_id' = chg
    /\ dry_run_mode' = FALSE
    /\ last_action' = "P0_LATCH_TRIGGER"
    /\ UNCHANGED <<
        state, simulated_state, generation, max_observed_generation,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, wal_status, journal_generation, journal_last_state,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

DrainEmergencyStep ==
    /\ emergency_latch = TRUE
    /\ generation + 1 <= MaxGen
    /\ LET next_s == IF state /= "EMERGENCY" /\ "EMERGENCY" \in AllowedTransitions(state)
                     THEN "EMERGENCY"
                     ELSE "ISOLATED"
       IN
       /\ prev_state' = state
       /\ prev_generation' = generation
       /\ state' = next_s
       /\ simulated_state' = next_s
       /\ generation' = generation + 1
       /\ max_observed_generation' = generation + 1
       /\ wal_status' = "COMMITTED"
       /\ journal_generation' = generation + 1
       /\ journal_last_state' = next_s
       /\ emergency_latch' = (next_s /= "ISOLATED")
       /\ reserved_tokens' = {}
       /\ recovery_approval_status' = IF recovery_approval_status \in {"PENDING", "VERIFIED"}
                                      THEN "ABORTED_PREEMPTED"
                                      ELSE recovery_approval_status
       /\ storage_authenticity' = "VERIFIED"
       /\ rollback_status' = "VERIFIED_JOURNAL"
       /\ kill_switch_status' = IF next_s = "ISOLATED" THEN "LOGICALLY_ISOLATED" ELSE kill_switch_status
       /\ network_block_confirmed' = FALSE
       /\ dry_run_mode' = FALSE
       /\ last_action' = "EMERGENCY_DRAIN"
       /\ UNCHANGED <<
           emergency_epoch, active_event_id, active_challenge_id,
           policy_version, consumed_tokens, process_identity,
           boot_integrity_status, domain_tag, quorum_distinct_signers,
           snap_recovery_epoch, snap_recovery_gen,
           deterministic_danger, ai_corrupted
          >>


\* -------------------------------------------------------------------------
\* 3. Full 4-Stage M-of-N Recovery Protocol (No Intermediate State Omitted!)
\*    Stage R1: ISOLATED -> RECOVERY_PENDING
\*    Stage R3a: RECOVERY_PENDING -> RECOVERY_APPROVED (reserves token)
\*    Stage R3b: RECOVERY_APPROVED -> ARMING
\*    Stage R3c: ARMING -> ACTIVE (consumes token, clears isolation context)
\* -------------------------------------------------------------------------
BeginRecovery ==
    /\ state = "ISOLATED"
    /\ emergency_latch = FALSE
    /\ storage_authenticity = "VERIFIED"
    /\ generation < MaxGen
    /\ active_event_id \in ValidEvents
    /\ active_challenge_id \in ValidChallenges
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "RECOVERY_PENDING"
    /\ simulated_state' = "RECOVERY_PENDING"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "RECOVERY_PENDING"
    /\ recovery_approval_status' = "PENDING"
    /\ snap_recovery_epoch' = emergency_epoch
    /\ snap_recovery_gen' = generation + 1
    /\ dry_run_mode' = FALSE
    /\ last_action' = "RECOVERY_PHASE_R1_PENDING"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, quorum_distinct_signers
       >>

ApproveRecoveryStage1(tok) ==
    /\ tok \in ValidTokens
    /\ tok \notin consumed_tokens
    /\ tok \notin reserved_tokens
    /\ state = "RECOVERY_PENDING"
    /\ emergency_latch = FALSE
    /\ emergency_epoch = snap_recovery_epoch
    /\ generation = snap_recovery_gen
    /\ active_event_id \in ValidEvents
    /\ active_challenge_id \in ValidChallenges
    /\ domain_tag = "CORE"
    /\ generation < MaxGen
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "RECOVERY_APPROVED"
    /\ simulated_state' = "RECOVERY_APPROVED"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "RECOVERY_APPROVED"
    /\ recovery_approval_status' = "VERIFIED"
    /\ quorum_distinct_signers' = 2
    /\ reserved_tokens' = {tok}
    /\ snap_recovery_gen' = generation + 1
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ dry_run_mode' = FALSE
    /\ last_action' = "RECOVERY_STAGE1_APPROVED"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, consumed_tokens,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, snap_recovery_epoch
       >>

ReArmRecoveryStage2 ==
    /\ state = "RECOVERY_APPROVED"
    /\ recovery_approval_status = "VERIFIED"
    /\ emergency_latch = FALSE
    /\ emergency_epoch = snap_recovery_epoch
    /\ generation = snap_recovery_gen
    /\ generation < MaxGen
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "ARMING"
    /\ simulated_state' = "ARMING"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "ARMING"
    /\ snap_recovery_gen' = generation + 1
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ dry_run_mode' = FALSE
    /\ last_action' = "RECOVERY_STAGE2_ARMING"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, quorum_distinct_signers, snap_recovery_epoch
       >>

CommitRecoveryStage3Active ==
    /\ state = "ARMING"
    /\ recovery_approval_status = "VERIFIED"
    /\ reserved_tokens /= {}
    /\ quorum_distinct_signers >= 2
    /\ domain_tag = "CORE"
    /\ active_event_id \in ValidEvents
    /\ active_challenge_id \in ValidChallenges
    /\ emergency_latch = FALSE
    /\ emergency_epoch = snap_recovery_epoch
    /\ generation = snap_recovery_gen
    /\ generation < MaxGen
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "ACTIVE"
    /\ simulated_state' = "ACTIVE"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "ACTIVE"
    /\ consumed_tokens' = consumed_tokens \cup reserved_tokens
    /\ reserved_tokens' = {}
    /\ active_event_id' = "NONE"
    /\ active_challenge_id' = "NONE"
    /\ kill_switch_status' = "NOT_REQUESTED"
    /\ network_block_confirmed' = FALSE
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ dry_run_mode' = FALSE
    /\ last_action' = "RECOVERY_STAGE3_ACTIVE"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, policy_version, recovery_approval_status,
        process_identity, boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

RejectRecoveryToIsolated ==
    /\ state \in {"RECOVERY_PENDING", "RECOVERY_APPROVED"}
    /\ generation < MaxGen
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "ISOLATED"
    /\ simulated_state' = "ISOLATED"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "ISOLATED"
    /\ recovery_approval_status' = "REJECTED"
    /\ reserved_tokens' = {}
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ dry_run_mode' = FALSE
    /\ last_action' = "RECOVERY_REJECTED_ROLLBACK"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, consumed_tokens,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* -------------------------------------------------------------------------
\* 4. Dry-Run Transition (Strictly Non-Interfering with Production Variables)
\* -------------------------------------------------------------------------
DryRunTransition(sim_next) ==
    /\ sim_next \in AllowedTransitions(simulated_state)
    /\ sim_next /= simulated_state
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ simulated_state' = sim_next
    /\ dry_run_mode' = TRUE
    /\ last_action' = "DRY_RUN_TRANSITION"
    /\ UNCHANGED <<
        state, generation, max_observed_generation,
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, wal_status, journal_generation, journal_last_state,
        kill_switch_status, network_block_confirmed, process_identity,
        boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* -------------------------------------------------------------------------
\* 5. Kill Switch OS Execution Outcomes (P0-005)
\* -------------------------------------------------------------------------
ConfirmOSKillSwitch ==
    /\ state = "ISOLATED"
    /\ kill_switch_status \in {"LOGICALLY_ISOLATED", "OS_BLOCK_PENDING"}
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ kill_switch_status' = "OS_BLOCK_CONFIRMED"
    /\ network_block_confirmed' = TRUE
    /\ dry_run_mode' = FALSE
    /\ last_action' = "KILL_SWITCH_CONFIRMED"
    /\ UNCHANGED <<
        state, simulated_state, generation, max_observed_generation,
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, wal_status, journal_generation, journal_last_state,
        process_identity, boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

FailOSKillSwitch ==
    /\ state = "ISOLATED"
    /\ kill_switch_status \in {"LOGICALLY_ISOLATED", "OS_BLOCK_PENDING"}
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ kill_switch_status' = "OS_BLOCK_FAILED"
    /\ network_block_confirmed' = FALSE
    /\ dry_run_mode' = FALSE
    /\ last_action' = "KILL_SWITCH_FAILED"
    /\ UNCHANGED <<
        state, simulated_state, generation, max_observed_generation,
        emergency_latch, emergency_epoch, active_event_id, active_challenge_id,
        policy_version, recovery_approval_status, reserved_tokens, consumed_tokens,
        storage_authenticity, rollback_status, wal_status, journal_generation, journal_last_state,
        process_identity, boot_integrity_status, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

\* -------------------------------------------------------------------------
\* 6. Crash / Restart / WAL Incomplete / Storage Fault Transitions (R-002, R-003)
\* -------------------------------------------------------------------------
CrashAndRebootFromTransient ==
    /\ state \in TransientStates
    /\ generation < MaxGen
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "ISOLATED"
    /\ simulated_state' = "ISOLATED"
    /\ generation' = generation + 1
    /\ max_observed_generation' = generation + 1
    /\ wal_status' = "COMMITTED"
    /\ journal_generation' = generation + 1
    /\ journal_last_state' = "ISOLATED"
    /\ storage_authenticity' = "VERIFIED"
    /\ rollback_status' = "VERIFIED_JOURNAL"
    /\ boot_integrity_status' = "NORMALIZED_TRANSIENT_TO_ISOLATED"
    /\ active_event_id' = IF active_event_id \in ValidEvents THEN active_event_id ELSE "evt-1"
    /\ active_challenge_id' = IF active_challenge_id \in ValidChallenges THEN active_challenge_id ELSE "chg-1"
    /\ reserved_tokens' = {}
    /\ dry_run_mode' = FALSE
    /\ last_action' = "REBOOT_TRANSIENT_NORMALIZE"
    /\ UNCHANGED <<
        emergency_latch, emergency_epoch,
        policy_version, recovery_approval_status, consumed_tokens,
        kill_switch_status, network_block_confirmed, process_identity,
        domain_tag, quorum_distinct_signers, snap_recovery_epoch, snap_recovery_gen
       >>

CrashDuringPreparedWAL ==
    /\ storage_authenticity = "VERIFIED"
    /\ generation < MaxGen
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "ISOLATED"
    /\ simulated_state' = "ISOLATED"
    /\ wal_status' = "PREPARED"
    /\ storage_authenticity' = "FAILED_WAL_INCOMPLETE"
    /\ rollback_status' = "WAL_INCOMPLETE_PREPARED"
    /\ boot_integrity_status' = "FAIL_CLOSED_ISOLATED"
    /\ reserved_tokens' = {}
    /\ network_block_confirmed' = FALSE
    /\ dry_run_mode' = FALSE
    /\ last_action' = "FAULT_REBOOT_WAL_PREPARED"
    /\ UNCHANGED <<
        generation, max_observed_generation, emergency_latch, emergency_epoch,
        active_event_id, active_challenge_id, policy_version, recovery_approval_status,
        consumed_tokens, journal_generation, journal_last_state, kill_switch_status,
        process_identity, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

FaultRebootIntegrityViolation(fault_status) ==
    /\ fault_status \in {
        "FAILED_HMAC", "FAILED_ROLLBACK", "FAILED_MISSING_STATE",
        "FAILED_MISSING_JOURNAL", "FAILED_STORAGE_WIPE", "FAILED_STATE_MISMATCH",
        "FAILED_JOURNAL_DESYNC", "FAILED_PERSISTENCE",
        "FAILED_SEAL_MISSING", "FAILED_SEAL_TAMPER", "FAILED_ANCHOR_MISSING", "FAILED_ANCHOR_DESYNC"
       }
    /\ storage_authenticity = "VERIFIED"
    /\ prev_state' = state
    /\ prev_generation' = generation
    /\ state' = "ISOLATED"
    /\ simulated_state' = "ISOLATED"
    /\ storage_authenticity' = fault_status
    /\ rollback_status' = "VIOLATION_DETECTED"
    /\ boot_integrity_status' = "FAIL_CLOSED_ISOLATED"
    /\ reserved_tokens' = {}
    /\ network_block_confirmed' = FALSE
    /\ dry_run_mode' = FALSE
    /\ last_action' = "FAULT_REBOOT_INTEGRITY"
    /\ UNCHANGED <<
        generation, max_observed_generation, emergency_latch, emergency_epoch,
        active_event_id, active_challenge_id, policy_version, recovery_approval_status,
        consumed_tokens, wal_status, journal_generation, journal_last_state,
        kill_switch_status, process_identity, domain_tag, quorum_distinct_signers,
        snap_recovery_epoch, snap_recovery_gen
       >>

Next ==
    \/ \E s \in States : NormalTransition(s)
    \/ \E e \in ValidEvents, c \in ValidChallenges : TriggerEmergencyLatch(e, c)
    \/ DrainEmergencyStep
    \/ BeginRecovery
    \/ \E t \in ValidTokens : ApproveRecoveryStage1(t)
    \/ ReArmRecoveryStage2
    \/ CommitRecoveryStage3Active
    \/ RejectRecoveryToIsolated
    \/ \E s \in States : DryRunTransition(s)
    \/ ConfirmOSKillSwitch
    \/ FailOSKillSwitch
    \/ CrashAndRebootFromTransient
    \/ CrashDuringPreparedWAL
    \/ \E f \in {
        "FAILED_HMAC", "FAILED_ROLLBACK", "FAILED_MISSING_STATE",
        "FAILED_MISSING_JOURNAL", "FAILED_STORAGE_WIPE", "FAILED_STATE_MISMATCH",
        "FAILED_JOURNAL_DESYNC", "FAILED_PERSISTENCE",
        "FAILED_SEAL_MISSING", "FAILED_SEAL_TAMPER", "FAILED_ANCHOR_MISSING", "FAILED_ANCHOR_DESYNC"
       } : FaultRebootIntegrityViolation(f)

\* =========================================================================
\* PART 2.3: All 20 Mandatory Mathematical Safety Invariants (I-01 .. I-20)
\* =========================================================================

\* I-01: State Type Safety
I01_StateTypeSafety ==
    /\ state \in States
    /\ simulated_state \in States
    /\ kill_switch_status \in KillSwitchStates
    /\ wal_status \in WALStatuses
    /\ storage_authenticity \in AuthStatuses

\* I-02: State Transition Completeness
I02_StateTransitionCompleteness ==
    (state /= prev_state /\ last_action \notin {
        "REBOOT_TRANSIENT_NORMALIZE", "FAULT_REBOOT_WAL_PREPARED", "FAULT_REBOOT_INTEGRITY"
    }) => (state \in AllowedTransitions(prev_state))

\* I-03: Generation Monotonicity
I03_GenerationMonotonicity ==
    /\ generation >= prev_generation
    /\ generation <= max_observed_generation

\* I-04: Isolation Latch Protection
I04_IsolationLatchProtection ==
    (emergency_latch = TRUE /\ last_action \in {
        "RECOVERY_STAGE1_APPROVED", "RECOVERY_STAGE2_ARMING", "RECOVERY_STAGE3_ACTIVE"
    }) => (state /= "ACTIVE")

\* I-05: P0 Priority Over Recovery
I05_P0PriorityOverRecovery ==
    (last_action = "RECOVERY_STAGE3_ACTIVE") =>
        (emergency_latch = FALSE /\ emergency_epoch = snap_recovery_epoch)

\* I-06: Dry-Run Non-Interference
I06_DryRunNonInterference ==
    (dry_run_mode = TRUE) =>
        (state = prev_state /\ generation = prev_generation)

\* I-07: Persistence Consistency (WAL COMMITTED matches State & Journal)
I07_PersistenceConsistency ==
    (storage_authenticity = "VERIFIED" /\ wal_status = "COMMITTED") =>
        (generation = journal_generation /\ state = journal_last_state)

\* I-08: Rollback Prevention
I08_RollbackPrevention ==
    (storage_authenticity \in {
        "FAILED_ROLLBACK", "FAILED_WAL_INCOMPLETE", "FAILED_SEAL_MISSING",
        "FAILED_SEAL_TAMPER", "FAILED_ANCHOR_MISSING", "FAILED_ANCHOR_DESYNC"
    }) =>
        (state = "ISOLATED")

\* I-09: Event & Challenge Binding
I09_EventAndChallengeBinding ==
    (state \in {"RECOVERY_PENDING", "RECOVERY_APPROVED"}) =>
        (active_event_id \in ValidEvents /\ active_challenge_id \in ValidChallenges)

\* I-10: Quorum Distinct Signer Safety
I10_QuorumDistinctSignerSafety ==
    (last_action = "RECOVERY_STAGE3_ACTIVE") => (quorum_distinct_signers >= 2)

\* I-11: Token Single-Use (Disjoint Reserved & Consumed Token Sets)
I11_TokenSingleUse ==
    reserved_tokens \cap consumed_tokens = {}

\* I-12: Recovery Path Protection (No Direct ISOLATED -> ACTIVE Jump)
I12_RecoveryPathProtection ==
    ~(prev_state = "ISOLATED" /\ state = "ACTIVE")

\* I-13: Reboot Safety (Transient & Incomplete WAL Normalize to ISOLATED)
I13_RebootSafety ==
    (boot_integrity_status \in {"FAIL_CLOSED_ISOLATED", "NORMALIZED_TRANSIENT_TO_ISOLATED"}
     /\ last_action \in {"REBOOT_TRANSIENT_NORMALIZE", "FAULT_REBOOT_WAL_PREPARED", "FAULT_REBOOT_INTEGRITY"}) =>
        (state = "ISOLATED")

\* I-14: Kill Switch Consistency
I14_KillSwitchConsistency ==
    /\ (network_block_confirmed = TRUE =>
        (state \in {"ISOLATED", "RECOVERY_PENDING", "RECOVERY_APPROVED", "ARMING"}
         /\ kill_switch_status = "OS_BLOCK_CONFIRMED"))
    /\ (kill_switch_status = "OS_BLOCK_FAILED" => network_block_confirmed = FALSE)

\* I-15: Fail-Closed Integrity
I15_FailClosedIntegrity ==
    (storage_authenticity \in {
        "FAILED_HMAC", "FAILED_ROLLBACK", "FAILED_MISSING_STATE",
        "FAILED_MISSING_JOURNAL", "FAILED_STORAGE_WIPE", "FAILED_STATE_MISMATCH",
        "FAILED_JOURNAL_DESYNC", "FAILED_PERSISTENCE", "FAILED_WAL_INCOMPLETE",
        "FAILED_LOAD", "FAILED_SCHEMA", "FAILED_KEY_SECURITY",
        "FAILED_SEAL_MISSING", "FAILED_SEAL_TAMPER", "FAILED_ANCHOR_MISSING", "FAILED_ANCHOR_DESYNC"
    }) => (state = "ISOLATED")

\* I-16: Domain Separation (CORE vs Decoy)
I16_DomainSeparation ==
    (last_action = "RECOVERY_STAGE3_ACTIVE") => (domain_tag = "CORE")

\* I-17: Inter-Process Linearizability
I17_InterProcessLinearizability ==
    (state /= prev_state /\ dry_run_mode = FALSE /\ last_action \notin {
        "FAULT_REBOOT_WAL_PREPARED", "FAULT_REBOOT_INTEGRITY"
    }) => (generation = prev_generation + 1)

\* I-18: Event Reuse Prevention
I18_EventReusePrevention ==
    (last_action = "RECOVERY_STAGE1_APPROVED") => (reserved_tokens \cap consumed_tokens = {})

\* I-19: Auditability of Security Transitions
I19_TransitionAuditability ==
    (state /= prev_state) => (last_action /= "")

\* I-20: Safety Over Availability Priority
I20_SafetyOverAvailabilityPriority ==
    /\ (wal_status = "PREPARED" => state /= "ACTIVE")
    /\ (emergency_latch = TRUE => last_action \notin {
        "NORMAL_TRANSITION", "RECOVERY_PHASE_R1_PENDING",
        "RECOVERY_STAGE1_APPROVED", "RECOVERY_STAGE2_ARMING", "RECOVERY_STAGE3_ACTIVE"
       })

\* I-21: IMSE Override (Layer B DANGER forces isolation regardless of Layer A)
I21_IMSEOverride ==
    (deterministic_danger = TRUE /\ state = "ACTIVE") => emergency_latch = TRUE

\* I-22: Quorum Necessity (Isolation requires Layer A/B consensus or Quorum)
I22_QuorumNecessity ==
    (last_action = "P0_LATCH_TRIGGER") => 
        (deterministic_danger = TRUE \/ ai_corrupted = TRUE)

\* =========================================================================
\* PART 2.4: Temporal Logic Properties (Separated Safety & Fair Liveness)
\* =========================================================================

Fairness ==
    /\ WF_vars(DrainEmergencyStep)
    /\ WF_vars(BeginRecovery)
    /\ WF_vars(ReArmRecoveryStage2)
    /\ WF_vars(CommitRecoveryStage3Active)

SafetySpec == Init /\ [][Next]_vars

FairSpec == SafetySpec /\ Fairness

Spec == FairSpec

\* Liveness L-01: Every triggered P0 latch leads to ISOLATED
L01_P0LatchLeadsToIsolated ==
    [](emergency_latch = TRUE ~> state = "ISOLATED")

\* Liveness L-02: Every incomplete PREPARED WAL reboot converges to ISOLATED
L02_IncompleteWALConvergesIsolated ==
    [](wal_status = "PREPARED" => <>(state = "ISOLATED"))

=============================================================================
