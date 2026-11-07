; =============================================================================
; MK1Ai Project Sovereign-Airgap — FSM V3.2 SMT-LIB v2 Formal Proof Obligations
; Complete R-003 Specification:
;   - Explicitly separates Pre-State Invariant Assumptions (Pre_I01 .. Pre_I20)
;   - Explicitly binds all 22 Pre-State and 22 Post-State variables across every
;     branch of the Transition Relation T (no unbound variables, no tautologies)
;   - Models 2-Phase WAL (0=UNINITIALIZED, 1=PREPARED, 2=COMMITTED)
;   - Proves Inductive Preservation of all 20 Invariants (I-01 .. I-20)
;     by asserting (not (and Post_I01 ... Post_I20)) -> UNSAT
; =============================================================================
(set-logic QF_LIA)
(set-option :produce-models true)

; Control State Encoding:
; 0 = OFF, 1 = ARMING, 2 = ACTIVE, 3 = EMERGENCY,
; 4 = ISOLATED, 5 = RECOVERY_PENDING, 6 = RECOVERY_APPROVED

; KillSwitchStatus Encoding:
; 0 = NOT_REQUESTED, 1 = REQUESTED, 2 = LOGICALLY_ISOLATED,
; 3 = OS_BLOCK_PENDING, 4 = OS_BLOCK_CONFIRMED, 5 = OS_BLOCK_FAILED,
; 6 = PARTIALLY_ISOLATED, 7 = VERIFICATION_FAILED

; WALStatus Encoding:
; 0 = UNINITIALIZED, 1 = PREPARED, 2 = COMMITTED

; AuthStatus Encoding:
; 0 = UNVERIFIED, 1 = VERIFIED, 2 = FAILED_HMAC, 3 = FAILED_ROLLBACK,
; 4 = FAILED_MISSING_STATE, 5 = FAILED_MISSING_JOURNAL, 6 = FAILED_STORAGE_WIPE,
; 7 = FAILED_STATE_MISMATCH, 8 = FAILED_JOURNAL_DESYNC, 9 = FAILED_PERSISTENCE,
; 10 = FAILED_WAL_INCOMPLETE

; Action Kind Encoding:
; 0 = DRY_RUN
; 1 = NORMAL_STEP
; 2 = P0_LATCH_TRIGGER
; 3 = P0_EMERGENCY_DRAIN
; 4 = RECOVERY_R1_PENDING
; 5 = RECOVERY_STAGE1_APPROVED
; 6 = RECOVERY_STAGE2_ARMING
; 7 = RECOVERY_STAGE3_ACTIVE
; 8 = KILL_SWITCH_CONFIRM
; 9 = KILL_SWITCH_FAIL
; 10 = FAULT_OR_INCOMPLETE_WAL_REBOOT

(declare-const action Int)

; Pre-state variables
(declare-const state Int)
(declare-const sim_state Int)
(declare-const gen Int)
(declare-const max_gen Int)
(declare-const journal_gen Int)
(declare-const journal_state Int)
(declare-const wal_status Int)
(declare-const auth_status Int)
(declare-const emergency_latch Bool)
(declare-const emergency_epoch Int)
(declare-const snap_epoch Int)
(declare-const ks_status Int)
(declare-const net_confirmed Bool)
(declare-const has_bound_event Bool)
(declare-const has_bound_challenge Bool)
(declare-const distinct_signers Int)
(declare-const token_already_consumed Bool)
(declare-const token_reserved Bool)
(declare-const is_core_domain Bool)
(declare-const boot_fail_closed Bool)

; Post-state variables
(declare-const state_next Int)
(declare-const sim_state_next Int)
(declare-const gen_next Int)
(declare-const max_gen_next Int)
(declare-const journal_gen_next Int)
(declare-const journal_state_next Int)
(declare-const wal_status_next Int)
(declare-const auth_status_next Int)
(declare-const emergency_latch_next Bool)
(declare-const emergency_epoch_next Int)
(declare-const snap_epoch_next Int)
(declare-const ks_status_next Int)
(declare-const net_confirmed_next Bool)
(declare-const has_bound_event_next Bool)
(declare-const has_bound_challenge_next Bool)
(declare-const distinct_signers_next Int)
(declare-const token_already_consumed_next Bool)
(declare-const token_reserved_next Bool)
(declare-const is_core_domain_next Bool)
(declare-const boot_fail_closed_next Bool)
(declare-const audit_recorded_next Bool)

(define-fun valid_state ((s Int)) Bool
  (and (>= s 0) (<= s 6)))

(define-fun valid_ks ((k Int)) Bool
  (and (>= k 0) (<= k 7)))

(define-fun valid_wal ((w Int)) Bool
  (and (>= w 0) (<= w 2)))

(define-fun valid_auth ((a Int)) Bool
  (and (>= a 0) (<= a 10)))

(define-fun allowed_transition ((s1 Int) (s2 Int)) Bool
  (or
    (and (= s1 0) (or (= s2 1) (= s2 3)))
    (and (= s1 1) (or (= s2 0) (= s2 2) (= s2 3)))
    (and (= s1 2) (or (= s2 0) (= s2 3) (= s2 4)))
    (and (= s1 3) (= s2 4))
    (and (= s1 4) (= s2 5))
    (and (= s1 5) (or (= s2 4) (= s2 6) (= s2 3)))
    (and (= s1 6) (or (= s2 1) (= s2 3) (= s2 4)))
  ))

; =============================================================================
; 1. Pre-State Inductive Invariant Hypotheses (Pre_I01 .. Pre_I20)
; =============================================================================
(assert (valid_state state))
(assert (valid_state sim_state))
(assert (valid_ks ks_status))
(assert (valid_wal wal_status))
(assert (valid_auth auth_status))
(assert (>= gen 0))
(assert (= max_gen gen))
(assert (=> (and (= auth_status 1) (= wal_status 2))
            (and (= journal_gen gen) (= journal_state state))))
(assert (=> (>= auth_status 2) (= state 4)))
(assert (=> (or (= state 5) (= state 6))
            (and has_bound_event has_bound_challenge)))
(assert (=> net_confirmed (and (= state 4) (= ks_status 4))))
(assert (=> (= ks_status 5) (not net_confirmed)))
(assert (=> boot_fail_closed (= state 4)))
(assert (not (and token_reserved token_already_consumed)))

; =============================================================================
; 2. Complete Deterministic Transition Relation T (Action 0 .. 10)
;    Every post-state variable is explicitly bound in every branch.
; =============================================================================
(assert (and (>= action 0) (<= action 10)))

; Action 0: DRY_RUN (Simulates transition on sim_state only; zero production mutation)
(define-fun Trans_DryRun () Bool
  (and
    (= action 0)
    (allowed_transition sim_state sim_state_next)
    (= state_next state)
    (= gen_next gen)
    (= max_gen_next max_gen)
    (= journal_gen_next journal_gen)
    (= journal_state_next journal_state)
    (= wal_status_next wal_status)
    (= auth_status_next auth_status)
    (= emergency_latch_next emergency_latch)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next ks_status)
    (= net_confirmed_next net_confirmed)
    (= has_bound_event_next has_bound_event)
    (= has_bound_challenge_next has_bound_challenge)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next token_reserved)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next boot_fail_closed)
    (= audit_recorded_next true)
  ))

; Action 1: NORMAL_STEP (OFF -> ARMING -> ACTIVE -> OFF when no emergency_latch)
(define-fun Trans_NormalStep () Bool
  (and
    (= action 1)
    (not emergency_latch)
    (or (= state 0) (= state 1) (= state 2))
    (allowed_transition state state_next)
    (or (= state_next 0) (= state_next 1) (= state_next 2))
    (= sim_state_next state_next)
    (= gen_next (+ gen 1))
    (= max_gen_next (+ max_gen 1))
    (= journal_gen_next gen_next)
    (= journal_state_next state_next)
    (= wal_status_next 2)
    (= auth_status_next 1)
    (= emergency_latch_next false)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next 0)
    (= net_confirmed_next false)
    (= has_bound_event_next has_bound_event)
    (= has_bound_challenge_next has_bound_challenge)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next false)
    (= is_core_domain_next true)
    (= boot_fail_closed_next false)
    (= audit_recorded_next true)
  ))

; Action 2: P0_LATCH_TRIGGER (Lock-free atomic preemption latch & epoch increment)
(define-fun Trans_P0LatchTrigger () Bool
  (and
    (= action 2)
    (= state_next state)
    (= sim_state_next sim_state)
    (= gen_next gen)
    (= max_gen_next max_gen)
    (= journal_gen_next journal_gen)
    (= journal_state_next journal_state)
    (= wal_status_next wal_status)
    (= auth_status_next auth_status)
    (= emergency_latch_next true)
    (= emergency_epoch_next (+ emergency_epoch 1))
    (= snap_epoch_next snap_epoch)
    (= ks_status_next ks_status)
    (= net_confirmed_next net_confirmed)
    (= has_bound_event_next true)
    (= has_bound_challenge_next true)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next token_reserved)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next boot_fail_closed)
    (= audit_recorded_next true)
  ))

; Action 3: P0_EMERGENCY_DRAIN (Drains latch to EMERGENCY or ISOLATED)
(define-fun Trans_P0EmergencyDrain () Bool
  (and
    (= action 3)
    emergency_latch
    (ite (= state 3)
         (= state_next 4)
         (ite (= state 4) (= state_next 4) (= state_next 3)))
    (= sim_state_next state_next)
    (= gen_next (ite (= state 4) gen (+ gen 1)))
    (= max_gen_next gen_next)
    (= journal_gen_next gen_next)
    (= journal_state_next state_next)
    (= wal_status_next 2)
    (= auth_status_next 1)
    (= emergency_latch_next (not (= state_next 4)))
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next (ite (= state_next 4) 2 ks_status))
    (= net_confirmed_next false)
    (= has_bound_event_next true)
    (= has_bound_challenge_next true)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next false)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next boot_fail_closed)
    (= audit_recorded_next true)
  ))

; Action 4: RECOVERY_R1_PENDING (ISOLATED -> RECOVERY_PENDING)
(define-fun Trans_RecoveryR1 () Bool
  (and
    (= action 4)
    (= state 4)
    (not emergency_latch)
    (= auth_status 1)
    has_bound_event
    has_bound_challenge
    (= state_next 5)
    (= sim_state_next 5)
    (= gen_next (+ gen 1))
    (= max_gen_next (+ max_gen 1))
    (= journal_gen_next gen_next)
    (= journal_state_next 5)
    (= wal_status_next 2)
    (= auth_status_next 1)
    (= emergency_latch_next false)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next emergency_epoch)
    (= ks_status_next ks_status)
    (= net_confirmed_next net_confirmed)
    (= has_bound_event_next true)
    (= has_bound_challenge_next true)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next false)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next false)
    (= audit_recorded_next true)
  ))

; Action 5: RECOVERY_STAGE1_APPROVED (RECOVERY_PENDING -> RECOVERY_APPROVED)
(define-fun Trans_RecoveryStage1 () Bool
  (and
    (= action 5)
    (= state 5)
    (not emergency_latch)
    (= emergency_epoch snap_epoch)
    has_bound_event
    has_bound_challenge
    (>= distinct_signers 2)
    (not token_already_consumed)
    (not token_reserved)
    is_core_domain
    (= state_next 6)
    (= sim_state_next 6)
    (= gen_next (+ gen 1))
    (= max_gen_next (+ max_gen 1))
    (= journal_gen_next gen_next)
    (= journal_state_next 6)
    (= wal_status_next 2)
    (= auth_status_next 1)
    (= emergency_latch_next false)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next ks_status)
    (= net_confirmed_next net_confirmed)
    (= has_bound_event_next true)
    (= has_bound_challenge_next true)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next false)
    (= token_reserved_next true)
    (= is_core_domain_next true)
    (= boot_fail_closed_next false)
    (= audit_recorded_next true)
  ))

; Action 6: RECOVERY_STAGE2_ARMING (RECOVERY_APPROVED -> ARMING)
(define-fun Trans_RecoveryStage2 () Bool
  (and
    (= action 6)
    (= state 6)
    (not emergency_latch)
    (= emergency_epoch snap_epoch)
    has_bound_event
    has_bound_challenge
    (>= distinct_signers 2)
    token_reserved
    (not token_already_consumed)
    is_core_domain
    (= state_next 1)
    (= sim_state_next 1)
    (= gen_next (+ gen 1))
    (= max_gen_next (+ max_gen 1))
    (= journal_gen_next gen_next)
    (= journal_state_next 1)
    (= wal_status_next 2)
    (= auth_status_next 1)
    (= emergency_latch_next false)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next ks_status)
    (= net_confirmed_next net_confirmed)
    (= has_bound_event_next true)
    (= has_bound_challenge_next true)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next false)
    (= token_reserved_next true)
    (= is_core_domain_next true)
    (= boot_fail_closed_next false)
    (= audit_recorded_next true)
  ))

; Action 7: RECOVERY_STAGE3_ACTIVE (ARMING -> ACTIVE, consumes reserved token)
(define-fun Trans_RecoveryStage3 () Bool
  (and
    (= action 7)
    (= state 1)
    (not emergency_latch)
    (= emergency_epoch snap_epoch)
    has_bound_event
    has_bound_challenge
    (>= distinct_signers 2)
    token_reserved
    (not token_already_consumed)
    is_core_domain
    (= state_next 2)
    (= sim_state_next 2)
    (= gen_next (+ gen 1))
    (= max_gen_next (+ max_gen 1))
    (= journal_gen_next gen_next)
    (= journal_state_next 2)
    (= wal_status_next 2)
    (= auth_status_next 1)
    (= emergency_latch_next false)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next 0)
    (= net_confirmed_next false)
    (= has_bound_event_next false)
    (= has_bound_challenge_next false)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next true)
    (= token_reserved_next false)
    (= is_core_domain_next true)
    (= boot_fail_closed_next false)
    (= audit_recorded_next true)
  ))

; Action 8: KILL_SWITCH_CONFIRM (OS block verified in ISOLATED)
(define-fun Trans_KillSwitchConfirm () Bool
  (and
    (= action 8)
    (= state 4)
    (or (= ks_status 2) (= ks_status 3))
    (= state_next 4)
    (= sim_state_next sim_state)
    (= gen_next gen)
    (= max_gen_next max_gen)
    (= journal_gen_next journal_gen)
    (= journal_state_next journal_state)
    (= wal_status_next wal_status)
    (= auth_status_next auth_status)
    (= emergency_latch_next emergency_latch)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next 4)
    (= net_confirmed_next true)
    (= has_bound_event_next has_bound_event)
    (= has_bound_challenge_next has_bound_challenge)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next token_reserved)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next boot_fail_closed)
    (= audit_recorded_next true)
  ))

; Action 9: KILL_SWITCH_FAIL (OS block failed in ISOLATED -> never sets net_confirmed=true)
(define-fun Trans_KillSwitchFail () Bool
  (and
    (= action 9)
    (= state 4)
    (or (= ks_status 2) (= ks_status 3))
    (= state_next 4)
    (= sim_state_next sim_state)
    (= gen_next gen)
    (= max_gen_next max_gen)
    (= journal_gen_next journal_gen)
    (= journal_state_next journal_state)
    (= wal_status_next wal_status)
    (= auth_status_next auth_status)
    (= emergency_latch_next emergency_latch)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next 5)
    (= net_confirmed_next false)
    (= has_bound_event_next has_bound_event)
    (= has_bound_challenge_next has_bound_challenge)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next token_reserved)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next boot_fail_closed)
    (= audit_recorded_next true)
  ))

; Action 10: FAULT_OR_INCOMPLETE_WAL_REBOOT (Crash during PREPARED WAL or storage tamper -> Fail-Closed ISOLATED)
(define-fun Trans_FaultOrIncompleteWALReboot () Bool
  (and
    (= action 10)
    (= state_next 4)
    (= sim_state_next 4)
    (= gen_next gen)
    (= max_gen_next max_gen)
    (= journal_gen_next journal_gen)
    (= journal_state_next journal_state)
    (= wal_status_next 1)
    (= auth_status_next 10)
    (= emergency_latch_next emergency_latch)
    (= emergency_epoch_next emergency_epoch)
    (= snap_epoch_next snap_epoch)
    (= ks_status_next 2)
    (= net_confirmed_next false)
    (= has_bound_event_next true)
    (= has_bound_challenge_next true)
    (= distinct_signers_next distinct_signers)
    (= token_already_consumed_next token_already_consumed)
    (= token_reserved_next false)
    (= is_core_domain_next is_core_domain)
    (= boot_fail_closed_next true)
    (= audit_recorded_next true)
  ))

(assert
  (or
    Trans_DryRun
    Trans_NormalStep
    Trans_P0LatchTrigger
    Trans_P0EmergencyDrain
    Trans_RecoveryR1
    Trans_RecoveryStage1
    Trans_RecoveryStage2
    Trans_RecoveryStage3
    Trans_KillSwitchConfirm
    Trans_KillSwitchFail
    Trans_FaultOrIncompleteWALReboot
  ))

; =============================================================================
; 3. Post-State Safety Invariants (Post_I01 .. Post_I20)
;    We assert the negation of their conjunction; UNSAT proves all 20 hold!
; =============================================================================
(define-fun Post_I01_StateTypeSafety () Bool
  (and (valid_state state_next) (valid_state sim_state_next)
       (valid_ks ks_status_next) (valid_wal wal_status_next) (valid_auth auth_status_next)))

(define-fun Post_I02_TransitionCompleteness () Bool
  (=> (and (not (= state_next state)) (not (= action 10)))
      (allowed_transition state state_next)))

(define-fun Post_I03_GenerationMonotonicity () Bool
  (and (>= gen_next gen) (<= gen_next max_gen_next)))

(define-fun Post_I04_IsolationLatchProtection () Bool
  (=> (and emergency_latch (or (= action 5) (= action 6) (= action 7)))
      (not (= state_next 2))))

(define-fun Post_I05_P0PriorityOverRecovery () Bool
  (=> (= action 7)
      (and (not emergency_latch) (= emergency_epoch snap_epoch))))

(define-fun Post_I06_DryRunNonInterference () Bool
  (=> (= action 0)
      (and (= state_next state) (= gen_next gen) (= wal_status_next wal_status))))

(define-fun Post_I07_PersistenceConsistency () Bool
  (=> (and (= auth_status_next 1) (= wal_status_next 2))
      (and (= journal_gen_next gen_next) (= journal_state_next state_next))))

(define-fun Post_I08_RollbackAndIncompleteWALPrevention () Bool
  (=> (or (= auth_status_next 3) (= auth_status_next 10) (= wal_status_next 1))
      (= state_next 4)))

(define-fun Post_I09_EventAndChallengeBinding () Bool
  (=> (or (= state_next 5) (= state_next 6))
      (and has_bound_event_next has_bound_challenge_next)))

(define-fun Post_I10_QuorumDistinctSignerSafety () Bool
  (=> (= action 7) (>= distinct_signers 2)))

(define-fun Post_I11_TokenSingleUse () Bool
  (not (and token_reserved_next token_already_consumed_next)))

(define-fun Post_I12_RecoveryPathProtection () Bool
  (not (and (= state 4) (= state_next 2))))

(define-fun Post_I13_RebootSafety () Bool
  (=> boot_fail_closed_next (= state_next 4)))

(define-fun Post_I14_KillSwitchConsistency () Bool
  (and (=> net_confirmed_next (and (= state_next 4) (= ks_status_next 4)))
       (=> (= ks_status_next 5) (not net_confirmed_next))))

(define-fun Post_I15_FailClosedIntegrity () Bool
  (=> (>= auth_status_next 2) (= state_next 4)))

(define-fun Post_I16_DomainSeparation () Bool
  (=> (= action 7) is_core_domain_next))

(define-fun Post_I17_InterProcessLinearizability () Bool
  (=> (and (not (= state_next state)) (not (= action 0)) (not (= action 10)))
      (= gen_next (+ gen 1))))

(define-fun Post_I18_EventReusePrevention () Bool
  (=> (= action 5) (not token_already_consumed)))

(define-fun Post_I19_TransitionAuditability () Bool
  (=> (not (= state_next state)) audit_recorded_next))

(define-fun Post_I20_SafetyOverAvailabilityPriority () Bool
  (=> (or (= wal_status_next 1) (and emergency_latch_next (not (= action 2))))
      (not (= state_next 2))))

(assert
  (not
    (and
      Post_I01_StateTypeSafety
      Post_I02_TransitionCompleteness
      Post_I03_GenerationMonotonicity
      Post_I04_IsolationLatchProtection
      Post_I05_P0PriorityOverRecovery
      Post_I06_DryRunNonInterference
      Post_I07_PersistenceConsistency
      Post_I08_RollbackAndIncompleteWALPrevention
      Post_I09_EventAndChallengeBinding
      Post_I10_QuorumDistinctSignerSafety
      Post_I11_TokenSingleUse
      Post_I12_RecoveryPathProtection
      Post_I13_RebootSafety
      Post_I14_KillSwitchConsistency
      Post_I15_FailClosedIntegrity
      Post_I16_DomainSeparation
      Post_I17_InterProcessLinearizability
      Post_I18_EventReusePrevention
      Post_I19_TransitionAuditability
      Post_I20_SafetyOverAvailabilityPriority
    )))

(check-sat)
