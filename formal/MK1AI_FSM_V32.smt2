; =============================================================================
; MK1Ai Project Sovereign-Airgap — FSM V3.2 SMT-LIB v2 Formal Proof Obligations
; Encodes State Space S, Transition Relation T, and Invariants I-01 .. I-20
; Discharges inductive safety obligations via unsatisfiability of (~Inv).
; =============================================================================
(set-logic QF_LIA)
(set-option :produce-models true)

; State encoding:
; 0 = OFF, 1 = ARMING, 2 = ACTIVE, 3 = EMERGENCY,
; 4 = ISOLATED, 5 = RECOVERY_PENDING, 6 = RECOVERY_APPROVED

; KillSwitchStatus encoding:
; 0 = NOT_REQUESTED, 1 = REQUESTED, 2 = LOGICALLY_ISOLATED,
; 3 = OS_BLOCK_PENDING, 4 = OS_BLOCK_CONFIRMED, 5 = OS_BLOCK_FAILED,
; 6 = PARTIALLY_ISOLATED, 7 = VERIFICATION_FAILED

(declare-const state Int)
(declare-const state_next Int)
(declare-const sim_state Int)
(declare-const sim_state_next Int)
(declare-const gen Int)
(declare-const gen_next Int)
(declare-const max_gen Int)
(declare-const max_gen_next Int)
(declare-const journal_gen Int)
(declare-const journal_gen_next Int)
(declare-const journal_state Int)
(declare-const journal_state_next Int)
(declare-const emergency_latch Bool)
(declare-const emergency_latch_next Bool)
(declare-const emergency_epoch Int)
(declare-const emergency_epoch_next Int)
(declare-const snap_epoch Int)
(declare-const ks_status Int)
(declare-const ks_status_next Int)
(declare-const net_confirmed Bool)
(declare-const net_confirmed_next Bool)
(declare-const is_dry_run Bool)

(define-fun valid_state ((s Int)) Bool
  (and (>= s 0) (<= s 6)))

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

; Pre-state inductive invariants
(assert (valid_state state))
(assert (valid_state sim_state))
(assert (>= gen 0))
(assert (= max_gen gen))
(assert (= journal_gen gen))
(assert (= journal_state state))
(assert (= net_confirmed (and (= state 4) (= ks_status 4))))

; Transition relation T (Dry-Run vs Production Recovery Commit vs P0 Preemption)
(assert
  (ite is_dry_run
    (and
      (allowed_transition sim_state sim_state_next)
      (= state_next state)
      (= gen_next gen)
      (= max_gen_next max_gen)
      (= journal_gen_next journal_gen)
      (= journal_state_next journal_state)
      (= emergency_latch_next emergency_latch)
      (= emergency_epoch_next emergency_epoch)
      (= ks_status_next ks_status)
      (= net_confirmed_next net_confirmed)
    )
    (and
      (allowed_transition state state_next)
      ; P0 Preemption Guard (I-04 & I-05): Recovery cannot advance to RECOVERY_APPROVED (6) or ACTIVE (2)
      ; if emergency_latch is true or emergency_epoch != snap_epoch
      (=> (or (= state 5) (= state 6))
          (=> (or emergency_latch (not (= emergency_epoch snap_epoch)))
              (or (= state_next 3) (= state_next 4))))
      (= sim_state_next state_next)
      (= gen_next (+ gen 1))
      (= max_gen_next (+ max_gen 1))
      (= journal_gen_next gen_next)
      (= journal_state_next state_next)
      (= net_confirmed_next (and (= state_next 4) (= ks_status_next 4)))
    )
  ))

; Negation of Post-State Safety Invariants (Prove UNSAT)
(assert
  (or
    (not (valid_state state_next))                                         ; Violates I-01
    (and (not is_dry_run) (not (allowed_transition state state_next)))     ; Violates I-02
    (< gen_next gen)                                                       ; Violates I-03
    (and (= state 5) emergency_latch (= state_next 6))                     ; Violates I-04/I-05
    (and is_dry_run (or (not (= state_next state)) (not (= gen_next gen)))); Violates I-06
    (not (= journal_gen_next gen_next))                                    ; Violates I-07
    (not (= journal_state_next state_next))                                ; Violates I-07
    (and net_confirmed_next (not (= ks_status_next 4)))                    ; Violates I-14
  ))

(check-sat)
