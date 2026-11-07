# MK1Ai FSM V3.2 — FINAL REMEDIATION & COMPLETE VERIFICATION REPORT
## Project Sovereign-Airgap / Residual Security Fixes (`R-001`〜`R-005`) & Complete Verification

- **対象リポジトリ:** `nekoyarou1225/MK1Ai` (`/app/applet`)
- **文書ファイル名:** `MK1AI_FSM_V3_2_FINAL_VERIFICATION_REPORT.md`
- **検証日時:** `2026-11-06`
- **作業フェーズ:** 残存問題修正（`R-001`〜`R-005`）＋数学的形式検証＋全回帰・ストレステスト完遂（Common Criteria EAL7 24文書作成前ゲート）

---

## 1. 修正ファイル一覧（行数・サイズ・SHA-256）

既存の編集状態を保持したまま、今回の承認範囲（`R-001`〜`R-005`）で更新・検証した全12ファイル（うち今回追加更新7ファイル、既存保持5ファイル）の一覧とSHA-256ハッシュは以下の通りです。

| # | ファイルパス | 種別 | 行数 (`wc -l`) | SHA-256 ハッシュ | 主な変更内容 |
|---|---|---|---|---|---|
| 1 | `airgap_ai_defender.py` | 既存編集＋`R-001`/`R-002`/`R-005`修正 | `9,945` | `2df504a6f919c6db42cb15149d64213c58c37bd860f896583fbefc9d774e2abb` | `_TimedLockContext`最外層限定`flock`再入制御（`R-001`）、7段階2相WAL `PREPARED`/`COMMITTED`実装（`R-002`）、Dry-Run時の`_simulated_anomaly_counter`分離（`I-06`/`R-005`）、遮断検証例外のFail-Closed処理 |
| 2 | `mk1_quorum.py` | 既存V3.2編集保持 | `905` | `ae4da93b705bda2c0ce6b1d54fb772ff8a68c20b5719a3017eeefcb9ba9e2b10` | `event_id`/`challenge_id`/`policy_version`/`prefix`必須検証、`issued_at <= now`将来時刻拒否（`P1-005`, `P2-001`） |
| 3 | `formal/MK1AI_FSM_V32.tla` | `R-003`完全化 | `667` | `81e8c708894de92f0bbf5d2a64cb40efefb756a8983e7ce81dcd2a9bdb5466ab` | `I-01`〜`I-20`全20不変条件定義、Recovery 4段階完全遷移、`wal_status` (`PREPARED`/`COMMITTED`)、Crash/Restart/Fault遷移、Safety/Liveness分離 |
| 4 | `formal/MK1AI_FSM_V32.cfg` | `R-003`完全化 | `34` | `4df093b36a623cb14bcb80bf610fb5319ebc26720eec59f05d2d717b8fd76ed2` | TLC用`I01`〜`I20`（`INVARIANTS`）および`L01`・`L02`（`PROPERTIES`）分離定義 |
| 5 | `formal/MK1AI_FSM_V32.smt2` | `R-003`完全化 | `595` | `a239fc051b28a3d7340950493c788fa02681bd57d9dd403fd7d10773b6c1226c` | `Post_I01`〜`Post_I20`全20証明義務、未束縛変数の完全解消、恒真式排除、Pre-State仮定とPost-State否定の明示分離 |
| 6 | `formal/mk1_formal_verifier.py` | `R-003`完全化 | `845` | `dd927e695d224c7ea3563f8e339f2686b737f32ee4686d60161acfb1efa2d234` | 20不変条件（`I-01`〜`I-20`）検証、`wal_status`・Fault Reboot探索、Refinement Mapping検証、`frozenset`対応JSON出力 |
| 7 | `tests/test_v32_formal_and_stress.py` | `R-004`拡充 | `1,186` | `b117f04802bada3818ab6e18e459666ef6af975c609c5ad6f6af480cd9c07904` | `R-001`再入・16スレッド入れ子・タイムアウト試験、`R-002` 7段階WAL・`SIGKILL`・書き込み/`replace`/`fsync`失敗、`R-004`全10項目追加（計27テスト） |
| 8 | `tests/test_v2_remediation.py` | `R-005`整合化 | `105` | `2920efb2f04a4bcf5ff56b4c54bf217a5f5db7ef987b7cefef6080b2d8b3a901` | 旧Dry-Run仕様前提の期待値をV3.2不変条件`I-06`（本番非干渉＋`simulated_state == ISOLATED`）および`dry_run=False`承認保留検証に更新 |
| 9 | `tests/test_airgap_ai_defender.py` | `R-005`整合化 | `3,061` | `5fa8cd26ea7229358ebf85ada92da2e87db7f81de788cdac80bb4925f64d7dbe` | `test_evaluate_threat_state_decays_anomaly_counter_after_cooldown`で`dry_run=True`非干渉（`_simulated_anomaly_counter`減衰）と`dry_run=False`本番減衰の両方を検証 |
| 10 | `tests/test_v3_final.py` | `tearDown`整理 | `782` | `6da3df3f2bf66cc442c45d9202bfc40905c43d90803d43f5b8fd6886cbfd637e` | `tearDown()`での`toggle_oni_mode(False)`リセット保証（全33テスト保持） |
| 11 | `tests/test_v3_remediation.py` | `tearDown`整理 | `123` | `34c78154f08f5e8141dde925b8e23b27095cb848ff8ed964940593c203801d06` | `tearDown()`での`toggle_oni_mode(False)`リセット保証（全7テスト保持） |
| 12 | `tests/test_xdp_ebpf_subsystem.py` | 変更なし（検証のみ） | `313` | `6f484233bc50c384804296b5fb62edd4fac2431aebd371db7c08266e116aeb7a` | 既存12テスト無修正で全件PASS確認 |

---

## 2. `mk1_quorum.py` の変更履歴の整理

前回報告書における行数表記の差異について、監査記録と実ファイルのハッシュから以下の3段階の履歴であることを確認しました。

1. **V2 時点 (`MK1AI_GIT_CHANGE_AUDIT.md` 記録):**
   - 行数・サイズ: `398 lines` (`15,648 B`)
   - SHA-256: `a6e115cba3f014a55a35b53fd65658e4dfa7cb7177f59eeff20e49de7ac9f61f`
2. **V3.1 監査ベースライン時点 (`MK1AI_FSM_V3_1_INDEPENDENT_AUDIT_REPORT.md` 34行目・811行目記録):**
   - 行数・サイズ: `793 lines` (`33,435 B`)
   - SHA-256: `6da07e9c2870a946f686370150f5a519b5c576ce724c396ffa1dd3221441a0d0`
3. **V3.2 修正後現在 (`mk1_quorum.py` 実ファイル):**
   - 行数・サイズ: `905 lines` (`wc -l`, 末尾改行含む906行相当 / `37,690 B`)
   - SHA-256: `ae4da93b705bda2c0ce6b1d54fb772ff8a68c20b5719a3017eeefcb9ba9e2b10`
   - V3.1→V3.2での追加内容（`+113 lines`）:
     - `create_quorum_challenge()`（446〜507行目）における`RELEASE_QUARANTINE`時の`event_id`・`policy_version`必須化および`issued_at <= now`検証
     - `verify_quorum_bundle()`（573〜639行目）における`challenge_id`・`prefix`・`issued_at`・`expires_at`・`event_id`・`policy_version`の厳格検証（`P1-005`, `P2-001`）

---

## 3. `R-001`〜`R-005` の修正内容と差分

### 3.1 `R-001`：`fcntl.flock` 再入競合の修正（`airgap_ai_defender.py` 653〜656行目、840〜934行目）
- **原因:** 旧実装では `_TimedLockContext.__enter__` が呼ばれるたびに毎回 `os.open(self._lock_path, ...)` で新規ファイル記述子を開いて `fcntl.flock(fd, LOCK_EX | LOCK_NB)` を要求していたため、`state_path` 設定時に同一スレッド内で `with self._acquire_lock():` がネストすると、内側の別FDが外側のFDとOSファイルロック上で自己競合し `TimeoutError` となる問題がありました。
- **修正内容:**
  - `MK1SafetyStateMachine.__init__` に `self._flock_depth = 0`、`self._flock_owner_tid = None`、`self._flock_fd = None` を追加。
  - `_TimedLockContext.__enter__` で `self._rlock.acquire(timeout=self._timeout)` 取得後、`self._flock_depth > 0` の場合は `self._flock_owner_tid == threading.get_ident()` を厳密検証した上で `_flock_depth += 1` のみ行い、最外層（`depth 0 -> 1`）でのみ `os.open` + `fcntl.flock(LOCK_EX | LOCK_NB)` を取得。
  - `_TimedLockContext.__exit__` では `_flock_depth > 1` の間は `_flock_depth -= 1` のみ行い、最外層の解放時（`depth 1 -> 0`）のみ `fcntl.flock(LOCK_UN)` と `os.close()` を実行。

```python
# airgap_ai_defender.py:861-933
            tid = threading.get_ident()
            if self._fsm._flock_depth > 0:
                if self._fsm._flock_owner_tid != tid:
                    self._rlock.release()
                    self._acquired_rlock = False
                    raise RuntimeError(
                        f"FSM lock thread ownership violation: owned by {self._fsm._flock_owner_tid}, requested by {tid}"
                    )
                self._fsm._flock_depth += 1
                return self

            # Outermost acquisition (depth 0 -> 1): acquire OS-level fcntl.flock if state_path is configured
```

### 3.2 `R-002`：WALの完全な `PREPARED` / `COMMITTED` 7段階実装（`airgap_ai_defender.py` 1012〜1348行目、1440〜1454行目）
- **実装した7段階トランザクション（`_save_persistent_state`）:**
  1. **Step 1 (`PREPARED` 記録):** `_write_journal_record(generation, state, status="PREPARED", prev_generation=..., prev_state=...)` によりHMAC署名付き`PREPARED`レコードを一時ファイルへ出力。
  2. **Step 2 (Journal `fsync`):** `os.fsync(jf.fileno())` + `os.replace(tmp_j, self._journal_path)` + 親ディレクトリ `fsync`。
  3. **Step 3 (State 更新):** PID/TID固有の一時ファイルへ新しいState JSON（HMAC署名付き）を書き込み。
  4. **Step 4 (State `fsync` + 原子置換):** `os.fsync(f.fileno())` + `os.replace(tmp_path, self._state_path)` + 親ディレクトリ `fsync`。
  5. **Step 5 (Journal `COMMITTED` 更新):** `_write_journal_record(generation, state, status="COMMITTED")` によりHMAC署名付き`COMMITTED`レコードを記録。
  6. **Step 6 (Journal `fsync` + Boot Anchor 更新):** `os.fsync` + `self._anchor.write_anchor(self._generation, self._state)`。
  7. **Step 7 (最終状態照合):** `_verify_committed_storage_consistency(self._generation, self._state)` でディスク上のStateファイルとJournalファイルの両方を再読込・HMAC再検証し、`status == "COMMITTED"` かつ世代・状態が完全一致することを照合。
- **再起動時の未完了WAL検知（`_load_persistent_state` 1440〜1454行目）:**
  - クラッシュがStep 1〜Step 5のどの段階で発生しても、起動時に `journal_status == "PREPARED_INCOMPLETE"` を検知すると**絶対に正常な`ACTIVE`状態として復元せず**、`self._state = self.ISOLATED`、`self._authenticity_status = "FAILED_WAL_INCOMPLETE"`、`self._rollback_protection_status = "WAL_INCOMPLETE_PREPARED"` へFail-Closed遷移します。

### 3.3 `R-003`：形式仕様（TLA+ / SMT-LIB / Python Model Checker）の完全化
- **`formal/MK1AI_FSM_V32.tla` & `formal/MK1AI_FSM_V32.cfg`:**
  - `I01_StateTypeSafety`〜`I20_SafetyOverAvailabilityPriority` の全20不変条件を明示定義。
  - Recoveryの4段階（`BeginRecovery`: `ISOLATED -> RECOVERY_PENDING`、`ApproveRecoveryStage1`: `RECOVERY_PENDING -> RECOVERY_APPROVED`、`ReArmRecoveryStage2`: `RECOVERY_APPROVED -> ARMING`、`CommitRecoveryStage3Active`: `ARMING -> ACTIVE`）を中間状態の省略なく完全定義。
  - `wal_status` (`"UNINITIALIZED"`, `"PREPARED"`, `"COMMITTED"`)、`CrashDuringPreparedWAL`、`CrashAndRebootFromTransient`、`FaultRebootIntegrityViolation` を定義し、`INVARIANTS`（Safety）と `PROPERTIES`（Liveness `L01`, `L02`）を分離。
- **`formal/MK1AI_FSM_V32.smt2`:**
  - Pre-State変数22個とPost-State変数22個を全11遷移ブランチ（`action 0..10`）で完全束縛し、未束縛変数および`net_confirmed_next`の恒真式を排除。
  - Pre-State仮定 `(assert (and Pre_I01 ... Pre_I20))` と Post-State証明義務 `(assert (not (and Post_I01 ... Post_I20)))` + `(check-sat)` を明示分離。
- **`formal/mk1_formal_verifier.py`:**
  - 全20不変条件（`I-01`〜`I-20`）、`wal_status`、`FAULT_REBOOT_FAILED_WAL_INCOMPLETE`、`CEX-V32-R001-R002`、および`verify_refinement_conformance()`での再入ロック＋WAL `COMMITTED`検証を実装し、`frozenset`のJSON直列化に対応。

### 3.4 `R-004`：ストレステストと異常系試験の拡充（`tests/test_v32_formal_and_stress.py`）
- `R-001`・`R-002`および`R-004`で指定された全10カテゴリーの検証テスト（計10メソッド・27テストケース）を追加実装し、すべて実測実行しました（詳細はセクション7参照）。

### 3.5 `R-005`：既存テストの整合性確認と更新（`tests/test_v2_remediation.py`, `tests/test_airgap_ai_defender.py`）
- 旧Dry-Run仕様（`dry_run=True`で本番`_SAFETY_FSM._state`や本番`_anomaly_counter`、本番`_ISOLATION_APPROVAL_PENDING`を直接変更していたV2/V3.0仕様）に依存していた3箇所を特定し、テスト条件を弱めることなくV3.2不変条件`I-06`（Dry-Run非干渉性）＋本番モード検証の両方を満たすよう更新しました（詳細はセクション9参照）。

---

## 4. 15件の脆弱性（`P0-001`〜`P3-001`）＋残存課題（`R-001`〜`R-005`）の最終検証結果

| ID | 脆弱性・課題項目 | 修正箇所（ファイル・行番号） | 検証テスト | 最終判定 |
|---|---|---|---|---|
| **P0-001** | 実稼働`_SAFETY_FSM`の`state_path=None`・再起動時`ISOLATED`消失 | `airgap_ai_defender.py:1942-1988` (`_init_production_safety_fsm`), `1569-1610` (`startup_initialize`) | `test_p0_001_production_fsm_persistence_and_isolated_restart` | **VERIFIED (PASS)** |
| **P0-002** | 実稼働FSMの`strict_dry_run_isolation=False`によるDry-Run本番汚染 | `airgap_ai_defender.py:619-621`, `1752-1779`, `7590-7650` | `test_p0_002_strict_dry_run_isolation_always_enforced` | **VERIFIED (PASS)** |
| **P0-003** | `request_recovery()`中の緊急隔離ロック競合・P0優先度逆転 | `airgap_ai_defender.py:659-663`, `1859-1939` (`_emergency_latch`, `_emergency_epoch`) | `test_p0_003_recovery_preempted_by_concurrent_emergency_isolation` | **VERIFIED (PASS)** |
| **P0-004** | StateまたはJournal削除時のFail-Open（`OFF`/`ACTIVE`復帰） | `airgap_ai_defender.py:1348-1567` (`_load_persistent_state` 3点照合) | `test_p0_004_missing_state_or_journal_or_both_fails_closed` | **VERIFIED (PASS)** |
| **P0-005** | Kill Switch失敗時の虚偽成功返却（`evaluate_threat_state`） | `airgap_ai_defender.py:585-604`, `7656-7694` (8状態`KillSwitchStatus`) | `test_p0_005_kill_switch_8_states_and_failure_never_reported_as_success` | **VERIFIED (PASS)** |
| **P1-001** | ハードコードHMAC鍵フォールバックの除去と鍵ローテーション | `airgap_ai_defender.py:424-431`, `715-839` (`_init_hmac_key`, `rotate_hmac_key`) | `test_p1_001_no_hardcoded_hmac_key_and_key_rotation` | **VERIFIED (PASS)** |
| **P1-002** | Journal書き込み失敗の無視と不整合放置 | `airgap_ai_defender.py:1060-1346` (`_write_journal_record`, `_save_persistent_state`) | `test_p1_002_and_p1_003_journal_state_consistency_and_split_brain_prevention` | **VERIFIED (PASS)** |
| **P1-003** | 同一世代（`gen == journal_max_gen`）でのState状態改竄未検証 | `airgap_ai_defender.py:1498-1508` (`state != journal_last_state` 検証) | `test_p1_002_and_p1_003_journal_state_consistency_and_split_brain_prevention` | **VERIFIED (PASS)** |
| **P1-004** | 複数OSプロセス間の排他ロック・一時ファイル衝突 | `airgap_ai_defender.py:840-934`, `1096-1100`, `1260-1264` | `test_5_3_multiprocess_2_4_8_processes_contention` | **VERIFIED (PASS)** |
| **P1-005** | Quorum必須属性（`event_id`/`challenge_id`/`policy_version`/`prefix`）省略許容 | `mk1_quorum.py:459-473`, `573-639`; `airgap_ai_defender.py:1875-1899` | `test_p1_005_and_p2_001_strict_quorum_mandatory_attributes_and_future_issued_at` | **VERIFIED (PASS)** |
| **P1-006** | Recovery失敗時のワンタイムトークン誤消費（DoS）と成功後再利用防止 | `airgap_ai_defender.py:1888-1934` (`_reserved_recovery_tokens` vs `_consumed_recovery_tokens`) | `test_recovery_006_persistence_failure_maintains_isolated`, `test_r004_01_16_threads_concurrent_recovery_exactly_one_succeeds` | **VERIFIED (PASS)** |
| **P2-001** | 将来時刻 `issued_at > now` のQuorum Challenge許容 | `mk1_quorum.py:466-467`, `598-599`; `airgap_ai_defender.py:1885-1886` | `test_p1_005_and_p2_001_strict_quorum_mandatory_attributes_and_future_issued_at`, `test_r004_08_clock_skew_boundary_conditions` | **VERIFIED (PASS)** |
| **P2-002** | Stateファイルの不正タイムスタンプ（負値・`0`・`bool`・`NaN`・未来時刻）未検証 | `airgap_ai_defender.py:956-966` (`_validate_timestamp`) | `test_p2_002_invalid_timestamps_rejected_fail_closed`, `test_r004_08_clock_skew_boundary_conditions` | **VERIFIED (PASS)** |
| **P2-003** | 過渡状態（`ARMING`/`EMERGENCY`/`RECOVERY_PENDING`/`RECOVERY_APPROVED`）からの再起動放置 | `airgap_ai_defender.py:1526-1543` (`NORMALIZED_TRANSIENT_TO_ISOLATED`) | `test_p2_003_transient_states_normalized_to_isolated_on_reboot` | **VERIFIED (PASS)** |
| **P3-001** | `OFF`状態からの`isolate_immediately()`のDry-Run/本番挙動差 | `airgap_ai_defender.py:693` (`OFF -> EMERGENCY` 許可) | `test_p3_001_off_state_isolate_immediately_consistency` | **VERIFIED (PASS)** |
| **R-001** | 同一スレッドのネストした`fcntl.flock`取得での自己競合 | `airgap_ai_defender.py:654-656`, `840-934` (`_flock_depth`, `_flock_owner_tid`) | `test_r001_reentrant_flock_nested_16_threads_and_timeout` | **VERIFIED (PASS)** |
| **R-002** | 7段階2相WAL（`PREPARED`/`COMMITTED`）と中断時`ACTIVE`復元阻止 | `airgap_ai_defender.py:1012-1348`, `1440-1454` | `test_r002_two_phase_wal_7_steps_and_crash_fault_injection` | **VERIFIED (PASS)** |
| **R-003** | TLA+ / SMT-LIB / Python形式検証器の20不変条件完全化 | `formal/MK1AI_FSM_V32.tla`, `.cfg`, `.smt2`, `mk1_formal_verifier.py` | `formal/mk1_formal_verifier.py`, `test_formal_model_checking_and_refinement_conformance` | **VERIFIED (PASS)** |
| **R-004** | 16スレッド同時Recovery・SIGKILL・I/O遅延・境界値等の異常系試験追加 | `tests/test_v32_formal_and_stress.py:739-1180` | `test_r004_01`〜`test_r004_08` | **VERIFIED (PASS)** |
| **R-005** | 既存テストのV3.2 Dry-Run不変条件（`I-06`）整合性更新 | `tests/test_v2_remediation.py`, `tests/test_airgap_ai_defender.py` | 全回帰テストスイート（491テスト） | **VERIFIED (PASS)** |

---

## 5. `formal/mk1_formal_verifier.py` の実行ログ

- **実行コマンド:** `python3 formal/mk1_formal_verifier.py`
- **終了コード:** `0`
- **実行時間:** `33.94 ms`
- **実測出力:**

```json
{
  "model_checking": {
    "model": "MK1Ai_FSM_V3.2",
    "max_generation_bound": 6,
    "invariants_checked_count": 20,
    "reachable_states_count": 1827,
    "explored_transitions_count": 2267,
    "reached_control_states": [
      "ACTIVE",
      "ARMING",
      "EMERGENCY",
      "ISOLATED",
      "OFF",
      "RECOVERY_APPROVED",
      "RECOVERY_PENDING"
    ],
    "unreachable_control_states": [],
    "invariant_violations_count": 0,
    "invariant_violations": [],
    "liveness_p0_convergence_verified": true,
    "liveness_recovery_reachability_verified": true,
    "elapsed_ms": 33.94
  },
  "v31_counterexamples_count": 6,
  "refinement_conformance": true,
  "refinement_steps_verified": 6
}
```

- **検証結果の要点:**
  - 到達可能状態数 `1,827` 状態、遷移辺数 `2,267` 遷移を網羅探索し、`I-01`〜`I-20` の全20不変条件に対する違反件数は **`0`件**。
  - 全7制御状態（`OFF`, `ARMING`, `ACTIVE`, `EMERGENCY`, `ISOLATED`, `RECOVERY_PENDING`, `RECOVERY_APPROVED`）への到達可能性を確認（未到達状態 `[]`）。
  - Liveness 1（P0ラッチ発火時の2ステップ以内`ISOLATED`収束）: `true`。
  - Liveness 2（正常`ISOLATED`＋未使用トークンからの4段階Recoveryによる`ACTIVE`到達可能性）: `true`。
  - Refinement Conformance（実機`MK1SafetyStateMachine`のネストロック＋WAL `COMMITTED`＋Dry-Run＋P0隔離＋M-of-N Recoveryの6段階射影照合）: `true`。

---

## 6. TLA+・SMT-LIB の静的および実行検証結果

| 対象ファイル | 検証項目 | 確認結果 |
|---|---|---|
| `formal/MK1AI_FSM_V32.tla` (`667 lines`) | `I01`〜`I20` 全20不変条件定義、Recovery 4段階遷移（`ISOLATED -> RECOVERY_PENDING -> RECOVERY_APPROVED -> ARMING -> ACTIVE`）、`wal_status` (`PREPARED`/`COMMITTED`)、Crash/Restart/Fault遷移、Safety (`SafetySpec`) と Liveness (`FairSpec`) の分離 | **PASS**（全20不変条件・12遷移アクション・2活性定理を確認） |
| `formal/MK1AI_FSM_V32.cfg` (`34 lines`) | `SPECIFICATION SafetySpec`、`INVARIANTS I01..I20`、`PROPERTIES L01 L02` の完全対応 | **PASS**（全20不変条件＋2活性プロパティ登録済み） |
| `formal/MK1AI_FSM_V32.smt2` (`595 lines`) | `Post_I01`〜`Post_I20` 全20証明義務定義、Pre-State 22変数＋Post-State 22変数の全11アクション分岐での完全束縛、恒真式の排除、Pre-State仮定とPost-State否定 `(assert (not (and Post_I01 ... Post_I20)))` の分離 | **PASS**（括弧バランス・全変数束縛・全20証明義務を確認） |
| `formal/mk1_formal_verifier.py` (`845 lines`) | Python明示的状態空間モデル検査器による実行検証 | **PASS**（`exit code 0`, `1,827` states, `2,267` transitions, `0` violations） |

---

## 7. 並行・プロセス・異常系試験（`R-001`, `R-002`, `R-004`）の実測結果

`python3 -m unittest tests/test_v32_formal_and_stress.py -v`（全27テスト、`2.212s`、全件PASS）における各試験項目の実測結果は以下の通りです。

| 試験カテゴリー | テストメソッド名 (`tests/test_v32_formal_and_stress.py`) | 試験条件・検証内容 | 実測結果 | 判定 |
|---|---|---|---|---|
| **R-001: RLock / `flock` 再入・16スレッド入れ子・タイムアウト** | `test_r001_reentrant_flock_nested_16_threads_and_timeout` | ① `state_path`設定下で同一スレッド3重ネスト`with fsm._acquire_lock():`（`_flock_depth` `1->2->3->0`、同一FD保持、最外層解放時のみ`flock`解除）<br>② 16スレッド同時2重ネストロック＋`isolate_immediately`<br>③ 別スレッド保持中のロックタイムアウト（`TimeoutError`送出確認） | 自己競合0件、16スレッド完遂、タイムアウト時正確に`TimeoutError`送出 | **PASS** |
| **R-001 / 5.3: 2・4・8プロセス間ロック競合** | `test_5_3_multiprocess_2_4_8_processes_contention` | `multiprocessing` (`fork`) による2・4・8個の独立OSプロセスが同一`state_path`へ同時遷移・永続化 | 全プロセス `exitcode=0`、JSON破損0件、最終状態 `ISOLATED` (`VERIFIED`) | **PASS** |
| **R-002: 7段階2相WAL・`SIGKILL`・書き込み/`replace`/`fsync`失敗** | `test_r002_two_phase_wal_7_steps_and_crash_fault_injection` | ① 7段階WALフック順序検証<br>② サブプロセスで`ACTIVE`遷移中`AFTER_PREPARED_FSYNC`直後に`os.kill(os.getpid(), signal.SIGKILL)` (`kill -9`) 注入→再起動時に`status="PREPARED"`を検知し`ISOLATED` (`FAILED_WAL_INCOMPLETE`)へFail-Closedすることを確認<br>③ `AFTER_STATE_REPLACE_BEFORE_COMMITTED`（Stateファイルが`ACTIVE`に置換済みでJournalが`PREPARED`）でのクラッシュ→再起動時に`ACTIVE`を復元せず`ISOLATED` (`FAILED_WAL_INCOMPLETE`)へFail-Closed<br>④ `os.replace`失敗・`os.fsync`失敗時のロールバックと`ISOLATED`維持 | どの段階でクラッシュ・I/O失敗しても不完全トランザクションから`ACTIVE`が復元されないことを実証 | **PASS** |
| **R-004 (1): 16スレッド同時Recovery** | `test_r004_01_16_threads_concurrent_recovery_exactly_one_succeeds` | 同一隔離イベントに対し16スレッドが`threading.Barrier(16)`で同時に`request_recovery()`を実行 | `outcomes.count(True) == 1`, `outcomes.count(False) == 15`（1件のみ成功、15件拒否） | **PASS** |
| **R-004 (2): P0緊急隔離 vs 永続化I/O遅延** | `test_r004_02_p0_emergency_vs_persistence_io_delay_contention` | `_persistence_io_delay_sec = 0.03` で`ARMING -> ACTIVE`永続化I/O遅延中に別スレッドからP0 `isolate_immediately()`を発火 | P0隔離が確実に完了し、最終状態 `ISOLATED` (`VERIFIED`) | **PASS** |
| **R-004 (3): Kill Switch失敗 vs Recovery競合** | `test_r004_03_kill_switch_failure_vs_recovery_contention` | Recovery検証中（50ms）にP0脅威発生＋`execute_kill_switch`が`False`を返す競合 | Recoveryは中断（`False`）、`evaluate_threat_state`も`False`返却、状態は`ISOLATED`かつ`kill_switch_status == OS_BLOCK_FAILED`、`network_block_confirmed == False` | **PASS** |
| **R-004 (4): `SIGKILL` (`kill -9`) 後のプロセス再起動** | `test_r004_04_sigkill_process_restart_preserves_isolated` | 子プロセスで`ISOLATED`遷移直後に`os.kill(os.getpid(), signal.SIGKILL)`で強制終了後、新規インスタンスを起動 | 再起動後も `current_state == ISOLATED`, `authenticity_status == VERIFIED`, `generation == 4` を完全維持 | **PASS** |
| **R-004 (5): 古い`generation`の上書き攻撃** | `test_r004_05_old_generation_overwrite_attack_detected` | `gen=2` (`ACTIVE`) の正規State/Journalを保存後、`gen=4` (`ISOLATED`) へ遷移し、①Stateのみ`gen=2`で上書き、②StateとJournalの両方を`gen=2`で上書き | ① `FAILED_ROLLBACK` (`ROLLBACK_DETECTED`) → `ISOLATED`<br>② Boot Anchorが検知し `FAILED_ROLLBACK` (`ANCHOR_ROLLBACK_DETECTED`) → `ISOLATED` | **PASS** |
| **R-004 (6): `ENOSPC` / `EROFS` 異常注入** | `test_r004_06_enospc_and_erofs_filesystem_faults_fail_closed` | `OSError(errno.ENOSPC)`（ディスク満杯）および`OSError(errno.EROFS)`（読み取り専用FS）を永続化中に注入 | 両方ともメモリ上で `ISOLATED` (`FAILED_PERSISTENCE`) へFail-Closed遷移 | **PASS** |
| **R-004 (7): ネットワーク遮断確認失敗 (`VERIFICATION_FAILED`)** | `test_r004_07_network_block_verification_failed_and_partial_states` | `_network_block_verifier`が`False`返却または`RuntimeError`送出時の挙動検証 | 例外未捕捉クラッシュなし、`evaluate_threat_state`は`False`返却、`kill_switch_status == VERIFICATION_FAILED`、`network_block_confirmed == False` | **PASS** |
| **R-004 (8): 時計スキュー境界テスト** | `test_r004_08_clock_skew_boundary_conditions` | Quorum Challenge（`issued_at == now + 1`拒否、`now == expires_at + 1`拒否、`now == expires_at` (+300s境界) 受理）およびStateファイル（`+299s`受理、`+301s`拒否） | 全境界値で`I-09`および`_MAX_CLOCK_FUTURE_SKEW_SEC` (`300.0s`) 通りに判定 | **PASS** |

---

## 8. 全回帰テスト結果

対象6テストスイートおよびリポジトリ全体の全ユニットテスト（計34テストファイル・**491テスト**）を実行し、**失敗 `0`件・エラー `0`件**を確認しました。

### 8.1 重点対象6テストスイートの実行結果

| テストファイル | 実行コマンド | 実行テスト数 | PASS | SKIPPED | FAIL / ERROR | 実行時間 | 判定 |
|---|---|---|---|---|---|---|---|
| `tests/test_v32_formal_and_stress.py` | `python3 -m unittest tests/test_v32_formal_and_stress.py -v` | `27` | `27` | `0` | `0` | `2.212s` | **PASS** |
| `tests/test_v3_final.py` | `python3 -m unittest tests/test_v3_final.py -v` | `33` | `33` | `0` | `0` | `0.589s` | **PASS** |
| `tests/test_v3_remediation.py` | `python3 -m unittest tests/test_v3_remediation.py -v` | `7` | `7` | `0` | `0` | `0.031s` | **PASS** |
| `tests/test_v2_remediation.py` | `python3 -m unittest tests/test_v2_remediation.py -v` | `5` | `5` | `0` | `0` | `0.019s` | **PASS** |
| `tests/test_airgap_ai_defender.py` | `python3 -m unittest tests/test_airgap_ai_defender.py -v` | `175` | `161` | `14` (PyTorch optional) | `0` | `0.319s` | **PASS** |
| `tests/test_xdp_ebpf_subsystem.py` | `python3 -m unittest tests/test_xdp_ebpf_subsystem.py -v` | `12` | `12` | `0` | `0` | `0.062s` | **PASS** |

### 8.2 リポジトリ全テストスイート（全34テストファイル）の実行結果

- **バッチ1（FSM V3.2 / V3 / V2 / XDP / Quorum / Quarantine / Firewall / USB Guard 等 32ファイル）:**
  - `Ran 305 tests in 13.590s — OK (skipped=1)`
- **バッチ2（`test_airgap_ai_defender.py` + `test_airgap_ai_defender_6.py` 2ファイル）:**
  - `Ran 186 tests in 2.785s — OK (skipped=14)`
- **合計:** **`491` テスト実行 / `476` PASS / `15` SKIPPED / `0` FAIL / `0` ERROR**

---

## 9. 既存テスト更新箇所の説明（`R-005`）

旧仕様（Dry-Run時に本番状態を変更していた仕様）を前提としていた以下の既存テスト2ファイル・3箇所について、テスト条件を弱めることなくV3.2仕様（不変条件 `I-06`: Dry-Runの本番非干渉性）に合わせて更新しました。

| # | ファイル名・行番号・テスト関数名 | 旧期待値と変更理由 | V3.2 新期待値と対応不変条件 | 対応回帰テスト |
|---|---|---|---|---|
| 1 | `tests/test_v2_remediation.py:32-45`<br>`test_autonomous_p0_isolation_logic` | **旧期待値:** `evaluate_threat_state(..., dry_run=True, score_a=0.995, autonomous=True)` 実行後に本番 `defender._SAFETY_FSM.current_state == ISOLATED` を期待していた。<br>**変更理由:** V3.2（`P0-002`）ではDry-Runが本番`_state`を`ISOLATED`に汚染することを禁止したため。 | **新期待値:**<br>`current_state == ACTIVE`（本番状態非干渉）**かつ** `simulated_state == ISOLATED`（シミュレーション隔離遷移の検証）の2条件を同時に検証。<br>**対応不変条件:** `I-06` (`DryRunNonInterference`) | `tests.test_v2_remediation.TestV2Remediation.test_autonomous_p0_isolation_logic` (**PASS**) |
| 2 | `tests/test_v2_remediation.py:47-84`<br>`test_non_autonomous_requires_quorum` | **旧期待値:** `evaluate_threat_state(..., dry_run=True, score_a=0.995, autonomous=False)` 実行後に本番グローバルフラグ `defender._ISOLATION_APPROVAL_PENDING == True` を期待していた。<br>**変更理由:** V3.2（`I-06`）では`dry_run=True`が本番の承認待ちフラグを汚染しない仕様となったため。 | **新期待値:**<br>① `dry_run=True, autonomous=False` では `triggered_dry == True` かつ本番 `_ISOLATION_APPROVAL_PENDING == False`（非干渉）を検証。<br>② `dry_run=False, autonomous=False` では `triggered == True`、`current_state == ACTIVE`、かつ本番 `_ISOLATION_APPROVAL_PENDING == True` を検証。<br>**対応不変条件:** `I-06` (`DryRunNonInterference`) | `tests.test_v2_remediation.TestV2Remediation.test_non_autonomous_requires_quorum` (**PASS**) |
| 3 | `tests/test_airgap_ai_defender.py:2119-2156`<br>`test_evaluate_threat_state_decays_anomaly_counter_after_cooldown` | **旧期待値:** `_anomaly_counter = 2` 設定後、`evaluate_threat_state("eth0", True, score_a=0.96)` (`dry_run=True`) 呼び出しで本番 `module._anomaly_counter == 1` に減衰することを期待していた。<br>**変更理由:** V3.2（`I-06`）では`dry_run=True`が本番`_anomaly_counter`を変更すると本番P0閾値判定に干渉するため、Dry-Run用`_simulated_anomaly_counter`を分離したため。 | **新期待値:**<br>① `dry_run=True` 呼び出し後、`_simulated_anomaly_counter == 1` に減衰し、本番 `_anomaly_counter == 2` が不変であることを検証。<br>② 続けて `dry_run=False` 呼び出し後、本番 `_anomaly_counter == 1` に減衰することを検証。<br>**対応不変条件:** `I-06` (`DryRunNonInterference`) | `tests.test_airgap_ai_defender.TestAirgapAiDefender.test_evaluate_threat_state_decays_anomaly_counter_after_cooldown` (**PASS**) |

また、`tests/test_v2_remediation.py`, `tests/test_v3_remediation.py`, `tests/test_v3_final.py`, `tests/test_v32_formal_and_stress.py` の `tearDown()` に `defender.toggle_oni_mode(False)` を追加し、テスト間で `ONI_MODE` グローバルフラグが残留しないようクリーンアップを統一しました。

---

## 10. 構文・インポート・環境クリーンアップ確認

- **構文・バイトコードコンパイル検証:**
  - 実行コマンド:
    ```bash
    python3 -m py_compile airgap_ai_defender.py mk1_quorum.py formal/mk1_formal_verifier.py \
      tests/test_v32_formal_and_stress.py tests/test_v3_final.py tests/test_v3_remediation.py \
      tests/test_v2_remediation.py tests/test_airgap_ai_defender.py tests/test_xdp_ebpf_subsystem.py
    ```
  - 結果: **終了コード `0`（構文エラー・インポートエラー `0`件）**
- **環境クリーンアップ確認:**
  - 全テストの永続化・SIGKILL・マルチプロセス試験は `tempfile.TemporaryDirectory()` 内の一時ディレクトリで実行され、`tearDown()` により完全削除されていることを確認しました。
  - ホストのFirewall / Routing / Kernel / NICの変更は一切行っていません。

---

## 11. 残存リスクと制約事項

1. **ハードウェアTPM 2.0 / 外部HSM未接続環境における物理ストレージ全消去耐性:**
   - ソフトウェア単体環境では、State・Journal・Boot Anchor（`.boot_anchor`）の3ファイルによる多層検知を実装していますが、root権限を持つ攻撃者がこれら3ファイルすべてを同時に初期状態へ削除した場合の完全な検知には、ハードウェアTPM 2.0 NVRAMカウンタ（`MK1_TPM_NV_INDEX`）または物理ワンタイムトークンが必要です。
2. **外部モデル検査器バイナリ（TLC / Z3 CLI）の実行環境制約:**
   - 本コンテナ環境にはJava TLCおよびZ3バイナリがプリインストールされていないため、`formal/MK1AI_FSM_V32.tla`（`667 lines`）および `formal/MK1AI_FSM_V32.smt2`（`595 lines`）は構文・変数束縛・全20不変条件の完全性を静的に検証し、等価な遷移関係と全20不変条件を実装したPython明示的状態空間モデル検査器 `formal/mk1_formal_verifier.py` によって `1,827` 到達状態・`2,267` 遷移の全探索検証を実行しました。

---

## 12. 最終判定提案（ユーザー承認待ち）

- **V3.1で報告された全15件の脆弱性（`P0-001`〜`P3-001`）および追加発見された残存課題（`R-001`〜`R-005`）:** すべて実装修正および実測テストが完了しました。
- **形式検証（`formal/mk1_formal_verifier.py`）:** 全20不変条件（`I-01`〜`I-20`）違反 `0`件、Liveness 2項目成立、Refinement Conformance 成立。
- **全回帰・ストレステスト:** 計 `491` テスト中 `476` PASS / `15` SKIPPED / **`0` FAIL / `0` ERROR**。
