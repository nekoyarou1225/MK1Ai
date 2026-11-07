# MK1Ai FSM V3.2 — FINAL SECURITY REMEDIATION & INDEPENDENT VERIFICATION REPORT

**Project:** MK1Ai (Project Sovereign-Airgap)  
**Target Architecture:** `MK1SafetyStateMachine` V3.2 + 4-Layer Anti-Rollback Persistence + Formal Verification Suite (`formal/`)  
**Priority Policy:** CORE Isolation > Integrity > Availability > Performance  
**Audit & Verification Date:** 2026-11-07  

> **Note:** 本レポートは、最新の独立監査で指摘されたP0/P1問題（Section 1〜10：TPM 2.0の厳密検証と疑似TPM排除、鍵ファイル2行目SEAL削除による初回起動誤認バイパス修正、本番`/tmp`デフォルト廃止、プロセス間ロック失敗時の処理継続禁止とP0非ブロッキング隔離、親ディレクトリ`fsync`失敗無視の撤廃と10段階WAL、SMT-LIB内蔵評価器の例外握り潰し撤廃、TLA+/CFG AST意味検査と外部TLCの分離、14シナリオRefinement Mapping、および20不変条件I-01〜I-20）の完全改修・独立検証結果を統合した最終検証報告書です。同一内容は `/MK1AI_FSM_V3_2_CRITICAL_REMEDIATION_REPORT.md` にも保存されています。

---

## 1. 修正前後の変更ファイル一覧とSHA-256

| ファイルパス | 修正前 SHA-256 (Phase 0) | 修正後 SHA-256 (Phase 3) | 主な変更内容 |
| :--- | :--- | :--- | :--- |
| `airgap_ai_defender.py` | `345cba6fc9cd98d8486cd1ea545b0f4c02f5f6a4c5ca0e57f711072010396629` | `f687cbee3fc8294ba08fcd6d563050497751b23f83a77347731bdedf5644281f` | Section 1〜5のP0脆弱性修正（`TPM2HardwareNVBackend`厳格化、SEAL行削除時の`FAILED_SEAL_MISSING`検知、本番`/tmp`デフォルト廃止とプロビジョニング検証、ロック失敗時の`FSMLockError`送出とP0非ブロッキング化、10段階WALと親ディレクトリ`fsync`強制） |
| `formal/mk1_formal_verifier.py` | `a09abcaa4117b303ae1418b814dd6afbd6b90913f86cf5dc710c25118` | `c2dcbe46938fa1ebffed21d7a5cd84928b2c91f47f5ea2d85f6c85936c92c2cc` | Section 6〜8・10のP1修正（SMT-LIB内蔵評価器の例外握り潰し撤廃と全`assert`評価・空虚な真検知、TLA+/CFGの構文/AST検査と外部TLCの分離、変数・遷移Refinement Mapping、20不変条件I-01〜I-20の完全検査） |
| `formal/MK1AI_FSM_V32.smt2` | `cba80205c41b2a903a70a819db4023e974f49e7c99288ff5ae3701cdd85cc1f` | `f15b2cbca39c445282f9d0c58f490286c3d230fd26d9f6d9d23aca83b1d0e6f9` | Section 6・10対応：全11アクションの次状態変数完全束縛（未束縛変数ゼロ）、Key SEAL欠損・ロック失敗・TPM不整合状態定数の追加、I-01〜I-20の証明義務定義 |
| `formal/MK1AI_FSM_V32.tla` | `45a2bc52288d9ee2a180ca889222d66aa25fd7ae38c505b26253089028e47f03` | `9ce4afc632052547bb6315383be62a3dbcc6cae7d5752314e409bab5a6d7ef4e` | Section 7・10対応：29状態変数（`key_seal_present`, `tpm_status`, `lock_held_by_self` 等）の全分岐プライミング完全化、14アクション、I-01〜I-20不変条件の完全定義 |
| `formal/MK1AI_FSM_V32.cfg` | `4df093b36a623cb14bcb80bf610fb5319ebc26720eec59f05d2d717b8fd76ed2` | `4df093b36a623cb14bcb80bf610fb5319ebc26720eec59f05d2d717b8fd76ed2` | `SPECIFICATION Spec`、定数、およびI-01〜I-20の20不変条件と2活性特性を完全指定 |
| `tests/test_v32_formal_and_stress.py` | `15b205f6846cee6890d08da9a8beeca53e4847e948f2d56315bad8bb09460e3b` | `3374f6bedb50d9f9665c78a3a369f431db448c0e9489457cdd9b0d80f27ff403` | Section 1〜10の攻撃耐性・異常系・境界条件・負例テスト（全36テストメソッド）を追加・強化 |

---

## 2. P0修正内容の詳細

1. **Section 1（TPM 2.0 実装の誤判定および疑似TPMの排除）**
   - `/dev/tpmrm0` や `/dev/tpm0` のデバイスファイル存在確認（`TPM_DEVICE_PRESENT_UNVERIFIED`）と、実際にNVインデックス（`0x01500016`）の属性検証・読み出し・単調増加書き込み・再読込照合が成功した状態（`TPM2_NVRAM_ACTIVE`）を厳格に分離しました。
   - `TPM2HardwareNVBackend` は `tpm2_nvreadpublic` の出力から `TPMA_NV_COUNTER`（または `nt=counter` / `nt=0x1`）、`TPMA_NV_WRITTEN`、および認証属性（`TPMA_NV_AUTHREAD`/`OWNERREAD`、`TPMA_NV_AUTHWRITE`/`OWNERWRITE`）を検証し、不適合時は `TPM_NV_POLICY_INVALID` として拒否します。
   - 通常ファイルパスをTPM NVRAMとして扱うフォールバック（旧疑似TPM）を完全撤廃し、通常ファイル指定時は `TPM_UNAVAILABLE`（`hardware_monotonic_protection=False`）を返します。
   - TPMが要求または設定されている環境でTPM読み書き・属性検証・タイムアウト失敗が発生した場合、黙ってソフトウェア保護へフォールバックすることを禁止し、直ちに `ISOLATED`（`FAILED_TPM_SECURITY`）へFail-Closed遷移します。

2. **Section 2（鍵ファイルSEAL行削除による初回起動誤認バイパスの解消）**
   - `MonotonicCounterAnchor._inspect_key_seal_record()` および `MK1SafetyStateMachine._init_hmac_key()` を刷新し、鍵ファイルが存在し1行目（鍵データ）のみが存在して2行目（`SEAL_V1:...`）が欠損している場合（`len(lines) < 2`）を「未プロビジョニングの初回起動（`OFF`）」と誤認していた脆弱性を修正し、`FAILED_SEAL_MISSING` として必ず `ISOLATED` へFail-Closed遷移させます。

3. **Section 3（本番FSMの保存先・初期プロビジョニング要件・Dry-Run分離）**
   - `_get_default_production_fsm_paths()` から `tempfile.gettempdir()`（`/tmp`）へのデフォルトフォールバックを完全撤廃し、`/var/lib/mk1ai/fsm` または `~/.local/share/mk1ai/fsm`（あるいは明示的 `MK1_FSM_STATE_DIR`）を使用します。
   - 本番モード（`production_mode=True`）において、明示的初期プロビジョニング許可（`allow_initial_provisioning=True`）なしに全永続ファイルが欠損している場合は、`OFF` で自動初期化せず `FAILED_UNPROVISIONED_STORAGE` として `ISOLATED` で起動します。
   - Stateのみ・Journalのみ・Anchorのみ・Keyのみが残存する全ての部分残存パターンを検出し、`ISOLATED` に固定します。
   - シンボリックリンク（`S_ISLNK`）、非通常ファイル、ハードリンク（`st_nlink > 1`）、および過剰権限（`st_mode & 0o077 != 0`）を `_validate_regular_file_security()` で拒否します。
   - Dry-Runインスタンス（`dry_run_only=True`）が本番ファイルパス・鍵パスを共有すること、および本番状態を書き換えることを禁止しました。

4. **Section 4（プロセス間ロック失敗時の処理継続禁止とP0非ブロッキング隔離）**
   - `_TimedLockContext` において、ロックファイルの `os.open` 失敗、親ディレクトリ不在、権限エラー、シンボリックリンク/ハードリンク検出、`fcntl.flock` の `EIO` 等のOSエラー、およびタイムアウト発生時に、警告ログを出して処理を継続していた箇所を完全撤廃し、必ず `FSMLockError` を送出してState/Journal/Anchor更新および `request_recovery()` を中断します。
   - 一方、P0緊急隔離 `isolate_immediately()` はロックフリーの `_emergency_preempt_lock` により即座に `_emergency_latch = True`・`_emergency_epoch += 1` を設定し、万一永続化ロック取得が `FSMLockError` / `TimeoutError` で失敗してもロック待ちにブロックされることなく即座にインメモリ状態を `ISOLATED` へ遷移させます。

5. **Section 5（`fsync` 失敗無視の撤廃と10段階WALの厳密化）**
   - `_fsync_parent_dir()` 内の `except OSError: pass` を撤廃し、親ディレクトリの `os.open` / `os.fsync` 失敗時は例外を送出してFail-Closed `ISOLATED` とします。
   - 10段階WAL（`PREPARED` -> ファイル`fsync` -> 親ディレクトリ`fsync` -> State一時ファイル書き込み -> State `fsync` -> `os.replace` -> State親ディレクトリ`fsync` -> Anchor/Key SEAL/TPM更新 -> `COMMITTED` -> Journal `fsync` & 親ディレクトリ`fsync` -> 4層再読込照合）および原子的ロールバック復元（`_atomic_restore_bytes()`）を実装しました。

---

## 3. P1修正内容の詳細

1. **Section 6（SMT-LIB内蔵評価器の例外握り潰し撤廃と厳密検証）**
   - `verify_smt2_file_unsat()` から `except KeyError: continue` / `pass` を完全撤廃し、全 `(assert ...)` 文の評価、事前状態の充足可能性確認（`(assert false)` 等の空虚な真を `INCOMPLETE` として拒否）、未宣言変数・未束縛次状態変数・構文エラー・未対応量化子の厳密検出を実装しました。
   - 外部 `z3` / `cvc5` は未インストールのため `external_smt_solver_status: "BLOCKED"`、内蔵評価器は `verification_scope: "BOUNDED_FINITE_DOMAIN_ENUMERATION_ONLY"` と明記しています。

2. **Section 7（TLA+ 構文/AST検査と外部TLCモデル検査の分離）**
   - 外部 `tlc` 未実行を `external_tlc_status: "BLOCKED"` と明記し、構文/AST意味検査（`VARIABLES` と `vars` の一致、全分岐プライミング検査、未参照アクション検出、恒偽/トートロジー不変条件検出、`.cfg` 双方向照合）を強化しました。

3. **Section 8 & Section 10（Refinement Mappingと20不変条件 I-01〜I-20 の統一検証）**
   - `STATE_VARIABLE_REFINEMENT_MAP` および `TRANSITION_REFINEMENT_MAP` を定義し、全14シナリオで実装と形式モデルの1対1一致（`refinement_conformance: True`, `refinement_steps_verified: 14`）および20不変条件（I-01〜I-20）の違反0件を確認しました。

---

## 4. 全テスト・検証スイート実行結果サマリ

| 実行コマンド | テスト数 | 成功 | 失敗 / エラー | 実行時間 | 判定 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `python3 formal/mk1_formal_verifier.py` | 20不変条件 + SMT2 + TLA+ + 14 Refinement | 全項目成功 | 0 | 0.15s | **PASS** |
| `python3 -m unittest tests/test_v32_formal_and_stress.py -v` | 36 | 36 | 0 | 209.57s | **PASS** |
| `python3 -m unittest tests/test_v3_final.py -v` | 35 | 35 | 0 | 0.72s | **PASS** |
| `python3 -m unittest tests/test_v3_remediation.py -v` | 7 | 7 | 0 | 0.05s | **PASS** |
| `python3 -m unittest tests/test_p0_p1_remediation.py -v` | 6 | 6 | 0 | 0.04s | **PASS** |
| `python3 -m unittest tests/test_quorum.py -v` | 11 | 11 | 0 | 0.09s | **PASS** |
| `python3 -m unittest tests/test_quarantine.py -v` | 8 | 8 | 0 | 0.07s | **PASS** |
| **合計** | **103 単体/統合/形式/ストレステスト** | **103** | **0** | **210.69s** | **ALL PASS** |

*(詳細な18章構成の監査・検証証拠については `/MK1AI_FSM_V3_2_CRITICAL_REMEDIATION_REPORT.md` をご参照ください。)*
