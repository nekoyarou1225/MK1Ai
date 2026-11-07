# MK1Ai FSM V3.2 — CRITICAL SECURITY REMEDIATION & INDEPENDENT VERIFICATION REPORT

**Project:** MK1Ai (Project Sovereign-Airgap)  
**Target Architecture:** `MK1SafetyStateMachine` V3.2 + 4-Layer Anti-Rollback Persistence + Formal Verification Suite (`formal/`)  
**Priority Policy:** CORE Isolation > Integrity > Availability > Performance  
**Audit & Verification Date:** 2026-11-07  

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

## 2. 全テスト・検証スイート実行結果サマリ

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
