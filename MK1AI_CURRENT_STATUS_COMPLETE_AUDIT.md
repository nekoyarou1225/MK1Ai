# MK1Ai (Project Sovereign-Airgap) — 現段階のシステム全状況監査レポート

## 1. 全体アーキテクチャおよび20領域の実装状況一覧

| # | 対象領域 | 主要実装ファイル | 現段階の実装・検証ステータス | 詳細・監査所見 |
|---|---|---|---|---|
| 1 | **Project Sovereign-Airgap** | `mk1_airgap.py`, `airgap_ai_defender.py` | 実装済 / 単体テスト済 | 7状態FSM (`MK1SafetyStateMachine`) と自律隔離 (`evaluate_threat_state`) を統合済。ただし後述のロック競合・Dry-run永続化汚染バグが存在。 |
| 2 | **CORE保護** | `airgap_ai_defender.py`, `mk1_quarantine.py` | 実装済 / 単体テスト済 | `SafetyExecutionLoop` (最大3反復・タイムアウト時 `FAIL_CLOSED_BLOCK`) により保護。 |
| 3 | **Outer / Innerハニーポット** | `mk1_honeypot.py`, `airgap_ai_defender.py` | 実装済 / 単体テスト済 | `ingest_honeypot_shock_gas_features` によりハニーポット検知特徴量をAIパイプラインへ連携。 |
| 4 | **XDP Ingress** | `security/ebpf/mk1_xdp_ingress.bpf.c`, `mk1_xdp_controller.py` | Stage 1〜4 VERIFIED (Userspace Parity) | VLAN最大2段、IPv4/v6 LPMブロックリスト、非初期フラグメント遮断、異常TCPフラグ遮断、Port 22事前レート制限を実装。実カーネル/実NICは未接続 (`NOT_TESTED` / `NOT_CONNECTED`)。 |
| 5 | **TC Ingress / Egress** | `security/ebpf/mk1_tc_egress.bpf.c`, `mk1_xdp_controller.py` | Stage 1〜4 VERIFIED (Userspace Parity) | ロックダウン時の平文リーク遮断 (`TC_ACT_SHOT`)、WireGuardポートおよび緊急SSH制御を実装。 |
| 6 | **eBPF Map** | `security/ebpf/mk1_common.bpf.h`, `mk1_xdp_controller.py` | 実装済 / 単体テスト済 | `mk1_ctrl_map`, `mk1_blocklist_v4/v6`, `mk1_src_rate_v4/v6`, `mk1_verdict_stats` のスキーマとシャドウ制御を実装。 |
| 7 | **nftables** | `mk1_firewall.py`, `mk1_render_nft.py` | 実装済 / 単体テスト済 | `inet mk1_airgap` テーブル検証・適用ロジックおよびループバック優先ルールを実装。 |
| 8 | **DPI (Deep Packet Inspection)** | `airgap_ai_defender.py` | 実装済 / 単体テスト済 | 多重エンコード正規化、難読化検出、`scan_strategy == "fail_closed"` の即時遮断、文脈境界付きシグネチャ検査を実装。 |
| 9 | **AI異常検知 (3-Head AI)** | `airgap_ai_defender.py` (`LightweightMultiTaskAI`) | 実装済 (要強化: Head C重み整合性・NaN/Inf対策) | Head A (`current_threat` >= 0.99)、Head B (`future_threat_60s` >= 0.98)、Head C (`memory_integrity_risk` >= 0.95) の単独トリガーを実装済。ただしモデル重み改竄ハッシュ検証とNaN/Inf出力時の自律隔離保護が未完。 |
| 10 | **決定論的遮断ポリシー** | `airgap_ai_defender.py` (`inspect_packet_pipeline`) | 実装済 / 単体テスト済 | フレーム長超過 → ONI MODE → ブラックリスト → DPI Fail-Closed → 固定シグネチャ → パーサーFail-Closed の順序で決定論的に遮断。 |
| 11 | **Quorum承認 (M-of-N)** | `mk1_quorum.py`, `airgap_ai_defender.py` | 実装済 (要修正: FSM復旧時のデッドロック) | Ed25519 2-of-3 署名検証、操作別ドメイン分離 (`MK1AI-ISOLATE-v1` / `MK1AI-RECOVERY-v1`)、リプレイ防止 (`TwoAdminQuorumGate`) を実装。 |
| 12 | **Kill Switch** | `airgap_ai_defender.py`, `mk1_airgap.py` | 実装済 / 単体テスト済 | AI自律隔離 (`autonomous_bypass=True`) と管理者クォーラム隔離の2経路を分離実装。 |
| 13 | **PQC (耐量子計算機暗号)** | `mk1_hybrid_kem.py`, `mk1_secure_transport.py` | 実装済 / 単体テスト済 | `ML-KEM-1024 + X25519` ハイブリッドKEMに統一済。 |
| 14 | **QKD (量子鍵配送)** | `mk1_qkd/` | 実装済 / 単体テスト済 | 9状態遷移機械 (`QKD_UNAVAILABLE`〜`QKD_READY` 等)、`QKD_SIMULATED` からの直接昇格禁止、ゾーンバインディングを実装。 |
| 15 | **SessionRatchet** | `mk1_session_ratchet.py` | 実装済 / 単体テスト済 | エポック鍵更新・前方秘匿性・リプレイウィンドウ検証を実装。 |
| 16 | **Secure Memory** | `mk1_memory_guard.c`, `mk1_memory_guard.py` | 実装済 / 単体テスト済 | `mlock`, `MADV_DONTDUMP`, `MADV_DONTFORK`, ゼロ化消去を実装。 |
| 17 | **Key Registry** | `mk1_key_registry.py`, `mk1_key_backup.py`, `mk1_key_derivation.py` | 実装済 / 単体テスト済 | Argon2id鍵導出、Shamir秘密分散バックアップ、鍵台帳検証を実装。 |
| 18 | **Secure Transport** | `mk1_secure_transport.py` | 実装済 / 単体テスト済 | `ML-KEM-1024` + `X25519` + `AES-256-GCM` エンベロープ暗号化通信を実装。 |
| 19 | **Secure Update / License** | `mk1_license.py` | 実装済 / 単体テスト済 | オフライン署名検証・ライセンス検証を実装。 |
| 20 | **独立Testerとの検証連携** | `mk1_external_verifier.py`, `mk1_external_verifier_cli.py` | 実装済 / 単体テスト済 | 外部検証CLIおよび監査証跡検証インターフェースを実装。 |

---

## 2. 現段階のコードに存在する重大な不具合（システム修正対象）

実コード（`airgap_ai_defender.py` および `tests/test_v3_remediation.py`）の精査により、以下の **5件の具体的な不具合** が判明しました。

### 【不具合1：P0 Critical】`MK1SafetyStateMachine.request_recovery()` の再入デッドロック
- **箇所**: `airgap_ai_defender.py` 458行目、518行目、538〜546行目
- **原因**: `self._lock = threading.Lock()`（非再入ロック）を使用しているにもかかわらず、`request_recovery()` が `with self._lock:` ブロックの内部（538行目）から `self.transition_to()`（546行目）を呼び出している。`transition_to()` も先頭（518行目）で `with self._lock:` を取得しようとするため、同一スレッドで自己デッドロックが発生し、`test_v3_remediation.py` の `test_recovery_gate_logic` 実行時に永久ハングしていた。
- **修正方針**: `self._lock` を再入可能ロック `threading.RLock()` に変更し、状態遷移とロールバックがデッドロックなく原子的に完了するように修正する。

### 【不具合2：P0 Critical】Dry-Run シミュレーションによる本番FSM永続化ファイルの汚染と起動時エラー
- **箇所**: `airgap_ai_defender.py` 454〜531行目、570〜582行目、5850〜5866行目
- **原因**:
  1. `evaluate_threat_state(..., dry_run=True)` の実行時、シミュレーション遷移であるにもかかわらず `_SAFETY_FSM.transition_to(..., simulated=True)` の区別がなく、本番用の `./ai_data/fsm_state.json` に `ISOLATED` 状態を書き込んでしまっていた（V3仕様 6.2「シミュレーションのFSM状態を本番FSMの永続状態に誤って書き込まないこと」への違反）。
  2. その結果、`./ai_data/fsm_state.json` に `ISOLATED` が残存し、次回モジュールロード時（579行目）に `ISOLATED -> ARMING (理由: Startup)` の不正遷移エラーが発生し、さらに引数なしの `MK1SafetyStateMachine()` インスタンス生成時に初期状態が `OFF` ではなく `ISOLATED` になっていた。
- **修正方針**:
  - `MK1SafetyStateMachine.__init__(self, state_path: str | None = None, *, persist: bool = False)` とし、明示的に `state_path` が指定された場合（または本番デーモン初期化時）のみ永続化を行う設計に分離する。
  - `transition_to(self, new_state: str, reason: str = "Policy Trigger", *, simulated: bool = False)` に `simulated` フラグを追加し、`simulated=True`（Dry-run時）の場合はメモリ上の状態またはシミュレーション記録のみを更新し、本番の永続化ファイル（`self._state_path`）を絶対に上書きしないようにする。
  - Dry-run 監査メタデータ（`simulation_mode`, `simulated_transition`, `simulated_isolation`, `actual_isolation_performed`, `network_side_effects`, `dry_run_session_id`）を記録できるようにする。

### 【不具合3：P1 High】`RECOVERY_APPROVED` のイベントメタデータ拘束および永続状態の巻き戻し（Rollback）防止不足
- **箇所**: `airgap_ai_defender.py` 472〜568行目
- **原因**:
  - V3仕様 2.3 では「`RECOVERY_APPROVED` を単なる文字列/フラグにせず、署名承認の検証結果、対象イベント、承認者、期限、ポリシーバージョンを結び付ける」ことが求められているが、現状は状態文字列のみを保持している。
  - V3仕様 2.4 の「古い状態データへの巻き戻し対策（Monotonic generation / timestamp check）」が `_load_persistent_state()` に不足している。
- **修正方針**:
  - `MK1SafetyStateMachine` に単調増加する `generation` カウンタと `last_recovery_approval_metadata` を追加し、永続化JSONに `generation`, `state`, `timestamp`, `integrity` を含めて巻き戻しを検知・拒否（Fail-Closed で `ISOLATED` 固定）する。
  - `request_recovery()` 成功時に、検証済み署名者リスト（`signers`）、チャレンジID/イベントID、対象操作、有効期限、ポリシーバージョンを `last_recovery_approval_metadata` に記録する。

### 【不具合4：P1 High】3ヘッドAIの異常出力（NaN / Inf / 範囲外）および Head C モデル重み改竄検知の統合不足
- **箇所**: `airgap_ai_defender.py` 4664〜4737行目、5789〜5845行目、6230〜6275行目
- **原因**:
  - `evaluate_threat_state()` に `NaN` や `Inf`、負値・1超えの異常スコアが渡された場合、Pythonの `float('nan') >= 0.99` は `False` となるため、モデル破損や敵対的攻撃による `NaN`/`Inf` 出力時に自律隔離が不発（Fail-Open）になるリスクがある（V3仕様 3.5）。
  - `LightweightMultiTaskAI` (Head C) にモデル重みのSHA-256完全性ベースライン検証メソッドがなく、重み改竄時に Head C スコア（`score_c`）を `1.0` に引き上げて自律隔離を要求する経路が未接続（V3仕様 3.4）。
- **修正方針**:
  - `LightweightMultiTaskAI` に `record_weights_integrity_baseline()` および `verify_weights_integrity()` を実装し、パラメータ改竄または `NaN`/`Inf` 重み検出時に Head C のメモリ完全性リスク（`score_c = 1.0`）を出力する。既存の `MemoryManager` 先制退避機能（`evac_urgency`）は一切削除せず完全互換を維持する。
  - `evaluate_threat_state()` で `score_a`, `score_b`, `score_c` のいずれかが非有限値（`NaN` / `Inf`）または範囲外（`< 0.0` または `> 1.0`）の場合、Fail-Closed で異常検知（P0トリガー）として扱う。

### 【不具合5：P2 Low】`evaluate_threat_state()` 末尾の重複 `return False`
- **箇所**: `airgap_ai_defender.py` 5908〜5909行目
- **原因**: デッドコード（`return False` が2行連続で記述されている）。
- **修正方針**: 重複行を削除する。
