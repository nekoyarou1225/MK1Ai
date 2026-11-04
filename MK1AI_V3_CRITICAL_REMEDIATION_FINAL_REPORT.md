# MK1Ai (Project Sovereign-Airgap) — V3 Critical Security Remediation & Hardening Final Report

- **監査・修正完了日時**: 2026-11-04
- **対象リポジトリ**: `/app/applet` (`MK1Ai — Project Sovereign-Airgap`)
- **基準ドキュメント**:
  - `MK1Ai (Project Sovereign-Airgap) — 最新完全技術仕様書` (`MK1AI-COMPLETE-SPEC-2026-11-01`)
  - `MK1AI_CURRENT_STATUS_COMPLETE_AUDIT.md`

---

## Section A: 修正前監査結果（READ-ONLY Baseline Audit）

### A.1 リポジトリ・環境ベースライン
- **Git状態**: コンテナワークスペース（`/app/applet`）には `.git` ディレクトリが存在しないため（`git status` は `fatal: not a git repository (or any of the parent directories): .git` で終了コード `128`）、ファイル単位の行数・バイト数・SHA-256ダイジェストを厳密な変更前後ベースラインとして記録した。
- **修正前ファイル状態**:
  - `airgap_ai_defender.py`: 8,401行 / SHA-256 `b59d3bf7a3fc69cfbf1d4261f773f33efec13a97822e48c70cd83e9eb55650c4`
  - `tests/test_v3_final.py`: 156行 / SHA-256 `35bf9780be0d7f63a84402849e141ec390e56e57b5b4a79da97dc7cbbf8cb299`

### A.2 修正前に特定された5つの重大不具合・脆弱性（実コード行番号付き）
1. **[P0-1] `MK1SafetyStateMachine.request_recovery()` の自己デッドロックと競合状態**
   - **場所**: `airgap_ai_defender.py` 旧 L462, L544–L602 (`MK1SafetyStateMachine`)
   - **原因**: `self._lock = threading.Lock()`（非再入可能ロック）を使用していたにもかかわらず、`request_recovery()` が `with self._lock:` を保持した状態で内部から `self.transition_to()`（再度 `with self._lock:` を取得）を呼び出していたため、呼び出しスレッドが永久に自己デッドロックしていた。また `RECOVERY_PENDING` / `RECOVERY_APPROVED` 状態から `EMERGENCY` / `ISOLATED` への緊急割り込み遷移が遷移行列に定義されていなかった。
2. **[P0-2] Dry-Run 実行時の本番 FSM・クールダウン・異常カウンタ汚染**
   - **場所**: `airgap_ai_defender.py` 旧 L516–L542 (`transition_to`), L6104–L6190 (`evaluate_threat_state`)
   - **原因**: `simulated=True` で `transition_to()` を呼んだ際、ディスク永続化のみスキップしてメモリ上の本番 `self._state` を `ISOLATED` に書き換えていた。さらに `evaluate_threat_state(..., dry_run=True)` が本番の `_KILL_SWITCH_EVENT.set()`、`_LAST_KILL_SWITCH_TRIGGER = now`（5秒間のクールダウン）、`_anomaly_counter`、`_LAST_THREAT_SCORE` を更新していたため、Dry-Run 直後の5秒間に到着した本物の脅威がクールダウン判定により無視される脆弱性が存在した。
3. **[P1-3] `RECOVERY_APPROVED` のイベント束縛・有効期限検証・リプレイ防止の欠落**
   - **場所**: `airgap_ai_defender.py` 旧 L544–L602 (`request_recovery`)
   - **原因**: `verify_quorum_bundle()` 呼び出し時に `now` 引数を渡していなかったため、`mk1_quorum.py` 内の `expires_at` 期限切れチェックがスキップされていた。また隔離イベントの `event_id`、`challenge_id`、`policy_version`、`MK1AI-RECOVERY-v1` ドメインプレフィックスの束縛検証、および使用済み承認バンドルのリプレイ防止台帳（`_consumed_recovery_tokens`）が未実装であった。
4. **[P1-4] FSM 永続状態の世代巻き戻し（ファイル丸ごと差し替え）耐性と HMAC 鍵分離の不足**
   - **場所**: `airgap_ai_defender.py` 旧 L463–L514 (`_compute_integrity`, `_save_persistent_state`, `_load_persistent_state`)
   - **原因**: 同一プロセス内のメモリ変数 `self._generation` とのみ比較していたため、過去に保存された正規の `ACTIVE` 状態ファイル（有効な HMAC 付き、低世代）で `fsm_state.json` を上書きしてプロセスを再起動すると、ロールバックを検知できず `ISOLATED` から `ACTIVE` に不正復帰させることが可能であった。
5. **[P1-5] 3ヘッド AI の重みハッシュの対象不足・署名付きマニフェスト未実装・推論パイプラインでの非有限値/次元異常のすり抜け**
   - **場所**: `airgap_ai_defender.py` 旧 L4888–L4925 (`LightweightMultiTaskAI`), L6555–L6588 (`inspect_packet_pipeline`)
   - **原因**: PyTorch 非導入環境（`_DummyTensor`）では `named_parameters()` が空となるため、重みバッファの改竄がハッシュに反映されなかった。また署名付きマニフェスト検証（`create_signed_weights_manifest` / `verify_signed_weights_manifest`）がなく、`inspect_packet_pipeline()` でモデルの重み改竄・`NaN`/`Inf`/範囲外出力・タプル次元異常・推論例外が発生した際に `stage="ai_integrity_failure"` で即座に Fail-Closed 遮断するパスが不完全であった。

---

## Section B: 実施した修正内容（P0-1〜P2-6）

| 項目 | 対象ファイル・クラス/関数 | 実施した修正内容 |
| :--- | :--- | :--- |
| **P0-1: FSM 自己デッドロック解消と並行制御** | `airgap_ai_defender.py` (`MK1SafetyStateMachine`, L463–L835) | `threading.RLock()` とタイムアウト付きコンテキスト `_TimedLockContext` (`_acquire_lock()`) を導入。内部遷移ヘルパー `_transition_to_locked()` を分離し、`request_recovery()` の自己デッドロックを完全解消。`RECOVERY_PENDING` / `RECOVERY_APPROVED` から `EMERGENCY` / `ISOLATED` への緊急割り込み遷移および `isolate_immediately()` を実装。 |
| **P0-2: Dry-Run の完全分離** | `airgap_ai_defender.py` (`MK1SafetyStateMachine._transition_to_locked`, `evaluate_threat_state`, L716–L745, L6260–L6370) | `strict_dry_run_isolation` により永続化対象 FSM では `simulated=True` 時に本番 `self._state`・`self._generation`・永続ファイルを一切変更せず、`self._simulated_state` と `self._last_dry_run_audit` のみを更新。`evaluate_threat_state(dry_run=True)` でも `_KILL_SWITCH_EVENT`、`_LAST_KILL_SWITCH_TRIGGER`、`_anomaly_counter`、`_LAST_THREAT_SCORE` を一切汚染しないよう分離。 |
| **P1-3: `RECOVERY_APPROVED` の厳格化** | `airgap_ai_defender.py` (`MK1SafetyStateMachine.request_recovery`, L836–L925) | `verify_quorum_bundle(..., now=current_ts)` による有効期限検証の強制、`event_id`・`challenge_id`・`policy_version`・`MK1AI-RECOVERY-v1` ドメイン束縛の検証、2名以上の異なる署名者（`len(set(signers)) >= 2`）の強制、`_consumed_recovery_tokens` によるリプレイ拒否、および永続化失敗時の `ISOLATED` ロールバックを実装。 |
| **P1-4: FSM 世代巻き戻し防止と HMAC 保護** | `airgap_ai_defender.py` (`MK1SafetyStateMachine`, L472–L685) | `hmac_key` 引数または環境変数 `MK1_FSM_HMAC_KEY` による鍵管理（状態 JSON 内への鍵保存を禁止）、アトミック書き込み（`.tmp` + `os.replace`）、独立した世代ハイウォーターマークジャーナル `<state_path>.gen_journal`（HMAC 付き）による再起動を跨いだ古い正規状態ファイルの差し替え検知、および `get_security_status_report()` を実装。 |
| **P1-5: 3ヘッド AI の出力・重み完全性検証** | `airgap_ai_defender.py` (`LightweightMultiTaskAI`, `evaluate_threat_state`, `inspect_packet_pipeline`, L5100–L5216, L6264–L6281, L6716–L6805) | パラメータ名・shape・dtype・`_weight_buffers` をソートして決定論的に計算する `compute_weights_hash()`、HMAC 署名付きマニフェスト `create_signed_weights_manifest()` / `verify_signed_weights_manifest()`、`require_baseline` 強制を実装。`inspect_packet_pipeline()` と `evaluate_threat_state()` で重み改竄・`NaN`/`Inf`/範囲外・次元異常・推論例外を検知した際に `block=True, stage="ai_integrity_failure", score=1.0` で Fail-Closed 遮断・自律隔離する機構を実装。 |
| **P2-6: コードクリーンアップ** | `airgap_ai_defender.py` (`evaluate_threat_state`, L6405) | `evaluate_threat_state()` 末尾の重複・到達不能コードを排除し、単一の `return False` に整理。 |

---

## Section C: 変更ファイル一覧・行数・SHA-256 ダイジェスト

| ファイルパス | 役割 | 行数 | SHA-256 ダイジェスト |
| :--- | :--- | ---: | :--- |
| `airgap_ai_defender.py` | メイン防衛エンジン（7状態FSM・3ヘッドAI・DPI・Kill Switch） | 8,622 | `62ce5e3a5159fd0fa1efa5c14b5a89130341d6f7506ab99e406990c22594420a` |
| `tests/test_v3_final.py` | V3 最終セキュリティ回帰テストスイート（全32テスト） | 765 | `01fa038160550f20f932661e34b49861507afb71c9018becd5ae66ff5c87c9b2` |
| `MK1AI_CURRENT_STATUS_COMPLETE_AUDIT.md` | 修正前後の完全技術監査ドキュメント | 70 | `49734dab96ae452e33e56fb73a4dd20d677a7d62d03654b6e37674a6cf6888c3` |

---

## Section D: テスト結果（全112テスト実行証跡）

### D.1 V3 / V2 / P0-P1 セキュリティ回帰テストスイート
- **実行コマンド**:
  ```bash
  python3 -m unittest tests/test_v3_remediation.py tests/test_v3_final.py tests/test_v2_remediation.py tests/test_p0_p1_remediation.py -v
  ```
- **実行結果**: `Ran 51 tests in 0.415s — OK` (51 PASS / 0 FAIL / 0 ERROR)
  - `tests/test_v3_remediation.py`: 8 tests PASS
  - `tests/test_v3_final.py`: 32 tests PASS（既存互換3テスト + 新規必須29テスト `TEST-FSM-001..004`, `TEST-DRY-001..005`, `TEST-RECOVERY-001..006`, `TEST-ROLLBACK-001..005`, `TEST-AI-001..010`）
  - `tests/test_v2_remediation.py`: 5 tests PASS
  - `tests/test_p0_p1_remediation.py`: 6 tests PASS

### D.2 サブシステム回帰テストスイート（XDP/eBPF・Quorum・QKD・Hybrid KEM・Secure Transport）
- **実行コマンド**:
  ```bash
  python3 -m unittest tests/test_xdp_ebpf_subsystem.py tests/test_quorum.py tests/test_qkd_subsystem.py tests/test_hybrid_kem.py tests/test_secure_transport.py -v
  ```
- **実行結果**: `Ran 61 tests in 1.490s — OK` (61 PASS / 0 FAIL / 0 ERROR)
  - `tests/test_xdp_ebpf_subsystem.py`: 12 tests PASS
  - `tests/test_quorum.py`: 12 tests PASS
  - `tests/test_qkd_subsystem.py`: 7 tests PASS
  - `tests/test_hybrid_kem.py`: 6 tests PASS
  - `tests/test_secure_transport.py`: 24 tests PASS

---

## Section E: セキュリティ検証マトリクス（Honesty Rules 準拠）

| 検証領域 | テストID / 検証項目 | 状態分類 | 根拠・証跡 |
| :--- | :--- | :--- | :--- |
| **FSM Concurrency & Deadlock** | `TEST-FSM-001`〜`004` (`RLock` 再入・`request_recovery` 1秒以内完了・16スレッド同時隔離・復旧中の緊急隔離割り込み) | `CONFIRMED` | `tests/test_v3_final.py` にて実スレッド・バリア同期・タイムアウト監視下で検証完了。 |
| **Dry-Run Isolation** | `TEST-DRY-001`〜`005` (本番FSM状態・世代・永続ファイル・クールダウン・再起動後の完全非汚染) | `CONFIRMED` | `tests/test_v3_final.py` にてバイト単位ファイル比較（`bytes_before == bytes_after`）を含め検証完了。 |
| **M-of-N Recovery Binding** | `TEST-RECOVERY-001`〜`006` (2-of-3 Ed25519署名・期限切れ拒否・リプレイ拒否・`event_id`/`challenge_id` 不一致拒否・永続化失敗時 `ISOLATED` 維持) | `CONFIRMED` | `mk1_quorum` 実 Ed25519 鍵ペア・署名検証と統合して `tests/test_v3_final.py` で検証完了。 |
| **FSM Rollback & HMAC** | `TEST-ROLLBACK-001`〜`005` (HMAC改竄・異鍵拒否・世代減少拒否・古い正規ACTIVEファイルの上書き差し替え拒否・欠損/破損JSON Fail-Closed) | `CONFIRMED` | `<state_path>.gen_journal` ハイウォーターマーク照合により再起動後のファイル差し替え検知を検証完了。 |
| **Hardware TPM / NV Counter** | ハードウェア TPM 2.0 モノトニックカウンタとの連携 | `NOT TESTED` | コンテナ環境に物理 TPM デバイスが存在しないため、ファイルベース HMAC ジャーナル（`VERIFIED_JOURNAL`）で検証。物理 TPM 連携は実機環境でのみ検証可能。 |
| **3-Head AI Integrity** | `TEST-AI-001`〜`010` (`NaN`/`Inf`/範囲外/各ヘッド単独隔離・重み1バイト改竄検知・署名付きマニフェスト・ベースライン必須化・次元異常・推論例外 Fail-Closed) | `CONFIRMED` | `evaluate_threat_state` および `inspect_packet_pipeline` の最終 `block=True, stage="ai_integrity_failure"` 到達を検証完了。 |
| **XDP / TC eBPF Dataplane** | Cソース構造・ユーザ空間エミュレータ（IPv6拡張ヘッダ、VLAN、断片化、Dead-Man Switch、TC Egress Lockdown） | `PARTIALLY VERIFIED` | Cソース構造と Python エミュレータは `test_xdp_ebpf_subsystem.py`（12テスト）で `CONFIRMED`。実 Linux カーネル BPF Verifier ロードおよび物理 NIC アタッチは非特権コンテナのため `NOT TESTED`。 |

---

## Section F: 残存リスクと今後の推奨事項（Remaining Risks）

1. **物理ホスト上での同一ディスク同時削除攻撃（ジャーナル＋状態ファイル同時削除）**
   - 現在のロールバック保護は `<state_path>.gen_journal` の HMAC 付きハイウォーターマークにより「古い正規 `fsm_state.json` の上書き差し替え」を確実に検知・遮断（`FAILED_ROLLBACK` -> `ISOLATED`）するが、root 権限を持つ攻撃者が状態ファイルとジャーナルファイルの双方を同時に削除した場合や、ハードウェア電源断からのコールドブート時には物理 TPM 2.0 NV カウンタが必要となる。実機デプロイ時には TPM 2.0 NV Index または HSM カウンタへのバインドを推奨する。
2. **非特権コンテナ環境における OS レベル NIC 遮断コマンドの制限**
   - 非 root 環境（`os.geteuid() != 0` かつ特権エージェント未起動）では `ip link set <iface> down` 等のカーネルネットワーク操作は失敗するが、本修正により論理 FSM 状態（`MK1SafetyStateMachine.ISOLATED`）およびパケット検査パイプラインは OS コマンドの成否にかかわらず確実に Fail-Closed 隔離状態へ遷移する。実運用時は root 権限または特権エージェント（`_PRIVILEGED_AGENT_ACTIVE`）を有効化して起動すること。

---

## Section G: 環境・Git・データ保全確認

- **Git 操作の遵守**: `git reset`, `git clean`, `git restore`, `checkout`, `commit`, `push` 等の履歴破壊・外部送信操作は一切実行していない。
- **ホスト環境・ネットワーク保全**: ホスト OS の Firewall / Routing / Kernel / 物理 NIC 設定の変更、外部ネットワーク通信、依存パッケージの無断追加は一切行っていない。
- **本番データ・モデル保全**: すべての回帰テストは `tempfile.TemporaryDirectory()` 上の一時ファイルを使用し、リポジトリ内の既存モデル重み・学習データ・設定ファイルを一切変更・削除していない。
