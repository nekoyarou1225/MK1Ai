# MK1AI_FINAL_REPORT_CONSISTENCY — Final Security Report Consistency Audit

## 1. 監査の目的と前提条件

本報告書は、提出済みの `MK1AI_REMEDIATION_REPORT.md` および関連5報告書（計6報告書）と、リポジトリ内の実ソースコード・単体テスト定義・ファイルハッシュ・実行環境を直接照合した**読み取り専用の独立最終監査報告書**である。

- **監査モード**: 読み取り専用（ソースコード変更・テスト期待値変更・外部通信・パッケージ追加・XDPロード・nftables実適用・Git変更操作は一切実施していない）
- **Gitメタデータの有無**: ワークスペース直下に `.git` ディレクトリは存在しない（`os.path.exists("/app/applet/.git") == False`）。したがって、変更前後の比較はGit履歴ではなく、初期スナップショット（128ファイル）と現在値のバイトサイズ・SHA-256ハッシュ照合に基づく。

---

## 2. 既存6報告書の横断的整合性監査

| 対象報告書 | 記載されていた不整合・誇張・欠落 | 実コード照合による事実（修正後の正確な評価） |
|---|---|---|
| `MK1AI_REMEDIATION_REPORT.md` | 1. 修正サマリ表で複数項目を「残存リスクなし」と記載<br>2. 変更統計を「11 files changed」としつつハッシュ表に6ファイルのみ記載<br>3. `mk1_quorum.py` の変更前サイズを `15,826 B` と誤記 | 1. DPI `fail_closed` 誤遮断・DoS、暗号通信未検査、フラグメント未再構成、`ONI_MODE` 二重管理、`feature_vector[9]` メモリ高負荷時Self-DoS、暗号/PyTorch/nftables/XDPの `NOT TESTED`、Kill Switch Dry-Run固定など、**「残存リスクなし」と言える項目は存在しない**。<br>2. 実際の変更済み既存ファイルは **6ファイル**、残り5ファイルは調査のみ（未変更）、これとは別に未追跡（Untracked）ファイルが作成されていた。<br>3. `mk1_quorum.py` の正確な変更前サイズは **`14,898 B`**（変更後 `15,648 B`、差分 `+750 B`）。 |
| `MK1AI_XDP_GAP_ANALYSIS.md` | XDP未実装の根本原因分析自体は正確だが、Python側修正で攻撃を「遮断」できるかのような表現が混在 | `airgap_ai_defender.py:5245` は `socket.AF_PACKET, socket.SOCK_RAW` によるクローン `sk_buff` の受動監視であり、Pythonが `block=True` を返してもカーネル内の元パケットはアプリケーションへ到達する（インライン遮断は未実装）。 |
| `MK1AI_XDP_REDESIGN.md` | 提案されたeBPF Cコード案（`mk1_xdp_ingress.bpf.c`）を「本番投入可能」と記載 | 1. リポジトリ内に `.bpf.c` / `.bpf.o` は **0ファイル（未実装・`NOT TESTED`）**。<br>2. 設計書内のCコード案自体にも、① TCP SYN rate-limitが `dport == 22 || dport == 8006` を無条件バイパスする欠陥、② IPv6 (`ETH_P_IPV6`) 検査の欠落、③ IPv4フラグメント (`frag_off & 0x3FFF`) 未検査の3点の設計欠陥が存在する。 |
| `MK1AI_XDP_ENFORCEMENT_MATRIX.md` | XDP / TC / nftables / Python の多層連携マトリクスを記載 | XDP層・TC層・BPF Map共有はすべて **未実装（`DESIGN ONLY` / `NOT TESTED`）**。`nftables` 層も文字列生成とモックテストのみで実カーネル適用は **`NOT TESTED`**。さらに `mk1ai_quarantine`（priority `-10`）と `mk1ai_egress`（priority `0`）を同時適用すると `management_safe_harbor` の応答通信が `mk1ai_egress` でDropされるポリシー競合が存在する。 |
| `MK1AI_REGRESSION_REPORT.md` | 「248 PASS (0 FAIL, 22 SKIPPED)」と記載し、Webプレビュー（`app.py`）では `REG-04` と `REG-06` が表から欠落 | 1. `248` は実行されたテスト総数であり、内訳は **`226 PASS` + `22 SKIPPED` = `248`（0 FAIL）**。<br>2. `cryptography` / `pqcrypto` / `flask` 未導入および非root環境のため、另有11テストファイル（計49テストメソッド）が `248` 件の母数から除外（`NOT TESTED`）されている。<br>3. `REG-04` と `REG-06` は `tests/test_airgap_ai_defender.py` には存在するが `app.py` のライブ表示テーブルから漏れていた（本報告書第5章で完全補完）。 |
| `MK1AI_PERFORMANCE_ROADMAP.md` | XDP + Python 하이브리드構成の性能目標を提示 | 実測ベンチマークは未実施（`NOT TESTED`）。さらにPython側では `TORCH_AVAILABLE = False` のため `_TorchStub` が動作しており、実PyTorch推論レイテンシやGPU/CPU負荷は **`NOT TESTED`**。 |

---

## 3. `ONI_MODE` の状態二重管理（Boolean と `threading.Event`）の監査

### 3.1 実コードの構造（`airgap_ai_defender.py:430–457`）

```python
_ONI_MODE_ACTIVE = threading.Event()

def ONI_MODE_is_active() -> bool:
    return bool(ONI_MODE) or _ONI_MODE_ACTIVE.is_set()

ONI_MODE = _ONI_MODE_ACTIVE.is_set()

def toggle_oni_mode(activate: Optional[bool] = None):
    global ONI_MODE
    if activate is None:
        activate = not ONI_MODE_is_active()
    else:
        activate = bool(activate)
    ONI_MODE = activate
    if activate:
        _ONI_MODE_ACTIVE.set()
    else:
        _ONI_MODE_ACTIVE.clear()
```

### 3.2 残存している競合・状態不整合（3点）

1. **論理OR（`bool(ONI_MODE) or _ONI_MODE_ACTIVE.is_set()`）による片側ラッチ（解除不能）バグ**
   - `ONI_MODE`（モジュールグローバル `bool`）と `_ONI_MODE_ACTIVE`（`threading.Event`）の2つのミュータブルな状態変数が並存している。
   - 外部コードや既存単体テスト（例：`tests/test_airgap_ai_defender.py:2700` の `test_packet_inspection_pipeline_blocks_immediately_in_oni_mode`）は `with mock.patch.object(module, "ONI_MODE", True):` のように `module.ONI_MODE` を直接書き換える。
   - もし一方の経路が `module.ONI_MODE = True` を直接代入した後に別スレッドが `_ONI_MODE_ACTIVE.clear()` のみを呼んだ場合（または逆）、`ONI_MODE_is_active()` は論理ORをとるため **永久に `True` のまま解除されない**。
   - 逆に `_ONI_MODE_ACTIVE.set()` が呼ばれた状態で外部から `module.ONI_MODE = False` が直接代入されると、`module.ONI_MODE` の参照値は `False` であるにもかかわらず `ONI_MODE_is_active()` は `True` を返し続ける（**状態の分裂**）。
2. **`toggle_oni_mode()` 内の非アトミック更新（Race Condition）**
   - `toggle_oni_mode()`（`lines 443–454`）には `threading.Lock` が存在しない。
   - スレッドAが `toggle_oni_mode(True)` を呼び `ONI_MODE = True` を実行した直後（`_ONI_MODE_ACTIVE.set()` の実行前）に、スレッドBが `toggle_oni_mode(False)` を割り込み実行して `ONI_MODE = False` → `_ONI_MODE_ACTIVE.clear()` を完了すると、直後に再開したスレッドAが `_ONI_MODE_ACTIVE.set()` を実行し、**`ONI_MODE == False` かつ `_ONI_MODE_ACTIVE.is_set() == True` という不整合状態**に陥る。
3. **`handle_packet_event()` における `"oni"` ステージの即時トリガー漏れ（`line 5948`）**
   - `inspect_packet_pipeline()`（`lines 5718–5725`）は `ONI_MODE_is_active()` が真のとき `stage="oni"` で `block=True` を返す。
   - しかし上位の `handle_packet_event()`（`line 5948`）では `backdoor_detected = stage in {"signature", "frame_length", "blacklist"}` とハードコードされており、`"oni"`（および `"dpi_fail_closed"`, `"parse_error"`）が含まれていない。そのため、`evaluate_threat_state()` で即時トリガー（1パケット目でのKill Switch要求）にならず、3連続パケット到達まで遅延する。

### 3.3 修正案の設計（コード変更なし）

- **単一情報源（Single Source of Truth）化**:
  - グローバル変数 `ONI_MODE` の直接保持を廃止するか、モジュールレベルの `__getattr__`（Python 3.7+）を用いて `ONI_MODE` 参照時は常に `_ONI_MODE_ACTIVE.is_set()` を返す読み取り専用属性とする。
  - 状態変更は `_ONI_MODE_LOCK = threading.Lock()` で保護された `toggle_oni_mode(activate: Optional[bool] = None) -> bool` のみに一本化し、`bool` と `Event` の二重保持を解消する。
- **`handle_packet_event()` のステージ統合**:
  - `backdoor_detected = stage in {"oni", "signature", "frame_length", "blacklist", "dpi_fail_closed", "parse_error"}` に統一する。

---

## 4. AI入力 `feature_vector` の仕様と `[0.0, 1.0]` 範囲制限の妥当性監査

### 4.1 現在の実装（`airgap_ai_defender.py:5861–5873`）

`inspect_packet_pipeline()` では、`feature_vector` の全10要素に対して以下の範囲検査を実施し、範囲外の要素が1つでもある場合は `stage="feature_validation"`, `reason="invalid_feature_vector"`, `block=True` で即座に通信を遮断する：

```python
for v in vec:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        valid_features = False
        break
    fv = float(v)
    if not math.isfinite(fv) or fv < 0.0 or fv > 1.0:
        valid_features = False
        break
```

### 4.2 既存コード内の特徴量生成・検証ロジックとの照合結果（重大な仕様矛盾）

同一ファイル（`airgap_ai_defender.py`）内の全箇所を調査した結果、**実際のパケットキャプチャ特徴量生成器の出力が `[0.0, 1.0]` を超えるケースが存在する**ことが判明した。

| 箇所（関数・行番号） | 各次元（`feat[0..9]`）の生成・検証仕様 | `[0.0, 1.0]` 制約との整合性 |
|---|---|---|
| `_packet_capture_worker()`<br>(`lines 5228–5309`) | - `feat[0]`: `min(pkt_len / 1500.0, 1.0)`<br>- `feat[1]`: `min(_ema_delta, 1.0)` （ただし `delta = now - _last_pkt_time` で `time.time()` 使用）<br>- `feat[2]`: TCP=`1.0`, UDP=`0.5`, 他=`0.0`<br>- `feat[3]`: TCP flags / `63.0` (`0.0..1.0`)<br>- `feat[4]`: `min(dport, 65535) / 65535.0`<br>- `feat[5]`: `min(sport, 65535) / 65535.0`<br>- `feat[6]`: `min(payload_len / 1500.0, 1.0)`<br>- `feat[7]`: シャノンエントロピー `/ 8.0` (`0.0..1.0`)<br>- `feat[8]`: ゼロバイト比率 (`0.0..1.0`)<br>- **`feat[9]`**: **`mem_mgr.get_usage_ratio()`（上限クランプなし！）** | **【不整合1：メモリ高負荷時に `feat[9] > 1.0`】**<br>`MemoryManager.get_usage_ratio()`（`lines 4604–4611`）は `raw = rss / self.max_bytes` を返すため、プロセスのRSSが上限（`max_memory_mb`）を超過すると **`1.0` を超える値を返す**（既存テスト `tests/test_airgap_ai_defender.py:2566` でも `self.assertGreater(ratio, 1.0)` を明示的に検証している）。<br>このとき `feat[9] > 1.0` となり、`inspect_packet_pipeline()` が **全正常通信を `invalid_feature_vector` として遮断（Self-DoS）する**。<br>**【不整合2：NTP時刻補正時に `feat[1] < 0.0`】**<br>`time.time()`（システム壁時計）を使用しているため、NTPによる時刻巻き戻しが発生すると `delta < 0` となり `_ema_delta < 0.0` となって `[0.0, 1.0]` を下回る。 |
| `load_raw_data_from_files()`<br>(`lines 4973–4985`) | `math.isfinite(value)` のみを検査し、**`[0.0, 1.0]` の範囲制限を行っていない**。 | **【不整合3】** 既存単体テスト（`tests/test_airgap_ai_defender.py:845, 1411`）では `[0.0, 1.0, ..., 9.0]` や `[0.0..204.0]` のような `1.0` 超の特徴量ベクトルを正常入力としてテストしている。 |
| `curate_and_save()`<br>(`lines 5089–5097`) | `len == 10` と `math.isfinite(value)` のみを検査。 | 上記と同様、`[0.0, 1.0]` 制限なし。 |
| `train_local_whitelist()` (`line 5157`) / `_build_rsi_payload()` (`line 6268`) / `_append_selected_feature_records()` (`line 6298`) | `math.isfinite(value) and 0.0 <= value <= 1.0` を要求。 | 学習・RSI保存系のみ `[0.0, 1.0]` を前提としている。 |

### 4.3 結論（`feature_vector` 範囲制限の評価）

- `inspect_packet_pipeline()` で `0.0 <= fv <= 1.0` を無条件の遮断条件（Fail-Closed）としたことは、`_packet_capture_worker()` の `feat[9] = mem_mgr.get_usage_ratio()`（`> 1.0` になり得る）および `feat[1]`（`time.time()` 逆行時に `< 0.0` になり得る）と**矛盾しており、メモリ逼迫時や時刻補正時に全通信を遮断する新たな可用性リスク（Self-DoS）を生んでいる**。
- 正しくは、特徴量生成側で `min(max(mem_mgr.get_usage_ratio(), 0.0), 1.0)` および `time.monotonic()` を用いるか、`inspect_packet_pipeline()` 側では `math.isfinite(fv)` と非負チェックを行い、`feat[9] > 1.0` は `1.0` にクランプした上で推論器へ渡す設計としなければならない。

---

## 5. `REG-04`、`REG-06` および `22 SKIPPED` テストの完全照合

### 5.1 Webプレビュー（`app.py`）で抜けていた `REG-04` と `REG-06` の検証内容

`app.py` の `run_live_verification_checks()` では `REG-01, REG-02, REG-03, REG-05, REG-07, REG-08, REG-09` の7項目のみを表示しており、`REG-04` と `REG-06` が抜けていた。実際のテストコード（`tests/test_airgap_ai_defender.py`）における `REG-01`〜`REG-09` の完全な対応は以下の通りである。

| 回帰ID | 検証対象 | 実テスト関数（`tests/test_airgap_ai_defender.py`） | 検証内容と結果 |
|---|---|---|---|
| `REG-01` | DPI `fail_closed` | `test_packet_inspection_pipeline_blocks_on_dpi_fail_closed` (`line 2873`) | `analyze_dpi_payload` が `scan_strategy="fail_closed"` を返した際、`inspect_packet_pipeline()` が `block=True, stage="dpi_fail_closed"` を返すことを確認（PASS）。 |
| `REG-02` | Raw payload signature | `test_packet_inspection_pipeline_blocks_raw_reverse_shell_signature_with_clean_l4` (`line 2862`) | 正常なEthernet+IPv4+TCPヘッダ（port 443）の背後に `/bin/sh -i` を含むフレームが `stage="signature"` で `block=True` となることを確認（PASS）。 |
| `REG-03` | Port 8080 removal | `test_packet_inspection_pipeline_does_not_treat_port_8080_as_backdoor_by_itself` (`line 2917`) | 良性ペイロードのTCP port 8080通信が `signature` ステージで誤遮断されないことを確認（PASS）。 |
| **`REG-04`** | **Malformed headers & progressive defense** | **`test_malformed_headers_fail_closed_and_progressive_defense_never_unblocks` (`lines 2888–2915`)** | - **`REG-04a`**: 10バイト短縮L2フレーム → `parse_error=True, parse_status="MALFORMED"`<br>- **`REG-04b`**: 18バイト短縮IPv4パケット → `parse_error=True`, `inspect_packet_pipeline()` が `block=True, stage="parse_error"`<br>- **`REG-04c`**: 偽装 `IHL=2`（8バイト `< 20`）IPv4ヘッダ → `parse_error=True, parse_status="MALFORMED"`<br>- 併せて `ProgressiveDefense.evaluate()` が高スコア時にブロック解除しないことを確認（PASS）。 |
| `REG-05` | IPv6 extension headers | `test_ipv6_fragment_extension_header_parses_inner_tcp_ports` (`line 2930`) | IPv6 Next Header `44`（Fragment Header 8B）の後ろにあるTCPヘッダ（sport `54321`, dport `4444`）を抽出し、`stage="signature"` で `block=True` となることを確認（PASS）。 |
| **`REG-06`** | **`ONI_MODE` toggle & pipeline block** | **`test_toggle_oni_mode_synchronizes_global_and_blocks_pipeline` (`lines 2944–2958`)** | `toggle_oni_mode(True)` により `ONI_MODE` と `ONI_MODE_is_active()` が `True` になり、`inspect_packet_pipeline()` が良性パケットに対しても即座に `block=True, stage="oni"` を返し、`toggle_oni_mode(False)` で解除されることを確認（PASS）。 |
| `REG-07` | Kill Switch gate | `test_evaluate_threat_state_holds_kill_switch_until_confirmed_and_approved` (`line 2777`) | 単発の非バックドア異常では即時Kill Switchを発火せず、3連続検知＋承認ゲートを経ることを確認（PASS）。 |
| `REG-08` | AI NaN / out-of-range features | `test_packet_inspection_pipeline_blocks_invalid_feature_vectors` (`line 2960`) | `NaN`、長さ不一致（5要素）、範囲外（`1.5`）の `feature_vector` に対して `block=True, stage="feature_validation"` を返すことを確認（PASS）。 |
| `REG-09` | `nftables` `ct state invalid drop` | `tests/test_firewall_nft.py:test_render_nft_transaction_strict_airgap_includes_base_drop_chains` (`line 16`) | 生成される `nftables` ルール文字列に `ct state invalid drop` が含まれ、不正IP（`10.0.0.1; flush ruleset`）が `FirewallValidationError` で拒否されることを確認（PASS）。 |

### 5.2 `248` テスト中の `22 SKIPPED` の全件一覧とスキップ理由

実行された8テストファイル（計248テストメソッド：`226 PASS` + `22 SKIPPED` = `248`）のうち、スキップされた22件の完全な内訳は以下の通りである。

| # | テストファイル | テストメソッド名 | 行番号 | スキップデコレータ / 条件 | 具体的な未検証理由（`NOT TESTED` の内容） |
|---|---|---|---|---|---|
| 1 | `tests/test_airgap_ai_defender.py` | `test_ai_persistence_rejects_mismatched_hmac` | 645 | `@requires_torch` | `torch` 未導入（`TORCH_AVAILABLE=False`）。実PyTorchモデルのHMAC不一致検証が未実施。 |
| 2 | `tests/test_airgap_ai_defender.py` | `test_ai_persistence_round_trip_restores_weights_and_ optimizer` | 661 | `@requires_torch` | `torch` 未導入。実モデル重みとOptimizer状態の保存・復元が未実施。 |
| 3 | `tests/test_airgap_ai_defender.py` | `test_auto_calibrate_thresholds_scales_with_ clean_validation_scores` | 685 | `@requires_torch` | `torch` 未導入。実モデル推論スコアを用いた閾値自動較正が未実施。 |
| 4 | `tests/test_airgap_ai_defender.py` | `test_curate_and_save_encrypts_with_configured_fernet_key` | 835 | `@requires_rsi_dependencies` | `cryptography`（Fernet）および `numpy` 未導入。学習データのFernet暗号化保存が未実施。 |
| 5 | `tests/test_airgap_ai_defender.py` | `test_curate_and_save_writes_hmac_companion_for_plaintext_fallback` | 886 | `@requires_rsi_dependencies` | `cryptography` / `numpy` 未導入。 |
| 6 | `tests/test_airgap_ai_defender.py` | `test_encrypted_training_data_round_trip` | 917 | `@requires_rsi_dependencies` | `cryptography` / `numpy` 未導入。暗号化訓練データの復号ラウンドトリップが未実施。 |
| 7 | `tests/test_airgap_ai_defender.py` | `test_gdrive_sync_downloads_verify_peer_tls` | 954 | `@requires_gdrive_dependencies` | Google Drive APIクライアント未導入。TLSピア検証付きダウンロードが未実施。 |
| 8 | `tests/test_airgap_ai_defender.py` | `test_gdrive_sync_rejects_oversized_remote_file` | 1004 | `@requires_gdrive_dependencies` | Google Drive APIクライアント未導入。 |
| 9 | `tests/test_airgap_ai_defender.py` | `test_gdrive_sync_uploads_encrypted_curated_data` | 1039 | `@requires_gdrive_dependencies` | Google Drive APIクライアント未導入。 |
| 10 | `tests/test_airgap_ai_defender.py` | `test_load_ai_state_rejects_corrupted_encrypted_checkpoint` | 1126 | `@requires_torch` | `torch` 未導入。破損チェックポイントの拒否動作が実PyTorchで未実施。 |
| 11 | `tests/test_airgap_ai_defender.py` | `test_load_ai_state_rejects_unsigned_legacy_checkpoint` | 1152 | `@requires_torch` | `torch` 未導入。未署名レガシーチェックポイントの拒否が実PyTorchで未実施。 |
| 12 | `tests/test_airgap_ai_defender.py` | `test_load_raw_data_from_files_skips_tampered_plaintext_companion` | 1177 | `@requires_rsi_dependencies` | `cryptography` / `numpy` 未導入。 |
| 13 | `tests/test_airgap_ai_defender.py` | `test_model_evolution_preserves_learned_weights_across_save_and_load` | 1246 | `@requires_torch` | `torch` 未導入。世代進化（Model Evolution）時の重み継承が実PyTorchで未実施。 |
| 14 | `tests/test_airgap_ai_defender.py` | `test_online_learning_reduces_reconstruction_error_for_repeated_clean_pattern` | 1317 | `@requires_torch` | `torch` 未導入。オンライン学習による再構成誤差低下が実PyTorchで未実施。 |
| 15 | `tests/test_airgap_ai_defender.py` | `test_save_ai_state_uses_secure_transport_envelope_when_enabled` | 1647 | `@skipUnless(TORCH_AVAILABLE and SECURE_TRANSPORT_AVAILABLE)` | `torch` および `pqcrypto`/`cryptography` 未導入。 |
| 16 | `tests/test_airgap_ai_defender.py` | `test_save_and_load_ai_state_with_aesgcm_encryption` | 1692 | `@requires_torch` + `@requires_aesgcm` | `torch` および `cryptography`（AESGCM）未導入。 |
| 17 | `tests/test_airgap_ai_defender.py` | `test_secure_transport_envelope_tamper_is_rejected_on_load` | 1732 | `@skipUnless(TORCH_AVAILABLE and SECURE_TRANSPORT_AVAILABLE)` | `torch` および `pqcrypto`/`cryptography` 未導入。 |
| 18 | `tests/test_airgap_ai_defender.py` | `test_secure_transport_round_trip_for_bytes` | 1775 | `@requires_secure_transport` | `pqcrypto` / `cryptography` 未導入。`mk1_secure_transport` の実暗号ラウンドトリップが未実施。 |
| 19 | `tests/test_airgap_ai_defender.py` | `test_secure_transport_rejects_expired_envelope` | 1791 | `@requires_secure_transport` | `pqcrypto` / `cryptography` 未導入。 |
| 20 | `tests/test_airgap_ai_defender.py` | `test_slime_mold_network_forward_pass_produces_three_head_outputs` | 1816 | `@requires_torch` | `torch` 未導入。`SlimeMoldNetwork` の実3ヘッド推論出力が未実施。 |
| 21 | `tests/test_airgap_ai_defender.py` | `test_verify_file_hmac_detects_single_byte_tampering` | 1922 | `@requires_aesgcm` | `cryptography` 未導入。 |
| 22 | `tests/test_scripts.py` | `test_panel_reports_missing_pqc_provider_and_can_require_it` | 81 | `skip("ncurses development headers are not installed")` | `ncurses.h`（`libncurses-dev`）未導入のため `mk1_panel.c` のビルド・検証が未実施。 |

### 5.3 `248` 件の母数から除外されていた11テストファイル（49テストメソッド：`NOT TESTED`）

さらに、リポジトリ内の `tests/` には以下の11テストファイル（計49テストメソッド）が存在するが、`cryptography`、`pqcrypto`、`flask`、または `CAP_SYS_ADMIN`（root権限）が環境にないため、`248` 件の実行対象に含まれていなかった（すべて **`NOT TESTED`**）：

1. `tests/test_hybrid_kem.py`（6テスト：`ML-KEM-1024 + X25519` 実鍵生成・カプセル化・改ざん検知）
2. `tests/test_secure_transport.py`（5テスト：`ML-KEM-768` + `AESGCM` トランスポート暗号化・復号）
3. `tests/test_session_ratchet.py`（4テスト：`SessionRatchet` の鍵導出・エポックローテーション・`destroy()`）
4. `tests/test_quorum.py`（6テスト：Ed25519クォーラム署名検証・リプレイ防止・タイムスタンプ検証）
5. `tests/test_key_registry.py`（5テスト：Ed25519ルート信頼・鍵失効リスト検証）
6. `tests/test_key_backup.py`（4テスト：Shamir秘密分散・鍵バックアップ復元）
7. `tests/test_key_derivation.py`（3テスト：HKDF/Argon2鍵導出）
8. `tests/test_external_verifier.py`（4テスト：外部監査ログのEd25519署名検証）
9. `tests/test_release_verification.py`（4テスト：リリースバイナリ署名検証）
10. `tests/test_quarantine.py`（5テスト：Linux network namespace / cgroup 隔離操作 — root権限必要）
11. `tests/test_remote_dashboard.py`（3テスト：FlaskリモートダッシュボードAPI — `flask` 必要）
