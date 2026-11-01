# MK1AI_REGRESSION_REPORT.md — 修正前後 再現実験・回帰テスト比較報告書

## 1. 概要（PART 10 / PART 11.5 準拠）

本報告書は、MK1Ai（Project Sovereign-Airgap）における各セキュリティ不具合について、**修正前のコードで不具合を実際に再現した結果（Pre-Fix）** と **修正後のコードで同一入力を再実行した結果（Post-Fix）**、および既存単体テスト・C言語テストの回帰実行結果を証拠とともに比較した記録である。

---

## 2. 修正前後（Pre-Fix vs Post-Fix）の挙動比較マトリクス

| Case ID | 検証カテゴリ / 入力ケース | 期待される安全動作 | 修正前の実測結果 (Pre-Fix) | 修正後の実測結果 (Post-Fix) | 判定 |
|---|---|---|---|---|---|
| **REG-01** | DPI `fail_closed` 時のパイプライン判定 (`_build_fail_closed_dpi_result`) | `block=True, stage="dpi_fail_closed", score=1.0` | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only', 'score': 0.35}` (**FAIL: Fail-Open**) | `{'block': True, 'stage': 'dpi_fail_closed', 'reason': 'dpi_fail_closed', 'score': 1.0}` | **PASS** |
| **REG-02a** | UTF-16LE 難読化 PowerShell (`"powershell -NoProfile -Command IEX".encode("utf-16le")`) | `block=True, stage="signature"` | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only'}` (**FAIL: すり抜け**) | `{'block': True, 'stage': 'signature', 'reason': 'fixed_payload_signature'}` | **PASS** |
| **REG-02b** | URLエンコード XSS (`GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E`) | `block=True, stage="signature"` | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only'}` (**FAIL: すり抜け**) | `{'block': True, 'stage': 'signature', 'reason': 'fixed_payload_signature'}` | **PASS** |
| **REG-02c** | NULLバイト挿入 XSS (`b"<scr\x00ipt>alert(1)</scr\x00ipt>"`) | `block=True, stage="signature"` | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only'}` (**FAIL: すり抜け**) | `{'block': True, 'stage': 'signature', 'reason': 'fixed_payload_signature'}` | **PASS** |
| **REG-03a** | 正常な Python 関数定義 (`b"def my_eval(x): return x + 1\n"`) | `block=False` (誤検知しないこと) | `{'block': True, 'stage': 'signature', 'reason': 'fixed_payload_signature'}` (**FAIL: 誤検知**) | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only'}` | **PASS** |
| **REG-03b** | 正常な PDF ドキュメント取得 (`GET /docs/powershell-guide.pdf HTTP/1.1`) | `block=False` (誤検知しないこと) | `{'block': True, 'stage': 'signature', 'reason': 'fixed_payload_signature'}` (**FAIL: 誤検知**) | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only'}` | **PASS** |
| **REG-03c** | 正常なテキストマニュアル取得 (`GET /manual/cmd.exe.txt HTTP/1.1`) | `block=False` (誤検知しないこと) | `{'block': True, 'stage': 'signature', 'reason': 'fixed_payload_signature'}` (**FAIL: 誤検知**) | `{'block': False, 'stage': 'advisory', 'reason': 'advisory_scores_only'}` | **PASS** |
| **REG-04a** | 短小 L2 フレーム (`b"\x00" * 10`, 10 Bytes) | `parse_error=True, parse_status="MALFORMED", block=True` | `parse_packet_transport -> {}`, `block: False, stage: 'advisory'` (**FAIL: Fail-Open**) | `{'parse_error': True, 'parse_status': 'MALFORMED', 'reason': 'truncated_l2_header'}`, `block: True, stage: 'parse_error'` | **PASS** |
| **REG-04b** | 短小 IPv4 ヘッダ (18 Bytes) | `parse_error=True, parse_status="MALFORMED", block=True` | `parse_packet_transport -> {}`, `block: False, stage: 'advisory'` (**FAIL: Fail-Open**) | `{'parse_error': True, 'parse_status': 'MALFORMED', 'reason': 'truncated_ipv4_header'}`, `block: True, stage: 'parse_error'` | **PASS** |
| **REG-04c** | 不正 IPv4 `IHL=2` (`ihl * 4 = 8 < 20`) | `parse_error=True, parse_status="MALFORMED", block=True` | `{'src_ip': '1.1.1.1', ..., 'src_port': 16, 'dst_port': 0}`, `block: False` (**FAIL: オフセット破壊・通過**) | `{'parse_error': True, 'parse_status': 'MALFORMED', 'reason': 'invalid_ipv4_ihl'}`, `block: True, stage: 'parse_error'` | **PASS** |
| **REG-05** | 同一送信元 (`10.9.9.9`) からの連続5回 `parse_error` (Progressive Defense) | 1〜5回目すべて `block=True` (3回目 `rate_limited`, 4〜5回目 `blacklist`) | Call 1〜2: `block=True` → **Call 3〜5: `block=False, stage='rate_limited', blacklisted=True`** (**FAIL: ブラックリスト後に通過**) | Call 1〜2: `block=True (parse_error)` → Call 3: `block=True (rate_limited)` → Call 4〜5: `block=True (blacklist)` | **PASS** |
| **REG-06** | `toggle_oni_mode()` 実行後の状態同期とパイプライン遮断 | `ONI_MODE == True`, `ONI_MODE_is_active() == True`, `block=True, stage="oni"` | `ONI_MODE=False`, `ONI_MODE_is_active()=True`, **`block=False, stage='advisory'`** (**FAIL: 鬼モード不発**) | `ONI_MODE=True`, `ONI_MODE_is_active()=True`, `block=True, stage='oni'` | **PASS** |
| **REG-07a** | IEEE 802.1Q VLAN (`0x8100`) カプセル化 `<script>alert(1)</script>` | ペイロード抽出成功 + `block=True` | `extract_payload_bytes -> b''`, **`block=False`** (**FAIL: VLANすり抜け**) | `extract_payload_bytes -> b'<script>alert(1)</script>'`, `block=True` | **PASS** |
| **REG-07b** | ICMP (`proto=1`) カプセル化 `<script>alert(1)</script>` | ペイロード抽出成功 + `block=True` | `extract_payload_bytes -> b''`, **`block=False`** (**FAIL: ICMPすり抜け**) | `extract_payload_bytes -> b'<script>alert(1)</script>'`, `block=True` | **PASS** |
| **REG-07c** | IPv6 Fragment 拡張ヘッダ (`next_hdr=44`) + `<script>alert(1)</script>` | ペイロード抽出成功 + `block=True` | `extract_payload_bytes -> b''`, **`block=False`** (**FAIL: IPv6拡張ヘッダすり抜け**) | `extract_payload_bytes -> b'<script>alert(1)</script>'`, `block=True` | **PASS** |
| **REG-08a** | 不正 `feature_vector=[0.5]*3` (要素数不足) | クラッシュせず `block=True, stage="feature_validation"` | `IndexError: list index out of range` (**FAIL: 例外クラッシュ**) | `block=True, stage='feature_validation', reason='invalid_feature_vector'` | **PASS** |
| **REG-08b** | 不正 `feature_vector=[-100.0]*10`, `[float('-inf')]*10`, `[float('nan')]*10` | `block=True, stage="feature_validation"` | `ai_score: -74.8` / `-inf`, `block=False` (**FAIL: Fail-Open**) | すべて `block=True, stage='feature_validation', reason='invalid_feature_vector'` | **PASS** |
| **REG-09** | `mk1_firewall.render_nft_transaction()` と非 root `remove_nft_policy()` | `lo` 許可 + `ct state invalid drop` ×3 + `last_nft_failure` 記録 | `lo` 許可なし、`ct state invalid drop` なし、非 root `remove_nft_policy()` で `last_nft_failure` 未更新 (**FAIL**) | `iifname "lo" accept`, `oifname "lo" accept`, `ct state invalid drop` ×3 出力、`last_nft_failure` 記録 | **PASS** |

---

## 3. 単体テストスイートおよび C モジュール検証結果一覧

### 3.1 Python 単体テスト実行結果

実行コマンド：
```bash
python3 -m unittest \
  tests/test_airgap_ai_defender.py \
  tests/test_firewall_nft.py \
  tests/test_config_templates.py \
  tests/test_airgap_paths.py \
  tests/test_usb_guard.py \
  tests/test_performance_capacity.py \
  tests/test_map_visualization.py \
  tests/test_mk1_memory_guard.py \
  tests/test_scripts.py \
  tests/test_proxmox_transfer_registration.py
```
- **実行結果**: **Ran 248 tests in 2.249s — OK (skipped=22, failures=0, errors=0)**

### 3.2 C 言語セキュリティモジュール単体テスト実行結果

| テストバイナリ | 対象 C ソース | 実行結果 | 判定 |
|---|---|---|---|
| `test_mk1_memory_guard` | `mk1_memory_guard.c`, `tests/test_mk1_memory_guard.c` | `[PASS] test_mk1_memory_guard` (Return Code 0) | **PASS** |
| `test_mk1_path_trust` | `mk1_path_trust.c`, `tests/test_mk1_path_trust.c` (`-D_XOPEN_SOURCE=700`) | Return Code 0 (全アサーション成功) | **PASS** |
| `test_mk1_tunnel` | `mk1_tunnel.c`, `tests/test_mk1_tunnel.c` | `[PASS] test_mk1_tunnel` (Return Code 0) | **PASS** |

### 3.3 オフライン環境で未導入の外部ライブラリに依存するテスト項目（PART 1.3 準拠の `NOT TESTED` 記録）

`PART 1.3`（「依存ライブラリをインストールしない。必要なライブラリが不足している場合は、勝手に代替実装を作ったりインストールしたりせず、`NOT TESTED` と記録してください」）に従い、以下の外部ライブラリ依存テストを正直に `NOT TESTED` と分類する：

| テストファイル | 不足している外部パッケージ | ステータス |
|---|---|---|
| `tests/test_external_verifier.py` | `cryptography` | **NOT TESTED** |
| `tests/test_hybrid_kem.py` | `cryptography`, `pqcrypto` | **NOT TESTED** |
| `tests/test_key_backup.py` | `cryptography` | **NOT TESTED** |
| `tests/test_key_derivation.py` | `cryptography` | **NOT TESTED** |
| `tests/test_key_registry.py` | `cryptography` | **NOT TESTED** |
| `tests/test_quarantine.py` | `cryptography` | **NOT TESTED** |
| `tests/test_quorum.py` | `cryptography` | **NOT TESTED** |
| `tests/test_release_verification.py` | `cryptography` | **NOT TESTED** |
| `tests/test_remote_dashboard.py` | `flask`, `cryptography` | **NOT TESTED** |
| `tests/test_secure_transport.py` | `cryptography`, `pqcrypto` | **NOT TESTED** |
| `tests/test_session_ratchet.py` | `cryptography` | **NOT TESTED** |
| `tests/integration/test_firewall_netns.py` | `CAP_SYS_ADMIN` (`unshare -Urn`) / Host `nft` | **NOT TESTED** |
