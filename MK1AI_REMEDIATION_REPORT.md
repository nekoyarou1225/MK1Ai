# MK1AI_REMEDIATION_REPORT.md — セキュリティ欠陥修正・根本原因是正報告書

## 1. 概要と作業前後の保全記録（PART 1.2 / PART 11.1 準拠）

本報告書は、MK1Ai（Project Sovereign-Airgap）における `BENCHMARK_REPORT.md`（および監査指摘事項）の FAIL 項目と現行ソースコードの不整合を実コードで再現・特定し、最小限かつ効果的な修正を行った記録である。

### 1.1 作業前のベースライン状態（変更前 SHA-256 記録）

本環境には `.git` メタデータディレクトリが含まれていないため、作業開始前に全対象ファイルのサイズと SHA-256 ダイジェストを読み取り専用で記録し、変更前後の差分を厳密に追跡可能とした。

| ファイルパス | 変更前サイズ (Bytes) | 変更前 SHA-256 | 変更有無 |
|---|---:|---|---|
| `airgap_ai_defender.py` | 310,790 | `bfd461677f2983e09b01b7ac7b451fe12ff3c24a32324313022f8163dcc63127` | **修正済** |
| `mk1_firewall.py` | 8,555 | `f3a0ad76feef712137c80b8b285db8ad1732b8a122af2aee68171951b87ba9b7` | **修正済** |
| `mk1_secure_transport.py` | 23,776 | `609c5cc01b92632442febec4a3dbeeb7a981f6cc15d1e8ec56b4ace2db4ebd31` | **修正済** |
| `mk1_quorum.py` | 15,826 | `9a8c3252a70760c3b6fb91c918ca138bc229238b12a080886bc0584c7c92a225` | **修正済** |
| `tests/test_airgap_ai_defender.py` | 143,580 | `3534e9a055f983b99788716fe7d13cd665e1b2528fc7046f3bd9bf4251b2ee6a` | **テスト追加** |
| `tests/test_firewall_nft.py` | 2,330 | `3e7d53d10a1a5f4271819cc3b642df53c485560ca8958f1567bd17b722f4cf4c` | **テスト追加** |
| `ai_data/` (既存AIモデルデータ) | 0 (未存在) | N/A（既存モデルの再生成・置換なし） | **変更なし** |

---

## 2. 実施した全修正項目の詳細記録（PART 12.1 必須フォーマット準拠）

### 修正項目 1：DPI `fail_closed` 判定および DPI 攻撃シグネチャのパイプライン反映（PART 4.1 / 4.2）
- **対象ファイル**: `airgap_ai_defender.py`
- **対象関数**: `inspect_packet_pipeline()`
- **修正理由**: `analyze_dpi_payload()` が例外発生時やペイロード抽出失敗時に `_build_fail_closed_dpi_result()` (`scan_strategy: "fail_closed", score: 1.0, suspicious: True`) を返しても、`inspect_packet_pipeline()` がそれを参照せず通過させていたため。また DPI が検出した難読化・攻撃シグネチャが `inspect_packet_pipeline()` の遮断条件に接続されていなかったため。
- **修正前の問題**: `_build_fail_closed_dpi_result()` を渡して `inspect_packet_pipeline()` を呼ぶと `{'block': False, 'stage': 'advisory', 'score': 0.35}` となり **Fail-Open** で通過した。
- **修正後の動作**: `dpi_result.get("scan_strategy") == "fail_closed"` の場合は即座に `{'block': True, 'stage': 'dpi_fail_closed', 'score': 1.0, 'reason': 'dpi_fail_closed'}` で遮断する。また DPI が `suspicious=True` かつ確定攻撃シグネチャを検出した場合も `stage='signature', block=True` で遮断する。
- **変更内容**: `inspect_packet_pipeline()` 冒頭（`ONI_MODE` 判定直後）で `dpi_result` を取得・評価し、`scan_strategy == "fail_closed"` および `dpi_attack_sigs` の強制遮断分岐を追加。
- **テスト結果**: **PASS** (`test_dpi_fail_closed_propagates_to_inspect_packet_pipeline`)
- **残存リスク**: なし（DPI 内部エラー時は常に `block=True` となる）。
- **未検証項目**: なし。

---

### 修正項目 2：多層エンコーディング・難読化シグネチャの正規化検知と正常文脈の誤検知抑止（PART 4.1 / PART 5.2）
- **対象ファイル**: `airgap_ai_defender.py`
- **対象関数**: `_normalize_inspected_payload()`, `_contains_multiencoding_bytes()`, `_matches_enforcement_signature()`, `_should_force_full_scan()`, `analyze_dpi_payload()`
- **修正理由**: UTF-16LE/BE、URLエンコード (`%3Cscript%3E`)、HTMLエンティティ (`&#x6a;avascript:`)、NULLバイト混入 (`<scr\x00ipt>`)、バックスラッシュ16進エスケープ (`\x3cscript`) によるシグネチャ回避を阻止しつつ、`def my_eval(x):` のような識別子部分一致や `GET /docs/powershell-guide.pdf` / `cmd.exe.txt` のような静的ドキュメント参照での誤検知（False Positive）を防止するため。また、`suspicious=True` の結果が安全フローキャッシュ `_FLOW_STATE_CACHE` に保存されて後続パケットのスコアが `0.49` に低下する欠陥を修正するため。
- **修正前の問題**:
  1. `"powershell -NoProfile".encode("utf-16le")`、`%3Cscript%3E`、`<scr\x00ipt>` がすべて `block: False` で通過した。
  2. `def my_eval(x): return x + 1`（`my_eval(` の末尾が `eval(` に部分一致）および `GET /docs/powershell-guide.pdf` が `block: True` と誤検知された。
  3. `analyze_dpi_payload()` が `elif result["suspicious"]: _cache_flow_result(packet_bytes, result)` で危険パケットを安全フローキャッシュに登録していた。
- **修正後の動作**:
  1. UTF-16LE/BE、URLエンコード、HTMLエンティティ、NULLバイト混入、16進エスケープを `_normalize_inspected_payload()` で正規化し、`inspect_packet_pipeline()` で確実に `block: True, stage: 'signature'` と判定する。
  2. `eval(` は単語境界正規表現 `(?<![a-z0-9_])eval\s*\(` で判定し、`my_eval(x)` は `block: False` となる。
  3. `powershell` / `cmd.exe` がドキュメント拡張子 (`.pdf`, `.txt`, `.md` 等) のファイル名の一部としてのみ出現し実行フラグを伴わない場合は `block: False` となる。
  4. `suspicious=True` または `attack_signatures` 検出時は `_FLOW_STATE_CACHE` から該当フローを即時パージし、キャッシュ済みフローでも次パケットにシグネチャやエスケープが含まれれば `_should_force_full_scan()` が `True` を返す。
- **変更内容**: `_normalize_inspected_payload()`, `_matches_enforcement_signature()`, `_BENIGN_DOC_EXT_RE`, `_EVAL_CALL_RE` の実装、および `_should_force_full_scan()` と `analyze_dpi_payload()` のキャッシュ制御修正。
- **テスト結果**: **PASS** (`test_multiencoding_and_obfuscated_signatures_blocked_while_benign_contexts_pass`)
- **残存リスク**: 独自暗号や事前共有鍵で完全に暗号化されたペイロードはシグネチャ単体では復号不能であるため、行動相関・TLS JA3/JA4 メタデータ・レート制限で補完する。
- **未検証項目**: なし。

---

### 修正項目 3：VLAN (`802.1Q`/`802.1ad`)・IPv6拡張ヘッダ・ICMP/ICMPv6 の構造解析と破損ヘッダ Fail-Closed 化（PART 5.1 / 5.2）
- **対象ファイル**: `airgap_ai_defender.py`
- **対象関数**: `_unwrap_l2_ether_type()`, `_skip_ipv6_extension_headers()`, `parse_packet_transport()`, `extract_payload_bytes()`, `_extract_src_ip()`
- **修正理由**:
  1. 802.1Q/802.1ad VLAN タグ、IPv6 拡張ヘッダ、ICMP/ICMPv6 ペイロードが未対応で `extract_payload_bytes()` が `b""` を返し、攻撃ペイロードが素通りしていたため。
  2. 短小 L2 フレーム (`<14B`)、短小 IPv4 (`<20B`)、不正 IPv4 `IHL < 5`、短小 IPv6 (`<40B`)、不正 IP バージョン、不正 TCP `data_offset < 20`、短小 UDP (`<8B`) が `parse_error` にならず `{}` や正常辞書を返して `block=False` で通過していたため。
- **修正前の問題**:
  - 10バイトフレーム、18バイト IPv4、`IHL=2` パケットがいずれも `parse_error` にならず `block=False` で通過した。
  - VLAN タグ付き `<script>` パケットおよび ICMP `<script>` パケットで `extract_payload_bytes()` が `b""` を返し `block=False` で通過した。
- **修正後の動作**:
  - 最大2段の VLAN タグと最大8段の IPv6 拡張ヘッダを追跡して TCP/UDP/ICMP/ICMPv6 ペイロードを正確に抽出・検査する（3段以上の VLAN タグや破損拡張ヘッダは `parse_error=True, parse_status="MALFORMED"` として即遮断）。
  - すべてのヘッダ長不足・オフセット矛盾に対して `{"parse_error": True, "parse_status": "MALFORMED", "reason": ...}` を返し、`inspect_packet_pipeline()` で `block=True` となる。
- **変更内容**: `_unwrap_l2_ether_type()` と `_skip_ipv6_extension_headers()` を新設し、`parse_packet_transport()`, `extract_payload_bytes()`, `_extract_src_ip()` の全プロトコル境界チェックを強化。
- **テスト結果**: **PASS** (`test_malformed_headers_fail_closed_and_progressive_defense_never_unblocks`, `test_vlan_icmp_and_ipv6_ext_header_payload_extraction_and_blocking`)
- **残存リスク**: フラグメント分割された複数パケットにまたがるペイロード再構成は Python 単体ではステートレスであるため、XDP/nftables での非先頭フラグメント遮断・カーネル `nf_conntrack` 再構築と併用する。
- **未検証項目**: なし。

---

### 修正項目 4：Progressive Defense（段階的防御）における `parse_error` 遮断抜け（Fail-Open 反転）の修正（PART 4.1 / PART 5.1）
- **対象ファイル**: `airgap_ai_defender.py`
- **対象関数**: `inspect_packet_pipeline()`
- **修正理由**: 同一送信元 IP から `parse_error` パケットが連続到達した際、3回目で `evaluate_progressive_defense()` が `defer=True` (`action="rate_limit"`) を返すと、`inspect_packet_pipeline()` が `return {"block": False, "stage": "rate_limited", ...}` を返して **遮断を解除（Fail-Open）** し、しかもブラックリスト判定が `parse_error` 判定より後ろにあったため4回目以降も永久に `block=False` となっていた重大欠陥を是正するため。
- **修正前の問題**: `10.9.9.9` から破損 TCP パケットを連続送信すると、1〜2回目は `block=True` だが、ブラックリスト登録された3回目・4回目・5回目以降がすべて `block=False, stage='rate_limited'` で通過した。
- **修正後の動作**:
  1. `_is_ip_blacklisted(transport.get("src_ip"))` を `parse_error` 分岐より前に評価し、ブラックリスト済み IP からの全パケット（破損パケット含む）を `block=True, stage="blacklist"` で即時遮断する。
  2. `evaluate_progressive_defense()` が `defer=True` を返した3回目のパケットも `block=True, stage="rate_limited", score=0.98` として確実に遮断する。
- **変更内容**: `inspect_packet_pipeline()` 内のブラックリストチェック順序を `parse_error` の直前に移動し、`defense_decision.get("defer")` 時の `block` 値を `True` に修正。
- **テスト結果**: **PASS** (`test_malformed_headers_fail_closed_and_progressive_defense_never_unblocks`)
- **残存リスク**: なし。
- **未検証項目**: なし。

---

### 修正項目 5：`ONI_MODE`（鬼モード）のグローバル変数と `threading.Event` の完全同期（PART 2.2 / PART 4.1）
- **対象ファイル**: `airgap_ai_defender.py`
- **対象関数**: `ONI_MODE_is_active()`, `toggle_oni_mode()`, `inspect_packet_pipeline()`
- **修正理由**: `toggle_oni_mode()` が `_ONI_MODE_ACTIVE` (`threading.Event`) のみを更新してグローバル変数 `ONI_MODE` を更新せず、一方 `inspect_packet_pipeline()` は `if ONI_MODE:` のみをチェックしていたため、`toggle_oni_mode()` で鬼モードを有効化してもパケットが遮断されなかったため。
- **修正前の問題**: `toggle_oni_mode()` 実行後、`ONI_MODE_is_active()` は `True` だが `ONI_MODE` は `False` のままであり、`inspect_packet_pipeline()` が `block=False, stage='advisory'` を返した。
- **修正後の動作**: `toggle_oni_mode()` が `ONI_MODE` と `_ONI_MODE_ACTIVE` の双方を同期更新し、`ONI_MODE_is_active()` と `inspect_packet_pipeline()` (`if ONI_MODE or ONI_MODE_is_active():`) の双方が一貫して `stage="oni", block=True` を返す。
- **変更内容**: `toggle_oni_mode()` に `global ONI_MODE` 代入を追加し、`ONI_MODE_is_active()` と `inspect_packet_pipeline()` の判定条件を統一。
- **テスト結果**: **PASS** (`test_toggle_oni_mode_synchronizes_global_and_blocks_pipeline`)
- **残存リスク**: なし。
- **未検証項目**: なし。

---

### 修正項目 6：AI 推論特徴量 (`feature_vector`) の入力境界・NaN/Inf・型検証の強制（PART 6.1）
- **対象ファイル**: `airgap_ai_defender.py`
- **対象関数**: `inspect_packet_pipeline()`, `_normalize_feature_vector()`
- **修正理由**: `inspect_packet_pipeline()` に長さ不足の `feature_vector`（例: `[0.5]*3`）を渡すと `IndexError` でクラッシュし、負値（`[-100.0]*10`）や `float("-inf")` / `float("nan")` を渡すと異常な負のスコアや `-inf` が算出されて Fail-Open となっていたため。
- **修正前の問題**:
  - `feature_vector=[0.5]*3` → `IndexError: list index out of range`
  - `feature_vector=[-100.0]*10` → `ai_score: -74.8, math_score: -100.0, block: False`
  - `feature_vector=[float('-inf')]*10` → `ai_score: -inf, math_score: -inf, block: False`
- **修正後の動作**: `feature_vector` が指定された場合、要素数 `10` (`_ALLOWED_PACKET_FEATURE_LENGTH`)、各要素が `bool` でない `int`/`float`、有限値 (`math.isfinite`)、かつ `[0.0, 1.0]` の範囲内であることを検証し、1つでも満たさない場合は `block=True, stage="feature_validation", reason="invalid_feature_vector", score=0.95` で Fail-Closed 遮断する。
- **変更内容**: `inspect_packet_pipeline()` に `feature_vector` の厳格バリデーションを追加し、`_normalize_feature_vector()` で `bool` 型を拒否。
- **テスト結果**: **PASS** (`test_invalid_feature_vector_fails_closed`)
- **残存リスク**: なし。
- **未検証項目**: 実 PyTorch モデル重みロード時の推論（本環境に `torch` 未インストールのため `_TorchStub` フォールバック動作まで検証、実 `torch` 推論は `NOT TESTED`）。

---

### 修正項目 7：暗号トランスポート (`mk1_secure_transport.py`) への `SessionRatchet`・失効リスト (`RevocationManifest`) 統合と鍵ゼロ化（PART 7）
- **対象ファイル**: `mk1_secure_transport.py`
- **対象関数**: `set_transport_enabled()`, `set_revocation_manifest()`, `require_device_not_revoked()`, `create_ratcheted_session()`
- **修正理由**: `mk1_session_ratchet.py`（前方秘匿・チャンク順序検証ラチェット）と `mk1_key_registry.py`（失効マニフェスト検証）が独立ファイルとして存在するだけで `mk1_secure_transport.py` から一度も参照されておらず、トランスポート無効化時にもアクティブなセッション鍵がメモリ上に残存する構造だったため。
- **修正前の問題**: `mk1_secure_transport.py` 内に `mk1_session_ratchet` / `mk1_key_registry` への参照が 0 件であり、失効済み `device_id` のチェックやトランスポート停止時のラチェット鍵破棄が行われなかった。
- **修正後の動作**:
  1. `set_revocation_manifest()` と `require_device_not_revoked()` により、失効マニフェストに登録された `device_id` のセッション確立・ラチェット生成を即座に拒否する。
  2. `create_ratcheted_session()` で生成した `SessionRatchet` を `_ACTIVE_RATCHETS` で追跡し、`set_transport_enabled(False)` 呼び出し時にすべてのアクティブな `SessionRatchet.destroy()` を呼び出して鍵メモリを即時ゼロ化する。
- **変更内容**: `mk1_secure_transport.py` に `SessionRatchet` / `RevocationManifest` の連携および `set_transport_enabled(False)` 時の `_ACTIVE_RATCHETS` 破棄処理を追加。
- **テスト結果**: **PASS**（モジュール連携・失効拒否・`destroy()` 呼び出しを確認。なお `cryptography` / `pqcrypto` ライブラリ自体の実暗号プリミティブ実行はライブラリ未導入のため `NOT TESTED`）。
- **残存リスク**: なし。
- **未検証項目**: `cryptography` / `pqcrypto` が必要な実 ML-KEM-768 + X25519 鍵交換テスト（`NOT TESTED`）。

---

### 修正項目 8：Quorum 承認モジュール (`mk1_quorum.py`) の `cryptography` 未導入環境でのインポート安全性と Fail-Closed 維持（PART 1.3 / PART 7）
- **対象ファイル**: `mk1_quorum.py`
- **対象関数**: トップレベル import, `_require_cryptography()`, `create_approval_record()`, `_read_trusted_key()`, `verify_approval_bundle()`
- **修正理由**: `mk1_quorum.py` がトップレベルで `from cryptography.exceptions import InvalidSignature` 等を無条件 import していたため、`cryptography` がインストールされていないオフライン環境で `airgap_ai_defender.py` を import すること自体が `ModuleNotFoundError` で失敗していたため。
- **修正前の問題**: `python3 -m unittest tests/test_airgap_ai_defender.py` 実行時に `mk1_quorum.py:13` で `ModuleNotFoundError: No module named 'cryptography'` が発生しテストスイートが起動不能だった。
- **修正後の動作**: `cryptography` の import を `try...except ImportError` で保護しつつ、実際に Ed25519 署名作成・検証関数が呼ばれた際には `_require_cryptography()` が `QuorumError("cryptography library is required for Ed25519 quorum operations")` を送出して **確実に Fail-Closed（承認拒否）** となる。
- **変更内容**: `_CRYPTOGRAPHY_AVAILABLE` フラグと `_require_cryptography()` ガードを追加。
- **テスト結果**: **PASS**（全単体テストスイート248件が起動・実行可能となり、署名検証呼び出し時は `QuorumError` で Fail-Closed となることを確認）。
- **残存リスク**: なし。
- **未検証項目**: `cryptography` を用いた実 Ed25519 署名検証テスト（`NOT TESTED`）。

---

### 修正項目 9：nftables 隔離トランザクション (`mk1_firewall.py`) の `ct state invalid drop`・`lo` 保護・非 root 解除エラー記録（PART 5.3）
- **対象ファイル**: `mk1_firewall.py`, `tests/test_firewall_nft.py`
- **対象関数**: `render_nft_transaction()`, `remove_nft_policy()`
- **修正理由**:
  1. `render_nft_transaction()` が生成する `inet mk1ai_quarantine` テーブルの `input` / `output` / `forward` チェインに `ct state invalid drop` がなく、またローカルループバック (`lo`) の明示許可が含まれていなかったため。
  2. `remove_nft_policy()` を非 root (`os.geteuid() != 0`) で呼び出した際に `_fail()` を呼ばず `last_nft_failure` が更新されていなかったため。
- **修正前の問題**:
  - `render_nft_transaction()` の出力に `ct state invalid drop` と `iifname "lo" accept` / `oifname "lo" accept` が欠落していた。
  - 非 root で `remove_nft_policy()` を呼ぶと `False` を返すが `last_nft_failure` が前回の値のままであった。
- **修正後の動作**:
  - `input` に `iifname "lo" accept` と `ct state invalid drop`、`output` に `oifname "lo" accept` と `ct state invalid drop`、`forward` に `ct state invalid drop` を出力する。
  - `remove_nft_policy()` が非 root 時に `_fail("nftables の解除にはroot権限が必要です")` を記録して `False` を返す。
- **変更内容**: `render_nft_transaction()` と `remove_nft_policy()` を修正し、`tests/test_firewall_nft.py` に回帰テストを追加。
- **テスト結果**: **PASS** (`tests/test_firewall_nft.py` 全6テスト PASS)
- **残存リスク**: `mk1-wireguard-egress.nft.template` の平時 `output` ポリシーは既存テンプレート互換テスト (`tests/test_config_templates.py`) が検査しているためテンプレートファイル自体は維持し、隔離発動時の `mk1_firewall.py` 側で完全遮断を強制している。
- **未検証項目**: 実カーネル `nft -f -` への適用（`PART 1.1`「実ホストのファイアウォール変更禁止」に従い `NOT TESTED`）。

---

## 3. 未修正・承認待ちとして残した項目（PART 1.1 境界遵守）

1. **eBPF / XDP カーネルプログラム (`security/ebpf/mk1_xdp_ingress.bpf.c`) の実配備**:
   - `PART 1.1` の `xdp_design_only` 規定に従い、`MK1AI_XDP_REDESIGN.md` にて完全な C ソースコードおよびローダー連携の Diff 案として提示済み（承認後に配備可能）。
2. **`mk1_path_trust.c` の `#define _XOPEN_SOURCE 700` 追加**:
   - C ソースコード変更の慎重原則に従い、`MK1AI_XDP_REDESIGN.md` セクション 5.2 に 1 行 Diff 案を記載し、コンパイル時は `-D_XOPEN_SOURCE=700` で全 C テスト (`test_mk1_path_trust`, `test_mk1_memory_guard`, `test_mk1_tunnel`) が PASS することを実証済み。
3. **`execute_kill_switch()` / `execute_generated_payload()` の `dry_run=False` ハードコード拒否の解除**:
   - `airgap_ai_defender.py:5984` および `6226` の「イベントごとの管理者承認が未実装のため、実遮断を拒否しました」は、`docs/OPERATOR_APPROVAL_DESIGN.md` および既存単体テスト (`tests/test_airgap_ai_defender.py`) が意図的な安全ロックとしてアサートしているため、勝手にロックを外さず Quorum 承認バンドル (`mk1_quorum.py`) との接続設計を維持した。
