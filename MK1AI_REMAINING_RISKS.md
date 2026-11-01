# MK1AI_REMAINING_RISKS — Comprehensive Re-Evaluation of Residual Risks

## 1. 監査方針

前回の `MK1AI_REMEDIATION_REPORT.md` において「残存リスクなし」と記載されていた項目を再監査した結果、**未検証事項（`NOT TESTED`）や設計・実装上の制約がすべての項目に残存しており、「残存リスクなし」という記述は不適切である**と判定した。

本報告書では、指定された全12項目について、実コードの行番号に基づく正確な残存リスクと検証状態（`VERIFIED IN UNIT TEST ONLY` / `NOT TESTED` / `NOT IMPLEMENTED`）を定義する。

---

## 2. 全12項目の残存リスク再評価マトリクス

| # | 評価項目 | 旧報告書の不適切な記載 | 再監査後の正確な判定 | 深刻度 | 検証ステータス |
|---|---|---|---|---|---|
| 1 | DPI `fail_closed` による正常通信の誤遮断・DoSリスク | 「残存リスクなし」 | **残存リスクあり（誤遮断・Self-DoS）** | **HIGH** | 単体テストのみ（実トラフィック `NOT TESTED`） |
| 2 | 暗号化ペイロードの検査限界 | 「残存リスクなし」 | **残存リスクあり（TLS/ESP/WGペイロード検査不能）** | **HIGH** | `NOT TESTED` |
| 3 | IPフラグメントの再構成 | 「残存リスクなし」 | **残存リスクあり（フラグメント再構成未実装）** | **HIGH** | `NOT IMPLEMENTED` / `NOT TESTED` |
| 4 | IPv6拡張ヘッダーの上限と未対応経路 | 「残存リスクなし」 | **残存リスクあり（上限8個・ESP誤計算・バイパス経路残存）** | **MEDIUM** | 単体テストのみ（1ケースのみ） |
| 5 | `ONI_MODE` の状態二重管理 | 「残存リスクなし」 | **残存リスクあり（`bool` と `Event` の非アトミック更新・ORラッチ）** | **MEDIUM** | 単体テストのみ（競合テスト `NOT TESTED`） |
| 6 | 実PyTorch推論の未検証とAI判定の非遮断仕様 | 「残存リスクなし」 | **残存リスクあり（`_TorchStub` のみ・AIスコアは `block=False`）** | **HIGH** | **`NOT TESTED`**（`torch` 未導入） |
| 7 | `SessionRatchet` の鍵ゼロ化限界 | 「完全ゼロ化・残存リスクなし」 | **残存リスクあり（Python `bytes`・OpenSSL内部鍵・未ロック領域に残存）** | **HIGH** | **`NOT TESTED`**（`cryptography` 未導入） |
| 8 | ML-KEMとX25519の実暗号テスト未実施・アルゴリズム不一致 | 「残存リスクなし」 | **残存リスクあり（実暗号未テスト・ML-KEM-768単独と1024+X25519の不整合）** | **HIGH** | **`NOT TESTED`**（`pqcrypto`/`cryptography` 未導入） |
| 9 | Ed25519の実署名検証未実施 | 「残存リスクなし」 | **残存リスクあり（実署名生成・検証とも未実行）** | **HIGH** | **`NOT TESTED`**（`cryptography` 未導入） |
| 10 | `nftables` 実カーネル適用の未検証とテーブル間競合 | 「残存リスクなし」 | **残存リスクあり（実カーネル未適用・`lo` 順序・`mk1ai_egress` 競合）** | **HIGH** | **`NOT TESTED`**（文字列生成・モックのみ） |
| 11 | XDP未実装とNative XDP未検証 | 「XDP設計完了」 | **残存リスクあり（XDP実装ゼロ・`AF_PACKET` 受動監視のみ）** | **CRITICAL** | **`NOT IMPLEMENTED` / `NOT TESTED`** |
| 12 | Kill Switchの実遮断未実装 | 「安全ゲート実装済み」 | **残存リスクあり（Dry-Run 4重ハードコードにより実遮断不能）** | **CRITICAL** | **実遮断 `NOT IMPLEMENTED` / `NOT TESTED`** |

---

## 3. 各項目の詳細根拠（実コード照合）

### 3.1 DPI `fail_closed` による正常通信の誤遮断・DoSリスク
- **該当コード**: `airgap_ai_defender.py:4289–4311` (`analyze_dpi_payload`), `lines 5780–5789` (`inspect_packet_pipeline`)
- **残存リスクの詳細**:
  1. `analyze_dpi_payload(payload)` は `if not payload:`（空ペイロード、`line 4291`）のとき `scan_strategy: "fail_closed"` を返す。`inspect_packet_pipeline()` 内では `if payload:`（`line 5773`）でガードしているが、他の呼び出し元が空バイト列 `b""` を直接 `analyze_dpi_payload()` に渡すと即座に `fail_closed` 判定となる。
  2. `inspect_packet_pipeline()`（`lines 5780–5789`）は `dpi_result.get("scan_strategy") == "fail_closed"` を検知すると無条件に `block=True, stage="dpi_fail_closed", score=1.0` を返す。
  3. 送信元IPが詐称可能な通信（UDPやTCP SYNパケット等）において、攻撃者が被害者（正常な業務端末やゲートウェイ）のIPを送信元に偽装し、パーサーエラー（`parse_error`）やDPI例外を誘発するパケットを3連続で送りつけると、`evaluate_threat_state()` が発火して正常通信やホスト自体を遮断する **自己DoS（Self-DoS）攻撃** が成立する。

### 3.2 暗号化ペイロードの検査限界
- **該当コード**: `airgap_ai_defender.py:4190–4256` (`analyze_packet_security_markers`), `lines 4289–4350` (`analyze_dpi_payload`)
- **残存リスクの詳細**:
  1. TLS 1.3 Application Data、SSH暗号化チャネル、IPsec ESP（IPプロトコル番号 `50`）、およびWireGuardカプセル化パケット（UDP `51820`）のペイロードは高エントロピーな暗号文であり、平文シグネチャ（`/bin/sh` 等）は一切一致しない。
  2. `analyze_packet_security_markers()` はTLS ClientHelloのバージョンやIPsec/WireGuardヘッダの存在を確認するのみで、暗号化トンネル内部の攻撃ペイロードは物理NIC（`eth0`）上では検査不能である。復号後の仮想インターフェース（`wg0` 等）でのインライン検査も現在未構成（`NOT TESTED`）である。

### 3.3 IPフラグメントの再構成
- **該当コード**: `airgap_ai_defender.py:681–768` (`parse_packet_transport`), `lines 646–678` (`_skip_ipv6_extension_headers`)
- **残存リスクの詳細**:
  1. `parse_packet_transport()` はIPv4の `Flags / Fragment Offset` フィールド（`pkt[20:22]`）を一切検査せず、IPフラグメント再構成バッファも持たない。
  2. **非先頭フラグメント（`frag_offset > 0`）の誤解釈**: 第2フラグメント以降にはTCP/UDPヘッダが存在せずIPヘッダ直後にデータ断片が続くが、`parse_packet_transport()` はオフセット `14 + ihl` の先頭4バイトをTCP/UDPの `sport` / `dport` として誤読する。
  3. **分割ペイロードによるDPI回避**: 攻撃者が `/bin/sh -i` 等のバックドア文字列を8バイト単位のIPフラグメントに分割して送信した場合、単一パケット単位のDPI（`analyze_dpi_payload`）ではシグネチャが一致せずすり抜ける。

### 3.4 IPv6拡張ヘッダーの上限と未対応コードパス
- **該当コード**: `airgap_ai_defender.py:646–678` (`_skip_ipv6_extension_headers`), `lines 4233–4245`, `lines 5283–5298`
- **残存リスクの詳細**:
  1. **上限8ヘッダ**: `_skip_ipv6_extension_headers()` は `max_headers=8` で打ち切るため、拡張ヘッダを8個連鎖させたパケットの誤判定リスクがある。
  2. **ESP（Next Header `50`）の誤スキップ**: `_IPV6_EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60, 135, 139, 140}` に `50`（ESP）が含まれており、通常の `(hdr_len + 1) * 8` 式（`line 674`）でスキップしようとしている。しかしESPヘッダは先頭が4バイトのSPI＋4バイトのSequence Numberであり `hdr_len` フィールドを持たない（かつ後続は暗号化されている）ため、SPIの下位バイトをヘッダ長と誤認してオフセット計算が破綻する。
  3. **他関数での未適用**: `_packet_capture_worker()`（`lines 5283–5298`）および `analyze_packet_security_markers()`（`lines 4233–4245`）は `_skip_ipv6_extension_headers()` を呼んでおらず、依然として `proto_num = pkt[20]` および `l4_offset = 14 + 40` をハードコードしているため、IPv6拡張ヘッダ付きパケットで特徴量 `feat[2..6]` およびTLSマーカー検査がバイパスされる。

### 3.5 `ONI_MODE` の状態二重管理
- **該当コード**: `airgap_ai_defender.py:430–457`, `line 5948`
- **残存リスクの詳細**:
  - `ONI_MODE`（`bool`）と `_ONI_MODE_ACTIVE`（`threading.Event`）の二重管理、論理ORによる片側ラッチ、`toggle_oni_mode()` のロック欠如、`handle_packet_event()` における `"oni"` ステージの即時トリガー漏れが残存している（詳細は `MK1AI_FINAL_REPORT_CONSISTENCY.md` 第3章参照）。

### 3.6 実PyTorch推論の未検証（`NOT TESTED`）とAI判定の非遮断仕様
- **該当コード**: `airgap_ai_defender.py:92–265` (`_TorchStub`), `lines 5861–5927` (`inspect_packet_pipeline`)
- **残存リスクの詳細**:
  1. 監査環境に `torch` がインストールされておらず（`TORCH_AVAILABLE == False`）、`SlimeMoldNetwork` の順伝播・逆伝播・重み保存・オンライン学習はすべて `_TorchStub` 上の疑似動作しかテストされていない（`@requires_torch` の11テストはすべて `SKIPPED` / **`NOT TESTED`**）。
  2. `inspect_packet_pipeline()`（`lines 5916–5927`）において、AI推論スコア（`head_a`, `head_b`, `head_c`）が閾値を超過しても `block=False, stage="advisory_scores_only"` を返す設計になっており、単一パケットのパイプライン判定ではAIスコア単独での遮断は行われない。
  3. 第4章（`MK1AI_FINAL_REPORT_CONSISTENCY.md`）で示した通り、`feat[9] = mem_mgr.get_usage_ratio()` がメモリ逼迫時に `1.0` を超えると、AI推論に到達する前の `feature_validation` ステージで全通信が遮断（Self-DoS）される。

### 3.7 `SessionRatchet` の鍵ゼロ化限界
- **該当コード**: `mk1_session_ratchet.py:33–49, 80–97, 118–177`, `mk1_memory_guard.py:190–214`, `mk1_secure_transport.py:221–240`
- **残存リスクの詳細**:
  - `bytearray`（`_send_chain`, `_receive_chain`）は `explicit_bzero` で上書きされるが、`HKDF.derive()` や `hmac.digest()` が返すイミュータブルな Python `bytes` オブジェクト、および `AESGCM(key)` が OpenSSL 内部に複製する鍵スケジュールはゼロ化できない。さらに実テスト（`tests/test_session_ratchet.py`）は `cryptography` 未導入のため **`NOT TESTED`** である（詳細は `MK1AI_CRYPTO_ZEROIZATION_AUDIT.md` 参照）。

### 3.8 ML-KEMとX25519の実暗号テスト未実施（`NOT TESTED`）およびアルゴリズム不一致
- **該当コード**: `mk1_hybrid_kem.py:1–180`, `mk1_secure_transport.py:28–45, 75–92`
- **残存リスクの詳細**:
  1. 環境に `pqcrypto` および `cryptography` がインストールされておらず、`tests/test_hybrid_kem.py`（6テスト）および `tests/test_secure_transport.py`（5テスト）は1件も実行されていない（**`NOT TESTED`**）。
  2. **重大なアーキテクチャ不整合**: `mk1_hybrid_kem.py` は `ML-KEM-1024 + X25519` のハイブリッドKEMを実装しているが、`mk1_secure_transport.py:35` は `mk1_hybrid_kem` をインポートせず、`pqcrypto.kem.ml_kem_768`（`ML-KEM-768` 単独、X25519なし）を直接呼び出している。

### 3.9 Ed25519の実署名検証未実施（`NOT TESTED`）
- **該当コード**: `mk1_quorum.py:31–45, 226–250`, `mk1_key_registry.py:1–160`
- **残存リスクの詳細**:
  - `cryptography` 未導入のため、テストされたのは `_CRYPTOGRAPHY_AVAILABLE == False` のときに `QuorumVerificationError` でFail-Closedする分岐のみであり、実際のEd25519鍵によるM-of-N署名検証、署名改ざん検知、失効鍵拒否、タイムスタンプ期限切れ検証（`tests/test_quorum.py`, `tests/test_key_registry.py`）は **`NOT TESTED`** である。

### 3.10 `nftables` 実カーネル適用の未検証（`NOT TESTED`）およびポリシー競合
- **該当コード**: `mk1_firewall.py:195–240`, `mk1-wireguard-egress.nft.template:1–20`
- **残存リスクの詳細**:
  - `nft -f -` によるLinuxカーネルNetfilterへの実適用は **`NOT TESTED`**。
  - さらに `ct state invalid drop` が `iifname "lo" accept` より前に配置されている問題、および `mk1ai_quarantine`（priority `-10`）の `management_safe_harbor` 許可通信が `mk1ai_egress`（priority `0`, `policy drop`）によって遮断される複数テーブル間競合が残存している（詳細は `MK1AI_NFTABLES_POLICY_AUDIT.md` 参照）。

### 3.11 XDP未実装（`NOT IMPLEMENTED`）とNative XDP未検証（`NOT TESTED`）
- **該当コード**: `airgap_ai_defender.py:5245`
- **残存リスクの詳細**:
  - リポジトリ内にeBPF/XDPのCソース・ビルド成果物・ローダーは存在せず（0ファイル）、パケット取得は `socket.AF_PACKET, socket.SOCK_RAW` による受動コピー監視のみである。したがって、カーネルXDP層でのパケット遮断（`XDP_DROP`）は一切行われていない（詳細は `MK1AI_XDP_IMPLEMENTATION_STATUS.md` 参照）。

### 3.12 Kill Switchの実遮断未実装（Dry-Run 4重ロック）
- **該当コード**: `airgap_ai_defender.py:417, 3989, 5573, 5984, 6933`
- **残存リスクの詳細**:
  - 現行コードは以下の4箇所で実遮断をハードコードで無効化している：
    1. `_DRY_RUN = True`（`line 417`）
    2. CLI引数 `--no-dry-run` 指定時に `parser.error("--no-dry-run is disabled...")` で起動拒否（`line 6933`）
    3. `_ISOLATION_APPROVAL_PENDING = True` による隔離保留（`line 5573`）
    4. `execute_kill_switch()`（`line 5984`）および `execute_generated_payload()`（`line 3989`）が `if not dry_run: return False` で常に即時終了
  - このため、脅威が3連続検知され承認が与えられたとしても、**システムが自律的にNICや通信を実遮断することはできない（`NOT IMPLEMENTED` / `NOT TESTED`）**。
