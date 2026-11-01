# MK1Ai — Post-Remediation Gap & Residual Risk Audit Report (`MK1AI_POSTFIX_GAP_REPORT.md`)

**監査対象**: `MK1AI_REMEDIATION_REPORT.md`, `MK1AI_XDP_GAP_ANALYSIS.md`, `MK1AI_XDP_ENFORCEMENT_MATRIX.md` および実ソースコード（`airgap_ai_defender.py`, `mk1_firewall.py`, `mk1-wireguard-egress.nft.template`）
**監査モード**: 独立読み取り専用監査（コード修正なし）

---

## 1. 「残存リスク：なし」「未検証項目：なし」記述の全面監査と訂正（Section 6）

`MK1AI_REMEDIATION_REPORT.md`（PART 3、項目 1〜9）において、複数の項目で「残存リスク：なし」または「未検証項目：なし」と断定されていた記述を再監査した結果、**単体テストの PASS と本番システムの安全性・可用性が混同されている箇所** を特定した。以下に全項目の誤りを訂正し、実際の残存リスクと未検証事項を明記する。

| 報告書項目 | 旧報告書の不正確な記述 | 監査による訂正（実際の残存リスク・未検証領域） |
|---|---|---|
| **項目1: DPI Fail-Closed 伝播** (`airgap_ai_defender.py:5780`) | 「未検証項目: なし」「残存リスク: なし」 | **【訂正】可用性（自己DoS）リスクおよび未検証領域が存在する。**<br>1. **Fail-Closed による DoS / 可用性リスク**: DPI が例外または不正入力で `fail_closed`（`risk_score=100, block=True`）を返すと、`inspect_packet_pipeline()` は当該パケットを遮断し、さらに呼び出し元が送信元 IP をブラックリスト登録する場合がある。攻撃者がソース IP を偽装（IP Spoofing）してパーサー/DPI 例外を誘発するパケットを送りつけた場合、**正常な通信先やゲートウェイ IP が自己遮断（Self-DoS）される可用性リスク** が存在する。<br>2. **実トラフィック未検証**: 巨大ジャンボフレームや高負荷連続フレームでの DPI 例外発生頻度は実機未検証。 |
| **項目2: 多段エンコード正規化・誤検知抑制** (`airgap_ai_defender.py:1037–1068`) | 「未検証項目: なし」「残存リスク: なし」 | **【訂正】難読化回避の残存リスクが存在する。**<br>1. URL デコードは最大2パス（`range(2)`）に制限されているため、3重以上の URL エンコード（`%25252e...`）、Base64 エンコード、UTF-7、Gzip/Deflate 圧縮ペイロード、チャンク分割、または TCP セグメント分割（複数パケットに跨る攻撃文字列）は検知できない。<br>2. 英語以外のマルチバイト文字（UTF-8 日本語や UTF-16 サロゲートペア）を含むバイナリ混在ペイロードでの誤検知率は未検証。 |
| **項目3: フローキャッシュ悪性スコア保存防止** (`airgap_ai_defender.py:2114`) | 「未検証項目: なし」 | **【訂正】サンプリングスキップ自体の構造的バイパスが残存している。**<br>悪性パケットがキャッシュに保存されるバグは修正されたが、`_should_force_full_scan()`（`lines 1084–1104`）は「同一 5-tuple で先頭5パケット（`count <= 5`）が良性かつペイロード長 `< 256` バイト」であれば、6〜15パケット目（`count % 8 != 0`）の DPI をスキップ（`sampled_skip`）する。したがって、**攻撃者が最初の5パケットに無害な短文を送り、6パケット目に 255 バイト以下の攻撃ペイロードを送信した場合、依然として DPI をバイパスできる**。 |
| **項目4: L2 VLAN / IPv6拡張ヘッダ / ICMP / 切り詰め解析** (`airgap_ai_defender.py:627–1003`) | 「未検証項目: なし」「残存リスク: なし」 | **【訂正】以下の4つのパーサーギャップが残存している。**<br>1. **IPv4 / IPv6 Non-first Fragment の素通り**: IPv4 で `frag_offset > 0`（後続フラグメント）の場合、または IPv6 Fragment Header（Next Header 44）で Fragment Offset > 0 の場合、L4 ヘッダが存在しないにもかかわらずオフセット位置を TCP/UDP ヘッダとして誤解釈するか、ペイロード検査をすり抜ける。<br>2. **IPv6 ESP (Next Header 50) のスキップ不整合**: `_skip_ipv6_extension_headers()`（`line 650`）に `50`（ESP）が含まれているが、ESP ペイロードは暗号化されており標準拡張ヘッダ形式の `(hdr_len + 1) * 8` フィールドを持たないため、後続オフセット計算が破綻する。<br>3. **未知の L2 EtherType の Fail-Open**: IPv4 (`0x0800`) でも IPv6 (`0x86DD`) でもない EtherType（ARP `0x0806`, MPLS `0x8847`, PPPoE `0x8864`, 3段以上の VLAN タグ等）は `parse_error=False` のまま `protocol="UNKNOWN"` を返し、`inspect_packet_pipeline()` を `block=False` で通過する。<br>4. **TCP Data Offset 改ざん時の生ペイロード漏洩**: TCP `data_offset > len(raw_data)` の場合、`parse_error=True` は立つが `result["payload"] = raw_data`（フレーム全体）が代入される。 |
| **項目5: Progressive Defense 判定順序と `defer` 遮断** (`airgap_ai_defender.py:5824–5842`) | 「未検証項目: なし」「残存リスク: なし」 | **【訂正】メモリ枯渇およびスプーフィング DoS リスクが残存している。**<br>1. `ProgressiveDefense` の送信元 IP トラッキング辞書に厳格な LRU 上限・署名検証がない場合、ランダムソース IP フラッドによりメモリ消費が増大する。<br>2. `defer=True` を即座に `block=True` としたことで安全性は向上したが、バースト通信を行う正規クライアントが閾値超過時に即座にドロップされるため、本番トラフィックプロファイルでの閾値調整が未検証。 |
| **項目6: `ONI_MODE` と `_ONI_MODE_ACTIVE` 同期** (`airgap_ai_defender.py:441–457`) | 「未検証項目: なし」「残存リスク: なし」 | **【訂正】直接属性変更に対する非同期リスクが残存している。**<br>`toggle_oni_mode()` 関数を経由せず、外部モジュールやテストから `airgap_ai_defender.ONI_MODE = True` とモジュール属性を直接書き換えた場合、内部関数が参照する `_ONI_MODE_ACTIVE` は `False` のまま取り残される。 |
| **項目7: AI 特徴量ベクトル検証** (`airgap_ai_defender.py:5861–5882`) | 「残存リスク: なし（スタブ環境でも決定論的に動作）」 | **【訂正】AI 判定が最終遮断に反映されない設計ギャップ（P1）が残存している。**<br>1. `feature_vector` が破損している場合は `block=True` で遮断されるが、**正常な形式の `feature_vector` に対して AI が高異常スコア（`ai_anomaly=True`）を出した場合、`inspect_packet_pipeline()`（`line 5920`）の `block = blacklisted or dpi_suspicious or zero_trust_violation` に `ai_anomaly` が含まれていないため、DPI と Zero-Trust が無反応であれば `block=False` で通過する（Advisory-Only）**。<br>2. 実 PyTorch モデル（`TORCH_AVAILABLE=True`）での推論精度・レイテンシは未検証。 |

---

## 2. DPI `fail_closed` 修正に伴う可用性・DoS 影響評価（Section 3 / Section 6）

### 2.1 動作メカニズム
1. `analyze_dpi_payload()`（`airgap_ai_defender.py:2010–2135`）は、入力 `payload` が `None`、空バイト列 `b""`（ただし `inspect_packet_pipeline()` では `if payload:` の場合のみ呼ばれる）、非 `bytes`/`str` 型、または内部解析中に例外が発生した場合に `_build_fail_closed_dpi_result()` を返す。
2. `_build_fail_closed_dpi_result()`（`lines 1018–1034`）は `{"suspicious": True, "risk_score": 100, "scan_strategy": "fail_closed", ...}` を生成する。
3. `inspect_packet_pipeline()`（`line 5780`）はこれを `dpi_suspicious = True` として扱い、`block = True, stage = "dpi"` を返す。

### 2.2 誤遮断（False Positive）および DoS リスクの評価
- **正常な空ペイロード（TCP SYN / ACK / FIN のみ）への影響**:
  - `inspect_packet_pipeline()` の `line 5773` は `if payload:` の条件付きで `analyze_dpi_payload(payload, ...)` を呼び出すため、ペイロード長 0 の正規 TCP 制御パケット（SYN, ACK 等）が誤って `analyze_dpi_payload(b"")` に渡されて `fail_closed` になることはない。
  - **ただし**、外部モジュールが `inspect_packet_pipeline()` を経由せず直接 `analyze_dpi_payload(b"")` を呼び出した場合は、`not payload` 分岐（`line 2033`）により `fail_closed`（`suspicious=True, risk_score=100`）が返る仕様となっている。
- **攻撃者による例外誘発型 DoS のリスク**:
  - 万が一、未知のマルチバイト境界条件等で `_normalize_inspected_payload()` 内部に例外を引き起こすペイロードが存在した場合、当該パケットは確実に遮断（Fail-Closed）されるため**機密性・突破防止は守られる**が、攻撃者が正規サーバの送信元 IP を詐称してそのパケットを送ると、正規サーバ IP が Progressive Defense の違反カウントに加算されブラックリスト入りする **自己遮断（Self-DoS）リスク** がある。

---

## 3. `nftables` の独立検証結果と既存レポート誤記の訂正（Section 5）

`mk1_firewall.py`（`lines 195–231`）、`mk1_render_nft.py`、および `mk1-wireguard-egress.nft.template` を直接検査し、さらに `MK1AI_XDP_GAP_ANALYSIS.md` と `MK1AI_XDP_ENFORCEMENT_MATRIX.md` の記述と照合した。

### 3.1 既存レポートにおける `mk1-wireguard-egress.nft.template` の重大な誤記訂正
- **誤記箇所**:
  - `MK1AI_XDP_GAP_ANALYSIS.md:39`（「`mk1-wireguard-egress.nft.template` の `output` チェインは `policy accept` となっており…」）
  - `MK1AI_XDP_ENFORCEMENT_MATRIX.md:10`（「`mk1-wireguard-egress.nft.template` の `output` ポリシーが `accept` になっている不整合」）
- **実ファイル（`/mk1-wireguard-egress.nft.template`）の事実**:
  - `table inet mk1ai_egress`（`lines 10–51`）のチェイン定義は以下の通り、**すべて `policy drop;` である**：
    - `chain prerouting`: `type filter hook prerouting priority raw; policy drop;`（`line 12`）
    - `chain input`: `type filter hook input priority filter; policy drop;`（`line 21`）
    - `chain forward`: `type filter hook forward priority filter; policy drop;`（`line 31`）
    - `chain output`: `type filter hook output priority filter; policy drop;`（`line 36`）
  - `policy accept;` が設定されているのは、ファイル末尾（`lines 53–59`）の **ARP 専用テーブル `table arp mk1_egress_arp` の `chain output`（`type filter hook output priority filter; policy accept;`，ただし `oifname != $ADMIN_IF drop` で制限）のみ** である。
  - よって、旧レポートの「IPv4/IPv6 Egress テンプレートの `output` が `policy accept` である」という記述は事実誤認であり、本監査報告にて正式に訂正する。

### 3.2 `mk1_firewall.py` の `render_nft_transaction()` 構成監査

| 確認項目 | `mk1_firewall.py` (`lines 195–231`) の実装内容 | 評価・監査結果 |
|---|---|---|
| **テーブル・ファミリ** | `table inet mk1_airgap`（IPv4/IPv6 デュアルスタック統合） | 適切（アトミック置換のため冒頭で `add table` → `delete table` → 再定義を実行）。 |
| **Base Chain / Hook / Priority / Policy** | ・`input`: `type filter hook input priority 0; policy drop;`<br>・`forward`: `type filter hook forward priority 0; policy drop;`<br>・`output`: `type filter hook output priority 0; policy drop;` | 3チェインすべてデフォルト `policy drop`（Fail-Closed）であり適切。 |
| **`ct state invalid drop` と `lo` の評価順序** | `input` チェイン (`lines 210–211`):<br>1. `ct state invalid drop`<br>2. `iifname "lo" accept`<br>3. `ct state established,related accept`<br>`output` チェイン (`lines 222–223`):<br>1. `ct state invalid drop`<br>2. `oifname "lo" accept`<br>3. `ct state established,related accept` | **【注意点（軽微な設計リスク）】**<br>`ct state invalid drop` が `iifname "lo" accept` / `oifname "lo" accept` より**前**に配置されている。Linux カーネルで `lo` インターフェースに対して `notrack` が設定されている環境や、非対称なローカルソケット通信で conntrack 状態が `invalid` と判定された場合、ループバック通信がドロップされる可能性がある。一般的なベストプラクティスでは `iifname "lo" accept` を先頭（1番目）、`ct state invalid drop` を2番目に配置する。 |
| **テンプレートとの役割分担・競合** | `mk1_firewall.py` は `table inet mk1_airgap`（`priority 0`）を生成し、`mk1-wireguard-egress.nft.template` は `table inet mk1ai_egress`（`prerouting priority raw (-300)` および `filter (0)`）を生成する。 | `nftables` では複数テーブルのベースチェインがすべて評価され、**いずれか一方でも `drop` すればパケットは破棄される**。したがって、`mk1_airgap` で許可されたパケットであっても、`mk1ai_egress` 側で WireGuard (`wg0`) 以外の Egress であれば破棄されるため、フェイルセーフ方向に機能する。 |
| **非root時の `remove_nft_policy()` 挙動** | `mk1_firewall.py:141–145` で `os.geteuid() != 0` の場合に `self._fail("remove_nft_policy requires root privileges")` を呼び出し、`last_nft_failure` にエラー文字列を記録して `False` を返す。 | 監査証跡が確実に残るよう修正されていることを実コードで確認済み。 |
| **実カーネルでの適用可否** | `tests/test_firewall_nft.py` は文字列生成と `subprocess.run` モックのみ。 | **実カーネルでの `nft -f -` 適用試験は未実施（`NOT_TESTED`）**。 |
