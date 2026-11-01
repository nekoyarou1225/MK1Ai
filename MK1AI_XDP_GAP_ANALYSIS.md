# MK1AI_XDP_GAP_ANALYSIS.md — XDP検査網すり抜けの根本原因調査とギャップ分析

## 1. エグゼクティブサマリー（結論）

MK1Ai（Project Sovereign-Airgap）において報告された「XDPによるカーネル側の検査網をすり抜けられた」事象について、現行リポジトリ全128ファイルのソースコード・ビルドスクリプト・systemd定義・テスト・性能プローブを網羅的に照合した結果、**すり抜けの最大かつ直接の根本原因は「リポジトリ内に実稼働する eBPF/XDP カーネルプログラム（`.bpf.c`）、ローダー、アタッチ処理、BPF Map 連携が一切実装されておらず、代わりに Python ユーザー空間の `AF_PACKET` (`SOCK_RAW`) 受動コピーソケットで受信フレームを傍受・事後判定する構造になっていること」**であると特定された。

---

## 2. リポジトリ内エビデンスに基づく事実確認（PART 2 / PART 3.1）

### 2.1 XDP / eBPF 実装の存在確認

| 調査項目 | 確認結果 | 根拠ファイル・行番号 | 判定 |
|---|---|---|---|
| `.bpf.c` / `bpf()` / `libbpf` / `xdp_md` / `SEC("xdp")` ソースコード | **0件（存在しない）** | リポジトリ全Cファイル (`mk1_memory_guard.c`, `mk1_panel.c`, `mk1_path_trust.c`, `mk1_test_runner.c`, `mk1_tunnel.c`, `mk1_tunnel_oqs.c`) に eBPF/XDP 関連コードなし | **FAIL（未実装）** |
| `ip link set ... xdp` / `bpftool` / `tc filter ... bpf` によるアタッチ処理 | **0件（存在しない）** | `security/`, `scripts/`, `airgap_ai_defender.py`, `mk1_firewall.py`, `mk1_quarantine.py` 全域で XDP アタッチ処理なし | **FAIL（未配備）** |
| `scripts/throughput_component_probe.py` における XDP の扱い | **合成ベンチマークのラベルのみ** | `scripts/throughput_component_probe.py:194-247` の `_stage_xdp_prefilter()` は Python の `memoryview` でオフセット `12:14` (EtherType) と `23` (Protocol) を読むだけのユーザー空間ループであり、カーネル XDP ではない | **FAIL（模擬関数のみ）** |
| `docs/THROUGHPUT_DESIGN.md` における記載 | **将来設計の言及のみ** | `docs/THROUGHPUT_DESIGN.md:36-41` にて「Stage 0 — NIC / XDP pre-filter ... Tracked as design work; not simulated in the component probe beyond recording the boundary」と明記 | **確認済み（設計文書のみ）** |
| 実際のパケット取得方式 | **`AF_PACKET, SOCK_RAW` によるユーザー空間コピー** | `airgap_ai_defender.py:6781` (`socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))`) | **FAIL（インライン遮断不可）** |

---

## 3. XDP検査網をすり抜けた10の根本原因（技術的メカニズム）

### 原因1：XDPプログラム自体が未実装・未アタッチ（最大の直接原因）
- **現象**: パケットが NIC ドライバの XDP フックで一切検査されずに Linux カーネルのネットワークスタック (`netif_receive_skb`) へそのまま通過する。
- **メカニズム**: `airgap_ai_defender.py:6781` は `AF_PACKET` (`SOCK_RAW`) ソケットを開いている。Linux カーネルにおいて `AF_PACKET` は `ptype_all` タップであり、**カーネルが sk_buff をクローンしてユーザー空間へ非同期コピーする傍受（ミラー）機構**である。Python 側が `inspect_packet_pipeline()` で `block=True` と判定した時点では、オリジナルパケットは既にカーネルの TCP/IP スタックおよびソケット受信バッファへ到達・処理済みである。

### 原因2：単一インターフェース (`--interface`、既定 `eth0`) のみの監視
- **現象**: `eth0` 以外のインターフェースを通過する通信が完全に未検査となる。
- **メカニズム**: `airgap_ai_defender.py:416` (`_MONITOR_INTERFACE = "eth0"`) および `raw_sock.bind((interface, 0))` (`airgap_ai_defender.py:6785`) により、単一 NIC のみをバインドしている。以下の通信経路は Python キャプチャからも漏れる：
  - ローカルループバック (`lo`)
  - WireGuard 仮想インターフェース (`wg0` — `mk1-wireguard-egress.nft.template` で参照)
  - Proxmox / KVM 仮想ブリッジ・タップ (`vmbr0`, `tap*`, `veth*`, `virbr*` — `proxmox-transfer-registration.sh` で使用)
  - USB Ethernet / 管理用セカンダリ NIC (`enp*`, `wlan0`)

### 原因3：送信通信（Egress）に対する XDP の構造的制約と TC Egress 不在
- **現象**: ホスト内部から外部へ出ていく C2 ビーコンや情報持ち出し（Egress）の初動パケットが XDP で止まらない。
- **メカニズム**: Linux カーネルの XDP は **Ingress（NIC 受信キュー）専用**であり、送信経路（Egress）にはフックを持たない。送信パケットを eBPF でインライン遮断するには **TC (`clsact` `tc-ebpf` egress)** または **cgroup eBPF (`BPF_CGROUP_INET_EGRESS`)** が不可欠だが、どちらも存在しない。さらに `mk1-wireguard-egress.nft.template:9` では `type filter hook output priority 0; policy accept;` と定義されており、平時の出力ポリシーが `accept` になっている。

### 原因4：VLAN (`802.1Q` / `802.1ad`)・IPv6拡張ヘッダ・ICMP カプセル化による検査回避
- **現象**: VLAN タグ付きフレームや IPv6 フラグメント/拡張ヘッダ、ICMP トンネリング通信のペイロードが未抽出のまま通過した。
- **メカニズム**:
  - 修正前の `parse_packet_transport()` (`airgap_ai_defender.py:679`) と `extract_payload_bytes()` (`airgap_ai_defender.py:725`) は Ethernet ヘッダ長を 14 バイト固定 (`ether_type = struct.unpack("!H", packet_bytes[12:14])[0]`) と仮定し、`0x0800` (IPv4) と `0x86DD` (IPv6) しか処理していなかった。
  - IEEE 802.1Q (`0x8100`) や QinQ (`0x88A8`) タグが付与されると `extract_payload_bytes()` は空バイト列 `b""` を返し、シグネチャ検査を素通りしていた。
  - IPv6 においても拡張ヘッダ（Hop-by-Hop `0`, Routing `43`, Fragment `44`, Destination Options `60`）をスキップせず `packet_bytes[20]` を直接 TCP/UDP と比較していたため、拡張ヘッダを1つ挟むだけでペイロード抽出が `b""` となり回避可能であった。
  - ICMP (`proto=1`) / ICMPv6 (`proto=58`) ペイロードも抽出対象外であった（**今回修正済み**）。

### 原因5：トランケート・不正ヘッダ (`IHL < 5` 等) に対する Fail-Open と Progressive Defense の遮断抜け
- **現象**: 短小フレームや不正 `IHL` パケットが `parse_error` にならず通過し、さらに同一送信元から3回以上連続で `parse_error` パケットを送ると3回目で `block=False` に反転して通過した。
- **メカニズム**:
  - 修正前の `parse_packet_transport()` はフレーム長 `< 14` や IPv4 長 `< 20`、`ihl < 20` に対して空辞書 `{}`（`parse_error` なし）を返していた。
  - さらに重大な欠陥として、`inspect_packet_pipeline()` で `evaluate_progressive_defense()` が3回目のエラーで `{"defer": True, "action": "rate_limit"}` を返した際、`return {"block": False, "stage": "rate_limited", ...}` と **Fail-Open (`block: False`)** を返しており、かつブラックリスト判定よりも先に `parse_error` 分岐が実行されていたため、ブラックリスト登録後も永久に `block: False` を返し続けていた（**今回修正済み**）。

### 原因6：DPI `fail_closed` 判定のパイプライン無視と多層エンコーディング回避
- **現象**: DPI で例外や抽出失敗が起きて `scan_strategy: "fail_closed"` が返されても、`inspect_packet_pipeline()` がそれを無視して `block: False` で通過させた。また UTF-16LE/BE・URLエンコード・NULLバイト挿入ペイロードが通過した。
- **メカニズム**:
  - `_build_fail_closed_dpi_result()` は `score: 1.0, suspicious: True, scan_strategy: "fail_closed"` を返すが、修正前の `inspect_packet_pipeline()` は `dpi_result` の `scan_strategy == "fail_closed"` も `dpi_result["attack_signatures"]` もブロック条件として参照しておらず、ハードコードされた生の5文字列 (`_ENFORCEMENT_SIGNATURES`) しかブロックしていなかった（**今回修正済み**）。

### 原因7：フローキャッシュ (`_FLOW_STATE_CACHE`) による後続パケットの検査スキップ
- **現象**: 同一 5-tuple で最初に正常パケットを送ってフローキャッシュに登録した後、同程度の長さの攻撃パケットを送るとサンプリング間隔 (`_FLOW_SAMPLE_INTERVAL = 4`) の間キャッシュ結果 (`score <= 0.49`) が返され検査をすり抜ける。また、疑わしいパケット自体も `elif result["suspicious"]: _cache_flow_result(...)` によりキャッシュされていた。
- **メカニズム**: `analyze_dpi_payload()` の行 2102 で `suspicious=True` の結果まで `_FLOW_STATE_CACHE` に保存し、次回キャッシュヒット時に `score` を `0.49` に切り詰めて返していた（**今回修正済み**）。

### 原因8：WireGuard カプセル化境界における順序問題（暗号化後 vs 復号後）
- **現象**: 物理 NIC (`eth0`) 上では WireGuard トラフィックは UDP ポート 51820（等）の暗号化ペイロードであり、物理 NIC の XDP や raw socket ではインナーパケットの L4/L7 ペイロードを検査できない。一方、復号後のインナーパケットが流れる `wg0` は L3 トンネルデバイスであり、そもそも監視対象になっていなかった。

### 原因9：`execute_kill_switch()` の承認ゲート未実装による実遮断の不発
- **現象**: パイプラインが `block=True` と判定して `evaluate_threat_state()` が `execute_kill_switch(interface, dry_run=False)` を呼び出しても、実際のインターフェース遮断や nftables 隔離が発動しない。
- **メカニズム**: `airgap_ai_defender.py:5984-5988` において、`if not dry_run: log.error("[AIRGAP] イベントごとの管理者承認が未実装のため、実遮断を拒否しました。"); return False` とハードコードされており、また既定動作も `_DRY_RUN = True` (`airgap_ai_defender.py:417`) であるため、検知してもパケットをインラインでも事後でも遮断しない。

### 原因10：`ONI_MODE` の状態分裂による緊急遮断モードの不発
- **現象**: `toggle_oni_mode()` を呼び出して鬼モード（全遮断）を有効化しても、`inspect_packet_pipeline()` が通常通りパケットを通過させた。
- **メカニズム**: `toggle_oni_mode()` は `_ONI_MODE_ACTIVE` (`threading.Event`) のみを更新し、グローバル変数 `ONI_MODE` (`bool`) を更新していなかった。一方、`inspect_packet_pipeline()` は `if ONI_MODE:` のみを参照していたため、`toggle_oni_mode()` による切替が完全に無視されていた（**今回修正済み**）。

---

## 4. 確認できた事実と未検証項目（PART 1.1 / PART 12 準拠）

### 4.1 リポジトリ内で確認・実証できた事実（VERIFIED）
1. eBPF/XDP の C ソースおよびローダーがリポジトリ内に存在しないこと（全ファイル走査で確認）。
2. Python パケットキャプチャが `AF_PACKET, SOCK_RAW` による非同期コピーであり、インライン Drop 機能を持たないこと。
3. Python 判定ロジックに存在した8系統のすり抜け・不整合（DPI `fail_closed` 無視、エンコーディング回避、誤検知、不正ヘッダ素通り、Progressive Defense の `block=False` 反転、`ONI_MODE` 不整合、VLAN/IPv6拡張ヘッダ/ICMP 未抽出、`feature_vector` 未検証）を実コードで再現し、すべて修正・単体テストで検証完了したこと。
4. `mk1_firewall.py` の `render_nft_transaction()` に `ct state invalid drop` およびループバック (`lo`) 保護を追加し、`remove_nft_policy()` の非 root 失敗理由記録を修正したこと。

### 4.2 今回の環境制約により未検証の項目（NOT TESTED）
- **実 NIC ドライバ上での Native XDP (`XDP_DRV`) アタッチとワイヤレート測定**: `PART 1.1` の規定（`xdp_design_only`・実ホストのファイアウォール/ルーティング/稼働中 BPF プログラム操作禁止）に従い、実カーネルへの XDP アタッチは実施せず、`MK1AI_XDP_REDESIGN.md` にて完全な設計および C eBPF / ローダーの Diff 案として提示している。
