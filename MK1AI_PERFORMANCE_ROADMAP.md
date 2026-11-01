# MK1AI_PERFORMANCE_ROADMAP.md — 性能検証計画・スケーラビリティロードマップ

## 1. 現状の性能計測値と目標値のギャップ分析（PART 8 / PART 11.6 準拠）

### 1.1 リポジトリ内の実測ベースラインと目標値

`BENCHMARK_REPORT.md`、`docs/performance-capacity.json`、`docs/throughput-component-baseline.json`、および今回オフライン環境で実測した `scripts/throughput_component_probe.py` の結果は以下の通りである。

| 指標 | リポジトリ基準値 (`performance-capacity.json`) | 今回コンテナ環境での実測値 (`throughput_component_probe.py`) | 将来目標値（ノード単体 / クラスタ全体） | 判定 |
|---|---|---|---|---|
| **Python フルパイプライン単一ワーカー処理性能** | **13.75 Mbps** (`0.01375 Gbps`, `1,802.27 pkt/s` @ 955B) | **15.05 Mbps** (`0.01505 Gbps`, `1,973.54 pkt/s` @ 955B) | **1.6 Tbps / node** (`1,600 Gbps`) | **INCONCLUSIVE / GAPPED（Python 単体では約 106,000 倍の乖離）** |
| **ユーザー空間模擬 XDP Pre-filter ステージ** | 1,680 Mbps (`1.68 Gbps`) | 1,093.74 Mbps (`1.09 Gbps`) | カーネル Native XDP で **100〜400 Gbps / NIC** | **模擬値のみ（実カーネル XDP 測定は `NOT TESTED`）** |
| **1.6 Tbps / node 達成に必要な Python ワーカー数** | **116,364 ワーカー** | **106,282 ワーカー** | SmartNIC / DPU + マルチ NIC Native XDP オフロード | **Python のみでの達成は物理的に不可能** |
| **5 Pbps 単方向システム総グッドプット** | **3,125 ノード**（1.6 Tbps/node 前提時）または **363,636,364 Python ワーカー** | 同左 | **3,125 ノード × 1.6 Tbps/node** (水平分散クラスタ) | **アーキテクチャ転換が必須** |

---

## 2. ボトルネックの科学的特定

`scripts/throughput_component_probe.py` によるステージ別レイテンシ内訳（実測値）：

1. **`dpi` ステージ (`analyze_dpi_payload`)**: 平均 **350.09 µs / packet**（全体の **69.1%**）
   - ペイロード全体のエントロピー計算 (`calculate_payload_entropy`)、正規表現走査、文字列スライス・デコードが Python バイトコード上で毎パケット実行されている。
2. **`pipeline` ステージ (`inspect_packet_pipeline`)**: 平均 **149.26 µs / packet**（全体の **29.5%**）
   - `parse_packet_transport()`、`analyze_packet_security_markers()`、複合スコア合成、ロック取得が Python 層で直列実行されている。
3. **`AF_PACKET` (`SOCK_RAW`) のカーネル・ユーザー空間コンテキストスイッチとメモリコピー**:
   - 1パケットごとに `sk_buff` 割り当てと `recvfrom()` システムコールが発生し、10 Gbps（約 14.88 Mpps @ 64B）ですら単一コアあたり 67 ns の処理予算しかないため、Python の関数呼び出しオーバーヘッドだけで飽和する。

---

## 3. 1.6 Tbps / Node および 5 Pbps 達成に向けた4段階ロードマップ

### Phase 1：カーネル Native XDP (`XDP_DRV`) + TC Egress による L2〜L4 ワイヤレート遮断（10〜100 Gbps / NIC）
- **実装内容**:
  - `MK1AI_XDP_REDESIGN.md` で設計した `mk1_xdp_ingress.bpf.c` を NIC ドライバの Native XDP (`XDP_DRV`) モードでアタッチし、LPM Trie ブラックリスト (`mk1_blocklist_v4/v6`)、VLAN 2段アンラップ、不正ヘッダ/非先頭フラグメント遮断、Per-IP レート制限を **sk_buff 割り当て前の DMA リングバッファ上で完結**させる。
  - パケットの 95% 以上（既知の正常フローまたは既知のブラックリスト/不正フレーム）を XDP 層（処理時間 `< 50 ns/packet`）で処理する。
- **検証方法**:
  - 同一ホストまたは対向パケットジェネレータ（TRex / MoonGen / `pktgen`）から 64B / 512B / 1518B フレームを注入し、`bpftool prog profile` と `ethtool -S` で `rx_xdp_drop` / `rx_xdp_pass` / `rx_xdp_redirect` の pps とドロップ率を計測する。

### Phase 2：`AF_XDP` (`XSKMAP`) ゼロコピー + Rust/C 共有メモリ DPI ワーカー化（100〜400 Gbps / Node）
- **実装内容**:
  - 詳細 DPI / AI 判定が必要な新規フロー（先頭 N パケット）や不審パケットのみを、XDP から `bpf_redirect_map(&xsks_map, rx_queue_index, 0)` で **`AF_XDP` UMEM ゼロコピーリング**へ転送する。
  - `_normalize_inspected_payload()`、エントロピー計算、Aho-Corasick / SIMD シグネチャマッチング（Hyperscan / Vectorscan 相当）、および量子化済みニューラル推論（INT8 ONNX / C 拡張）を **GIL のない C/Rust ワーカースレッド（NIC RX キューごとにコアピン留め）** へ移行する。
  - Python (`airgap_ai_defender.py`) はコントロールプレーン（ポリシー管理、BPF Map 更新、Quorum 承認、監査ログ、ハードニング状態遷移）に専念させる。

### Phase 3：SmartNIC / DPU（NVIDIA BlueField-3 / Intel IPU / FPGA）ハードウェアオフロードによる 1.6 Tbps / Node 達成
- **実装内容**:
  - 単一サーバーで **1.6 Tbps（= 4 × 400GbE または 2 × 800GbE）** の双方向インライン検査・暗号化（WireGuard / IPsec / ML-KEM ハイブリッド鍵更新）を行うには、CPU バス（PCIe Gen5 x16 = 片方向最大 64 GB/s = 512 Gbps）を往復させず、**SmartNIC / DPU のハードウェアフローテーブル（DOCA Flow / rte_flow / XDP HW Offload `XDP_FLAGS_HW_MODE`）と正規表現アクセラレータ**で処理する。
  - 1ノードあたり 4 枚の 400GbE SmartNIC を搭載し、各 SmartNIC が 400 Gbps の XDP/Flow オフロード + インライン暗号検証を担うことで **1.6 Tbps / node** を達成する。

### Phase 4：水平クラスタリング（3,125+ ノード）による 5 Pbps 単方向グッドプット達成
- **実装内容**:
  - **5 Pbps（5,000 Tbps）** の単方向グッドプットは、1.6 Tbps/node の防衛ゲートウェイノードを **最低 3,125 ノード（N+1 冗長構成で 3,400 ノード）** ECMP / Anycast BGP ファブリック（Clos トポロジ）で並列配置することで達成する。
  - 各ノードは共有状態を持たない Share-Nothing データプレーンとして動作し、脅威インテリジェンス（ブラックリスト LPM、失効マニフェスト `RevocationManifest`、署名付きモデルハッシュ）のみを PQC ハイブリッド署名付きゴシップ / コントロールプレーンで非同期配信する。

---

## 4. 段階的性能検証テスト計画（Verification Protocol）

| フェーズ | 検証環境 | 測定ツール | 合格基準 (Pass Criteria) | 現在のステータス |
|---|---|---|---|---|
| **Stage A: コンポーネント単体プローブ** | オフライン CI / コンテナ | `scripts/throughput_component_probe.py`, `scripts/performance_capacity.py` | 再現性 CV < 10%、機能テスト 100% PASS | **PASS（実測 15.05 Mbps、全単体テスト PASS）** |
| **Stage B: カーネル XDP / TC 機能・性能検証** | Linux Kernel 6.x + `veth` / 実 NIC (10GbE/25GbE) | `pktgen`, `bpftool`, `nft` | `XDP_DROP` >= 14.88 Mpps/core、すべり抜けパケット 0 件 | **NOT TESTED（`xdp_design_only` 制約）** |
| **Stage C: マルチ NIC 400GbE / 1.6 Tbps ノード検証** | PCIe Gen5 サーバー + 4×400GbE NIC | TRex / RFC 2544 / RFC 9411 ベンチマーク | 1.6 Tbps ゼロパケットロス（正常通信）、攻撃遮断遅延 < 1 ms | **NOT TESTED（ハードウェア未接続）** |
| **Stage D: 5 Pbps クラスタ外挿・ファブリック検証** | マルチポッド Clos テストベッド | テラビットトラフィックジェネレータ群 | 線形スケール効率 >= 96%、コントロールプレーン収束 < 500 ms | **NOT TESTED（クラスタ環境未接続）** |
