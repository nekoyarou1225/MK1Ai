# MK1Ai — Next-Stage Kernel XDP Implementation Readiness & Specification (`MK1AI_XDP_IMPLEMENTATION_READINESS.md`)

**監査対象**: `MK1AI_XDP_GAP_ANALYSIS.md`, `MK1AI_XDP_REDESIGN.md`, `MK1AI_XDP_ENFORCEMENT_MATRIX.md`, `MK1AI_PERFORMANCE_ROADMAP.md`
**位置付け**: 本番実装フェーズ（Phase 2）に向けた実行可能な XDP / TC / `nftables` / WireGuard 統合実装計画書（**※現時点では設計完了段階 `xdp_design_only` であり、カーネル XDP は未実装・実機未検証である**）

---

## 1. 現行の実装ステータスと前提整理

- **現状の正確な分類**:
  - リポジトリ内に `.bpf.c` ソース、`libbpf` ローダー、BPF マップ Pinning、TC `clsact` フィルタ、`AF_XDP` ソケットの実装は **0行（完全未実装）** である。
  - `airgap_ai_defender.py:3903` は `AF_PACKET` (`SOCK_RAW`) による受動コピー監視であり、カーネル network stack へのパケット流入を遮断できない。
- **前回作成された `MK1AI_XDP_REDESIGN.md` 内の設計コード（`mk1_xdp_ingress.bpf.c` 案）に対する独立監査で発見された4つの欠陥**:
  次期フェーズで C コードを実装する際、`MK1AI_XDP_REDESIGN.md`（`lines 91–289`）のドラフトをそのままビルド・適用してはならない。以下の4点を必ず修正して実装する必要がある：
  1. **【重大欠陥】TCP 宛先ポート 22（SSH）の無条件レート制限免除（`lines 247–248`）**:
     - 旧設計ドラフトでは `if (bpf_ntohs(th->dest) == 22) return XDP_PASS;` と記述されており、攻撃者が宛先ポート 22 へ向けて SYN フラッドや不正フラグ攻撃を送ると、`mk1_src_rate_v4`（PPS レート制限）を完全にバイパスして `XDP_PASS` してしまう。ポート22であっても必ず PPS トークンバケット検査を通さなければならない。
  2. **【重大欠陥】IPv6 パケットに対するブロックリストおよび拡張ヘッダ検査の欠落（`lines 176–198`）**:
     - 旧設計ドラフトでは `ETH_P_IPV6` の場合に `mk1_blocklist_v6` マップを参照しておらず、さらに `nh_off += sizeof(struct ipv6hdr)` で固定オフセット加算しているため、IPv6 拡張ヘッダ（Routing, Fragment, Hop-by-Hop）が付与されたパケットで L4 TCP/UDP 検査がすべてバイパスされる。
  3. **【中度欠陥】802.1Q / QinQ VLAN タグにおける `vlan_tci` 検査の欠落（`lines 136–146`）**:
     - VLAN ヘッダを最大2段スキップするのみで、許可されていない VLAN ID（VID）や Priority Tagging（VID 0）を検証していない。
  4. **【中度欠陥】Non-first IPv4/IPv6 フラグメントの素通り（`lines 160–175`）**:
     - IPv4 の `frag_off & bpf_htons(0x1FFF)`（Fragment Offset > 0）を検査していないため、L4 ヘッダを持たない後続フラグメントが L4 検査をバイパスして `XDP_PASS` となる。

---

## 2. カーネル XDP 実装仕様（修正版アーキテクチャ）

### 2.1 コンポーネント構成とファイル配置
```text
security/ebpf/
├── mk1_common.bpf.h          # 共通構造体・定数・BPFマップキー定義
├── mk1_xdp_ingress.bpf.c     # L0: Native XDP Ingress フィルタ (SEC("xdp"))
├── mk1_tc_egress.bpf.c       # L1: TC clsact Egress/Ingress 境界フィルタ (SEC("tc"))
└── mk1_ebpf_loader.c         # libbpf ベースのローダー・Pinning・ヘルスチェックデーモン
```

### 2.2 `libbpf` ローダー仕様 (`mk1_ebpf_loader.c`)
1. **CO-RE (Compile Once – Run Everywhere)**:
   - `vmlinux.h` と `<bpf/bpf_helpers.h>` / `<bpf/bpf_endian.h>` を用い、`clang -O2 -g -target bpf -D__TARGET_ARCH_x86` でビルドする。
2. **アトミックロードと Pinning**:
   - `bpf_object__open_file("mk1_xdp_ingress.bpf.o", NULL)` → `bpf_object__load(obj)` を実行。
   - 全 BPF マップを `/sys/fs/bpf/mk1/` 配下に Pinning（`bpf_map__pin()`）し、権限を `0600 (root:root)` に固定する。
   - 既存 XDP プログラムが稼働中の場合は、`bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_REPLACE, &opts)` によりダウンタイム 0 でアトミック置換する。

### 2.3 Native XDP ドライバ要件と対象 NIC
| インターフェース種別 | 対象 NIC 例 | 必須 XDP モード | ドライバ要件・注意点 |
|---|---|---|---|
| **物理 WAN / 境界 NIC** | `eth0` / `enp*` | `XDP_FLAGS_DRV_MODE` (Native XDP) | Intel `i40e` / `ice` / `igb`、Mellanox `mlx5_core`、または Proxmox `virtio_net`（Multi-queue 有効）。ドライバ非対応時は自動で `SKB_MODE` にフォールバックせず、起動エラー（Fail-Closed）とする設定をデフォルトとする。 |
| **Proxmox ブリッジ** | `vmbr0` | `XDP_FLAGS_SKB_MODE` + 物理スレーブ NIC に `DRV_MODE` | Linux ブリッジ自体には Native XDP が効かないため、必ず物理アップリンク NIC 側に Native XDP をアタッチする。 |
| **WireGuard トンネル** | `wg0` | **TC `clsact` (`ingress` / `egress`)** | `wg0` は L3 仮想デバイス（Ethernet ヘッダなし）であり Native XDP 非対応のため、**TC eBPF (`SEC("tc")`)** をアタッチして復号後平文パケットを検査する。 |

---

## 3. TC (Traffic Control) Ingress / Egress・`nftables`・WireGuard の協調設計

### 3.1 パケット処理パイプラインと WireGuard 復号前後の検査ポイント
```text
[物理 NIC (eth0)]
   │
   ▼ ① 【復号前検査】Native XDP Ingress (mk1_xdp_ingress.bpf.c)
   │    - 0x8100/0x88A8 VLAN VID ホワイトリスト検査
   │    - IPv4/IPv6 LPM ブロックリスト即時 XDP_DROP
   │    - 不正 TCP フラグ (NULL/XMAS/SYN+FIN/SYN+RST)・切り詰めヘッダ XDP_DROP
   │    - IPv4/IPv6 Non-first フラグメントまたは異常拡張ヘッダ XDP_DROP
   │    - 送信元 IP 単位 Token Bucket (Port 22 含む全ポート対象) 超過時 XDP_DROP
   │    - WireGuard 外装 UDP パケット (例: UDP 51820) のサイズ・レート検査
   │    - ユーザ空間ハートビート (mk1_control_map) タイムアウト時は管理通信以外全 XDP_DROP
   │
   ▼ ② 【復号前ステートフル検査】nftables (table inet mk1_airgap / mk1ai_egress)
   │    - ct state invalid drop
   │    - 許可外 UDP/TCP ポートの完全遮断
   │
   ▼ ③ 【WireGuard カーネルモジュール (wg0)】
   │    - Noise_IKpsk2 + ML-KEM-1024/X25519 PSK によるパケット復号
   │
   ▼ ④ 【復号後検査】wg0 TC clsact Ingress / Egress (mk1_tc_egress.bpf.c)
   │    - 復号された内部 IPv4/IPv6 ヘッダと内部送信元 IP のゼロトラスト照合
   │    - 内部ペイロードの AF_XDP / RingBuf メタデータ抽出 → Python DPI / AI エンジンへ転送
   │    - Egress 方向: wg0 以外のインターフェースへ出ようとする平文リークを TC_ACT_SHOT で即時破棄
```

### 3.2 `nftables` との役割分担
- **XDP (L0)**: ステートレスな高速フィルタリング（LPM ブロックリスト、パケット構造異常、SYN/UDP フラッドの Token Bucket 制限）。conntrack テーブルを消費させないために `nf_conntrack` 到達前に `XDP_DROP` する。
- **TC `clsact` (L1)**: Egress 方向の情報漏洩防止（Kill Switch 発動時の `TC_ACT_SHOT`）および L3 デバイス（`wg0`）上の復号後検査。
- **`nftables` (L2)**: コネクション状態追跡（`ct state established,related` / `ct state invalid drop`）および動的 `set` による L3/L4 ポリシー強制。

---

## 4. BPF マップ完全定義と Fail-Closed 制御設計

| マップ名 | BPF マップ種別 | Key 型 (サイズ) | Value 型 (サイズ) | `max_entries` | 用途・Pinning パス |
|---|---|---|---|---:|---|
| `mk1_control_map` | `BPF_MAP_TYPE_ARRAY` | `__u32` (4B) | `struct mk1_ctrl_cfg` (32B: `heartbeat_ns`, `lockdown_mode`, `allowed_vlan_bitmap`) | 1 | `/sys/fs/bpf/mk1/control_map`<br>デーモン死活監視・ロックダウン制御・Kill Switch 即時発動 |
| `mk1_blocklist_v4` | `BPF_MAP_TYPE_LPM_TRIE` | `struct lpm_v4_key` (8B: `prefixlen` + `addr`) | `__u64` (8B: 遮断時刻/理由コード) | 65,536 | `/sys/fs/bpf/mk1/blocklist_v4`<br>IPv4 単一IP (`/32`) およびサブネット遮断 |
| `mk1_blocklist_v6` | `BPF_MAP_TYPE_LPM_TRIE` | `struct lpm_v6_key` (20B: `prefixlen` + `addr[16]`) | `__u64` (8B: 遮断時刻/理由コード) | 65,536 | `/sys/fs/bpf/mk1/blocklist_v6`<br>IPv6 単一アドレス (`/128`) およびプレフィックス遮断 |
| `mk1_src_rate_v4` | `BPF_MAP_TYPE_LRU_HASH` | `__be32` (4B: IPv4 src) | `struct rate_bucket` (16B: `last_ns`, `tokens`) | 131,072 | `/sys/fs/bpf/mk1/src_rate_v4`<br>IPv4 送信元単位 PPS レート制限 |
| `mk1_src_rate_v6` | `BPF_MAP_TYPE_LRU_HASH` | `struct in6_addr` (16B: IPv6 src) | `struct rate_bucket` (16B: `last_ns`, `tokens`) | 65,536 | `/sys/fs/bpf/mk1/src_rate_v6`<br>IPv6 送信元単位 PPS レート制限 |
| `mk1_verdict_stats` | `BPF_MAP_TYPE_PERCPU_ARRAY` | `__u32` (4B: 理由ID) | `__u64` (8B: パケットカウンタ) | 16 | `/sys/fs/bpf/mk1/verdict_stats`<br>ロックフリー統計カウンタ |
| `mk1_xsks_map` | `BPF_MAP_TYPE_XSKMAP` | `__u32` (4B: `queue_id`) | `__u32` (4B: `xsk_fd`) | 64 | `/sys/fs/bpf/mk1/xsks_map`<br>Python/C DPI エンジンへの `AF_XDP` ゼロコピー転送 |

### 4.1 Fail-Closed デッドマンズスイッチ（Dead-Man's Switch）仕様
- Python 防御エンジン（または C 監視デーモン）は 1秒周期で `bpf_ktime_get_ns()` 相当のモノトニック時刻を `mk1_control_map[0].heartbeat_ns` に書き込む。
- XDP プログラムはパケット受信時に `now_ns - ctrl->heartbeat_ns > 5,000,000,000ULL`（5秒超過）または `ctrl->lockdown_mode == 1` を検知した場合、ユーザ空間デーモンがクラッシュまたはハングしたと判定し、**全パケットを自動的に `XDP_DROP`（Fail-Closed）** する。

---

## 5. 切り戻し（Rollback）手順と隔離検証環境での回帰テスト計画

### 5.1 緊急切り戻し（Rollback）手順
万が一、本番導入時に XDP プログラムの不具合で正常な管理通信が途絶した場合に備え、以下の3段階の切り戻し手段を実装する：
1. **マップフラグによるソフトバイパス（ミリ秒単位）**:
   - `bpftool map update pinned /sys/fs/bpf/mk1/control_map key 0 0 0 0 value ...` によりメンテナンスモードへ遷移。
2. **XDP デタッチ（`nftables` L2 防御は維持）**:
   - `ip link set dev <IFACE> xdp off` および `tc qdisc del dev <IFACE> clsact` を実行。この際も `table inet mk1_airgap`（`policy drop`）がカーネル内で稼働し続けるため、ノーガード状態（Fail-Open）にはならない。
3. **systemd Watchdog 自動ロールバック**:
   - ローダー起動後 30 秒以内にヘルスチェック確認が完了しない場合、`ExecStopPost` フックにより旧 BPF オブジェクトへ自動復元する。

### 5.2 隔離検証環境（`ip netns` + `veth` + `BPF_PROG_TEST_RUN`）での回帰テスト計画
実ホストの NIC やルーティングに一切触れずに XDP / TC / `nftables` を完全検証するため、次フェーズでは以下の2段階テストを実施する：

1. **Stage 1: `bpf_prog_test_run_opts()` による単体カーネルベリファイア＆パケット判定テスト**:
   - 物理 NIC にアタッチせず、`BPF_PROG_TEST_RUN` システムコールにテストパケット（802.1Q/QinQ、IPv6 拡張ヘッダ、TCP XMAS/NULL/SYN+FIN、Port 22 SYN フラッド、切り詰めヘッダ、ハートビート期限切れ）を入力し、戻り値が `XDP_DROP (1)` であることをアサートする。
2. **Stage 2: 隔離 Network Namespace (`mk1_test_ns`) + `veth` ペア統合テスト**:
   - `ip netns add mk1_test_ns` 内に仮想インターフェース `veth_mk1` を作成し、名前空間内部でのみ XDP プログラム、TC `clsact`、および `nft -f`（`table inet mk1_airgap`）を適用して実パケット送受信試験を行う。
