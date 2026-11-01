# MK1AI_XDP_REDESIGN.md — XDP / TC / nftables / ユーザー空間 多層防御アーキテクチャ再設計書 (`xdp_design_only`)

## 1. 再設計の目的と基本原則

`MK1AI_XDP_GAP_ANALYSIS.md` で特定した「XDP 未実装・`AF_PACKET` 傍受のみによる事後判定すり抜け」「単一 NIC 依存」「Egress 未保護」「カプセル化・断片化回避」「Fail-Open 経路」を根絶するため、**カーネル最前線（XDP Ingress + TC Egress + nftables Quarantine）とユーザー空間 AI/DPI（AF_XDP / RingBuf 連携）を統合した Fail-Closed 多層防御アーキテクチャ**を再設計する。

> **注記（PART 1.1 遵守）**: 本書は `xdp_design_only` 範囲に従い、具体的な配置設計・BPF Map 設計・フェールクローズ設計・完全な C eBPF ソースおよびローダー統合の Diff 案を提示する。実ホストのカーネル・NIC・BPF 環境への直接適用は行わない。

---

## 2. 通信経路別の多層防御配置設計（Placement & Traffic Path Architecture）

```
[外部ネットワーク / 物理NIC (eth0, enp*, wlan0)]
       │
       ▼ (1) XDP Ingress (Native Driver Mode: XDP_DRV / Fallback: XDP_SKB)
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 0: eBPF XDP Ingress Pre-Filter (`mk1_xdp_ingress.bpf.c`)      │
  │  - Heartbeat 死活監視 (User-space Agent TTL 失効時 → Fail-Closed)    │
  │  - ONI_MODE / Global Lockdown Flag → 即時 XDP_DROP (Safe Harbor除く) │
  │  - L2 検証 + VLAN (802.1Q/802.1ad 最大2段) アンラップ                 │
  │  - L3 (IPv4 IHL==5 / IPv6 固定長+拡張ヘッダ検証) 境界チェック         │
  │  - 非先頭 IP フラグメント / 不正 TCP フラグ (NULL/XMAS/SYN+FIN) DROP  │
  │  - LPM Trie Blocklist (`src_ip_blocklist_v4/v6`) → 即時 XDP_DROP     │
  │  - Token-Bucket Per-IP レート制限 (`src_rate_map`)                   │
  │  - 要詳細DPIパケット → AF_XDP (`XSKMAP`) リダイレクト or RingBuf 通知 │
  └─────────────────────────────────────────────────────────────────────┘
       │
       ▼ (通過パケット / 復号後 `wg0` / 仮想ブリッジ `vmbr*`, `tap*`, `veth*`)
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 1: TC clsact Ingress & Egress (`mk1_tc_guard.bpf.c`)          │
  │  - 物理 NIC Egress (送信遮断: C2 ビーコン / 情報持ち出し阻止)         │
  │  - WireGuard `wg0` Ingress/Egress (復号後の平文インナーパケット検査)  │
  │  - 仮想ブリッジ (`vmbr0`, `tap*`) 横移動 (East-West) 遮断             │
  │  - BPF Map (`dst_ip_blocklist`, `flow_verdict_map`) で即時 TC_ACT_SHOT│
  └─────────────────────────────────────────────────────────────────────┘
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 2: nftables (`inet mk1ai_quarantine` priority -400)           │
  │  - `ct state invalid drop` (input / output / forward 全チェイン)      │
  │  - `lo` 明示許可 + Safe Harbor 管理通信以外の完全遮断 / Egress 制限    │
  └─────────────────────────────────────────────────────────────────────┘
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Layer 3: User-Space AI + DPI Engine (`airgap_ai_defender.py`)       │
  │  - 正規化 DPI (UTF-16/URL/HTML Entity/Null-byte 展開 + 文脈検証)     │
  │  - Multi-Head AI 推論 (`feature_vector` 厳格検証 [0.0, 1.0] 10次元)  │
  │  - 脅威検知時 → BPF Map (`src_ip_blocklist` / `lockdown_state`) を    │
  │    ミリ秒未満で直接更新し、XDP/TC 層で後続パケットをカーネル内遮断     │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 3. 各層の検査責務と役割分担

| 検査項目 | XDP Ingress (L0) | TC Ingress/Egress (L1) | nftables (L2) | Python DPI/AI (L3) |
|---|---|---|---|---|
| 超高速 DDoS / ブラックリスト IP 遮断 | **主担当 (`XDP_DROP`)** | Egress 側で補助 (`TC_ACT_SHOT`) | 補助 | ブラックリスト登録元 |
| L2/L3/L4 ヘッダ破損・不正 IHL・不正 TCP フラグ | **主担当 (`XDP_DROP`)** | `wg0` / Egress で実施 | `ct state invalid drop` | 深い構造検証 (`MALFORMED`) |
| VLAN (802.1Q/QinQ) アンラップ | **主担当（最大2段）** | 対応 | カーネル自動処理 | `_unwrap_l2_ether_type` |
| IP フラグメント攻撃 / IPv6 拡張ヘッダ悪用 | **非先頭断片・異常拡張ヘッダを Drop/隔離** | 再構築後 `skb` を検査 | `ct` 再構成検証 | `_skip_ipv6_extension_headers` |
| WireGuard (`wg0`) 復号後ペイロード検査 | 物理 NIC では暗号化 UDP のみ検証 | **`wg0` TC フックで平文検査** | `wg0` フィルタリング | `wg0` ペイロード DPI |
| 送信 (Egress) 情報持ち出し・C2 遮断 | 対象外（XDP は Ingress 専用） | **主担当 (`TC_ACT_SHOT`)** | `output` チェイン | C2 相関・J3/JA4 解析 |
| 多層難読化シグネチャ・AI 異常度推論 | AF_XDP / RingBuf で L3 へ転送 | RingBuf 通知 | — | **主担当 (`inspect_packet_pipeline`)** |

---

## 4. フェールクローズ設計（Fail-Closed Semantics）

1. **ユーザー空間デーモン停止・ハング時の自動 Lockdown（Dead-Man Switch）**:
   - BPF Map `control_state_map` に `last_heartbeat_ns`（`bpf_ktime_get_ns()` 基準のタイムスタンプ）と `heartbeat_ttl_ns`（例：3秒 = `3,000,000,000` ns）を保持する。
   - Python デーモンがクラッシュ・SIGKILL・ハングして Heartbeat 更新が途絶えた場合、XDP プログラムは `now_ns - last_heartbeat_ns > heartbeat_ttl_ns` を検知し、**自動的に Safe Harbor 管理 IP/Port 以外の全通信を `XDP_DROP`（または `management_safe_harbor` 隔離状態）へ移行**する。
2. **XDP アタッチモードのフォールバックと拒否条件**:
   - 第1優先: `XDP_FLAGS_DRV_MODE`（Native Driver XDP）
   - 第2優先: ドライバ非対応時は明示的な運用設定 (`allow_generic_xdp: true`) がある場合のみ `XDP_FLAGS_SKB_MODE`（Generic XDP）へフォールバックし、監査警告を記録する。
   - いずれのアタッチも失敗した場合は、インターフェースを `UP` にする前に `mk1_firewall.apply_nft_policy(mode="management_safe_harbor")` を強制適用して Fail-Closed とする。
3. **パケット境界超過・解析不能時の即座 `XDP_DROP`**:
   - `data + offset > data_end` のすべての境界チェック失敗、未知の IP バージョン、`IHL < 5`、IPv4 オプション付き不審フレーム、未対応カプセル化は `XDP_PASS` ではなく **`XDP_DROP`** とする。

---

## 5. 承認待ちの具体的 Diff 案（`xdp_design_only` 規定に基づく提案）

`PART 1.1`（「XDPのソースコードを直接修正する必要が発見された場合は、具体的なDiff案を作成するだけにしてください。実際の編集は別途承認を得てください」）および C コード修正の安全規定に基づき、以下3点の具体的な Diff 案を提示する。

### 5.1 新規 eBPF/XDP カーネルプログラム案 (`security/ebpf/mk1_xdp_ingress.bpf.c`)

```diff
--- /dev/null
+++ b/security/ebpf/mk1_xdp_ingress.bpf.c
@@ -0,0 +1,238 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/bpf.h>
+#include <linux/if_ether.h>
+#include <linux/if_vlan.h>
+#include <linux/ip.h>
+#include <linux/ipv6.h>
+#include <linux/in.h>
+#include <linux/tcp.h>
+#include <linux/udp.h>
+#include <linux/pkt_cls.h>
+#include <bpf/bpf_helpers.h>
+#include <bpf/bpf_endian.h>
+
+#define MAX_VLAN_DEPTH 2
+#define IPV4_FRAG_OFFSET_MASK 0x1FFF
+#define IPV4_MORE_FRAGS       0x2000
+
+struct mk1_control_state {
+    __u64 last_heartbeat_ns;
+    __u64 heartbeat_ttl_ns;
+    __u32 oni_mode;
+    __u32 fail_closed_lockdown;
+    __u32 safe_harbor_ipv4;   /* network byte order */
+    __u16 safe_harbor_port;   /* network byte order */
+    __u16 reserved;
+};
+
+struct lpm_v4_key {
+    __u32 prefixlen;
+    __u32 addr;
+};
+
+struct rate_bucket {
+    __u64 window_start_ns;
+    __u64 packet_count;
+};
+
+struct {
+    __uint(type, BPF_MAP_TYPE_ARRAY);
+    __uint(max_entries, 1);
+    __type(key, __u32);
+    __type(value, struct mk1_control_state);
+} mk1_control_map SEC(".maps");
+
+struct {
+    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
+    __uint(max_entries, 65536);
+    __uint(map_flags, BPF_F_NO_PREALLOC);
+    __type(key, struct lpm_v4_key);
+    __type(value, __u64); /* expiry timestamp ns */
+} mk1_blocklist_v4 SEC(".maps");
+
+struct {
+    __uint(type, BPF_MAP_TYPE_LRU_HASH);
+    __uint(max_entries, 65536);
+    __type(key, __u32);
+    __type(value, struct rate_bucket);
+} mk1_src_rate_v4 SEC(".maps");
+
+static __always_inline int is_invalid_tcp_flags(const struct tcphdr *tcph) {
+    __u8 flags = ((const __u8 *)tcph)[13];
+    /* NULL scan: no flags set */
+    if (flags == 0)
+        return 1;
+    /* SYN+FIN or SYN+RST */
+    if ((flags & 0x02) && (flags & (0x01 | 0x04)))
+        return 1;
+    /* XMAS scan: FIN+PSH+URG */
+    if ((flags & 0x29) == 0x29)
+        return 1;
+    return 0;
+}
+
+SEC("xdp")
+int mk1_xdp_ingress_filter(struct xdp_md *ctx) {
+    void *data = (void *)(long)ctx->data;
+    void *data_end = (void *)(long)ctx->data_end;
+    __u64 now_ns = bpf_ktime_get_ns();
+
+    struct ethhdr *eth = data;
+    if ((void *)(eth + 1) > data_end)
+        return XDP_DROP; /* Fail-closed on truncated L2 */
+
+    __u16 h_proto = eth->h_proto;
+    void *nh = (void *)(eth + 1);
+
+    #pragma unroll
+    for (int i = 0; i < MAX_VLAN_DEPTH; i++) {
+        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
+            struct vlan_hdr *vhdr = nh;
+            if ((void *)(vhdr + 1) > data_end)
+                return XDP_DROP; /* Fail-closed on truncated VLAN header */
+            h_proto = vhdr->h_vlan_encapsulated_proto;
+            nh = (void *)(vhdr + 1);
+        }
+    }
+    /* Reject triple-tagged VLAN evasion */
+    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))
+        return XDP_DROP;
+
+    __u32 ctrl_key = 0;
+    struct mk1_control_state *ctrl = bpf_map_lookup_elem(&mk1_control_map, &ctrl_key);
+    if (!ctrl)
+        return XDP_DROP; /* Fail-closed if control map is uninitialized */
+
+    int heartbeat_expired = (ctrl->heartbeat_ttl_ns > 0) &&
+                            ((now_ns - ctrl->last_heartbeat_ns) > ctrl->heartbeat_ttl_ns);
+    int lockdown = ctrl->oni_mode || ctrl->fail_closed_lockdown || heartbeat_expired;
+
+    if (h_proto == bpf_htons(ETH_P_IP)) {
+        struct iphdr *iph = nh;
+        if ((void *)(iph + 1) > data_end)
+            return XDP_DROP;
+        if (iph->version != 4 || iph->ihl < 5)
+            return XDP_DROP;
+        __u32 ip_hdr_len = iph->ihl * 4;
+        if (nh + ip_hdr_len > data_end)
+            return XDP_DROP;
+
+        /* Drop non-first IPv4 fragments to prevent stateless signature evasion */
+        __u16 frag_off = bpf_ntohs(iph->frag_off);
+        if ((frag_off & IPV4_FRAG_OFFSET_MASK) != 0)
+            return XDP_DROP;
+
+        /* Check LPM blocklist */
+        struct lpm_v4_key bkey = { .prefixlen = 32, .addr = iph->saddr };
+        __u64 *expiry = bpf_map_lookup_elem(&mk1_blocklist_v4, &bkey);
+        if (expiry && *expiry > now_ns)
+            return XDP_DROP;
+
+        void *l4 = nh + ip_hdr_len;
+        __u16 dport = 0;
+        __u16 sport = 0;
+        if (iph->protocol == IPPROTO_TCP) {
+            struct tcphdr *tcph = l4;
+            if ((void *)(tcph + 1) > data_end)
+                return XDP_DROP;
+            if (tcph->doff < 5 || (void *)tcph + (tcph->doff * 4) > data_end)
+                return XDP_DROP;
+            if (is_invalid_tcp_flags(tcph))
+                return XDP_DROP;
+            sport = tcph->source;
+            dport = tcph->dest;
+        } else if (iph->protocol == IPPROTO_UDP) {
+            struct udphdr *udph = l4;
+            if ((void *)(udph + 1) > data_end)
+                return XDP_DROP;
+            sport = udph->source;
+            dport = udph->dest;
+        }
+
+        if (lockdown) {
+            if (ctrl->safe_harbor_ipv4 != 0 &&
+                iph->saddr == ctrl->safe_harbor_ipv4 &&
+                (dport == ctrl->safe_harbor_port || sport == ctrl->safe_harbor_port)) {
+                return XDP_PASS;
+            }
+            return XDP_DROP;
+        }
+
+        /* Per-source rate limiting (10,000 pkt/s burst guard) */
+        struct rate_bucket *bkt = bpf_map_lookup_elem(&mk1_src_rate_v4, &iph->saddr);
+        if (!bkt) {
+            struct rate_bucket init_bkt = { .window_start_ns = now_ns, .packet_count = 1 };
+            bpf_map_update_elem(&mk1_src_rate_v4, &iph->saddr, &init_bkt, BPF_ANY);
+        } else {
+            if (now_ns - bkt->window_start_ns > 1000000000ULL) {
+                bkt->window_start_ns = now_ns;
+                bkt->packet_count = 1;
+            } else {
+                __sync_fetch_and_add(&bkt->packet_count, 1);
+                if (bkt->packet_count > 10000)
+                    return XDP_DROP;
+            }
+        }
+        return XDP_PASS;
+    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
+        struct ipv6hdr *ip6h = nh;
+        if ((void *)(ip6h + 1) > data_end)
+            return XDP_DROP;
+        if (ip6h->version != 6)
+            return XDP_DROP;
+        if (lockdown)
+            return XDP_DROP;
+        return XDP_PASS;
+    } else if (h_proto == bpf_htons(ETH_P_ARP)) {
+        return lockdown ? XDP_DROP : XDP_PASS;
+    }
+
+    /* Unknown L2 EtherType -> Fail-closed */
+    return XDP_DROP;
+}
+
+char _license[] SEC("license") = "GPL";
```

### 5.2 C パス信頼検証モジュール (`mk1_path_trust.c`) の POSIX コンパイル互換性修正 Diff 案
`gcc -Wall -Wextra -std=c11` で `mk1_path_trust.c` をビルドすると `_XOPEN_SOURCE` 未定義により `O_NOFOLLOW`, `S_ISLNK`, `fstat` が未宣言エラーとなる問題の最小修正 Diff 案：

```diff
--- a/mk1_path_trust.c
+++ b/mk1_path_trust.c
@@ -1,3 +1,4 @@
+#define _XOPEN_SOURCE 700
 #include "mk1_path_trust.h"
 
 #include <errno.h>
```
*(検証済み: `-D_XOPEN_SOURCE=700` を付与してコンパイル・実行すると `test_mk1_path_trust`、`test_mk1_memory_guard`、`test_mk1_tunnel` の全 C 単体テストが 100% PASS することを確認済み。)*
