# MK1AI_NFTABLES_POLICY_AUDIT — nftables Rule Order, Chain Priority & Policy Audit

## 1. 監査の目的と対象ファイル

リポジトリ内のすべての `nftables` 関連ファイル（以下の3ファイル＋1テストファイル）を直接照合し、`input` / `output` / `forward` チェーン、hook、priority、デフォルトpolicy、ルール評価順序、複数テーブル間の競合、および実カーネル適用の有無を監査した。

- `/mk1_firewall.py`（`render_nft_transaction()`, `lines 195–240`）
- `/mk1-wireguard-egress.nft.template`（`lines 1–20`）
- `/mk1_render_nft.py`（`lines 1–85`）
- `/tests/test_firewall_nft.py`（`lines 1–80`）

---

## 2. テーブル・チェーン・Hook・Priority・デフォルトPolicy一覧

リポジトリには2系統の `nftables` 定義（隔離用 `mk1_firewall.py` と、通常時WireGuard出力制限用 `mk1-wireguard-egress.nft.template`）が存在する。

| 生成元ファイル | テーブル名（ファミリ） | チェーン名 | Hook | Priority | デフォルト Policy | 定義されているルール（上から評価順） |
|---|---|---|---|---|---|---|
| `mk1_firewall.py`<br>(`strict_airgap` モード) | `inet mk1ai_quarantine` | `input` | `input` | **`-10`** | **`drop`** | 1. `ct state invalid drop`<br>2. `iifname "lo" accept` |
| `mk1_firewall.py`<br>(`strict_airgap` モード) | `inet mk1ai_quarantine` | `output` | `output` | **`-10`** | **`drop`** | 1. `ct state invalid drop`<br>2. `oifname "lo" accept` |
| `mk1_firewall.py`<br>(`strict_airgap` モード) | `inet mk1ai_quarantine` | `forward` | `forward` | **`-10`** | **`drop`** | （ルールなし — 全パケットが `policy drop` で遮断） |
| `mk1_firewall.py`<br>(`management_safe_harbor` モード) | `inet mk1ai_quarantine` | `input` | `input` | **`-10`** | **`drop`** | 1. `ct state invalid drop`<br>2. `iifname "lo" accept`<br>3. `ip/ip6 saddr <mgmt_ip> tcp dport <port> accept`<br>4. `ip/ip6 saddr <mgmt_ip> tcp sport <port> accept` |
| `mk1_firewall.py`<br>(`management_safe_harbor` モード) | `inet mk1ai_quarantine` | `output` | `output` | **`-10`** | **`drop`** | 1. `ct state invalid drop`<br>2. `oifname "lo" accept`<br>3. `ip/ip6 daddr <mgmt_ip> tcp sport <port> accept`<br>4. `ip/ip6 daddr <mgmt_ip> tcp dport <port> accept` |
| `mk1_firewall.py`<br>(`management_safe_harbor` モード) | `inet mk1ai_quarantine` | `forward` | `forward` | **`-10`** | **`drop`** | （ルールなし — 全パケットが `policy drop` で遮断） |
| `mk1-wireguard-egress.nft.template` | `inet mk1ai_egress` | `output` | `output` | **`0`** | **`drop`** | 1. `oifname "lo" accept`<br>2. `oifname "<WG_INTERFACE>" accept`<br>3. `<WG_ENDPOINT_RULES>` (`ip/ip6 daddr <ep> udp dport <port> accept`)<br>4. `<MK1_DHCP_RULES>` (任意: UDP `68 -> 67 accept`)<br>*(※ `input` / `forward` チェーンは未定義)* |
| `mk1-wireguard-egress.nft.template` | `arp mk1_egress_arp` | `output` | `output` | **`0`** | **`accept`** | （ルールなし — 全インターフェースへのARP出力を無条件許可） |

---

## 3. ルール評価順序と設計上の問題点（4点）

### 3.1 `ct state invalid drop` と `lo`（ループバック）の評価順序の逆転
- **実コード（`mk1_firewall.py:210–214`）**:
  ```nft
  add rule inet mk1ai_quarantine input ct state invalid drop
  add rule inet mk1ai_quarantine input iifname "lo" accept
  add rule inet mk1ai_quarantine output ct state invalid drop
  add rule inet mk1ai_quarantine output oifname "lo" accept
  ```
- **問題点**:
  - `ct state invalid drop` が `iifname "lo" accept` / `oifname "lo" accept` **よりも前（第1ルール）** に配置されている。
  - Linux Netfilterにおいて、ループバック（`lo`）上のローカルIPC通信（特にconntrackテーブルのリセット直後の中途ストリームパケットや一部のRAWソケット通信）が `ct state invalid` と判定された場合、`lo` ルールに到達する前に第1ルールでDropされる。
  - 標準的な `nftables` ベストプラクティスでは、第1ルールを `iifname "lo" accept`（および `oifname "lo" accept`）、第2ルールを `ct state invalid drop` とすべきである。

### 3.2 複数テーブル（`mk1ai_quarantine` と `mk1ai_egress`）のPriority競合による Safe Harbor 遮断バグ
- **問題点**:
  - Linuxカーネルの `nftables` では、同一hook（例：`output`）に複数のベースチェーンが存在する場合、**priorityの数値が小さい順**（`-10` → `0`）に評価される。
  - あるベースチェーンで `drop` されたパケットは即座に破棄されるが、**先行チェーン（priority `-10`）で `accept` されたパケットは後続チェーン（priority `0`）の評価も通過しなければならない**。
  - 通常運用時に `table inet mk1ai_egress`（`output priority 0; policy drop`）がロードされている状態で、`mk1_firewall.py` が `management_safe_harbor` モードで `table inet mk1ai_quarantine`（`output priority -10; policy drop`）を追加投入すると：
    1. 管理端末（`<mgmt_ip>`）へのSSH/HTTPS応答パケットは、まず `mk1ai_quarantine output`（priority `-10`）で `accept` される。
    2. 次に `mk1ai_egress output`（priority `0`）へ進むが、管理端末が物理LAN（`eth0` 等、`wg0` 以外）に存在する場合、`mk1ai_egress` には管理端末許可ルールが存在しないため、**`mk1ai_egress` のデフォルトポリシー `policy drop` によって破棄される**。
  - すなわち、**`mk1ai_egress` が有効な環境では、`management_safe_harbor` モードが意図通りに機能せず管理通信まで完全遮断される**。

### 3.3 `management_safe_harbor` におけるステートレスTCP許可の過剰開放
- **実コード（`mk1_firewall.py:222–233`）**:
  ```nft
  add rule inet mk1ai_quarantine input ip saddr <addr> tcp dport <port> accept
  add rule inet mk1ai_quarantine input ip saddr <addr> tcp sport <port> accept
  add rule inet mk1ai_quarantine output ip daddr <addr> tcp sport <port> accept
  add rule inet mk1ai_quarantine output ip daddr <addr> tcp dport <port> accept
  ```
- **問題点**:
  - `ct state established,related` や方向別の `ct state new` 制限を設けておらず、`saddr` と `sport`/`dport` の一致のみで双方向のTCPパケットを許可している。
  - このため、管理IP（`<addr>`）の送信元ポートを `<port>`（例：`22` や `443`）に偽装した任意の宛先ポートへのインバウンドTCP SYNパケット（`input ip saddr <addr> tcp sport <port> accept`）が、隔離中のホストの別サービスポートへ通過できる。

### 3.4 `mk1-wireguard-egress.nft.template` における `input`/`forward` 未定義と ARP 無条件許可
- **問題点**:
  1. `table inet mk1ai_egress` は `output` チェーンのみを定義しており、`input` チェーン、`forward` チェーン、および `ct state invalid drop` を持たない。
  2. `table arp mk1_egress_arp`（`lines 16–20`）は `chain output { type filter hook output priority 0; policy accept; }` のみでルールが1行もなく、全インターフェースへのARP送信を無条件に `accept` している。

---

## 4. テスト範囲と実カーネル適用の検証ステータス

| 検証項目 | ステータス | 根拠 |
|---|---|---|
| `render_nft_transaction()` のルール文字列生成 | **VERIFIED（単体テストのみ）** | `tests/test_firewall_nft.py` にて生成文字列の部分一致を確認。 |
| IPアドレス・ポート・インターフェース名のバリデーション | **VERIFIED（単体テストのみ）** | `tests/test_firewall_nft.py` にてインジェクション文字列の拒否を確認。 |
| `apply_firewall_policy()` の `subprocess.run` 呼び出し | **MOCKED ONLY** | `tests/test_firewall_nft.py` では `unittest.mock` で `subprocess.run` を差し替えており、`nft` バイナリは呼ばれていない。 |
| **実カーネル（Linux Netfilter）への `nft -f -` 適用・構文検証** | **`NOT TESTED`** | 非root環境かつ実環境保護ルールにより、カーネルへのルールロードは一度も実行していない。 |
| **実パケットによる遮断・`lo` 通信・Safe Harbor 疎通確認** | **`NOT TESTED`** | 実ネットワーク・実カーネルでのパケット通過/遮断試験は未実施。 |
