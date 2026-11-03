# MK1AI_CORE_ISOLATION_FAILURE_ANALYSIS.md — CORE隔離フェイルオーバー・障害モード分析

## 1. 隔離失敗シナリオの分析

自律型エアギャップにおいて、CORE 隔離が不完全になる、または解除できないリスクを以下の障害モード（Failure Modes）ごとに評価した。

## 2. 障害モードマトリクス (FMEA)

| 障害イベント | 影響 | 対策 (Mitigation) |
|---|---|---|
| **デコイ停止失敗** | 他のデコイから CORE への横展開リスク。 | デコイ停止の成否にかかわらず CORE 隔離（物理/論理）を継続。CORE 側での Ingress Drop を強制。 |
| **制御プロセス停止** | 隔離要求の不達、ONI MODE 非同期。 | **Dead-Man Switch (5s)**。コントローラー停止を検知したカーネル eBPF が自律的に全遮断（Level 2 Lockdown）へ遷移。 |
| **nftables 適用エラー** | フィルタリングの不備。 | `validate_nft_policy()` で原子性を保証。適用失敗時は既存の XDP/TC 境界防御のみで CORE を保護し、管理者に警告。 |
| **監査ログ保存失敗** | 証跡の喪失、復旧判断の困難。 | **Secure Memory Buffer (Head C)**。RAM 内に直近 256 事件を保持。ディスク書き込み失敗時も、管理者は WebAuthn コンソールから RAM 情報を直接読み取れる。 |

## 3. Fail-Secure 設計の維持

システム再起動時、`QuarantineStateStore` はブートプロセスの極めて早い段階で隔離状態を読み込み、ネットワークインターフェースが `UP` になる前に `nftables` または `ip link set down` を適用する。

---
**検証ステータス**: `STATICALLY_ANALYZED`
