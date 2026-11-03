# MK1AI_ONI_MODE_REDESIGN.md — ONI MODE（鬼モード）の状態機械化と防御強化設計

## 1. 現状の課題 (CF-03)

現在の `ONI_MODE` は、有効化されると `inspect_packet_pipeline` で即座に全パケットを遮断 (`stage="oni"`) する極端な実装になっている。これは本来の「監視強化・感度上昇」という目的を逸脱し、正常な管理通信すら不可能にするリスクがある。

## 2. MK1SafetyStateMachine の導入

単なる Boolean フラグから、明示的な状態機械（FSM）へ移行する。

| 状態 (State) | 振る舞い | 遷移条件 |
|---|---|---|
| **NORMAL** | 標準 DPI、標準 AI 閾値 (0.88) | 初期状態、または正常復旧後 |
| **ONI_ARMED** | DPI 全走査、AI 閾値低下 (0.01)、レート制限強化 | 攻撃予兆検知 (Head B) または手動トグル |
| **EMERGENCY** | **CORE 通信全遮断**、デコイ隔離 | 重大攻撃検知 (Head A) またはメモリ侵害 (Head C) |
| **ISOLATED** | 永続的遮断維持、管理コンソールのみ許可 | 隔離完了後 |
| **RECOVERY** | M-of-N 承認プロセス実行中 | 管理者による復旧要求受理 |

## 3. 防御の連動

### 3.1 ONI_ARMED (鬼モード) 有効時
- `_NORMAL_MODE_AI_THRESHOLD` を `_ONI_MODE_SCORE_THRESHOLD` (0.01) へ動的にスワップ。
- `FULL_PACKET_INSPECTION` を強制的に `True` に設定。
- 未知プロトコルスコアに +0.20 のブーストを適用。

### 3.2 自律隔離との同期
`ONI_ARMED` 状態で一定時間（例: 5分）異常が検知されない場合、自動的に `NORMAL` へ戻る「自己修復（Auto-Cooldown）」機能を検討（可用性の確保）。

## 4. 排他制御の堅牢化

`_ONI_MODE_LOCK` に加え、状態遷移の原子的更新を保証するため、`QuarantineStateStore` との書き込み同期を強化する。

---
**検証ステータス**: `DESIGN_PROPOSED`
