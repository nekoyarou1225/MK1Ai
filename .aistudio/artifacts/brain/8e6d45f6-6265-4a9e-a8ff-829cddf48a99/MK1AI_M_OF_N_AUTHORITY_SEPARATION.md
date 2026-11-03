# MK1AI_M_OF_N_AUTHORITY_SEPARATION.md — 自律隔離と管理者操作の権限分離設計

## 1. 権限分離の基本設計

MK1Ai は「検知は自律、復旧は厳格な承認」という哲学に基づき、以下の権限分離を実装する。

### 1.1 自律型操作 (Autonomous - M-of-N 不要)
- **CORE 隔離 (ISOLATE_NETWORK)**: AI または DPI が重大な侵害を検知した場合。
- **メモリ退避 (MEMORY_EVACUATION)**: RAM 逼迫または侵害予兆時。
- **デコイ停止 (DECOY_HALT)**: ハニーポット内の侵害検知時。

### 1.2 管理者操作 (Administrative - M-of-N 必須)
- **隔離解除 (RECOVERY_ADMIN)**: 通信経路の再有効化。
- **ポリシー変更 (SET_POLICY)**: 閾値やルールの変更。
- **任意コマンド (EXEC_PAYLOAD)**: `execute_generated_payload` による非定型操作。
- **信頼ルート更新 (UPDATE_KEYS)**: 管理者署名鍵の追加・削除。

## 2. 実装上の対策 (CF-04)

### 2.1 ドメイン分離メッセージ
`mk1_quorum.py` における署名対象メッセージに、操作種別（Domain Label）を強制的に含める。

- **隔離メッセージ**: `MK1AI-ISOLATE-v1`
- **復旧メッセージ**: `MK1AI-RECOVERY-v1`

これにより、隔離開始用に取得した管理者の署名を、隔離解除（復旧）に使い回すリプレイ攻撃を数学的に防止する。

### 2.2 署名なし自律パスの安全確保
AI が署名なしで隔離を実行する場合、`execute_kill_switch` の引数 `containment_mode` を `"full_isolation"` に固定し、`management_safe_harbor`（管理経路の維持）への昇格を禁止する（AI が自ら管理経路を「開ける」ことを防ぐ）。

## 3. 監査証跡

すべての自律操作には、AI の判定スコアと各ヘッドの推論根拠（Evidence Reference）を署名と同等レベルの重要ログとして `QuarantineStateStore` に記録する。

---
**検証ステータス**: `DESIGN_FINALIZED`
