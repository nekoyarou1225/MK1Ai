# MK1AI_AUTONOMOUS_AIRGAP_REMEDIATION.md — 自律型エアギャップ隔離の再設計と実装計画

## 1. 目的

現在の MK1Ai は、AI が深刻な脅威を検知しても人間の M-of-N 署名（クォーラム承認）を待つ設計になっており、緊急時の隔離遅延が P0 級の脆弱性となっている。本改修では、AI 3ヘッドの判断に基づく「自律型隔離（Autonomous Isolation）」パスを新設し、人間の承認を待たずに CORE を保護する。

## 2. 現在の実装の欠陥（CF-01 / CF-02）

- **ファイル**: `airgap_ai_defender.py`
- **該当箇所**: `evaluate_threat_state()` (line 5684)
- **問題点**: 
    - `dry_run=False` の場合、`verify_event_isolation_approval()` が `True` を返さない限り実遮断が実行されない。
    - `approval_bundle` は外部（管理者）から提供される必要があり、AI 単独では発行できない。
    - 3ヘッドのうち Head A のスコアのみがトリガーとなっており、B/C の独立した判断が隔離に反映されない。

## 3. 自律型エアギャップ隔離の設計

### 3.1 権限分離の原則

- **自律隔離 (Autonomous)**: AI が検知した証拠に基づき、**CORE 隔離のみ**を即座に実行する。任意コマンドの実行や隔離の解除は許可しない。
- **管理者承認 (Administrative)**: 隔離の解除、復旧、ポリシー変更、および AI が判断できない例外的な操作（任意ペイロード実行）に M-of-N 承認を要求する。

### 3.2 自律隔離シーケンス

1.  **AI Request**: Head A/B/C のいずれかが閾値を超え、重大な脅威（侵入、予測、メモリ侵害）を検知。
2.  **Autonomous Trigger**: `evaluate_threat_state` 内で `approval_bundle` が `None` であっても、AI の判定値のみで `execute_kill_switch(autonomous=True)` を呼び出す。
3.  **Bounded Operation**: 自律モードの `execute_kill_switch` は、あらかじめハードコードされた「CORE 隔離ペイロード」のみを実行。
4.  **State Persistence**: 隔離状態を `QuarantineStateStore` に永続化し、解除には管理者の署名付き復旧トークンを必須とする。

## 4. 回帰リスクと対策

- **リスク**: AI の誤検知（False Positive）による自律隔離の頻発。
- **対策**: 
    - 3ヘッドの証拠相関（Evidence-based verification）の導入。
    - 隔離開始は自律的に行うが、誤検知の場合でも解除は人間が行うことで、安全側（Fail-Closed）を維持する。
    - ONI MODE `ARMED` 状態でのみ感度を上げ、通常状態では高い確信度を要求する。

---
**ステータス**: `DESIGN_PROPOSED` (コード修正承認待ち)
