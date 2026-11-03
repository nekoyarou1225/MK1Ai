# MK1AI_REMEDIATION_DIFF_PLAN.md — セキュリティ改修・実装差分（Unified Diff）案

## 1. 修正の概要

本改修では、`airgap_ai_defender.py` を中心に、自律隔離パスの有効化と 3 ヘッド AI の役割再定義を行う。

## 2. 修正対象と変更内容

### 2.1 airgap_ai_defender.py
- **`evaluate_threat_state()`**: 
    - `autonomous` 引数を追加。
    - `approval_bundle` が `None` の場合でも、AI 3 ヘッドの確信度に基づき `execute_kill_switch` を実遮断モードで呼び出す分岐を新設。
- **`LightweightMultiTaskAI.forward()`**:
    - Head B を時系列予測、Head C をメモリ完全性異常として返り値を整理。
- **`toggle_oni_mode()`**:
    - `MK1SafetyStateMachine` クラスを定義し、状態遷移をカプセル化。

### 2.2 mk1_quorum.py
- **`create_quorum_challenge()`**:
    - `operation` ごとに異なるプレフィックス (`MK1AI-ISOLATE-`, `MK1AI-RECOVERY-`) を付与。

## 3. 実装の整合性

各修正は、既存の `dry_run=True` テストに影響を与えないよう、デフォルト引数を慎重に設定する。

---
**ステータス**: `IMPLEMENTATION_DRAFT` (承認待ち)
