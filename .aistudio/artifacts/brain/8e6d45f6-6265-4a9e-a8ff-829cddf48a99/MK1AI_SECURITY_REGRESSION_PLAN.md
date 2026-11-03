# MK1AI_SECURITY_REGRESSION_PLAN.md — セキュリティ回帰テストおよび新機能検証計画

## 1. 回帰テストの目的

本改修が、既存の 248 件の Python 単体テスト、および C 言語モジュールの整合性を損なわないことを保証する。

## 2. 新規テスト項目 (V2 固有)

### 2.1 3ヘッドAI独立隔離
- `test_head_a_autonomous_isolation`: Head A の閾値超過だけで M-of-N 抜きで隔離が実行されるか。
- `test_head_b_predictive_isolation`: Head B の予兆検知だけで隔離要求が発行されるか。
- `test_head_c_memory_breach_isolation`: メモリ改ざん検知時に隔離が実行されるか。

### 2.2 権限分離検証
- `test_unauthorized_recovery_rejection`: 自律隔離後に、署名なしの隔離解除要求が確実に拒絶されるか。
- `test_domain_signature_isolation`: 復旧用の署名を隔離開始要求にリプレイして拒否されるか。

### 2.3 ONI MODE FSM
- `test_oni_state_transition`: NORMAL -> ARMED -> EMERGENCY -> ISOLATED の遷移が正しいか。

## 3. 実行環境

- `PYTHONPATH=. python3 -m unittest tests/test_v2_remediation.py`
- 既存テストの全件再実行。

---
**検証ステータス**: `PLAN_FINALIZED`
