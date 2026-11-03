# MK1AI_THREE_HEAD_SECURITY_AUDIT.md — 3ヘッドAIアーキテクチャの現状と機能拡張計画

## 1. 現状の構成監査

現在の `LightweightMultiTaskAI` (line 4554) の実装状態は以下の通り。

| ヘッド | 現在の名称 | 現在の役割（実装） | 要求される役割（修正後） |
|---|---|---|---|
| **Head A** | `head_a` | トラフィック異常スコア（現在脅威） | リアルタイム攻撃検知・DPI相関・隔離要求 |
| **Head B** | `head_b` | 正常通信判定（EWC用） | **60秒後予測脅威・侵入経路予測・事前隔離要求** |
| **Head C** | `head_c` | RAM退避緊急度（ヒステリシス） | **メモリ完全性監視・侵害検知・隔離要求** |

## 2. 指摘事項 (CF-02)

- **Head B の乖離**: 現状は Fisher 情報を用いた「学習の重み付け」に使われており、脅威予測としての推論ロジックがパイプラインに接続されていない。
- **Head C の限定的利用**: `MemoryManager` に閉じられており、メモリ改ざんや機密流出を検知した場合に CORE 全体を遮断する権限が与えられていない。
- **独立性の欠如**: 隔離判断ロジック `evaluate_threat_state` が `score_a` のみを受け取る引数設計になっており、B と C の出力が無視されている。

## 3. 修正方針

### 3.1 Head A: Current Threat (現在)
- DPI 検知結果 (`suspicious`, `attack_signatures`) を入力特徴量へフィードバック。
- 重大なシグネチャ一致時はスコア 0.99 を強制し、即時自律隔離。

### 3.2 Head B: Predictive Threat (予測)
- 過去 16 パケットの履歴から攻撃の「予兆」を判定。
- 予測スコアが閾値を超えた場合、`evaluate_threat_state` へ `PREDICTIVE_ISOLATION` 要求を発行。
- 予測理由（evidence_reference）として、どの特徴量（ジッタ、特定ポートへの周期アクセス等）が寄与したかをログに記録。

### 3.3 Head C: Memory Integrity (メモリ)
- `mk1_memory_guard` からの例外や `mlock` 失敗をスコアに反映。
- モデル重みのハッシュ不一致を検知した場合、自己防衛としての CORE 隔離要求を発行。

## 4. 独立性の保証

各ヘッドの出力を個別のイベント ID と紐付け、1つのヘッドが NaN や Inf を出力しても、他のヘッドや非 AI ルールによる防御が停止しないように `inspect_packet_pipeline` を堅牢化する。

---
**検証ステータス**: `STATICALLY_AUDITED` / `FIX_PLANNED`
