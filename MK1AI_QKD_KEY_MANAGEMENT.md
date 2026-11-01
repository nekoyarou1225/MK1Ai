# MK1AI_QKD_KEY_MANAGEMENT — Key Lifecycle, 9-Environment Isolation & Custodial Governance

> **実装・検証ステータス明示**:
> - ローカル決定論的鍵導出（`mk1_key_derivation.py`, `mk1_key_registry.py`）およびSLIP-39分割（`mk1_key_backup.py`）は **コード実装済み・実暗号ランタイム未検証（`NOT TESTED`）**。
> - QKD鍵のライフサイクル管理および「本丸＋外側4環境＋内側4環境（計9領域）」の厳格な鍵分離は **設計完了（`DESIGN ONLY`）・未実装（`NOT IMPLEMENTED`）** である。

---

## 1. 本丸（Honmaru）と8環境（Outer-1〜4 / Inner-1〜4）の完全鍵分離設計（Section 6）

MK1Aiの多層防衛アーキテクチャでは、外部からの攻撃を吸収・観測する「外側4環境（Outer-1〜4：影武者/デコイ層）」、中間検証を行う「内側4環境（Inner-1〜4：緩衝・検疫層）」、および最終保護対象である「本丸（Honmaru：コア領域）」の**計9つの独立したセキュリティドメイン（Key Domain / Security Zone）**を定義する。

### 1.1 9つの鍵領域（Key Domains）と権限マトリクス

```text
+-----------------------------------------------------------------------------------+
|                        Outer Ring (影武者 / Decoy Zones)                           |
|   [OUTER_1]          [OUTER_2]          [OUTER_3]          [OUTER_4]              |
|   Key Domain: O1     Key Domain: O2     Key Domain: O3     Key Domain: O4         |
|   - QKD Key Access: PROHIBITED (No KME access, No Honmaru/Inner keys)             |
|   - Allowed Keys: Ephemeral per-node decoy keys only (isolated memory/storage)    |
+-----------------------------------------------------------------------------------+
          | (One-way telemetry observation only; automatic key transfer PROHIBITED)
          v
+-----------------------------------------------------------------------------------+
|                        Inner Ring (緩衝・検疫 / Buffer Zones)                      |
|   [INNER_1]          [INNER_2]          [INNER_3]          [INNER_4]              |
|   Key Domain: I1     Key Domain: I2     Key Domain: I3     Key Domain: I4         |
|   - QKD Key Access: Dedicated Inner SAE IDs only (Cannot read Honmaru keys)       |
|   - Allowed Keys: Zone-scoped transport & quarantine verification keys            |
+-----------------------------------------------------------------------------------+
          | (Approved out-of-band / hardware diode + M-of-N Quorum verification)
          v
+-----------------------------------------------------------------------------------+
|                        Core Citadel (本丸 / Honmaru)                               |
|   [HONMARU_CORE]                                                                  |
|   Key Domain: HONMARU                                                             |
|   - Dedicated Root Key, Dedicated QKD Key Pool, Admin Quorum Trust Anchors,       |
|     User One-Tap Encryption Master KEKs                                           |
|   - NEVER shared with or accessible from Outer-1..4 or Inner-1..4                 |
+-----------------------------------------------------------------------------------+
```

| 鍵領域 ID (`zone_id`) | 環境区分 | 本丸QKD鍵・秘密鍵へのアクセス | 管理者資格情報（Quorum秘密鍵・WebAuthnプロファイル）の保持 | 実ユーザーのワンタップ暗号化データの復号権限 | 侵害時の影響範囲（Blast Radius） |
|---|---|---|---|---|---|
| **`HONMARU`** | 本丸（最深部エアギャップ領域） | **許可（本丸専用スコープのみ）** | **検証用公開鍵のみ保持**（署名用秘密鍵はオフライン管理者トークンで分離保管） | **あり（承認・認証通過時のみ）** | 本丸単体で完結（外部への自動送信経路なし） |
| **`INNER_1` 〜 `INNER_4`** | 内側4環境（検疫・中継影武者） | **全面禁止（ハードウェア/暗号学的に分離）** | **全面禁止** | **全面禁止（復号鍵・KEKともに存在しない）** | 当該 `INNER_n` インスタンスの局所セッション鍵のみ。本丸および他Inner環境は無傷。 |
| **`OUTER_1` 〜 `OUTER_4`** | 外側4環境（対外影武者・ハニーポット） | **全面禁止（QKD接続自体を禁止）** | **全面禁止** | **全面禁止** | 当該 `OUTER_n` の使い捨て鍵のみ。本丸・Innerのいかなる暗号鍵も漏洩しない。 |

### 1.2 暗号学的な領域分離（Domain Separation）の強制仕様

現行の `mk1_key_registry.py`（`lines 45–77`）の `derive_device_purpose_key()` を拡張し、すべての鍵導出・鍵ID登録・AEAD追加認証データ（AAD）に **`zone_id`** を必須パラメータとして組み込む。

1. **ゾーン識別子の閉じた列挙型定義**:
   ```python
   ALLOWED_ZONES = frozenset({
       "HONMARU",
       "INNER_1", "INNER_2", "INNER_3", "INNER_4",
       "OUTER_1", "OUTER_2", "OUTER_3", "OUTER_4",
   })
   ```
2. **HKDF `info` パラメータによる暗号学的分離**:
   - 鍵導出時の `info` フィールドを以下の形式に固定する：
     ```text
     b"MK1-zone-purpose-key-v2\0" + zone_id.encode("ascii") + b"\0" + purpose.encode("ascii")
     ```
   - さらに大前提として、**`HONMARU` と `INNER_1..4` と `OUTER_1..4` は同一の `root_key` を共有してはならない**（各環境は物理的に別個に生成された独立ルートシードを持つ）。
3. **影武者（Outer/Inner）から本丸への鍵素材自動転送の禁止**:
   - `OUTER_1..4` および `INNER_1..4` で生成・取得されたいかなる鍵素材、セッションシード、チェックポイント暗号鍵も、本丸（`HONMARU`）へネットワーク経由またはスクリプト経由で自動転送・インポートすることをコードレベルで拒否する（`if source_zone != "HONMARU": raise KeyRegistryError("Cross-zone key import into HONMARU is strictly prohibited")`）。

---

## 2. QKD鍵および暗号鍵のライフサイクル管理（生成〜消費〜失効〜破棄）

### 2.1 QKD鍵素材の属性（`QKDKeyRecord` メタデータ仕様）

KMEから取得されたすべてのQKD鍵は、以下のメタデータと共に管理される（**生の鍵バイト列 `raw_key: bytearray` はインメモリの `mlock` 領域のみに保持し、ディスクやSQLiteには絶対に書き込まない**）：

| フィールド名 | 型 | 説明・制約 |
|---|---|---|
| `key_id` | `str` (UUIDv4) | ETSI GS QKD 014で割り当てられた128ビット識別子。 |
| `zone_id` | `str` | 所属環境（`HONMARU` または `INNER_1..4` のみ。`OUTER_1..4` はQKD取得不可）。 |
| `sae_pair` | `tuple[str, str]` | `(master_SAE_ID, slave_SAE_ID)`。 |
| `purpose` | `str` | `"kek-wrapping"`（ワンタップ暗号化KEK導出）または `"transport-seed"`（SessionRatchet初期シード合成）のみ。**QKD生鍵による直接データ暗号化は禁止**。 |
| `acquired_at_ns` | `int` | 取得時の単調増加時刻およびUTCエポックナノ秒。 |
| `expires_at_ns` | `int` | 有効期限（デフォルト最大TTL：トランスポート用 `900秒`、KEKラップ用 `3600秒`）。 |
| `state` | `Enum` | `AVAILABLE` → `RESERVED` → `CONSUMED` → `WIPED`（または `REVOKED`）。 |

### 2.2 単一消費原則（One-Time Consumption Rule）とプール管理

1. **生QKD鍵の再利用禁止**:
   - 1つの `key_id`（256ビットQKD鍵素材）は、**1回のハイブリッドKDF導出（1つのセッション確立、または1つのKEK導出）にのみ使用可能**とする。
   - KDFに入力された直後、`raw_key`（`bytearray`）は `finally` ブロック内で直ちに `mk1_memory_guard.wipe_buffer(raw_key)`（`explicit_bzero`）によってゼロ化され、`state` は `CONSUMED` → `WIPED` へ遷移する。
2. **ワンタップ暗号化における復号時の鍵取得**:
   - ファイルやバックアップを長期保存するワンタップ暗号化では、KMEが古い `key_id` を無期限に保持し続けることはできない。
   - そのため、ワンタップ暗号化では以下の2方式のいずれかを明示的に選択する（詳細は `MK1AI_ONE_TAP_ENCRYPTION_DESIGN.md` 参照）：
     - **モード1（リアルタイム送受信・短期保管メッセージ）**: 送信側が `enc_keys` で取得した `key_id` をメタデータに記録し、受信側がTTL内に `dec_keys(key_id)` でKMEから同一鍵を取得して復号する。
     - **モード2（長期保管ファイル・バックアップ）**: QKD+PQCハイブリッド鍵と本丸のユーザーパスフレーズ派生ルート鍵（`mk1_key_derivation.py`）から導出した **ローカル保護ラップ鍵（Local Storage KEK）** でデータ暗号化鍵（DEK）を包む（Envelope Encryption）。これにより、KME上のQKD一時鍵が消去された後も、本丸内の承認された保管庫で復号可能とする。

### 2.3 鍵の有効期限・ローテーション・緊急失効

| トリガー条件 | 閾値・条件 | 実行される強制アクション |
|---|---|---|
| **メッセージ数上限到達** | `SessionRatchet` で片方向 `4,096` チャンク到達 | 現ラチェットを `destroy()` し、新しい `key_id`（QKD）＋新しいエフェメラル鍵（ML-KEM + X25519）で再ハンドシェイクを強制。 |
| **セッション時間上限到達** | セッション開始から `15分（900秒）` 経過 | 同上（`SessionRatchetError("Session ratchet has expired")`）。 |
| **QKD未消費プール鍵のTTL超過** | KMEから取得後、未使用のまま `300秒` 経過 | メモリ上の `raw_key` を `wipe_buffer()` で破棄し、`key_id` を期限切れリストへ登録。 |
| **失効マニフェスト受信** | `verify_revocation_manifest()` で新しい `generation` の失効リストを受理 | 失効対象の `device_id` / `sae_id` / `key_id` に関連する全セッション・全キャッシュ鍵を即時 `destroy()` し、`QKD_REVOKED` へ遷移。 |
| **セキュリティ異常・隔離発動** | `ONI_MODE` 発動、USB違反検知、または `set_transport_enabled(False)` | C側 `mk1_secure_key_wipe()` およびPython側 `_ACTIVE_ENVELOPES` / `_ACTIVE_RATCHETS` / `QKDKeyRegistry` の全鍵バッファを一斉パージ。 |
