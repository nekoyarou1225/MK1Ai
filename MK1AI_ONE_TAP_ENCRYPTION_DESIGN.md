# MK1AI_ONE_TAP_ENCRYPTION_DESIGN — One-Tap Authenticated Envelope Encryption Specification

> **実装・検証ステータス明示**:
> - 本書で定義する「ワンタップ暗号化・復号機能（One-Tap Encryption / Decryption）」は **設計完了（`DESIGN ONLY`）** であり、現行リポジトリには **未実装（`NOT IMPLEMENTED` / `NOT TESTED`）** である。
> - 「ワンタップ」とは承認済みセッション内でのユーザーの操作ステップ（クリック/コマンド回数）を最小化するUI/UX設計であり、**鍵認証・改ざん検証・失効チェック・権限確認を省略するものではない**。

---

## 1. 対象データと機能スコープ（Section 5）

ワンタップ暗号化・復号エンジン（予定モジュール名：`mk1_one_tap_crypto.py`）は、以下の5種類のデータオブジェクトを統一的なエンベロープ形式（`.mk1enc`）で保護する。

| # | 対象カテゴリ (`target_type`) | 対象データの具体例 | 用途制限ラベル (`purpose`) | 最大サイズ制限（DoS防止） |
|---|---|---|---|---|
| 1 | **テキスト (`TEXT`)** | 機密メモ、設定スニペット、クリップボード文字列 | `"onetap-text-aead"` | `1 MiB` |
| 2 | **メッセージ (`MESSAGE`)** | 管理者間連絡、拠点間承認ペイロード、アラート通知 | `"onetap-message-aead"` | `16 MiB` |
| 3 | **ファイル (`FILE`)** | 任意のドキュメント、証跡ファイル、キャプチャPCAP、バイナリ | `"onetap-file-aead"` | `64 MiB` / チャンク分割ストリーム対応 |
| 4 | **バックアップ (`BACKUP`)** | `ai_data/` チェックポイント、SQLite DB、設定バックアップ | `"onetap-backup-aead"` | `512 MiB`（4 MiBチャンクAEAD） |
| 5 | **エクスポートデータ (`EXPORT`)** | 外部監査用ログパッケージ、検疫レポート、モデル重みエクスポート | `"onetap-export-aead"` | `256 MiB`（4 MiBチャンクAEAD） |

---

## 2. エンベロープ暗号化（Envelope Encryption）アーキテクチャ

データ本体を直接QKD鍵や長期鍵で暗号化するのではなく、**データ暗号化鍵（DEK）** と **鍵暗号化鍵（KEK）** を分離する2階層エンベロープ暗号化を採用する。

```text
+-----------------------------------------------------------------------------------+
|                        Key Establishment & KEK Derivation                         |
|   [QKD Key (ETSI 014)] + [ML-KEM-768/1024 + X25519] + [Zone Root Key (Argon2id)]  |
|                                        |                                          |
|                           HKDF-SHA384 (Domain Separated)                          |
|                                        v                                          |
|                      Key Encryption Key (KEK: 256-bit, mlock)                     |
+----------------------------------------+------------------------------------------+
                                         |
            AES-256-GCM Key Wrap         |  (Wraps 32-byte random DEK + Key Metadata)
            (96-bit wrap_nonce + AAD)    v
+-----------------------------------------------------------------------------------+
|                     Wrapped DEK Blob (ciphertext_dek + tag_dek)                   |
+-----------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------+
|                           Data Encryption Layer (DEK)                             |
|   Fresh CSPRNG DEK (os.urandom(32) in mlock bytearray)                            |
|   + Unique 96-bit data_nonce (os.urandom(12) + chunk counter)                     |
|   + Canonical Header bytes as AAD (Additional Authenticated Data)                 |
|                                        |                                          |
|                                  AES-256-GCM                                      |
|                                        v                                          |
|                Authenticated Ciphertext + 128-bit GMAC Auth Tag                   |
+-----------------------------------------------------------------------------------+
```

### 2.1 暗号化・復号時の8つの必須検証項目（Section 5）

| # | 検証項目 | 実装仕様 | 失敗時の動作（Fail-Closed） |
|---|---|---|---|
| 1 | **鍵生成と用途制限** | DEKは毎回 `os.urandom(32)` で新規生成し、`bytearray`（`mlock`）に保持。KEKは `zone_id`（`HONMARU` 等）と `purpose`（`"onetap-file-aead"` 等）を `HKDF-SHA384` の `info` に束縛して導出する。異なる用途や異なるゾーンのKEKではDEKをアンラップできない。 | `KeyPurposeMismatchError` で即時拒否。 |
| 2 | **nonceの一意性** | - DEKラップ用 `wrap_nonce`: 毎回 `os.urandom(12)`（96bit CSPRNG）を生成（KEK自体もソルト付きHKDFで毎回異なるため衝突確率は $2^{-96}$ 以下）。<br>- データ暗号化用 `data_nonce`: 8バイトのCSPRNGランダムプレフィックス ＋ 4バイトのビッグエンディアン・チャンク連番（`0x00000000`〜）により、同一DEK内でnonceが絶対に重複しない構造とする。 | チャンク番号オーバーフローまたはnonce長不一致時は即時暗号化中止。 |
| 3 | **認証タグ（128-bit GMAC）** | `AES-256-GCM` の16バイト（128ビット）認証タグを必須とし、タグ短縮（Truncation）は一切認めない。 | 16バイト未満のタグはスキーマ違反として復号前に拒否。 |
| 4 | **ファイルの改ざん検知** | 各チャンクの暗号文には16バイトのGCMタグが付与され、さらに最終チャンクには終端マーカー（`is_final=0x01`）をAADに含めることで、チャンクの順序入替・途中切断（Truncation Attack）・末尾追加を100%検知する。 | `InvalidTag` 発生時は即座に例外を送出し、出力バッファをゼロ化。 |
| 5 | **メタデータの完全性** | エンベロープヘッダ全体（`version`, `suite_id`, `zone_id`, `target_type`, `key_id`, `qkd_key_id`, `created_at`, `expires_at`, `wrap_nonce`, `data_nonce_prefix`）を正規化JSON（Canonical JSON）にシリアライズし、**DEKラップ時とデータ暗号化時の両方の `AES-256-GCM` の AAD（Additional Authenticated Data）に指定**する。 | ヘッダ内の `key_id` や `expires_at` が1ビットでも書き換えられた場合、DEKのアンラップ自体が `InvalidTag` で失敗する。 |
| 6 | **復号時の認証** | 復号処理は「①ヘッダスキーマ検証 → ②ゾーン・鍵失効・有効期限検証 → ③KEKによるDEKアンラップ（GCMタグ検証） → ④DEKによるデータチャンク復号（GCMタグ検証）」の順で行い、**すべての検証が成功するまで復号平文を呼び出し元やファイルに出力しない**。 | 途中チャンクで失敗した場合は一時出力ファイルを `wipe` して `unlink` し、部分的な平文を絶対に残さない。 |
| 7 | **失効鍵の拒否** | 復号前にヘッダ内の `key_id`、`qkd_key_id`、`device_id` を `mk1_key_registry.py`（`RevocationManifest`）および `QKDKeyRegistry` と照合する。 | 失効リストに含まれる鍵ID、または有効期限（`expires_at`）を過ぎた自己期限付きデータは、暗号学的に復号可能であってもポリシーにより復号を拒否する。 |
| 8 | **エラー時の安全な処理** | 例外発生時は `finally` ブロックで `dek_buffer`, `kek_buffer`, `plaintext_buffer` をすべて `mk1_memory_guard.wipe_buffer()` でゼロ化し、詳細な内部鍵情報はエラーメッセージに含めない。 | **復号失敗時に平文や未検証バイト列を返すことはいかなる場合も禁止**。 |

---

## 3. エンベロープフォーマット仕様（秘密鍵の埋め込み禁止）

**QKD鍵素材（生の鍵ビット列）、PQC秘密鍵、KEK、DEKの平文を暗号化ファイルやヘッダに埋め込むことは厳禁とする。** 保存されるのは公開識別子（`key_id`, `qkd_key_id`）とラップ済み暗号文のみである。

```json
{
  "magic": "MK1ENC",
  "version": 1,
  "zone_id": "HONMARU",
  "target_type": "FILE",
  "purpose": "onetap-file-aead",
  "cipher_suite": "AES-256-GCM",
  "kdf_suite": "HKDF-SHA384",
  "kem_suite": "MK1-SUITE-TRIPLE-QKD-PQC-v1",
  "qkd_state_at_encryption": "QKD_READY",
  "key_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "qkd_key_id": "550e8400-e29b-41d4-a716-446655440000",
  "key_generation": 4,
  "created_at_utc": 1793529600,
  "key_expires_at_utc": 1796121600,
  "chunk_size_bytes": 4194304,
  "total_chunks": 1,
  "kdf_salt_b64": "<Base64 16-byte salt>",
  "kem_ciphertext_b64": "<Base64 ML-KEM ciphertext>",
  "ephemeral_x25519_pub_b64": "<Base64 32-byte X25519 public key>",
  "wrap_nonce_b64": "<Base64 12-byte nonce>",
  "wrapped_dek_b64": "<Base64 32-byte encrypted DEK + 16-byte GCM tag>",
  "data_nonce_prefix_b64": "<Base64 8-byte nonce prefix>",
  "payload_sha384_hex": "<64-byte hex SHA-384 of authenticated ciphertext chunks>"
}
```
*(上記正規化JSONヘッダの直後に、バイナリチャンク列 `[chunk_len(4B) || ciphertext || gcm_tag(16B)]` が続く)*

---

## 4. UI / 操作パネル設計仕様（Section 5）

Web管理画面およびローカル操作パネル（`mk1_panel.c` / Web UI）に設けるワンタップ暗号化パネルの必須表示項目と動作仕様は以下の通りである。

### 4.1 必須UIコンポーネント（8項目）

```text
+-----------------------------------------------------------------------------------+
|  MK1Ai One-Tap Sovereign Encryption Console             [Zone: HONMARU (Isolated)] |
+-----------------------------------------------------------------------------------+
|  [3] 使用鍵ID (Key ID) : a1b2c3d4...8f90 (Gen #4) | QKD KSID: 550e8400-...-440000 |
|  [4] 暗号方式 (Suite)  : AES-256-GCM / KEK: ML-KEM-1024 + X25519 + HKDF-SHA384     |
|  [5] QKD状態 (Status)  : [● QKD_UNAVAILABLE (実機未接続 - PQCハイブリッドモード)]  |
|  [7] 鍵の有効期限      : 2026-12-01 00:00:00 UTC (残り 30日 / 失効状態: 有効)       |
+-----------------------------------------------------------------------------------+
|  対象種別: (●) テキスト  ( ) メッセージ  ( ) ファイル  ( ) バックアップ  ( ) エクスポート |
|  +-----------------------------------------------------------------------------+  |
|  | 入力データまたは対象ファイルパス...                                         |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
|   [ [1] ワンタップ暗号化 (Encrypt & Verify) ]   [ [2] ワンタップ復号 (Verify & Decrypt) ] |
+-----------------------------------------------------------------------------------+
|  [6] 暗号化結果の検証 (Verification Result):                                      |
|      - ヘッダAAD完全性 : VERIFIED (SHA-384一致)                                   |
|      - DEKラップ認証   : VERIFIED (128-bit GCM Tag OK)                            |
|      - ペイロード認証  : VERIFIED (全1チャンク GCM Tag OK / 改ざん検知なし)       |
|      - 鍵失効チェック  : PASSED (RevocationManifest Gen #4 照合済)                |
+-----------------------------------------------------------------------------------+
|  [8] 暗号化・復号履歴 (Audit History - 鍵素材非表示・ハッシュチェーン記録):       |
|   時刻 (UTC)          | 操作    | 種別   | 鍵ID (先頭8文字) | QKD状態         | 結果 |
|   2026-11-01 10:25:00 | ENCRYPT | BACKUP | a1b2c3d4...      | QKD_UNAVAILABLE | PASS |
|   2026-11-01 10:26:12 | DECRYPT | FILE   | 9f8e7d6c...      | QKD_REVOKED     | DENY |
+-----------------------------------------------------------------------------------+
```

1. **ワンタップ暗号化ボタン**: 押下時に①鍵有効性・失効チェック、②CSPRNG DEK生成、③KEKによるDEKラップ、④AES-256-GCM暗号化、⑤生成された暗号文に対する即時自己検証（ヘッダAAD・タグ整合性チェック）、⑥メモリ上のDEKゼロ化、⑦監査履歴への記録を1トランザクションで自動実行する。
2. **ワンタップ復号ボタン**: 押下時に①ヘッダ解析、②ゾーン境界チェック（他ゾーンの鍵は拒否）、③失効マニフェスト＆有効期限チェック、④DEKアンラップ認証、⑤チャンクGCMタグ検証・復号、⑥DEKゼロ化を実行する。検証失敗時は平文を一切表示せず拒否理由を表示する。
3. **使用鍵の識別子 (`key_id` / `qkd_key_id`)**: 鍵のSHA-384フィンガープリントまたはUUIDのみを表示し、鍵ビット列は絶対に出力しない。
4. **暗号方式**: AEAD方式（`AES-256-GCM`）、KDF（`HKDF-SHA384`）、およびKEM/QKDスイート名を明示する。
5. **QKD状態**: 9状態（`QKD_UNAVAILABLE`, `QKD_SIMULATED`, `QKD_READY` 等）を正確に表示する。**QKD実機がない環境では必ず `QKD_UNAVAILABLE`（またはシミュレータ接続時のみ `QKD_SIMULATED`）と表示し、`QKD_READY` と偽装表示しない。**
6. **暗号化結果の検証**: 暗号化直後のラウンドトリップ整合性・AAD完全性・128ビット認証タグ検証結果をステータス表示する。
7. **鍵の有効期限**: 使用中のKEK/セッション鍵の有効期限（UTC時刻および残り時間）と世代番号（`generation`）を表示する。期限切れ鍵による新規暗号化はワンタップ押下時にブロックする。
8. **暗号化履歴**: 操作日時、操作種別（`ENCRYPT` / `DECRYPT` / `REJECT`）、対象種別、使用した `key_id`、当時の `QKDState`、検証結果（`PASS` / `DENY`）、および監査ログのSHA-384チェーンハッシュを一覧表示する。
