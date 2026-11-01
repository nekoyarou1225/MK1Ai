# MK1AI_CRYPTO_INTEGRATION_TEST_PLAN — Cryptographic, QKD & One-Tap Encryption Verification Plan

> **テスト環境の分類原則**:
> - 本計画書では、**①現在のオフライン制限環境（暗号ライブラリ・実機なし）**、**②オフラインWheel導入後のソフトウェア実暗号テスト環境（QKDはシミュレータ `QKD_SIMULATED`）**、**③QKD実機接続ラボ環境（`QKD_READY`）** の3段階を厳密に区別する。
> - **シミュレータ（`QKD_SIMULATED`）でのPASSを、実量子通信装置（`QKD_READY`）の検証完了として報告することは禁止する。**

---

## 1. テスト環境の3段階定義と現在の実施状況

| テスト段階 | 環境構成 | 対象テスト範囲 | 現在の実施ステータス |
|---|---|---|---|
| **Stage 0: 依存なしベースライン環境**<br>（現在のワークスペース） | Python 3.12 + OpenSSL (C) + `libc`。<br>`cryptography`, `pqcrypto`, `liboqs`, `torch` 未導入。QKD装置なし。 | - C側 `mk1_memory_guard` (`explicit_bzero`, `mlock`)<br>- C側 `mk1_tunnel` (`AES-256-GCM` OpenSSL EVP)<br>- Python側の `_CRYPTOGRAPHY_AVAILABLE == False` 時 Fail-Closed 拒否動作 | **TESTED (実施済み)**<br>Cテスト 3/3 PASS、Python 226 PASS / 22 SKIPPED |
| **Stage 1: 実暗号ライブラリ導入・QKDシミュレータ環境** | オフライン検証済みWheel（`cryptography==50.0.2`, `pqcrypto==1.0.0`, `argon2-cffi==25.1.0`, `shamir-mnemonic==0.3.0`）＋ `liboqs` ＋ ローカルmTLS ETSI 014シミュレータ。 | - `ML-KEM-768` / `ML-KEM-1024` + `X25519` 実鍵交換<br>- `Ed25519` 実署名検証 (`mk1_quorum.py`, `mk1_key_registry.py`)<br>- `SessionRatchet` / ワンタップ `AES-256-GCM` 実暗号化・改ざん検知<br>- QKD 9状態遷移（ただし上限状態は **`QKD_SIMULATED`** まで） | **`NOT TESTED` (ライブラリ未導入・実装前)** |
| **Stage 2: QKD実機＋ダークファイバー統合ラボ環境** | 商用QKD送受信機ペア（Alice/Bob）＋ KMEペア（ETSI GS QKD 014 v1.1.1）＋ ダークファイバー（または光減衰器）＋ 単方向ダイオード / HSMトークン。 | - 実量子チャネルでの鍵配送と **`QKD_READY`** 遷移<br>- 光減衰・盗聴模擬によるQBER上昇 → `QKD_DEGRADED` / `QKD_ERROR` 遷移<br>- KME間の `key_ID` 同期と単一消費（One-Time Use）実機確認 | **`NOT TESTED` (`HARDWARE MISSING`)** |

---

## 2. 機能別テストケース仕様（全24項目）

### 2.1 PQC + X25519 ハイブリッドKEM & 既存暗号テスト（Stage 1 対象）

| テストID | 対象モジュール | 検証内容 | 期待される結果（合否基準） | 現状 |
|---|---|---|---|---|
| `CT-PQC-01` | `mk1_hybrid_kem.py` | `ML-KEM-1024` + `X25519` + `WireGuard-PSK` の正常カプセル化・デカプセル化一致 | InitiatorとResponderで同一の32バイト `shared_secret` が導出され、中間バッファが `wipe_buffer` されること。 | `NOT TESTED` |
| `CT-PQC-02` | `mk1_hybrid_kem.py` | `kem_ciphertext` または `client_x25519_public_key` の1ビット改ざん | デカプセル化後の共有秘密が不一致となり、後段のAEAD認証タグ検証で100%拒否されること。 | `NOT TESTED` |
| `CT-PQC-03` | `mk1_secure_transport.py` | `ML-KEM-768` + `X25519` 統合後のエンベロープ暗号化・復号ラウンドトリップ | 正しい鍵ペアで復号成功し、不正な公開鍵フィンガープリントでは `SecureTransportError` で拒否されること。 | `NOT TESTED` |
| `CT-PQC-04` | `mk1_quorum.py`<br>`mk1_key_registry.py` | `Ed25519` 2-of-3 クォーラム署名検証、重複署名者拒否、期限切れ拒否、ロールバック世代拒否 | 正規の異なる2署名のみPASSし、同一鍵の2重署名・改ざんペイロード・旧 `generation` はすべて拒否されること。 | `NOT TESTED` |
| `CT-PQC-05` | `mk1_key_derivation.py`<br>`mk1_key_backup.py` | `Argon2id` + `HKDF-SHA384` ルート鍵導出と `SLIP-39` M-of-N 分割・復元 | 20バイト未満のパスフレーズ拒否、閾値未満のシェアでの復元拒否、閾値以上のシェアでの完全一致復元。 | `NOT TESTED` |

### 2.2 QKDアーキテクチャ・状態遷移・フォールバック拒否テスト（Stage 1 シミュレータ / Stage 2 実機）

| テストID | 対象モジュール | 検証内容 | 期待される結果（合否基準） | 現状 |
|---|---|---|---|---|
| `CT-QKD-01` | `mk1_qkd/policy_controller.py` | QKD装置未設定時の初期状態確認 | 状態が必ず `QKD_UNAVAILABLE` であり、`QKD_READY` と表示されないこと。 | `DESIGN ONLY` |
| `CT-QKD-02` | `mk1_qkd/device_adapter.py` | ローカルシミュレータ接続時の状態キャップ確認 | シミュレータ接続時は `Get_status` が正常でも状態は **`QKD_SIMULATED`** に留まり、絶対に `QKD_READY` へ遷移しないこと。 | `DESIGN ONLY` |
| `CT-QKD-03` | `mk1_qkd/kmi_etsi.py` | ETSI GS QKD 014 mTLS相互認証失敗テスト | 未承認CA証明書、期限切れクライアント証明書、または平文HTTP接続時に `QKD_AUTH_FAILED` へ遷移し鍵取得を拒否すること。 | `DESIGN ONLY` |
| `CT-QKD-04` | `mk1_qkd/key_validation.py` | 不正QKD鍵素材の拒否（全ゼロ鍵・長さ不一致・低エントロピー） | KMEが32バイト以外の鍵や `b"\x00" * 32` を返した場合、`QKDValidationError` を送出して `QKD_ERROR` へ遷移すること。 | `DESIGN ONLY` |
| `CT-QKD-05` | `mk1_qkd/key_registry.py` | `key_ID` の単一消費（One-Time Consumption）強制とリプレイ拒否 | 一度KDFで消費された `key_ID` を再度指定して暗号化またはセッション確立を試みた場合、`KeyAlreadyConsumedError` で100%拒否されること。 | `DESIGN ONLY` |
| `CT-QKD-06` | `mk1_qkd/policy_controller.py` | **サイレント・フォールバック禁止テスト** | `QKD_MANDATORY` または `HYBRID_QKD_PQC` モード中にKMEを停止（`QKD_UNAVAILABLE` / `QKD_KEY_EXHAUSTED`）させた際、自動的に `PQC_APPROVED` へ切り替わらず、鍵確立がFail-Closedで拒否されること。 | `DESIGN ONLY` |
| `CT-QKD-07` | `mk1_qkd/policy_controller.py` | クォーラム承認付きモード変更テスト | 有効な2-of-3 Ed25519承認バンドルを提示した場合のみポリシー変更が受理され、無署名または1署名の要求は拒否されること。 | `DESIGN ONLY` |
| `CT-QKD-08` | 実機QKD装置 + KME (Stage 2) | ダークファイバー上での実量子鍵配送とQBER異常注入試験 | 正常減衰下で `QKD_READY` となり、光減衰器でQBERを閾値以上に悪化させた際に `QKD_DEGRADED` → `QKD_ERROR` へ自動遷移すること。 | `HARDWARE MISSING` |

### 2.3 本丸＋8環境（Outer-1〜4 / Inner-1〜4）鍵分離テスト（Stage 1 対象）

| テストID | 対象モジュール | 検証内容 | 期待される結果（合否基準） | 現状 |
|---|---|---|---|---|
| `CT-ZONE-01` | `mk1_key_registry.py` | ゾーン間鍵導出の完全非互換性テスト | 同一の `device_id`, `purpose`, `generation` であっても、`zone_id="OUTER_1"`、`zone_id="INNER_1"`、`zone_id="HONMARU"` で導出される鍵が完全に異なり、かつ別ゾーンの `root_key` へのアクセスが拒否されること。 | `DESIGN ONLY` |
| `CT-ZONE-02` | `mk1_qkd/key_registry.py` | 影武者（`OUTER_1..4`）からのQKD鍵取得拒否テスト | `OUTER_1..4` のコンテキストからQKD鍵取得を要求した場合、ACLにより即座に拒否されること。 | `DESIGN ONLY` |
| `CT-ZONE-03` | `mk1_one_tap_crypto.py` | 影武者（`OUTER_1..4` / `INNER_1..4`）での本丸暗号化データの復号拒否テスト | `HONMARU` ゾーンでワンタップ暗号化された `.mk1enc` ファイルを `INNER_1` または `OUTER_1` に持ち込んでも、本丸KEKが存在せずヘッダAADの `zone_id` も不一致となるため100%復号失敗すること。 | `DESIGN ONLY` |
| `CT-ZONE-04` | `mk1_key_registry.py` | 影武者から本丸への鍵素材インポート拒否テスト | `source_zone != "HONMARU"` の鍵バンドルを本丸へインポートしようとした場合、`KeyRegistryError` で拒否されること。 | `DESIGN ONLY` |

### 2.4 ワンタップ暗号化・復号テスト（Stage 1 対象）

| テストID | 対象モジュール | 検証内容 | 期待される結果（合否基準） | 現状 |
|---|---|---|---|---|
| `CT-OTAP-01` | `mk1_one_tap_crypto.py` | 5種別（テキスト・メッセージ・ファイル・バックアップ・エクスポート）の暗号化・復号ラウンドトリップ | 全5種別で元データと復号データがビット単位で一致し、自己検証ステータスが `VERIFIED` となること。 | `DESIGN ONLY` |
| `CT-OTAP-02` | `mk1_one_tap_crypto.py` | エンベロープヘッダ内に秘密鍵・生QKD鍵・平文DEKが含まれないことの検査 | 出力された `.mk1enc` バイナリ全体を走査し、`dek`, `kek`, `qkd_raw_key`, `root_key` のバイト列が1バイトも含まれないこと。 | `DESIGN ONLY` |
| `CT-OTAP-03` | `mk1_one_tap_crypto.py` | 暗号文1ビット改ざん・チャンク順序入替・末尾チャンク切断の検知 | いずれの改ざんに対しても `InvalidTag` / `IntegrityError` で復号が拒否され、**平文ファイルや部分出力が1バイトも生成されない**こと。 | `DESIGN ONLY` |
| `CT-OTAP-04` | `mk1_one_tap_crypto.py` | ヘッダメタデータ（`key_id`, `zone_id`, `key_expires_at_utc`, `purpose`）改ざんの検知 | ヘッダJSONの1文字でも変更すると、DEKアンラップ時のGCM AAD検証が失敗して復号が拒否されること。 | `DESIGN ONLY` |
| `CT-OTAP-05` | `mk1_one_tap_crypto.py` | 失効鍵（`RevocationManifest`）および有効期限切れ鍵の拒否テスト | 暗号化後に `key_id` を失効マニフェストへ追加、または時刻を `key_expires_at_utc` 以降に進めた場合、復号および新規暗号化が確実に拒否されること。 | `DESIGN ONLY` |
| `CT-OTAP-06` | `mk1_one_tap_crypto.py` | Nonce一意性テスト | 10,000回の連続ワンタップ暗号化およびマルチチャンク暗号化において、`wrap_nonce` および `(data_nonce_prefix, chunk_index)` ペアの衝突が0件であること。 | `DESIGN ONLY` |
| `CT-OTAP-07` | `mk1_one_tap_crypto.py` | エラー発生時のDEK/KEKゼロ化確認 | 復号失敗（不正タグ）を発生させた直後に、`dek_buffer` および `kek_buffer` の長さが `0`（全バイト `0x00`）に消去されていること。 | `DESIGN ONLY` |
