# MK1AI_QKD_DEVICE_REQUIREMENTS — QKD Hardware, ETSI Interface & Classical Channel Authentication Specification

> **実装・検証ステータス明示**:
> - 本書はQKD実機導入およびインターフェース実装のための **要件・プロトコル仕様書（`DESIGN ONLY` / `HARDWARE MISSING` / `NOT TESTED`）** である。
> - 現在、QKDハードウェアおよびKME（Key Management Entity）は接続されておらず、API定義の存在をもって量子鍵配送が動作していると報告してはならない。

---

## 1. QKD装置および通信路の物理要件

QKDシステムは以下の2つの物理通信路と3つのハードウェアコンポーネントで構成される。

### 1.1 必須通信路（2系統）
1. **量子通信路（Quantum Channel）**:
   - **媒体**: シングルモード・ダークファイバー（ITU-T G.652.D / G.654.E、波長1550 nm C-band または 1310 nm O-band）。光増幅器（EDFA）や一般的なアクティブ光スイッチは単一光子の量子状態を破壊（デコヒーレンス）するため経路上に介在させてはならない。
   - **伝送損失・距離目安**: ポイント・ツー・ポイントで最大 10〜20 dB（約 50〜100 km、装置仕様に依存）。
   - **監視指標**: QBER（Quantum Bit Error Rate：量子ビット誤り率）を常時監視し、閾値（例：BB84で `QBER >= 8.0%`、警報閾値 `5.0%`）を超過した場合は盗聴（光子数分割攻撃・Intercept-Resend攻撃）またはファイバー異常とみなして鍵生成を即時停止し、`QKD_DEGRADED` または `QKD_ERROR` へ遷移する。
2. **認証済み古典通信路（Authenticated Classical Channel）**:
   - **役割**: 基底照合（Sifting）、誤り訂正（LDPC / Cascade）、秘匿性増幅（Privacy Amplification）、およびKME間の鍵ID同期を行う。
   - **必須セキュリティ性質**: **QKDはそれ自体では通信相手（Alice/Bob）の身元を認証しない**。古典通信路が認証されていない場合、攻撃者が量子チャネルと古典チャネルの双方に割り込む **中間者攻撃（Man-in-the-Middle Attack）によってQKDは100%破られる**。
   - **認証方式**:
     - 初回ブートストラップ時：事前共有された高エントロピー初期認証鍵（Pre-Shared Initial Secret: 256bit以上）を用いた **Wegman-Carter普遍ハッシュMAC（情報理論的安全性を持つメッセージ認証）**、および耐量子署名（`ML-DSA-87` または `SLH-DSA`）＋古典署名（`Ed25519`）のハイブリッド相互認証。
     - 継続運用時：前回生成されたQKD鍵プールの一部を次ラウンドのWegman-Carter MAC認証鍵として消費する認証連鎖（Key Recycling for Authentication）。

---

## 2. 標準KMI（Key Management Interface）規格の選定と互換性（Section 2.2）

ベンダーロックインを防ぎ、東芝（Toshiba Digital Solutions）、ID Quantique（IDQ）、QuintessenceLabs、LuxQuanta等の商用QKD装置と相互運用するため、ETSI ISG QKDの以下の3規格を用途別に採用する。

| ETSI規格番号 | 規格名称・バージョン | MK1Aiにおける採用区分 | プロトコル・API仕様 |
|---|---|---|---|
| **ETSI GS QKD 014**<br>(v1.1.1, 2019-02) | *Protocol and data format of REST-based key delivery API* | **【第一標準（Primary）】**<br>SAE（MK1Ai）とローカルKME間の鍵取得APIとして標準採用 | HTTPS（TLS 1.3 + mTLS相互証明書認証）上のJSON REST API：<br>1. `GET /api/v1/keys/{slave_SAE_ID}/status`<br>2. `POST /api/v1/keys/{slave_SAE_ID}/enc_keys`<br>3. `POST /api/v1/keys/{master_SAE_ID}/dec_keys` |
| **ETSI GS QKD 004**<br>(v2.1.1, 2020-08) | *Application Interface* | **【第二標準（Low-Latency Option）】**<br>高頻度セッション鍵要求やQoS予約が必要な場合のソケットAPIとしてアダプタ対応 | ステートフルAPI：<br>1. `OPEN_CONNECT(source, dest, QoS, Key_stream_ID)`<br>2. `GET_KEY(Key_stream_ID, index, key_buffer, Metadata)`<br>3. `CLOSE(Key_stream_ID)` |
| **ETSI GS QKD 020**<br>(v1.1.1) | *Protocol and data format of REST-based Inter-KME interface* | **【KME間連携要件】**<br>複数拠点KME間の中継・鍵同期プロトコル（KME装置側に要求） | KME-to-KME間の相互認証・鍵リレー仕様（MK1AiのSAEから直接叩くAPIではなく、調達するQKD KMS装置に対する必須準拠要件）。 |

### 2.1 ETSI GS QKD 014 API リクエスト・レスポンス厳格スキーマ

MK1Aiの `mk1_qkd/kmi_etsi.py` は、KMEからのレスポンスを以下の閉じたJSONスキーマ（未知フィールド・重複キー拒否）で検証する。

1. **`GET /api/v1/keys/{slave_SAE_ID}/status`（ステータス確認）**:
   ```json
   {
     "source_KME_ID": "KME-HONMARU-01",
     "target_KME_ID": "KME-REMOTE-01",
     "master_SAE_ID": "SAE-MK1AI-HONMARU",
     "slave_SAE_ID": "SAE-MK1AI-PEER",
     "key_size": 256,
     "stored_key_count": 1024,
     "max_key_count": 4096,
     "max_key_per_request": 16,
     "max_key_size": 1024,
     "min_key_size": 256,
     "max_SAE_ID_count": 0
   }
   ```
   - `stored_key_count == 0` の場合は即座に `QKD_KEY_EXHAUSTED` 状態へ遷移する。

2. **`POST /api/v1/keys/{slave_SAE_ID}/enc_keys`（Master SAEによる鍵素材＋鍵ID取得）**:
   - リクエスト：`{"number": 1, "size": 256}`（原則として1セッションあたり256ビット＝32バイトの鍵を1個ずつ要求）
   - レスポンス：
     ```json
     {
       "keys": [
         {
           "key_ID": "550e8400-e29b-41d4-a716-446655440000",
           "key": "<Base64-encoded 32-byte raw quantum key>"
         }
       ]
     }
     ```
   - **重要制約**: Base64デコード後のバイト列は即座に `bytearray`（`mk1_memory_guard.lock_buffer()` 適用）へ格納し、JSONレスポンス文字列バッファは直ちに破棄する。`key`（秘密鍵ビット列）をネットワーク上へ送信することは絶対に禁止し、対向ノードへは `key_ID`（UUID文字列）のみを送信する。

3. **`POST /api/v1/keys/{master_SAE_ID}/dec_keys`（Slave SAEによる同一鍵IDの引き当て）**:
   - リクエスト：`{"key_IDs": [{"key_ID": "550e8400-e29b-41d4-a716-446655440000"}]}`
   - レスポンス：Master側と同一の32バイト鍵素材を受け取る。

---

## 3. 多層認証・アクセス制御・リプレイ防止要件（Section 2.3）

QKD装置およびKMEを取り巻く8つの認証・検証要件を以下のように規定する。

| # | 認証・検証項目 | 必須実装仕様 | 失敗時の動作（Fail-Closed） |
|---|---|---|---|
| 1 | **QKD装置の認証** | QKD送受信機（Alice/Bob）内のHSM/TPMに格納されたデバイス証明書および初期共有秘密（Wegman-Carter MAC鍵）により、対向QKD装置を物理接続時に相互認証する。 | 量子鍵生成プロセスを停止し、KMEへの鍵供給を遮断（`QKD_AUTH_FAILED`）。 |
| 2 | **Key Manager (KME) の認証** | MK1Ai（SAE）は、ローカルKMEのTLSサーバー証明書（SPKI SHA-384ピン留め必須、パブリックCA不信、専用オフラインRoot CAのみ信頼）を検証する。ホスト名・IP一致（`127.0.0.1` または専用直結IF）を必須とする。 | 接続を即時切断し、`QKD_AUTH_FAILED` へ遷移。鍵取得は一切行わない。 |
| 3 | **相互認証（mTLS）** | KME側もMK1Ai（SAE）のクライアント証明書（`SAE_ID` がSAN/CNにバインドされたX.509証明書、秘密鍵は `0400` 権限保護）を検証する。単方向TLSや平文HTTPでのETSI 014通信はコードレベルで拒否する。 | HTTP 401/403またはTLS Alertで即時拒否。 |
| 4 | **SAEアクセス制御（ACL）** | KMEは要求元のクライアント証明書 `SAE_ID` を確認し、その `SAE_ID` に許可された環境スコープ（例：`INNER_1` のSAEは `HONMARU` の `key_ID` を絶対に取得できない）を強制する。 | KME側およびMK1Ai側の双方でスコープ違反を検知・拒否し、監査アラートを発報。 |
| 5 | **鍵ID（`key_ID`）の検証** | `key_ID` は厳格なRFC 4122 UUIDv4形式（`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`）のみを受理し、インジェクション文字列やパストラバーサル文字を拒否する。 | `QKDValidationError` を送出し、`QKD_ERROR` へ遷移。 |
| 6 | **リプレイ対策** | 1. 対向SAEからの `key_ID` 通知メッセージには、単調増加エポック番号、64ビットランダムnonce、送信時刻（UTC）、およびPQC/Ed25519署名を付与する。<br>2. ローカルの `QKDKeyRegistry` に「消費済み `key_ID` ブルームフィルタ＋永続SQLite台帳」を保持し、**一度でも使用または破棄された `key_ID` の再指定を永久に拒否**する。 | リプレイ検知時はセッションを即座に破棄し、当該対向ノードからの鍵同期要求を遮断。 |
| 7 | **メッセージ完全性** | 対向SAE間で交換するハンドシェイク・トランスクリプト（`SUITE_ID`, `key_ID`, `kem_ciphertext`, `x25519_pub`, `nonce`, `timestamp`）全体のSHA-384ハッシュをKDFの `salt` にバインドし、さらに認証タグ（AEADまたはEd25519/ML-DSA署名）で保護する。 | 1ビットでも改ざんがあれば鍵導出結果が不一致となり、AEADタグ検証で確実に拒否される。 |
| 8 | **失効処理（Revocation）** | `mk1_key_registry.py` の `RevocationManifest` スキーマを拡張し、`revoked_sae_ids`, `revoked_kme_ids`, `revoked_key_id_epochs` を追加する。失効マニフェスト受信時は該当する全キャッシュ鍵を `explicit_bzero` で即時消去し、状態を `QKD_REVOKED` に固定する。 | 失効済みKME/SAE/鍵IDを用いた新規暗号化および復号を即時拒否。 |

---

## 4. 現在の環境における不足機材・依存関係と代替テスト方針（Section 9）

| 項目 | 現在のワークスペースの状態 | 本番稼働に必要な要件 | 現時点での安全な代替策 |
|---|---|---|---|
| **QKD送受信機・KME実機** | **未接続（`HARDWARE MISSING`）** | ETSI GS QKD 014 v1.1.1 準拠のKMEペア＋ダークファイバー接続されたQKD光学モジュール | ループバック上で動作するモックKMEサーバーを用いた単体テストのみ実施し、状態は必ず **`QKD_SIMULATED`** と明示する（`QKD_READY` 詐称禁止）。 |
| **暗号ライブラリ (`cryptography`, `pqcrypto`, `liboqs`)** | **未導入（`NOT INSTALLED`）** | オフライン検証済みWheelパッケージ（`requirements-secure-transport.txt` のSHA-256固定ロック）および `liboqs` C共有ライブラリ | 外部通信・勝手なインストールが禁止されているため、現在は型定義・インターフェース設計・Fail-Closedガード検証にとどめ、実暗号演算は **`NOT TESTED`** として正確に報告する。 |
