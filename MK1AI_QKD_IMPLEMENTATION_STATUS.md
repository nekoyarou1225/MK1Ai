# MK1AI_QKD_IMPLEMENTATION_STATUS — QKD, PQC, SessionRatchet & Cryptographic Implementation Audit

## 1. 最重要原則と結論サマリ

本監査では、**QKD（量子鍵配送）、PQC（耐量子計算機暗号）、X25519/Ed25519（古典楕円曲線暗号）、SessionRatchet（対称鍵ラチェット）、AES-256-GCM（共通鍵AEAD暗号）を厳密に別の技術レイヤーとして分離**し、現行リポジトリ（全ソースコード・C実装・設定・依存定義）における実態を証拠付きで判定した。

### 総合結論
1. **QKD（量子鍵配送）は現行リポジトリに一切実装されていない（`NOT IMPLEMENTED` / `0行`）。**
   - QKD装置ドライバ、ETSI GS QKD 004 / 014 / 020 クライアント、量子チャネル制御、古典チャネル認証、QKD Key Manager（KME/KMS）連携、鍵ID（KSID）同期のいずれもソースコード内に存在しない。
   - また、実QKD装置（光学送受信機）も接続されておらず（`HARDWARE MISSING`）、したがってQKD状態は必ず **`QKD_UNAVAILABLE`** でなければならず、「QKD対応済み」「QKD利用中」と表示・報告することは厳禁である。
2. **ワンタップ暗号化・復号機能（One-Tap Encryption / Decryption）は現行リポジトリに未実装である（`NOT IMPLEMENTED`）。**
   - 現行コードに存在するのはRSI学習データ送信用エンベロープ（`mk1_secure_transport.py`）およびプロセス内RAM退避暗号化（`MemoryManager`）のみであり、任意のテキスト・メッセージ・ファイル・バックアップ・エクスポートデータを対象としたユーザー向けワンタップ暗号化/復号UI・CLI・履歴・鍵有効期限表示は未実装である。
3. **PQC（ML-KEM）および古典暗号（X25519, Ed25519, AES-256-GCM）はソースコードのみ存在するが、Pythonランタイム実暗号テストは未検証（`NOT TESTED`）である。**
   - 本監査環境に `pqcrypto`, `cryptography`, `argon2-cffi`, `shamir-mnemonic`, `liboqs` が導入されていないため、Python側の実暗号プリミティブ演算は一度も実行されていない（C側のOpenSSL `AES-256-GCM` と `explicit_bzero` のみ `mk1_test_runner` で実行確認済み）。

---

## 2. 暗号技術の厳密な分類と混同防止マトリクス

| 分類カテゴリ | 技術・アルゴリズム名 | 暗号学的性質 | 現行リポジトリ内の該当箇所 | 実装・検証ステータス |
|---|---|---|---|---|
| **QKD（量子鍵配送）** | BB84 / COW / DPS / CV-QKD + ETSI GS QKD 004/014/020 | 量子力学的不確定性（単一光子・連続変数の観測擾乱）と認証済み古典通信路を用いた物理層鍵共有 | **該当ファイルなし（0件）** | **`NOT IMPLEMENTED`**<br>**`HARDWARE MISSING`**<br>**`NOT TESTED`** |
| **PQC（耐量子計算機暗号：KEM）** | **ML-KEM-768** (FIPS 203) | 格子問題（Module-LWE）の計算量的困難性に基づく公開鍵カプセル化機構（量子通信路は不要） | `mk1_secure_transport.py:35`<br>`mk1_tunnel.c`, `mk1_tunnel_oqs.c:44`<br>`mk1-remote-nginx.conf.template:7` | **コード実装あり（単体）**<br>ランタイム実行は **`NOT TESTED`**（`pqcrypto`/`liboqs` 未導入） |
| **PQC（耐量子計算機暗号：KEM）** | **ML-KEM-1024** (FIPS 203) | Module-LWE（NIST Security Category 5）に基づく公開鍵カプセル化機構 | `mk1_hybrid_kem.py:17` | **独立モジュールのみ存在（本体未接続）**<br>ランタイム実行は **`NOT TESTED`**（`pqcrypto` 未導入） |
| **PQC（耐量子計算機暗号：KEM）** | **ML-KEM-512** | Module-LWE（Category 1） | **該当なし** | **`NOT IMPLEMENTED` / 使用禁止**（セキュリティ強度不足のため不採用） |
| **PQC（耐量子計算機暗号：署名）** | **ML-DSA** (FIPS 204: ML-DSA-65 / ML-DSA-87) | 格子問題（Module-LWE / Module-SIS）に基づくデジタル署名 | **該当なし**（`MK1AI_TECHNICAL_SECURITY_REPORT.md:61` で未実装と明記） | **`NOT IMPLEMENTED`** |
| **PQC（耐量子計算機暗号：署名）** | **SLH-DSA** (FIPS 205: SPHINCS+) | ハッシュ関数のみに基づくステートレス署名 | **該当なし** | **`NOT IMPLEMENTED`** |
| **古典公開鍵暗号（ECDH鍵共有）** | **X25519** (RFC 7748) | Curve25519上の楕円曲線Diffie-Hellman鍵共有。<br>**※従来型暗号でありPQCでもQKDでもない（Shorのアルゴリズムに対して脆弱）** | `mk1_hybrid_kem.py:11–14`<br>`mk1-remote-nginx.conf.template:7`<br>WireGuard内部ハンドシェイク | **コード実装あり**（`mk1_hybrid_kem.py` のみ、`mk1_secure_transport.py` には未統合）<br>Python実演算は **`NOT TESTED`** |
| **古典公開鍵暗号（デジタル署名）** | **Ed25519** (RFC 8032) | Edwards25519上のSchnorr型署名。<br>**※従来型暗号でありPQCではない** | `mk1_quorum.py`<br>`mk1_key_registry.py`<br>`mk1_external_verifier.py` | **コード実装あり**<br>実署名生成・検証は **`NOT TESTED`**（`cryptography` 未導入） |
| **対称鍵ラチェット（KDF連鎖）** | **SessionRatchet** (`HKDF-SHA384` + `HMAC-SHA384`) | 確立済みの32バイト共有秘密からメッセージ毎の対称鍵を単方向導出する仕組み。<br>**※鍵確立（QKD/KEM）自体ではない** | `mk1_session_ratchet.py`<br>`mk1_secure_transport.py:321–350` | **コード実装あり**<br>実暗号導出は **`NOT TESTED`**（`cryptography` 未導入） |
| **共通鍵認証付き暗号（AEAD）** | **AES-256-GCM** (NIST SP 800-38D) | 256ビット共通鍵による対称暗号化＋128ビットGMAC認証タグ。<br>**※鍵配送方式（QKD/PQC）ではない** | `mk1_secure_transport.py`<br>`mk1_session_ratchet.py`<br>`airgap_ai_defender.py`<br>`mk1_tunnel.c` | **コード実装あり**<br>C側OpenSSL EVPのみ **TESTED**<br>Python側 `AESGCM` は **`NOT TESTED`** |
| **パスワード鍵導出・秘密分散** | **Argon2id** + **HKDF-SHA384** + **SLIP-39 Shamir** | ユーザーパスフレーズからのルート鍵導出とM-of-Nニーモニック分割 | `mk1_key_derivation.py`<br>`mk1_key_backup.py` | **コード実装あり**<br>ランタイム実行は **`NOT TESTED`**（`argon2-cffi`, `shamir-mnemonic` 未導入） |
| **レガシー・制限付きアルゴリズム** | **Fernet** (AES-128-CBC + HMAC-SHA256) / **SHA-1** | - `Fernet`: `airgap_ai_defender.py` の旧学習データ保存用（128bit強度のため新規暗号用途では禁止）<br>- `SHA-1`: `mk1_map.py:136` のWebSocket RFC 6455固定ハンドシェイクのみ（暗号署名・ハッシュ用途は禁止） | `airgap_ai_defender.py`<br>`mk1_map.py:136` | **用途限定・新規利用禁止** |

---

## 3. QKD（量子鍵配送）11項目の実装状況監査（Section 1.1）

現行コードベース全体を監査した結果、QKDに関する全11項目は以下の通りすべて **未実装（`NOT IMPLEMENTED`）** かつ **実機不在（`HARDWARE MISSING`）** である。

| # | QKD監査項目 | ステータス | 実コード照合結果と根拠 |
|---|---|---|---|
| 1 | QKD送信・受信モジュールとの接続 | **`NOT IMPLEMENTED` / `HARDWARE MISSING`** | リポジトリ内にQKD光学送受信機（Alice/Bob）またはベンダーSDKへの接続コードは0行。 |
| 2 | 量子通信路（Quantum Channel） | **`HARDWARE MISSING`** | 専用のダークファイバーまたは自由空間光学（FSO）リンクおよびQBER（量子ビット誤り率）監視機構は存在しない。 |
| 3 | 認証済み古典通信路（Authenticated Classical Channel） | **`NOT IMPLEMENTED`** | 基底照合（Sifting）・誤り訂正（Error Correction）・秘匿性増幅（Privacy Amplification）用の情報理論的認証（Wegman-Carter MAC等）またはPQC認証チャネルは未実装。 |
| 4 | QKD Key Management（KME / KMS） | **`NOT IMPLEMENTED`** | ETSI GS QKD 014 / 004 / 020 に準拠したKME（Key Management Entity）クライアント・サーバー実装は存在しない。 |
| 5 | 鍵素材の取得 | **`NOT IMPLEMENTED`** | KMEから鍵ビット列を取得するAPI呼び出し（`Get_key`, `Get_key_with_key_IDs` 等）は存在しない。 |
| 6 | 鍵ID（Key ID / KSID）の管理 | **`NOT IMPLEMENTED`** | QKDの128bit UUID鍵識別子（`key_ID`）を管理・照合するデータ構造は存在しない（`mk1_key_registry.py` はパスフレーズ派生鍵の `device_id` と `generation` のみ管理）。 |
| 7 | 鍵素材の認証・検証 | **`NOT IMPLEMENTED`** | KME応答のmTLS証明書検証、応答署名検証、エントロピー健全性検査、ゼロオール鍵検査は未実装。 |
| 8 | 鍵の用途制限 | **`NOT IMPLEMENTED`（QKD用）** | `mk1_key_registry.py:26–33` に `ALLOWED_PURPOSES`（6種類）が定義されているが、これはローカル `HKDF` 派生鍵専用であり、QKD鍵の用途バインディング（KEK専用・DEK直接利用禁止等）は未実装。 |
| 9 | 鍵の期限・失効 | **`NOT IMPLEMENTED`（QKD用）** | QKD鍵の取得時刻・TTL・単一消費（One-Time Consumption）フラグ・緊急失効パージは未実装。 |
| 10 | 対向装置との鍵同期 | **`NOT IMPLEMENTED`** | 送信側SAE（Secure Application Entity）と受信側SAEの間で `key_ID` を交換して同一QKD鍵を引き当てるプロトコルは未実装。 |
| 11 | MK1Ai Secure Transportとの連携 | **`NOT IMPLEMENTED`** | `mk1_secure_transport.py` は `ML-KEM-768` 単体のみを使用しており、QKD鍵を入力またはハイブリッド合成するインターフェースを持たない。 |

> **厳守事項**: QKD装置が存在しない環境および未実装の現状において、UI・CLI・ログ・報告書のいかなる場所でも **「QKD利用中 (`QKD_READY`)」と表示してはならない**（必ず `QKD_UNAVAILABLE` またはテスト時のみ `QKD_SIMULATED` と区別する）。

---

## 4. PQC + X25519 ハイブリッド実装の不整合監査（Section 1.2）

現行リポジトリ内のPQC実装を精査した結果、以下の **3つのモジュール間不整合** と **未検証状態** が確認された。

1. **`mk1_hybrid_kem.py` と `mk1_secure_transport.py` の乖離**:
   - `mk1_hybrid_kem.py`（全227行）は、`ML-KEM-1024`（`pqcrypto.kem.ml_kem_1024`）と古典ECDHである `X25519`（`cryptography.hazmat.primitives.asymmetric.x25519`）および `wireguard_psk`（32B）を、`HKDF-SHA384`（`SUITE_ID = b"MK1-HYBRID-ML-KEM-1024-X25519-WG-PSK-v1"`）で結合する関数 `encapsulate()` / `decapsulate()` を実装している。
   - しかし、実際にアプリケーション（`airgap_ai_defender.py`）が呼び出す `mk1_secure_transport.py`（`line 35`）は **`mk1_hybrid_kem.py` をインポートしておらず、`ML-KEM-768` 単独（X25519なし、`HKDF-SHA256`）で鍵確立を行っている**。
   - さらにC言語側の `mk1_tunnel.c` / `mk1_tunnel_oqs.c` も `ML-KEM-768` 単独（`OQS_KEM_new("ML-KEM-768")`、X25519なし、`HKDF-SHA256`）となっている。
2. **`X25519` の分類に関する厳密な定義**:
   - `X25519` は255ビット素数体上のモンゴメリ曲線（Curve25519）を用いた**従来型（古典）楕円曲線Diffie-Hellman鍵共有（ECDH）**であり、耐量子計算機暗号（PQC）ではない。ハイブリッド方式（`ML-KEM-768 + X25519` または `ML-KEM-1024 + X25519`）における役割は、「万が一格子暗号（ML-KEM）に数学的脆弱性が発見された場合でも、古典暗号としての安全性（約128bit安全性）を維持する」ための古典側コンポーネントである。
3. **実動作の検証状況**:
   - 本環境には `pqcrypto` および `cryptography` がインストールされていないため、`ML-KEM-768`、`ML-KEM-1024`、`X25519` の実際の鍵生成・カプセル化・共有秘密導出は **すべて `NOT TESTED`（ランタイム未実行）** である。

---

## 5. `SessionRatchet` と `mk1_secure_transport.py` の連携・ゼロ化監査（Section 1.3）

`mk1_session_ratchet.py`（全188行）と `mk1_secure_transport.py` の9つの監査項目に対する実コード評価は以下の通りである。

| # | 監査項目 | 実コードの箇所 | 実装状況・技術的評価 | 検証状態 |
|---|---|---|---|---|
| 1 | セッション初期化 | `mk1_session_ratchet.py:55–98`<br>`mk1_secure_transport.py:321–350` | 32バイトの `session_secret`（`bytearray`）と16バイトの `session_id`、方向（`initiator` / `responder`）を受け取り、`HKDF-SHA384` で初期送信チェーン鍵 `_send_chain`（32B）と初期受信チェーン鍵 `_receive_chain`（32B）に分離導出する。入力 `session_secret` は `finally` で `wipe_buffer()` される。 | コード確認済 / 実暗号導出は **`NOT TESTED`** |
| 2 | 鍵更新（Ratchet Step） | `mk1_session_ratchet.py:33–49, 120–168` | メッセージ送信/受信ごとに `hmac.digest(bytes(chain_key), b"MK1-ratchet-step-v1\0" + seq, hashlib.sha384)` で次ステップのチェーン鍵（先頭32B）を計算し、`b"MK1-message-key-v1\0" + seq` で当該メッセージ専用のAES-256-GCM鍵（32B）を導出する。 | コード確認済 / **`NOT TESTED`** |
| 3 | 前方秘匿性（Forward Secrecy） | `mk1_session_ratchet.py:134, 165` | 各メッセージ処理後に旧 `_send_chain` / `_receive_chain` の `bytearray` を `wipe_buffer()` で上書きしてから `next_chain` に差し替える設計。ただし後述⑦の通り、CPythonヒープ上の不変 `bytes` コピーが残存するため、プロセスメモリダンプに対する物理的な前方秘匿性は完全ではない。 | 論理設計のみ / 物理消去は **不完全** |
| 4 | チャンク順序検証 | `mk1_session_ratchet.py:148–153` | `decrypt()` 内で `if sequence != self._receive_sequence: raise SessionRatchetError("Out-of-order or replayed session chunk")` を強制しており、**順序逆転（Out-of-order）や欠落を一切許容しない厳格な逐次順序検証（ウィンドウサイズ=1）** となっている。また12バイトnonceに方向バイト（`0x00`/`0x01`）と8バイトの `sequence` を埋め込み、AADにも `session_id + direction + sequence` をバインドしている。 | コード確認済 / **`NOT TESTED`** |
| 5 | セッション失効 | `mk1_session_ratchet.py:25–26, 107–117` | `MAX_MESSAGES_PER_DIRECTION = 4096`（片方向最大4096メッセージ）および `SESSION_TTL_SECONDS = 15 * 60`（15分、単調増加クロック `monotonic()` で判定）を超過すると、即座に `self._destroy_locked()` を呼んで鍵を破棄し `SessionRatchetError` を送出する。 | コード確認済 / **`NOT TESTED`** |
| 6 | トランスポート無効化 | `mk1_secure_transport.py:276–292` | `set_transport_enabled(False)` 呼び出し時、`_TRANSPORT_LOCK` 下で `_ACTIVE_ENVELOPES` を `destroy()` し、さらに `_ACTIVE_RATCHETS` 内の全 `SessionRatchet` インスタンスに対して `ratchet.destroy()` を呼び出してリストをクリアする。 | 単体テスト（モック）で呼び出し確認済 |
| 7 | `destroy()` 処理と物理消去の限界 | `mk1_session_ratchet.py:172–181`<br>`mk1_memory_guard.py:190–214` | **【重要】`destroy()` が呼ばれることと、メモリ上の全秘密鍵コピーが物理消去されたことは同義ではない。**<br>1. `self._send_chain` と `self._receive_chain`（`bytearray`）は `explicit_bzero` でゼロ化される。<br>2. しかし `HKDF.derive(bytes(secret_buf))`、`hmac.digest(bytes(chain_key), ...)`、スライス `[:32]`、`AESGCM(bytes(key))` が生成する **Pythonの不変 `bytes` オブジェクト**、および **OpenSSL `EVP_CIPHER_CTX` 内のAES拡大鍵（240B）** は `wipe_buffer()` では消去できず、CPythonヒープやCヒープ上に残存する。<br>3. さらに `ratchet.destroy()` を直接呼んだ場合、`mk1_secure_transport._ACTIVE_RATCHETS` から削除されない参照リークがあり、`set_memory_guard_enabled()` も `_ACTIVE_RATCHETS` を走査しない。 | **`bytearray` 以外は消去不能（限界あり）** |
| 8 | 並行実行（Thread Safety） | `mk1_session_ratchet.py:72, 120, 146, 179` | インスタンスごとに `self._lock = threading.Lock()` を保持し、`encrypt()`, `decrypt()`, `destroy()` の全操作を排他制御している。 | コード確認済 |
| 9 | エラー復旧 | `mk1_session_ratchet.py:155–167` | `AESGCM.decrypt()` が認証タグ不一致（`InvalidTag`）で失敗した場合、`_receive_chain` と `_receive_sequence` を進める前に例外 `SessionRatchetError("Session chunk authentication failed")` を送出するため、偽造パケット挿入によって受信ラチェット状態が破壊（Desync DoS）されることはない。ただし、正規パケットがネットワーク上で1個でも欠落した場合は順序不一致となるため、上位層でのセッション再確立（Re-keying）が必要となる。 | コード確認済 / **`NOT TESTED`** |

---

## 6. 既存報告書（`MK1AI_REMEDIATION_REPORT.md` 等）の不適切記述の訂正一覧（Section 7）

既存ファイル保護ルール（Section 9）に従い、既存ファイル自体は書き換えず、`MK1AI_REMEDIATION_REPORT.md` 等に含まれていた不適切な記述を本監査記録にて正式に訂正する。

| 旧報告書内の記述 | 該当箇所 | 訂正後の正確な記述（監査結論） |
|---|---|---|
| 「残存リスク: なし」 | `MK1AI_REMEDIATION_REPORT.md` 修正項目 1, 4, 5, 6, 7, 8 | **「残存リスクあり」に訂正。**<br>DPI `fail_closed` 誤遮断・Self-DoS、暗号通信未検査、フラグメント未再構成、`ONI_MODE` 二重管理、メモリ高負荷時 `feature_vector[9] > 1.0` による全通信遮断、不変 `bytes` の鍵残存、実暗号未検証など重大な残存リスクが存在する。 |
| 「未検証項目: なし」 | `MK1AI_REMEDIATION_REPORT.md` 修正項目 1, 2, 3, 4, 5 | **「未検証項目あり（実通信・実トラフィック・マルチスレッド競合は `NOT TESTED`）」に訂正。**<br>実施されたのはPython関数単体テストのみであり、実NIC・実パケット・高負荷下での検証は未実施。 |
| 「すべてのアクティブな `SessionRatchet.destroy()` を呼び出して鍵メモリを即時ゼロ化する」 | `MK1AI_REMEDIATION_REPORT.md` 修正項目 7 (`line 128`) | **「管理対象の `bytearray` バッファのみをゼロ化するが、Pythonの不変 `bytes` オブジェクト・OpenSSL内部の鍵スケジュール・未ロックメモリ上のコピーは消去できず、完全ゼロ化は保証されない」に訂正。** |
| 「実 ML-KEM-768 + X25519 鍵交換テスト（`NOT TESTED`）」 | `MK1AI_REMEDIATION_REPORT.md` 修正項目 7 (`line 132`) | **「`mk1_secure_transport.py` は `ML-KEM-768` 単体（X25519なし）であり、`mk1_hybrid_kem.py`（`ML-KEM-1024 + X25519`）とは統合されていない。さらに両者ともライブラリ未導入のため `NOT TESTED` である」に訂正。** |
| 「QKD対応」「暗号化完了」「実遮断完了」と誤解され得る表現 | 関連ドキュメント全般 | - **QKD**: **未実装（`NOT IMPLEMENTED` / `HARDWARE MISSING`）**<br>- **ワンタップ暗号化**: **未実装（`NOT IMPLEMENTED`）**<br>- **Python実暗号プリミティブ**: **未検証（`NOT TESTED`）**<br>- **XDP / Kill Switch実遮断**: **未実装（`AF_PACKET` 受動監視のみ / Kill SwitchはDry-Run 4重固定）** |
