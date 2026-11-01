# MK1AI_PQC_HYBRID_DESIGN — QKD + PQC + Classical ECDH Hybrid Key Establishment Specification

> **実装・検証ステータス明示**:
> - 現行リポジトリには `mk1_hybrid_kem.py`（`ML-KEM-1024 + X25519 + WireGuard-PSK`）と `mk1_secure_transport.py`（`ML-KEM-768` 単体）が別々に存在し、**統合されていない**。また両方とも暗号ライブラリ未導入のため **ランタイム未検証（`NOT TESTED`）** である。
> - 本書で定義する「QKD + ML-KEM + X25519 ハイブリッド鍵確立仕様」および「厳格なフォールバック禁止ポリシー」は **設計完了（`DESIGN ONLY`）・未実装（`NOT IMPLEMENTED`）** である。

---

## 1. ハイブリッド鍵確立の設計原則（Section 4）

1. **独自暗号・単純XOR・単純連結の絶対禁止**:
   - `K = K_QKD ^ K_PQC` のような単純XORや、長さを固定しない単純バイト連結 `K_QKD || K_PQC` をそのまま暗号鍵として用いることは、一方の鍵生成源にバイアスや操作可能性（Malleability / Related-key attack）がある場合に安全性を損なうため厳禁とする。
2. **標準化されたKDF（NIST SP 800-56C Rev. 2 / RFC 5869 HKDF-SHA384 / IETF Hybrid KEM Draft）の採用**:
   - 各鍵素材（QKD鍵、ML-KEM共有秘密、X25519共有秘密、必要に応じ事前共有PSK）をそれぞれ固定長検証した上で、公開コンテキスト（`SUITE_ID`, `zone_id`, `key_ID`, `kem_ciphertext`, `x25519_public_keys`, `purpose`）を長さプレフィックス付きでトランスクリプトハッシュに束縛し、`HKDF-Extract` / `HKDF-Expand`（`SHA-384`）によって最終鍵を導出する。
3. **3つの構成要素の独立した安全性寄与（Multi-Key PRF Property）**:
   - **QKD鍵（`SS_QKD`, 32B）**: 量子計算機に対しても情報理論的安全性（Information-Theoretic Security）を提供。
   - **PQC KEM（`SS_MLKEM`, 32B）**: `ML-KEM-768`（または `ML-KEM-1024`）により、万一QKD装置のKME内部や光トランシーバにサイドチャネルがあった場合でも、量子計算機に対する計算量的安全性（Module-LWE）を提供。
   - **古典ECDH（`SS_X25519`, 32B）**: `X25519` により、万一格子暗号（ML-KEM）に未知の数学的解読法が見つかった場合でも、従来型暗号としての128ビット安全性を提供。

---

## 2. 現行リポジトリ内のPQC不整合の解消設計

現在リポジトリ内で分裂している2つの方式を、以下の2つの正式プロファイル（Suite）として整理・統合する：

| プロファイル識別子 (`SUITE_ID`) | 構成アルゴリズム | 対象ゾーン・用途 | 現状と統合方針 |
|---|---|---|---|
| **`MK1-SUITE-PQC-HYBRID-768-v2`**<br>`b"MK1-MLKEM768-X25519-HKDF-SHA384-v2"` | **ML-KEM-768** (PQC) + **X25519** (古典ECDH) + **HKDF-SHA384** | PQCモード（`PQC_ONLY` ポリシー時）の標準トランスポートおよびワンタップ暗号化KEK | 現行 `mk1_secure_transport.py`（ML-KEM-768単体）に `X25519` と `HKDF-SHA384` を統合し、ML-KEM単体利用を廃止する。 |
| **`MK1-SUITE-PQC-HYBRID-1024-v2`**<br>`b"MK1-MLKEM1024-X25519-WGPSK-SHA384-v2"` | **ML-KEM-1024** (PQC) + **X25519** (古典ECDH) + **WireGuard-PSK** + **HKDF-SHA384** | 本丸・高保証ノード間のPQC最高強度モード | 現行 `mk1_hybrid_kem.py` の実装を維持し、`mk1_secure_transport.py` から選択可能に接続する。 |
| **`MK1-SUITE-TRIPLE-QKD-PQC-v1`**<br>`b"MK1-QKD014-MLKEM1024-X25519-SHA384-v1"` | **QKD (ETSI 014 256bit)** + **ML-KEM-1024** (PQC) + **X25519** (古典ECDH) + **HKDF-SHA384** | ハイブリッドモード（`HYBRID_QKD_PQC`）における本丸・Inner境界の標準鍵確立 | 新設する `mk1_qkd/transport_bridge.py` にて実装する。 |

---

## 3. 検証済み鍵合成（Key Combiner）の数理仕様

`MK1-SUITE-TRIPLE-QKD-PQC-v1` における鍵合成関数 `combine_qkd_pqc_hybrid()` の厳密な導出ステップを以下に定義する。

### 3.1 入力検証（すべて固定長・型検査必須）
1. `qkd_key`: `bytearray`、長さ厳密に `32` バイト（256ビット）。全ゼロ・低エントロピーでないこと。
2. `qkd_key_id`: `str`、RFC 4122 UUIDv4 形式（36文字 ASCII）。
3. `mlkem_secret`: `bytearray`、長さ厳密に `32` バイト（`ML-KEM-1024` または `ML-KEM-768` の `encaps`/`decaps` 出力）。
4. `x25519_secret`: `bytearray`、長さ厳密に `32` バイト（`X25519` 出力、全ゼロ出力はRFC 7748に従い拒否）。
5. `zone_id`: `ALLOWED_ZONES`（`"HONMARU"`, `"INNER_1"`..`"INNER_4"`）のいずれか。
6. `purpose`: `ALLOWED_PURPOSES`（`"transport-seed"`, `"one-tap-kek"` 等）のいずれか。

### 3.2 トランスクリプト・バインディングと2段階 HKDF-SHA384 導出

長さプレフィックス（4バイトビッグエンディアン `struct.pack(">I", len(x))`）を用いてすべての公開パラメータを一意にシリアライズし、ドメイン分離を行う：

```python
# Step 1: 公開トランスクリプトハッシュ (Context Transcript Hash) の計算
context_transcript = hashlib.sha384(b"".join((
    SUITE_ID,                                           # b"MK1-QKD014-MLKEM1024-X25519-SHA384-v1"
    struct.pack(">I", len(zone_id)), zone_id.encode("ascii"),
    struct.pack(">I", len(purpose)), purpose.encode("ascii"),
    struct.pack(">I", len(qkd_key_id)), qkd_key_id.encode("ascii"),
    struct.pack(">I", len(kem_ciphertext)), kem_ciphertext,
    struct.pack(">I", len(kem_public_key)), kem_public_key,
    client_x25519_public_key,                           # 32 bytes
    server_x25519_public_key,                           # 32 bytes
    struct.pack(">I", len(protocol_transcript)), protocol_transcript,
))).digest()                                            # 48 bytes (SHA-384)

# Step 2: 個別ドメインラベル付き抽出（各鍵素材の境界を固定）
ikm_buffer = bytearray(
    b"QKD_KEY_V1:" + qkd_key                            # 11 + 32 = 43 bytes
    + b"MLKEM_SS_V1:" + mlkem_secret                    # 12 + 32 = 44 bytes
    + b"X25519_SS_V1:" + x25519_secret                  # 13 + 32 = 45 bytes
)

# Step 3: HKDF-SHA384 (Extract + Expand)
info_label = (
    SUITE_ID + b"\0"
    + zone_id.encode("ascii") + b"\0"
    + purpose.encode("ascii") + b"\0"
    + qkd_key_id.encode("ascii")
)
derived_key = HKDF(
    algorithm=hashes.SHA384(),
    length=32,
    salt=context_transcript,
    info=info_label,
).derive(ikm_buffer)
```

- 導出完了後、`finally` ブロックで `qkd_key`, `mlkem_secret`, `x25519_secret`, `ikm_buffer` の全 `bytearray` に対して即座に `mk1_memory_guard.wipe_buffer()` を実行する。

---

## 4. 動作モードと厳格なフォールバックポリシー（Section 4）

**QKDが利用できないときに、管理者のクォーラム承認なしに安全性の異なる方式（PQCのみ、または古典暗号）へ自動切替（サイレント・ダウングレード）することは重大なセキュリティ違反であり、絶対に禁止する。**

システムは以下の3つの明示的ポリシーモード（`CryptoPolicyMode`）を持ち、モード間の変更には **M-of-N 管理者クォーラム署名バンドル（`mk1_quorum.py` の `verify_approval_bundle()`）** を必須とする。

| ポリシーモード | 成立条件 | QKD利用不可時（`QKD_UNAVAILABLE` / `EXHAUSTED` / `ERROR`）の動作 | 自動フォールバックの可否 |
|---|---|---|---|
| **1. QKD必須モード**<br>(`QKD_MANDATORY`) | `QKD_READY` であり、有効な実機QKD鍵（`is_simulated == False`）が取得できる場合のみ鍵確立を許可。 | **即時拒否（Fail-Closed）**。<br>一切の鍵確立・新規暗号化・セッション開始をブロックし、`QKDUnavailableError` を送出する。 | **全面禁止**（PQCモードへの自動切替なし）。 |
| **2. ハイブリッドモード**<br>(`HYBRID_QKD_PQC`) | `QKD_READY` の実機QKD鍵 ＋ `ML-KEM` ＋ `X25519` の**3要素すべてが正常に成立した場合のみ**鍵確立を許可。 | **即時拒否（Fail-Closed）**。<br>QKD要素またはPQC要素のいずれか1つでも欠落・失敗した場合は鍵確立を拒否する。 | **全面禁止**（勝手にQKD要素を省略してPQC単独で続行することは禁止）。 |
| **3. PQCモード**<br>(`PQC_APPROVED`) | 事前に承認された構成（またはQKD未導入環境）において、`ML-KEM-768/1024 + X25519` ハイブリッド鍵確立を利用。 | QKDは使用しない。ただしUI/メタデータには必ず `MODE: PQC_HYBRID (QKD_UNAVAILABLE)` と明記し、QKD保護があるかのように誤認させない。 | **`ML-KEM` または `X25519` が失敗した場合に片方単独や平文へダウングレードすることは全面禁止**。 |

### 4.1 管理者承認による非常時モード切替手順（Downgrade Governance）
万一、実運用中に光ファイバー断線等で `HYBRID_QKD_PQC` から `PQC_APPROVED` へ一時的に切り替える必要がある場合は、自動切替ではなく以下の手順を強制する：
1. システムは通信・新規鍵確立を停止（Fail-Closed）し、UI/操作パネルに `QKD_ERROR: 鍵確立停止中（自動ダウングレード禁止）` を表示する。
2. 2名以上の独立した管理者がオフライン署名ツール（`mk1_quorum_cli.py`）を用いて、`action="crypto_policy_change"`, `target_mode="PQC_APPROVED"`, `generation=N+1`, `expiry_timestamp` を含む承認バンドルにEd25519（将来はML-DSA併用）署名を付与する。
3. `QKDPolicyController` が `verify_approval_bundle()` を通過したことを確認し、監査ログにハッシュチェーン記録を残した上で初めて `PQC_APPROVED` モードへ遷移する。
