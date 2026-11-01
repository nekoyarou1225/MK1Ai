# MK1Ai — Cryptographic, Memory Guard & AI Verification Status Report (`MK1AI_CRYPTO_VERIFICATION_STATUS.md`)

**監査対象**: `mk1_session_ratchet.py`, `mk1_memory_guard.py`, `mk1_memory_guard.c`, `mk1_secure_transport.py`, `mk1_hybrid_kem.py`, `mk1_quorum.py`, `mk1_key_registry.py`, `mk1_tunnel.c`, `mk1_test_runner.c`, `airgap_ai_defender.py`
**監査モード**: 独立読み取り専用監査（コード修正なし）

---

## 1. 暗号・メモリ保護・AI 検証ステータスの総合マトリクス（Section 4）

最初に結論として、**実環境でバイナリ実行された項目（`TESTED`）** と、**コード実装は存在するが依存ライブラリ（`cryptography`, `pqcrypto`, `liboqs`, `torch`）未導入のためランタイム未実行の項目（`NOT_TESTED` / `SKIPPED`）** を厳密に分離する。

| 対象コンポーネント | アルゴリズム / 機能 | 実装ファイル | 検証ステータス | 検証根拠・制限事項 |
|---|---|---|---|---|
| **C Memory Guard** | `explicit_bzero` / `OPENSSL_cleanse` / `mlock` / `MADV_DONTDUMP` | `mk1_memory_guard.c`, `mk1_test_runner.c` | **TESTED (実バイナリ実行 PASS)** | `./mk1_test_runner` 実行により、`mlock` されたバッファのゼロ化と OpenSSL `OPENSSL_cleanse` の動作を実メモリ上で確認済み。 |
| **C OpenSSL EVP Cipher** | OpenSSL `AES-256-GCM` EVP コンテキスト取得・解放 | `mk1_tunnel.c`, `mk1_test_runner.c:293–310` | **TESTED (実バイナリ実行 PASS)** | `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)` の成功を `./mk1_test_runner` で確認済み。 |
| **Python Memory Guard** | `ctypes` 経由の `libmk1_memory_guard.so` 呼び出しと `bytearray` ゼロ化 | `mk1_memory_guard.py` | **TESTED (単体テスト PASS)** | `wipe_buffer()` が `bytearray` / `memoryview` をインプレースでゼロ埋めすることを確認済み（ただし Python `bytes` に対する限界あり：後述 Section 2）。 |
| **Python SessionRatchet** | HKDF-SHA256 送信/受信チェイン鍵ラチェット | `mk1_session_ratchet.py` | **NOT_TESTED (ランタイム SKIPPED)** | コード実装および `mk1_secure_transport.py` への配線は完了しているが、`cryptography` 未導入のため実 HKDF 導出テスト4件は `SKIPPED`。 |
| **Python PQC Hybrid KEM** | **ML-KEM-1024 + X25519 + HKDF-SHA256** (`mk1_hybrid_kem.py`) vs **ML-KEM-768** (`mk1_secure_transport.py`) | `mk1_hybrid_kem.py`, `mk1_secure_transport.py` | **NOT_TESTED (ランタイム SKIPPED + 仕様不整合あり)** | `pqcrypto` / `cryptography` 未導入のため実カプセル化は未実行。さらにモジュール間で **ML-KEM-1024+X25519** と **ML-KEM-768 単体** の不整合が存在（後述 Section 3）。 |
| **C PQC Tunnel (`liboqs`)** | `OQS_KEM_alg_ml_kem_768` (`mk1_tunnel_oqs.c`) | `mk1_tunnel.c`, `mk1_tunnel_oqs.c` | **NOT_TESTED (ビルド時無効)** | `Makefile` で `MK1_USE_LIBOQS` が有効化されておらず、`liboqs` 未リンクのため C テストはスタブ経路のみ実行。 |
| **Quorum / Key Registry** | Ed25519 署名生成・検証・M-of-N クォーラム・失効マニフェスト | `mk1_quorum.py`, `mk1_key_registry.py` | **PARTIAL (Fail-Closed ガードのみ TESTED / 実署名は NOT_TESTED)** | `cryptography` 不在時に `QuorumError` で Fail-Closed になる動作は実測確認済み。実 Ed25519 署名検証テスト（計9件）は `SKIPPED`。 |
| **AI 推論パイプライン** | 特徴量ベクトル検証 + ニューラルネットワーク異常検知 | `airgap_ai_defender.py` | **PARTIAL (入力検証のみ TESTED / 実モデル推論は NOT_TESTED)** | `TORCH_AVAILABLE = False` のため `_TorchStub` 上で入力検証（`NaN`/負数/要素不足の Fail-Closed 遮断）のみ実測確認済み。実 PyTorch 推論は未実行。 |

---

## 2. `SessionRatchet` のメモリ保護境界と `destroy()` 監査（Section 4.1）

`mk1_session_ratchet.py`（全200行）および `mk1_memory_guard.py`（全138行）を精査した結果、以下のメモリゼロ化範囲と **Python ランタイム固有の限界・実装バグ** を確認した。

### 2.1 `bytearray` としてゼロ化（`explicit_bzero`）されるオブジェクト
`mk1_session_ratchet.py` では、以下のバッファがミュータブルな `bytearray` として保持され、`wipe_buffer()`（C 拡張 `mk1_Shared_wipe` → `explicit_bzero`）の対象となる：
1. `session_secret`: `__init__()` 終了時（`line 68`）に `wipe_buffer(secret_buf)` でゼロ化（ただし呼び出し元が immutable `bytes` を渡した場合はコピー元の `bytes` は残存する）。
2. `self._send_chain` / `self._receive_chain`（各32バイト `bytearray`）: ラチェット進行時（`lines 109, 134, 155`）に旧チェインが `wipe_buffer()` でゼロ化され、`destroy()` 時（`lines 171–172`）にもゼロ化される。
3. 導出途中の `next_chain` / `key`（`bytearray`）: `_derive_pair()` 内（`lines 78–79`）および `finally` ブロック（`lines 118, 137, 158, 160`）で `wipe_buffer()` される。
4. `self._skipped_keys` 内の滞留メッセージ鍵（`bytearray`）: 消費時（`line 125`）、上限超過パージ時（`line 145`）、および `destroy()` 時（`lines 173–175`）にすべて `wipe_buffer()` される。

### 2.2 ゼロ化できない（メモリ上に残存する）Python `bytes` / C ヒープオブジェクト
以下の3箇所では、Python の不変オブジェクト（`bytes`）または OpenSSL 内部コンテキストの仕様により、**`wipe_buffer()` では物理メモリから消去できない平文鍵コピーがヒープ上に残存する**：
1. **`HKDF.derive()` および `hmac.digest()` の戻り値 (`bytes`)**:
   - `mk1_session_ratchet.py:76` の `derived = bytearray(hkdf.derive(bytes(chain_key)))` において、`bytes(chain_key)` で生成された一時 `bytes` オブジェクトと、`hkdf.derive(...)` が返す 64バイトの `bytes` オブジェクトは Python の immutable `bytes` であり、ガベージコレクタ（GC）に回収されるまで CPython ヒープ上に平文で残る。
2. **`AESGCM(bytes(key))` に渡される一時 `bytes` と OpenSSL `EVP_CIPHER_CTX`**:
   - `mk1_session_ratchet.py:113, 127, 156` の `AESGCM(bytes(key))` は、32バイトの鍵を再度 immutable `bytes` に変換して `cryptography` ライブラリへ渡し、さらに OpenSSL 内部で展開された AES ラウンド鍵スケジュール（`EVP_CIPHER_CTX`）を生成する。関数終了後に `key` (`bytearray`) を `wipe_buffer()` しても、`bytes(key)` と GC 未回収の `AESGCM` インスタンス内部の鍵は即座には消去されない。
3. **監査で発見した `_ACTIVE_RATCHETS` の2つの欠陥**:
   - **欠陥①（`destroy()` 時の登録解除漏れ）**: `mk1_session_ratchet.py:66` で `_ACTIVE_RATCHETS.append(self)` によりグローバルリストへ自身を登録しているが、`destroy()`（`lines 170–177`）内で `_ACTIVE_RATCHETS` から `self` を削除していないため、破棄済み `SessionRatchet` インスタンスへの参照がプロセス終了までリークし続ける。
   - **欠陥②（`set_memory_guard_enabled()` との未連携）**: `mk1_session_ratchet.py:180–187` に `purge_all_ratchets()` が定義されているが、`mk1_memory_guard.py` の `set_memory_guard_enabled(False)` はこれを呼び出していない。

---

## 3. PQC ハイブリッド鍵交換（ML-KEM / X25519）の実装不整合と検証状態（Section 4.2）

実コードを直接照合した結果、リポジトリ内の2つのモジュールで **使用している PQC アルゴリズムとハイブリッド構成が一致していない** 重大な設計不整合を確認した。

| 比較項目 | `mk1_hybrid_kem.py` (`lines 15–26`) | `mk1_secure_transport.py` (`lines 35–42`) | `mk1_tunnel.c` / `mk1_tunnel_oqs.c` |
|---|---|---|---|
| **KEM アルゴリズム** | **ML-KEM-1024** (`from pqcrypto.kem import ml_kem_1024`) | **ML-KEM-768** (`from pqcrypto.kem.ml_kem_768 import ...`) | **ML-KEM-768** (`OQS_KEM_alg_ml_kem_768`) |
| **古典 ECDH とのハイブリッド** | **あり（X25519 + ML-KEM-1024 + HKDF-SHA256）**<br>`SUITE_ID = b"MK1-HYBRID-ML-KEM-1024-X25519-WG-PSK-v1"` | **なし（ML-KEM-768 単体）** | **なし（ML-KEM-768 単体）** |
| **用途** | WireGuard PSK 導出用 | トランスポートセッション確立用 | C トンネルハンドシェイク用 |
| **実行検証ステータス** | **NOT_TESTED (`SKIPPED` 5/5)** | **NOT_TESTED (`pqcrypto` 不在)** | **NOT_TESTED (`liboqs` 未リンク)** |

- **監査結論**:
  - `mk1_secure_transport.py` は `mk1_hybrid_kem.py` を呼び出しておらず、独自の `ml_kem_768` 単体インポートを使用しているため、X25519 とのハイブリッド構成になっていない。
  - また、本コンテナ環境には `pqcrypto`、`cryptography`、`liboqs` のいずれもインストールされていないため、**ML-KEM-768、ML-KEM-1024、X25519、Python 側 AES-256-GCM の実暗号演算は一度もランタイム実行されていない（`NOT_TESTED`）**。

---

## 4. `mk1_quorum.py` / `mk1_key_registry.py`（Ed25519）の検証状態（Section 4.3）

- **修正確認（`TESTED`）**:
  - `mk1_quorum.py:13–26` にて `cryptography` の import を `try...except ImportError` で保護し、`_CRYPTOGRAPHY_AVAILABLE = False` の環境でもモジュールを安全に import できることを確認済み。
  - `_require_cryptography()`（`lines 29–35`）が `generate_operator_keypair()`（`line 151`）、`sign_approval()`（`line 237`）、`verify_quorum()`（`line 321`）の先頭で呼び出され、ライブラリ不在時に **Fail-Open（承認成功）にならず確実に `QuorumError` を送出して拒否する** ことを実測で確認済み。
- **未検証領域（`NOT_TESTED`）**:
  - 実 Ed25519 秘密鍵による署名生成・公開鍵検証・M-of-N 閾値合意・有効期限切れ拒否・リプレイ防止の各テスト（`tests/test_quorum.py` 4件、`tests/test_key_registry.py` 5件）は、`cryptography` 未導入のため **すべて `SKIPPED`（`NOT_TESTED`）** である。

---

## 5. AI 推論パイプラインのスタブ動作と実モデル推論の分離（Section 4.4）

- **スタブ環境で確認済みの動作（`TESTED`）**:
  - 本環境では `torch` が未導入であるため、`airgap_ai_defender.py` は `TORCH_AVAILABLE = False` となり `_TorchStub` で動作する。
  - `inspect_packet_pipeline()`（`lines 5861–5882`）に追加された `feature_vector` バリデーションにより、要素数 `< 3`、非数値、`NaN`/`Inf`、負数を含む破損ベクトルは、PyTorch の有無にかかわらず `block=True, stage="ai"` で **Fail-Closed 遮断** されることを `REG-08` で実測確認済み。
- **未検証および残存する構造的課題（`NOT_TESTED` / `GAP`）**:
  1. **実モデル推論は未検証（`NOT_TESTED`）**: 本物の PyTorch テンソル計算および学習済み重みファイルを用いた推論は一度も実行されていない。
  2. **AI 異常判定が遮断条件から除外されている（Advisory-Only ギャップ）**: `inspect_packet_pipeline()`（`line 5920`）の最終遮断式は `block = blacklisted or dpi_suspicious or zero_trust_violation` であり、AI が正常な特徴量ベクトルから未知の攻撃を検知して `ai_anomaly = True`（`anomaly_score >= threshold`）と判定しても、**DPI シグネチャと Zero-Trust に引っかからなければ `block = False` としてパケットを通過させてしまう**。
