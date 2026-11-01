# MK1AI_CRYPTO_ZEROIZATION_AUDIT — Cryptographic Key Zeroization & PQC Verification Audit

## 1. 監査の目的

`SessionRatchet.destroy()`（`mk1_session_ratchet.py`）および `mk1_secure_transport.py` / `mk1_memory_guard.py` による鍵消去処理について、**「完全ゼロ化」という主張が成立しない理由**を実コードに基づいて証明し、保証範囲を6つのレイヤーに厳密に分離して報告する。また、ML-KEM / X25519 / Ed25519 の実暗号テスト状況を明記する。

---

## 2. 鍵ゼロ化の保証範囲 6段階分離マトリクス

| 分離項目 | 監査結果（実コード上の挙動） | 保証の有無 |
|---|---|---|
| **① `destroy()` の呼び出し有無** | - `SessionRatchet.encrypt()` / `decrypt()` 内でエポック上限またはTTL超過時に `self._destroy_locked()` が呼ばれる（`mk1_session_ratchet.py:112, 116`）。<br>- `mk1_secure_transport.set_transport_enabled(False)` 呼び出し時に `_ACTIVE_RATCHETS` 内の全ラチェットに対して `ratchet.destroy()` が呼ばれる（`mk1_secure_transport.py:285–287`）。<br>- **【欠陥1】** 利用側が `ratchet.destroy()` を直接呼んだ場合、`mk1_secure_transport._ACTIVE_RATCHETS` リストから当該インスタンスが削除されない（参照リーク）。<br>- **【欠陥2】** `mk1_secure_transport.set_memory_guard_enabled()`（`lines 221–240`）は `_ACTIVE_ENVELOPES` のみを走査し、**`_ACTIVE_RATCHETS` を一切走査しない**ため、後からメモリガードを有効化/無効化しても既存ラチェットのバッファには反映されない。 | **条件付き（一部経路で漏れあり）** |
| **② 管理対象ミュータブルバッファ（`bytearray`）の上書き** | - `SessionRatchet._destroy_locked()`（`mk1_session_ratchet.py:172–177`）は、`self._send_chain`（`bytearray(32)`）および `self._receive_chain`（`bytearray(32)`）に対して `wipe_buffer()` → `mk1_memory_guard.c` の `explicit_bzero()`（C拡張未ロード時はPythonループでの `0x00` 代入）を実行し、バッファ長を `0` に縮小（`buffer[:] = b""`）する。<br>- `__init__()` 内の `secret_buf`、`encrypt()` / `decrypt()` 内の一時変数 `key`（`bytearray`）および `next_chain`（`bytearray`）も `finally` ブロックで `wipe_buffer()` される。 | **保証あり（`bytearray` のみ）** |
| **③ Python `bytes`（イミュータブルオブジェクト）の残存コピー** | - **【決定的な未ゼロ化経路1：HKDF導出時】**<br>`mk1_session_ratchet.py:81–96` において、`HKDF(...).derive(bytes(secret_buf))` はまず **`bytes(secret_buf)` でイミュータブルな32バイトの `bytes` コピーを生成**し、さらに `.derive(...)` の戻り値として **64バイトのイミュータブルな `bytes` オブジェクト（初期送信/受信チェーン鍵）を生成**する。その後 `bytearray(...)` にコピーされるが、元の `bytes` オブジェクト2個はPythonの仕様上 `wipe_buffer()` で上書きできず、GC回収後もCPythonのヒープ/フリーリスト上に平文のまま残存する。<br>- **【決定的な未ゼロ化経路2：ラチェット進行（HMAC）時】**<br>`_derive_step()`（`lines 33–40`）および `_derive_message_key()`（`lines 42–49`）において、`hmac.digest(bytes(chain_key), ...)` は：① 引数 `bytes(chain_key)` でイミュータブルな `bytes` コピーを生成し、② 戻り値として48バイトのイミュータブルな `bytes` ダイジェストを生成し、③ スライス `[:SESSION_KEY_BYTES]` でさらに32バイトのイミュータブルな `bytes` オブジェクトを生成する。これらはすべて **`wipe_buffer()` の対象外であり、毎メッセージ暗号化/復号のたびにヒープ上に平文鍵の複製が蓄積する**。 | **保証なし（平文コピーが残存）** |
| **④ 暗号ライブラリ（`cryptography` / OpenSSL）内部コピー** | - `mk1_session_ratchet.py:132, 161` の `AESGCM(bytes(key))` は、まず `bytes(key)` でPython `bytes` のコピーを作り、さらに `cryptography` ライブラリ経由でOpenSSLの `EVP_CIPHER_CTX`（Cヒープ領域）へ鍵を渡してAES-256ラウンド鍵スケジュール（240バイト）に展開する。<br>- Python側の `wipe_buffer(key)` はOpenSSL内部の `EVP_CIPHER_CTX` やPythonの `AESGCM` オブジェクト内部バッファを直接ゼロ化することはできない（OpenSSL側の `EVP_CIPHER_CTX_free` がGC時に呼ばれるまでメモリ上に残存する）。 | **保証なし（ライブラリ依存）** |
| **⑤ OS / プロセスメモリ残存（スワップ・コアダンプ・ページキャッシュ）** | - `mk1_memory_guard.lock_buffer()`（`mlock` + `MADV_DONTDUMP`）は、`mk1_memory_guard._ENABLED == True` のときのみ実行される（`mk1_memory_guard.py:190`: `if not _ENABLED or not buffer: return`）。デフォルトは `_ENABLED = False`（`line 29`）であるため、明示的に有効化しない限り `mlock` も `MADV_DONTDUMP` も**一切呼ばれない（No-op）**。<br>- さらに `_ENABLED == True` であっても、③のイミュータブル `bytes` が配置されるCPython汎用アリーナページや、`_derive_message_key()` の一時 `key`（`lock_buffer` 未呼び出し）は `mlock` されておらず、OSのスワップ領域やコアダンプに漏洩し得る。 | **保証なし（部分的なベストエフォート）** |
| **⑥ 実際に検証できた範囲（テスト証拠）** | - **検証済み（VERIFIED）**: `mk1_memory_guard.c`（C単体テスト `test_mk1_memory_guard`）および `tests/test_mk1_memory_guard.py` により、Cのガード付きページ確保（`mk1_alloc_guarded`）と `bytearray` に対する `explicit_bzero` の動作のみ確認済み。<br>- **未検証（`NOT TESTED`）**: 環境に `cryptography` パッケージが存在しないため、`SessionRatchet` 自体のテスト（`tests/test_session_ratchet.py` 全4件）および `mk1_secure_transport.py` の実暗号テスト（`tests/test_secure_transport.py` 全5件）は **1件も実行されていない（`NOT TESTED`）**。 | **`SessionRatchet` 実動作は `NOT TESTED`** |

---

## 3. 暗号プリミティブ（ML-KEM / X25519 / Ed25519）の検証ステータス監査

| 暗号コンポーネント | 対象ファイル | 実装内容と設計上の問題点 | 実暗号テストの実施状況 |
|---|---|---|---|
| **ML-KEM + X25519 ハイブリッドKEM** | `mk1_hybrid_kem.py`<br>`tests/test_hybrid_kem.py` | `ML-KEM-1024`（`pqcrypto`）と `X25519`（`cryptography`）の共有秘密を `HKDF-SHA384` で結合する実装。 | **`NOT TESTED`**<br>`pqcrypto` および `cryptography` 未導入のため、鍵生成・カプセル化・デカプセル化・改ざん検知の全6テストが未実行。 |
| **セキュアトランスポート暗号化** | `mk1_secure_transport.py`<br>`tests/test_secure_transport.py` | **【設計不整合】** `mk1_hybrid_kem.py`（ML-KEM-1024 + X25519）を使用せず、`pqcrypto.kem.ml_kem_768`（**ML-KEM-768単独、X25519ハイブリッドなし**）を直接呼び出している（`line 35`）。 | **`NOT TESTED`**<br>`pqcrypto` および `cryptography` 未導入のため、実暗号ラウンドトリップテストはすべて未実行（`tests/test_airgap_ai_defender.py` 内の関連4テストも `SKIPPED`）。 |
| **Ed25519 クォーラム署名・鍵レジストリ** | `mk1_quorum.py`<br>`mk1_key_registry.py`<br>`mk1_external_verifier.py` | `_CRYPTOGRAPHY_AVAILABLE == False` のときに `QuorumVerificationError` を送出するFail-Closedガードは実装済み（`mk1_quorum.py:228`）。 | **`NOT TESTED`**<br>`cryptography` 未導入のため、実際のEd25519秘密鍵による署名生成、公開鍵による署名検証、不正署名の拒否、失効鍵の拒否は **すべて未実行（`NOT TESTED`）**。 |

---

## 4. 結論

1. `SessionRatchet.destroy()` は管理対象の `bytearray`（`_send_chain`, `_receive_chain`）をゼロ化するが、CPythonヒープ上のイミュータブル `bytes`（`HKDF.derive`, `hmac.digest` の引数・戻り値・スライス）およびOpenSSL内部の鍵スケジュールを消去できないため、**「完全ゼロ化」とは呼べない**。
2. `SessionRatchet`、ML-KEM、X25519、Ed25519 の実暗号処理は、本監査環境に暗号ライブラリ（`cryptography`, `pqcrypto`）が存在しないため、すべて **`NOT TESTED`（実暗号テスト未実施）** である。
