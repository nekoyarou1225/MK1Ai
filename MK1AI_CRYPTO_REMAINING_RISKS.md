# MK1AI_CRYPTO_REMAINING_RISKS — Cryptographic, QKD & Key Management Residual Risk Assessment

## 1. 監査方針

本報告書では、MK1Aiの暗号サブシステム（既存PQC・古典暗号・`SessionRatchet`・メモリガード、および新規設計したQKD連携・ワンタップ暗号化・9環境鍵分離）における **すべての未実装事項（`NOT IMPLEMENTED`）、未検証事項（`NOT TESTED`）、ハードウェア不在（`HARDWARE MISSING`）、およびアーキテクチャ上の残存リスク** を隠さず明記する。

---

## 2. 暗号・QKD・ワンタップ暗号化に関する残存リスク一覧（全10項目）

| # | リスク領域 | 現在のステータス | 深刻度 | 残存リスクの技術的詳細と限界 |
|---|---|---|---|---|
| 1 | **QKDモジュールおよび実機ハードウェアの不在** | **`NOT IMPLEMENTED`**<br>**`HARDWARE MISSING`**<br>**`NOT TESTED`** | **CRITICAL** | 現行コードベースにはQKD関連コードは1行も存在せず、QKD光学送受信機およびKME（Key Management Entity）も存在しない。したがって現時点では量子鍵配送による情報理論的安全性は一切提供されていない。 |
| 2 | **ワンタップ暗号化・復号エンジンの未実装** | **`NOT IMPLEMENTED`**<br>**`NOT TESTED`** | **HIGH** | テキスト・メッセージ・ファイル・バックアップ・エクスポートデータ向けのワンタップエンベロープ暗号化モジュールおよび8項目のUI表示は設計のみ完了（`DESIGN ONLY`）しており、実コードはまだ実装されていない。 |
| 3 | **Python実暗号プリミティブのランタイム未検証** | **コードあり / `NOT TESTED`** | **HIGH** | 本監査環境に `cryptography`, `pqcrypto`, `argon2-cffi`, `shamir-mnemonic`, `liboqs` が導入されていないため、`ML-KEM-768`, `ML-KEM-1024`, `X25519`, `Ed25519`, Python `AESGCM`, `HKDF`, `Argon2id`, `SLIP-39` の実暗号演算テストは一度も実行されていない。関数呼び出しモックやImportError時のFail-Closedガード確認を、実暗号の検証成功とみなしてはならない。 |
| 4 | **`mk1_secure_transport.py` と `mk1_hybrid_kem.py` のアルゴリズム分裂** | **コード不整合残存** | **HIGH** | `mk1_hybrid_kem.py` は `ML-KEM-1024 + X25519 + HKDF-SHA384` を実装しているが、`mk1_secure_transport.py`（および `mk1_tunnel.c`）は `ML-KEM-768` 単体（X25519ハイブリッドなし、`HKDF-SHA256`）を使用しており、両者が統合されていない。 |
| 5 | **デジタル署名におけるPQC署名（`ML-DSA` / `SLH-DSA`）の未実装** | **`NOT IMPLEMENTED`** | **HIGH** | クォーラム承認（`mk1_quorum.py`）、鍵失効マニフェスト（`mk1_key_registry.py`）、外部検証（`mk1_external_verifier.py`）の署名はすべて古典暗号の **`Ed25519` のみ** である。`Ed25519` は量子計算機（Shorのアルゴリズム）に対して脆弱であるため、将来的な耐量子安全性には `ML-DSA-87 + Ed25519` 等のハイブリッド署名への移行が不可欠である。 |
| 6 | **Python不変 `bytes` とOpenSSL内部コンテキストによる鍵メモリ残存** | **言語・ランタイム上の構造的限界** | **HIGH** | `SessionRatchet.destroy()` や `wipe_buffer()` はミュータブルな `bytearray` を `explicit_bzero` で消去するが、`HKDF.derive()`、`hmac.digest()`、スライス演算、`AESGCM(bytes(key))` が生成する **Pythonの不変 `bytes` オブジェクト**、および **OpenSSL `EVP_CIPHER_CTX` 内のAESラウンド鍵コピー** はPythonからは消去できない。したがって、プロセスメモリダンプやコールドブート攻撃に対する「完全な物理ゼロ化」は保証されない（完全なゼロ化には鍵導出・ラチェット・AEADの全体をC拡張 `mk1_tunnel.c` 側へ閉じ込め、Pythonヒープに秘密鍵を一切渡さない設計変更が必要）。 |
| 7 | **`_ACTIVE_RATCHETS` の参照リークと `set_memory_guard_enabled()` の走査漏れ** | **軽微な実装バグ残存** | **MEDIUM** | `mk1_secure_transport.py` において、`set_transport_enabled(False)` は `_ACTIVE_RATCHETS` を破棄するが、個別の `ratchet.destroy()` 直接呼び出し時には `_ACTIVE_RATCHETS` からインスタンスが除去されない。また `set_memory_guard_enabled()`（`lines 221–240`）は `_ACTIVE_ENVELOPES` のみを走査し、`_ACTIVE_RATCHETS` を走査していない。 |
| 8 | **本丸＋8環境（Outer-1〜4 / Inner-1〜4）のゾーン鍵分離の未実装** | **`DESIGN ONLY` / `NOT IMPLEMENTED`** | **HIGH** | 現行の `mk1_key_registry.py` は `device_id` と `purpose` のみを分離軸としており、`zone_id`（`HONMARU`, `INNER_1..4`, `OUTER_1..4`）による暗号学的分離およびゾーン間インポート拒否ガードはまだコード化されていない。 |
| 9 | **QKD導入時におけるTrusted Node（KME）侵害および物理サイドチャネルリスク** | **QKD固有の物理・運用限界** | **MEDIUM** | QKDはファイバー上の量子チャネル盗聴を検知できるが、**両端のQKD送受信機内部やKME（Key Management Entity）自体のOS/ファームウェア侵害、光検出器へのトロイの木馬光子注入攻撃（Blinding Attack）、およびエンドポイント侵害（`T.HW_COMPROMISE`）は防げない**。そのため、QKD単独に依存せず、必ずPQC（`ML-KEM`）＋古典暗号（`X25519`）＋本丸ユーザーパスフレーズ（`Argon2id`）との多要素ハイブリッド構成としなければならない。 |
| 10 | **トラフィックメタデータ（通信タイミング・サイズ・宛先）の非秘匿性** | **プロトコル上の構造的限界** | **LOW / INFO** | `docs/ST.md`（`line 67, 100`）に明記されている通り、QKDやPQC+AES-256-GCMでペイロードを暗号化しても、パケットのサイズ・送受信タイミング・フロー量はネットワーク上で観測可能である。本丸の完全な秘匿には方式B（物理エアギャップ維持＋オフライン承認移送）またはトラフィックパディングが必要である。 |

---

## 3. 実装済み・設計済み・未実装・未検証の最終総括表（Section 10 完了条件）

最後に、本プロジェクトにおける暗号・QKD・ワンタップ暗号化関連の全機能を **「①実装済み（検証済み）」「②実装済み（実暗号未検証 `NOT TESTED`）」「③設計済み（`DESIGN ONLY` / 未実装）」「④未実装・機材待ち（`NOT IMPLEMENTED` / `HARDWARE MISSING`）」** の4区分に厳密に分類して報告する。

| 機能カテゴリ | コンポーネント / 機能項目 | 現在の正確な区分 | 詳細根拠 |
|---|---|---|---|
| **メモリゼロ化 (C / Python `bytearray`)** | `mk1_memory_guard.c` (`explicit_bzero`, `mlock`, `MADV_DONTDUMP`) + `mk1_memory_guard.py` (`wipe_buffer`) | **① 実装済み・単体検証済み (`TESTED`)** | `mk1_test_runner`（C 3/3 PASS）および `tests/test_mk1_memory_guard.py` で動作確認済み。ただしPython不変 `bytes` とOpenSSL内部鍵はゼロ化対象外。 |
| **C言語トンネル AEAD** | `mk1_tunnel.c` (`AES-256-GCM` OpenSSL EVP + `HKDF-SHA256` + `OPENSSL_cleanse`) | **① 実装済み・単体検証済み (`TESTED`)** | `mk1_test_runner` でAES-256-GCM暗号化・復号・改ざん拒否・鍵消去を確認済み（`liboqs` 連携部分は未リンクのため `NOT TESTED`）。 |
| **Quorum Fail-Closed ガード** | `mk1_quorum.py` (`_CRYPTOGRAPHY_AVAILABLE == False` 時の承認拒否ガード) | **① 実装済み・単体検証済み (`TESTED`)** | 暗号ライブラリ不在時に例外 `QuorumError` で確実にFail-Closedとなることを単体テストで確認済み。 |
| **PQC KEM (Python)** | `mk1_secure_transport.py` (`ML-KEM-768` 単体) / `mk1_hybrid_kem.py` (`ML-KEM-1024 + X25519`) | **② コード実装済み・実暗号未検証 (`NOT TESTED`)** | ソースコードは存在するが、`pqcrypto` / `cryptography` 未導入のため実カプセル化は未実行。また両モジュールの統合が未完了。 |
| **SessionRatchet** | `mk1_session_ratchet.py` (`HKDF-SHA384` + `HMAC-SHA384` + `AES-256-GCM` 順序検証ラチェット) | **② コード実装済み・実暗号未検証 (`NOT TESTED`)** | コード実装および `set_transport_enabled(False)` 時の `destroy()` 呼び出し配線は完了しているが、`cryptography` 未導入のため実暗号導出は未実行。 |
| **Ed25519 署名・鍵導出・秘密分散** | `mk1_quorum.py`, `mk1_key_registry.py`, `mk1_external_verifier.py`, `mk1_key_derivation.py` (`Argon2id`), `mk1_key_backup.py` (`SLIP-39`) | **② コード実装済み・実暗号未検証 (`NOT TESTED`)** | ソースコードは存在するが、`cryptography`, `argon2-cffi`, `shamir-mnemonic` 未導入のため実暗号テストは未実行。 |
| **QKD 8モジュール・9状態管理・ETSI 014連携** | `QKD Device Adapter`, `ETSI 014/004 KMI`, `Key Validation`, `Key Registry`, `Session Manager`, `Policy Controller`, `Transport Bridge`, `Audit Monitor` | **③ 設計済み (`DESIGN ONLY`) / 未実装 (`NOT IMPLEMENTED`)** | `MK1AI_QKD_ARCHITECTURE.md` および `MK1AI_QKD_DEVICE_REQUIREMENTS.md` にて詳細設計完了。リポジトリ内の実装コードは0行。 |
| **本丸エアギャップ整合（方式A/B/C）と9環境鍵分離** | `HONMARU` / `INNER_1..4` / `OUTER_1..4` のゾーン別鍵分離・自動転送禁止・オフライン承認移送（方式B/C） | **③ 設計済み (`DESIGN ONLY`) / 未実装 (`NOT IMPLEMENTED`)** | `MK1AI_QKD_ARCHITECTURE.md` および `MK1AI_QKD_KEY_MANAGEMENT.md` にて詳細設計完了。コードへの `zone_id` 組み込みは未実装。 |
| **QKD + PQC + X25519 ハイブリッド鍵合成** | `MK1-SUITE-TRIPLE-QKD-PQC-v1` (`HKDF-SHA384` トランスクリプト束縛合成) ＋ サイレントフォールバック禁止ポリシー | **③ 設計済み (`DESIGN ONLY`) / 未実装 (`NOT IMPLEMENTED`)** | `MK1AI_PQC_HYBRID_DESIGN.md` にて数理仕様と承認ゲートを設計完了。コード実装は未着手。 |
| **ワンタップ暗号化・復号機能** | 5種別（テキスト/メッセージ/ファイル/バックアップ/エクスポート）の `AES-256-GCM` エンベロープ暗号化と8項目UI | **③ 設計済み (`DESIGN ONLY`) / 未実装 (`NOT IMPLEMENTED`)** | `MK1AI_ONE_TAP_ENCRYPTION_DESIGN.md` にてフォーマット・検証ステップ・UI仕様を設計完了。コード実装は未着手。 |
| **実機QKD通信・PQC署名 (`ML-DSA` / `SLH-DSA`)** | QKD光学送受信機（Alice/Bob）・ダークファイバー・実機KME接続、および `ML-DSA-87` / `SLH-DSA` 署名実装 | **④ 未実装・機材待ち (`NOT IMPLEMENTED` / `HARDWARE MISSING` / `NOT TESTED`)** | 実機ハードウェアおよびPQC署名ライブラリが未導入であり、現在のステータスは `QKD_UNAVAILABLE` である。 |
