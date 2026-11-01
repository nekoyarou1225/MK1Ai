# MK1AI_QKD_ARCHITECTURE — Sovereign-Airgap QKD System & Boundary Architecture

> **実装・検証ステータス明示**:
> - 本ドキュメントに記載するQKDアーキテクチャは **設計のみ完了（`DESIGN ONLY`）** であり、現行リポジトリへのコード実装は **未実装（`NOT IMPLEMENTED`）**、実QKD装置は **機材待ち（`HARDWARE MISSING`）**、実通信検証は **未検証（`NOT TESTED`）** である。

---

## 1. アーキテクチャ設計の基本原則

1. **暗号レイヤーの厳格な分離**:
   - **QKD層**: 物理量子チャネル＋認証済み古典チャネルにより、対向拠点のKME（Key Management Entity）間で情報理論的安全性を有する対称鍵素材（`QKD_RAW_KEY`）と128ビット鍵ID（`KSID` / `key_ID`）を共有する。
   - **PQC / ハイブリッドKEM層**: `ML-KEM-768`（または `ML-KEM-1024`）と古典ECDH `X25519` により、計算量的安全性に基づく共有秘密（`PQC_HYBRID_SECRET`）を確立する。
   - **KDF（鍵合成・導出）層**: QKD鍵素材とPQCハイブリッド共有秘密を、NIST SP 800-56C Rev. 2 / FIPS 203 準拠のドメイン分離付き2段階 `HKDF-SHA384` で結合し、用途別のKEK（Key Encryption Key）またはセッション初期シードを導出する（独自XORや単純連結は禁止）。
   - **SessionRatchet / AEAD層**: 導出されたシードから `SessionRatchet` でメッセージ毎のDEK（Data Encryption Key）を導出し、`AES-256-GCM` でペイロードを認証付き暗号化する。
2. **本丸（Honmaru）のエアギャップ保護と8環境（Outer-1〜4 / Inner-1〜4）との完全分離**:
   - QKDファイバーを接続することは「物理的な有線光学接続」を設けることであり、完全な物理エアギャップ（無配線）とは異なる。したがって、本丸の物理エアギャップを維持したままQKD鍵を活用するための3つの境界方式（方式A・方式B・方式C）を定義し、管理者の明示的承認なしに本丸のネットワーク・配線構成を変更することを禁止する。

---

## 2. QKDサブシステム 8モジュール構成（Section 2）

MK1AiのQKD機能は、既存コードと疎結合かつFail-Closedに動作する以下の8モジュール（新規パッケージ案 `mk1_qkd/`）として設計する。

```text
+-----------------------------------------------------------------------------------+
|                              MK1Ai Application Layer                              |
|   One-Tap Encryption Engine  |  MK1Ai Secure Transport (mk1_secure_transport.py)  |
+------------------------------+----------------------------------------------------+
                               | (7) MK1Ai Secure Transport Integration
                               v
+-----------------------------------------------------------------------------------+
|                        MK1Ai QKD Subsystem (mk1_qkd/*)                            |
|                                                                                   |
|  +------------------------+   +------------------------+   +-------------------+  |
|  | (6) QKD Policy         |   | (5) QKD Session        |   | (8) Audit &       |  |
|  |     Controller         |<->|     Manager            |-->|     Monitoring    |  |
|  | (Mode: Mandatory/Hyb)  |   | (KSID sync, Epoch/TTL) |   | (Hash-chained log)|  |
|  +-----------+------------+   +-----------+------------+   +---------+---------+  |
|              |                            |                          ^            |
|              v                            v                          |            |
|  +------------------------+   +------------------------+             |            |
|  | (4) QKD Key Registry   |<--| (3) QKD Key Validation |-------------+            |
|  | (Environment Scope,    |   | (Entropy, Zero-check,  |                          |
|  |  One-time consume, Rev)|   |  Auth tag, KSID match) |                          |
|  +------------------------+   +-----------+------------+                          |
|                                           ^                                       |
|                                           |                                       |
|                               +-----------+------------+                          |
|                               | (2) QKD Key Management |                          |
|                               |     Interface (KMI)    |                          |
|                               | (ETSI GS QKD 014/004)  |                          |
|                               +-----------+------------+                          |
|                                           ^                                       |
|                                           |                                       |
|                               +-----------+------------+                          |
|                               | (1) QKD Device Adapter |                          |
|                               | (Vendor Driver Abstract|                          |
|                               |  Toshiba/IDQ/Quintess.)|                          |
|                               +-----------+------------+                          |
+-------------------------------------------|---------------------------------------+
                                            | Local Point-to-Point mTLS (ETSI 014)
                                            v (Loopback / Dedicated KMS NIC)
+-----------------------------------------------------------------------------------+
|                    External Hardware: QKD Key Manager (KME / KMS)                 |
|                                           |                                       |
|                    External Hardware: QKD Transceiver (Alice / Bob)               |
+-------------------------------------------|---------------------------------------+
                                            |
                  ==========================+==========================
                  || (a) Quantum Channel (Dark Fiber: Single Photons)||
                  || (b) Authenticated Classical Channel (Sifting/EC)||
                  ==========================+==========================
                                            |
                                            v
                                  Remote Peer QKD Node
```

### 各モジュールの責務定義

| # | モジュール名 | 予定ファイルパス（設計案） | 主な責務とセキュリティ境界 |
|---|---|---|---|
| 1 | **QKD Device Adapter** | `mk1_qkd/device_adapter.py` | ベンダー固有のKME/QKD装置API（ID Quantique Clarion KX、東芝デジタルソリューションズ QKD KMS、QuintessenceLabs 等）およびシミュレータ（ETSI 014テストスタブ）の差異を吸収する抽象化ドライバ層。実機とシミュレータのフラグ（`is_simulated: bool`）をハードウェア証明書チェーンで強制判定する。 |
| 2 | **QKD Key Management Interface (KMI)** | `mk1_qkd/kmi_etsi.py` | **ETSI GS QKD 014 v1.1.1**（REST/HTTPS + 相互TLS認証）を第一標準、**ETSI GS QKD 004 v2.1.1**（セッション型ソケットAPI）を低遅延オプションとして実装するクライアント層。`Get_status`, `Get_key`, `Get_key_with_key_IDs` を提供する。 |
| 3 | **QKD Key Validation** | `mk1_qkd/key_validation.py` | KMEから取得した鍵素材（`bytearray`）に対し、①鍵長一致（256bit = 32B）、②全ゼロ・全1・周期パターンの拒否、③シャノンエントロピーおよびNIST SP 800-90B相当の簡易連続性検査、④KME応答のmTLSピア証明書ピン留め検証とタイムスタンプ新鮮性検証を実施する。 |
| 4 | **QKD Key Registry** | `mk1_qkd/key_registry.py` | 取得済みQKD鍵のメタデータ（`key_id` [UUIDv4 128bit]、取得時刻、有効期限TTL、所属環境スコープ［`HONMARU` / `INNER_1..4` / `OUTER_1..4`］、許可用途、消費状態 `CONSUMED` / `REVOKED`）を管理する。**同一 `key_id` の再利用（二重消費）をハードウェア/DBレベルで禁止（One-Time Use Enforcement）** する。 |
| 5 | **QKD Session Manager** | `mk1_qkd/session_manager.py` | 対向ノードとの間で `key_id`（秘密鍵そのものではなくUUID識別子のみ）を通知・同期し、双方が自身のローカルKMEから同一 `key_id` の鍵素材を引き当て、後段のハイブリッドKDFへ供給する。 |
| 6 | **QKD Policy Controller** | `mk1_qkd/policy_controller.py` | 暗号動作モード（`QKD_MANDATORY` / `HYBRID_QKD_PQC` / `PQC_ONLY`）と状態遷移（9状態）を管理する。**QKD障害時に管理者クォーラム承認（`mk1_quorum.py`）なしで自動的に `PQC_ONLY` 等へフォールバック（ダウングレード）することを厳格に阻止（Fail-Closed）** する。 |
| 7 | **MK1Ai Secure Transport Integration** | `mk1_qkd/transport_bridge.py` | `mk1_secure_transport.py` およびワンタップ暗号化エンジンに対し、QKD+PQCハイブリッドKEK（Key Encryption Key）を供給し、`SessionRatchet` の初期シードまたはファイル暗号化DEKのラッピングを行う。 |
| 8 | **Audit and Monitoring** | `mk1_qkd/audit_monitor.py` | QKD状態遷移、使用された `key_id`（鍵ビット列は絶対に出力しない）、KMEエラー、認証失敗、QBER警報、フォールバック拒否イベントをハッシュチェーン付き監査ログに記録する。 |

---

## 3. QKD状態管理（9状態の厳密定義と遷移規則 — Section 2.4）

QKDの状態は以下の9つの列挙値（`QKDState`）で管理し、**`QKD_SIMULATED` を `QKD_READY` としてUIやログに表示することをコードレベルで禁止**する。

| 状態名 (`QKDState`) | 定義・成立条件 | 鍵取得・暗号化処理の可否 | UI表示ラベル・警告色 |
|---|---|---|---|
| `QKD_UNAVAILABLE` | QKD装置/KMEが未設定、未接続、またはドライバ未導入（**現在のMK1Aiのデフォルト状態**）。 | **不可**（QKD必須モードでは通信・暗号化を即拒否） | `QKD未接続 / 利用不可`（グレー/赤） |
| `QKD_SIMULATED` | 開発・結合テスト用のソフトウェアKMEシミュレータに接続中。物理的な量子安全性は一切ない。 | **テスト環境のみ可**（本番プロファイルでは拒否、`QKD_READY` への昇格禁止） | **`QKDシミュレーション中（実量子保護なし）`**（黄/警告） |
| `QKD_CONNECTING` | KMEとのmTLSハンドシェイク、相互認証、`Get_status` による初期ヘルスチェックを実行中。 | **不可**（待機またはタイムアウト失敗） | `QKD装置接続・認証中...`（青） |
| `QKD_READY` | 実機QKD KMEとの相互認証が完了し、量子チャネルQBERが閾値未満、かつ十分な鍵プール残量が確認された正常状態。 | **可**（実QKD鍵の取得・消費が可能） | `QKD正常稼働 (READY)`（緑） |
| `QKD_DEGRADED` | KMEは稼働し残存プール鍵はあるが、量子チャネルのQBER上昇・光減衰・一時的同期遅延により新規鍵生成レートが低下している状態。 | **制限付き可**（高優先度通信・緊急暗号化のみ許可、早期ローテーション警報） | `QKD品質低下 (DEGRADED)`（橙） |
| `QKD_KEY_EXHAUSTED` | KME内の利用可能な鍵プールが枯渇（残量0または要求サイズ未満）し、新規鍵供給が追いつかない状態。 | **不可**（鍵再利用は絶対禁止のためFail-Closedで拒否） | `QKD鍵プール枯渇 (EXHAUSTED)`（赤） |
| `QKD_AUTH_FAILED` | KMEとのmTLSクライアント/サーバー証明書検証失敗、古典チャネル認証エラー、またはSAE ID不一致を検知した状態。 | **不可**（即時セッション遮断・監査アラート発報） | `QKD認証失敗 (AUTH_FAILED)`（赤・点滅） |
| `QKD_REVOKED` | 署名付き失効マニフェスト（`RevocationManifest`）または緊急操作により、対向SAE・KME証明書・特定エポックのQKD鍵群が失効された状態。 | **不可**（該当鍵での復号・新規暗号化を即時拒否、メモリ上の鍵を破棄） | `QKD鍵/装置失効 (REVOKED)`（赤） |
| `QKD_ERROR` | KMEプロトコル違反、鍵検証（エントロピー/長さいずれか）失敗、ハードウェア故障、内部例外が発生した状態。 | **不可**（Fail-Closedで拒否） | `QKDシステム異常 (ERROR)`（赤） |

### 状態遷移図（Fail-Closed保証）

```text
[QKD_UNAVAILABLE] --(Simulator Config)--> [QKD_SIMULATED] (※絶対に QKD_READY へ遷移しない)
       |
  (Hardware Config)
       v
[QKD_CONNECTING] --(mTLS/Cert/SAE Auth Fail)--> [QKD_AUTH_FAILED]
       |
  (mTLS OK + Hardware KME Attested + Pool > Min)
       v
  [QKD_READY] <-----(QBER Normalized)-----> [QKD_DEGRADED]
       |                                          |
       +---(Key Pool == 0)------------------------+---> [QKD_KEY_EXHAUSTED]
       |
       +---(Manifest Revocation / Tamper Alert)-------> [QKD_REVOKED]
       |
       +---(Validation Error / KME Fault / Timeout)---> [QKD_ERROR]
```

---

## 4. 本丸（Honmaru）のエアギャップとQKD導入方式の比較評価（Section 3）

### 4.1 物理エアギャップ・論理隔離・専用光通信路の厳密な区別

- **物理エアギャップ（Physical Air-Gap）**: 本丸の筐体から外部へ向かう有線ケーブル（Ethernet, 光ファイバー, USB, シリアル等）および無線モジュールが**物理的に一切接続されていない状態**。
- **専用光通信路による接続（Dedicated Optical Link）**: QKD用のダークファイバー（量子チャネル）およびKME間制御線（古典チャネル）を接続した状態。IPインターネットからは隔離されているが、**物理的な配線が存在するため「完全な物理エアギャップ」ではない**（光トランシーバのファームウェア脆弱性や古典チャネル経由の攻撃面が発生する）。
- **論理隔離（Logical Isolation）**: `nftables`（`mk1_firewall.py`）、Network Namespace（`mk1_quarantine.py`）、VLAN、または `ip link set down` によってソフトウェア的に通信を遮断した状態。

### 4.2 本丸へのQKD導入 3方式（A / B / C）の比較マトリクス

| 比較項目 | **方式A：本丸専用の量子通信路＋認証済み古典通信路を直接設ける方式** | **方式B：外部QKD装置側で鍵を取得し、承認済みの安全な移送手段で本丸へ渡す方式（推奨）** | **方式C：外部の安全境界（DMZ/Inner境界）でQKD鍵管理を行い、本丸へは限定された鍵素材だけを単方向移送する方式** |
|---|---|---|---|
| **概要** | 本丸の部屋・ラック内にQKD送受信機（Alice）とKMEを設置し、外部拠点（Bob）とダークファイバー＋古典チャネルで直結する。 | 本丸は**完全な物理エアギャップ（配線ゼロ）を維持**。別室のQKD境界ノードでKMEから鍵を取得し、M-of-Nクォーラム署名付きの専用耐タンパーHSMトークン（またはQR/光学読み取り等の非ネットワーク媒体）で本丸へ鍵を搬入する。 | QKD装置とKMEを外部境界ゲートウェイに配置し、用途制限・TTL制限を施した派生鍵（KEK）のみをハードウェア単方向データダイオード（光カプラ）または厳格検証ゲート経由で本丸へ注入する。 |
| **物理的な接続とエアギャップ維持** | **× 物理エアギャップは維持されない**（量子ファイバー＋古典通信ファイバーが本丸へ引き込まれる）。 | **◎ 完全な物理エアギャップが維持される**（本丸への通信ケーブル引き込みゼロ）。 | **△ 条件付き**（ハードウェア単方向光データダイオードを用いる場合のみ本丸からの漏洩経路を物理遮断可能だが、受信側の光配線は存在する）。 |
| **通信経路** | 本丸 ⇄ ローカルKME ⇄（光ファイバー）⇄ 対向KME | QKD境界ノード ⇄ ローカルKME（ここまで通信あり） ／ 境界ノード →（物理移送＋クォーラム検証）→ 本丸（通信なし） | 対向KME ⇄ 境界KME →（単方向ダイオード / 境界フィルタ）→ 本丸 |
| **鍵素材の移送方法** | ETSI 014 mTLS APIによるリアルタイム取得 | 移送用ラップ鍵（SLIP-39 / PQC + 管理者パスフレーズ）で暗号化・Ed25519/ML-DSAクォーラム署名した鍵バッチをオフライン搬入 | 境界KMEで用途バインド派生（`HKDF-SHA384`）した短命KEKのみを単方向フレームで注入 |
| **管理権限と承認** | 本丸のネットワーク/PCIe/NIC構成変更を伴うため、**最高レベルの管理者クォーラム承認＋物理配線監査が必須** | 本丸のネットワーク構成変更なし。鍵搬入時に2名以上のオペレータ承認（`mk1_quorum.py`）を実施 | 境界ゲートウェイのポリシー管理権限と本丸の受信検証権限を分離 |
| **攻撃面（Attack Surface）** | **大**：QKD装置の古典チャネルTCP/IPスタック、KMEのREST API、光トランシーバのファームウェアが本丸に直接接続されるため、KME侵害時に本丸が直接攻撃される。 | **極小**：本丸にはネットワーク攻撃面が一切増えない。移送媒体のマルウェア混入リスクは、USB HID拒絶（`mk1_usb_guard.py`）＋隔離QEMUスキャン＋厳格な固定長スキーマ署名検証で封じ込める。 | **中**：境界ゲートウェイが侵害された場合、不正な鍵IDやDoSフレームが単方向リンク経由で本丸へ送り込まれるリスクがある。 |
| **障害時・侵害時の復旧方法** | 物理ファイバーの抜線＋ローカルKMEの電源遮断＋本丸の全セッション鍵パージ | 移送トークンの失効（`RevocationManifest` 更新）のみ。本丸の隔離状態は無傷で維持される。 | 単方向リンクのシャットダウン＋境界KMEの切り離し＋該当エポック鍵の一括失効 |

### 4.3 本丸エアギャップ整合性の設計結論

1. **デフォルト推奨構成は「方式B（オフライン承認移送方式）」または「方式C（単方向ダイオード＋境界分離方式）」とする。**
2. **方式A（本丸へのQKD直接接続）は、物理エアギャップを解消して「専用光閉域網接続」へ変更する行為であるため、ユーザーの明示的な設計変更承認なしに採用・構成してはならない。**
3. いずれの方式においても、**本丸のネットワーク設定（`nftables`, NIC状態, ルーティング）を自動変更することは禁止**し、すべての鍵導入はクォーラム署名検証（`mk1_quorum.py`）を通過した場合にのみ有効化される設計とする。
