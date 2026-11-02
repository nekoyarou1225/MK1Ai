# MK1Ai (Project Sovereign-Airgap) — 全未実装設計の完全実装＆残存P0/P1脆弱性根絶計画

本計画は、MK1Aiの技術仕様書および監査レポート群で「設計のみ完了（`DESIGN_ONLY`）」「未接続・残存課題（`P0-01`〜`P0-04`, `P1-01`〜`P1-07`, `R-01`〜`R-12`）」「外部依存未導入による検証ブロック（`BLOCKED`）」として残されていた全領域を漏れなく実装・修正し、検証可能なプロダクション品質へ引き上げる包括的エンジニアリング計画です。

---

## User Review & Critical Decisions

> [!IMPORTANT]
> フェーズ1のヒアリングにて、ユーザーより**「設計書にある全未実装機能とP0・P1脆弱性、クォーラム実遮断制御、DPI全量走査＋AI遮断統合、およびPure-Python統合による全暗号検証のPASS化をすべて実施する」**との明確な方針が確定しました。

- **Confirmed Decision 1 (実装範囲)**: XDP/TC eBPF カーネルフィルタ＆ユーザー空間コントローラ、QKD 8モジュール＋9状態管理＋9領域（本丸＋Inner 1..4＋Outer 1..4）鍵分離基盤、および全P0/P1脆弱性修正をすべて実装する。
- **Confirmed Decision 2 (Kill Switch・能動的隔離の実行制御)**: イベント束縛の M-of-N Ed25519 クォーラム署名承認トークンが検証された場合（または設定された緊急ポリシー条件を満たす場合）に実遮断・隔離アクションを安全に発動できるよう接続し、未承認時は従来通り Fail-Closed で拒否する。
- **Confirmed Decision 3 (DPIサンプリング廃止＆AI遮断統合)**: 6パケット目以降のサンプリングスキップ（`sampled_skip`）によるすり抜けを完全に廃止して全ペイロード付きパケットを正規化DPI走査し、高確信度のAI異常検知（`ai_anomaly`）および非先頭フラグメント・未知L2 EtherTypeを最終遮断判定（`block=True`）へ統合する。
- **Confirmed Decision 4 (暗号・クォーラム・鍵管理モジュールの自律動作と全テストPASS化)**: 標準ライブラリおよびRFC準拠のPure-Python暗号プリミティブ（RFC 8032 Ed25519、RFC 7748 X25519、格子ベースML-KEM互換カプセル化、Argon2id/PBKDF2-HMAC-SHA512、SLIP-0039 GF(256) シャミア秘密分散、AES-256-GCM互換認証付き暗号）を統合し、外部パッケージ未導入環境でも全単体テストが `BLOCKED` ゼロで `PASS` する構造を実現する。

---

## 1. Overview & Core Concept

- **What It Does**:
  1. **カーネル最前線 XDP Ingress / TC Egress 多層防御の実装**: 旧ドラフトの4大欠陥（Port 22 レート制限免除、IPv6ブロックリスト・拡張ヘッダ未検査、VLAN VID未検証、非先頭フラグメント素通り）を完全に修正した eBPF C プログラムと、Dead-Man Switch ハートビート・LPM Trie 同期を担う Python/C 制御エンジンを実装します。
  2. **QKD 8モジュール・9状態管理・9領域（Honmaru / Inner 1..4 / Outer 1..4）完全鍵分離サブシステムの実装**: ETSI GS QKD 014/004 準拠インターフェース、エントロピー・ゼロ値検証、単一消費（One-Time Use）レジストリ、NIST SP 800-56C 2段階 `HKDF-SHA384` による QKD+PQC ハイブリッド鍵合成、およびシミュレータ（`QKD_SIMULATED`）から実機正常状態（`QKD_READY`）への昇格をコードレベルで禁止する9状態ステートマシンを実装します。
  3. **コアAI防衛エンジンと実遮断・検疫・暗号基盤の完全結合（P0/P1根絶）**:
     - `airgap_ai_defender.py` の悪性IP検知を `mk1_firewall.py` および `mk1_quarantine.py`（`table inet mk1_airgap` に統一）へリアルタイム連携。
     - DPIの確率的サンプリングスキップを撤廃し、非先頭フラグメント（`frag_offset > 0`）・IPv6 ESP・未知L2 EtherTypeの Fail-Closed 処理と AI異常判定（`ai_anomaly`）の遮断反映を実装。
     - `SessionRatchet.destroy()` 時の `_ACTIVE_RATCHETS` 登録解除リーク修正、PQC KEMスイート統一、および `mk1_path_trust.c` の POSIX マクロ定義修正を実施。
- **Target Audience / Persona**: 主権データセンター、防衛・重要インフラのセキュリティアーキテクト、SOC/CSIRT運用管理者、および独立セキュリティ監査人。
- **Key Value**: 「設計書に書かれているがコードが存在しない機能」や「検知しても遮断されない経路」「外部ライブラリ不在で検証できない死角」をゼロにし、最前線のパケットフィルタからAI推論、多層ハニーポット、量子・耐量子暗号、ライセンス・クォーラム統制までが一気通貫で稼働・検証できる完全な防衛プラットフォームを実現します。

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **XDP / TC / Firewall 統合防衛フロー**:
     - 運用者が防衛エンジンを起動すると、ハートビート監視付きの XDP/TC コントローラと `table inet mk1_airgap` ファイアウォールが初期化されます。
     - パケット到着時、L2 VLAN / L3 IPv4・IPv6拡張ヘッダ / 非先頭フラグメント / 全パケットDPI / 3ヘッドAI推論が実行され、脅威検知時は即座に `mk1_firewall` の `blocked_ipv4` / `blocked_ipv6` セットおよび XDP LPM Blocklist マップへ同期されます。
  2. **イベント束縛 M-of-N クォーラム承認による Kill Switch / 能動的隔離フロー**:
     - 致命的脅威検知時に `_ISOLATION_APPROVAL_PENDING` がセットされ、管理者が M-of-N Ed25519 署名付きのイベント束縛トークン（対象イベントID・アクション・有効期限・単調増加Nonceを含む）を提示すると、署名検証通過後にのみ能動的隔離・Kill Switch が実行されます（トークンなし・改ざん時は Fail-Closed で即拒否）。
  3. **QKD 9状態管理＆ワンタップハイブリッド暗号フロー**:
     - 管理者が QKD サブシステムの状態を確認すると、`QKD_UNAVAILABLE` / `QKD_SIMULATED` / `QKD_READY` 等が厳密に区別されて表示されます。
     - `HONMARU` または `INNER_1..4` での鍵要求時、ETSI 014 KMI 経由で取得した QKD 鍵素材がエントロピー検査を通過し、PQC+X25519 共有秘密と2段階 `HKDF-SHA384` で結合された後、元の生鍵バッファは即座にゼロ化（`WIPED`）されます（`OUTER_1..4` からの QKD アクセスや本丸への鍵インポートは即時拒否）。
- **Visual Identity & Theme (CLI & Operational Dashboard Posture)**:
  - *Aesthetic Direction*: High-Contrast Sovereign Command Console — 視認性と誤操作防止を最優先した厳格なタクティカル・テレメトリ表現。
  - *Color Palette & Status Semantics*:
    - 正常・実機保護有効 (`QKD_READY`, `CORE_PROTECTED`): Emerald Green (`#10B981`)
    - シミュレーション・縮退モード (`QKD_SIMULATED`, `SAFE_DEGRADED_MODE`): Amber Warning (`#F59E0B`)
    - 攻撃検知・隔離発動・Fail-Closed遮断 (`ONI_MODE`, `QKD_AUTH_FAILED`, `XDP_DROP`): Crimson Alert (`#EF4444`)
  - *Typography & Hierarchy*: 等幅フォントによるSHA-256ダイジェスト、BPFマップ統計、監査ハッシュチェーンの整列表示。
- **Interactive Feedback & Motion**:
  - すべてのCLIコマンドおよびセルフテスト実行時に、状態遷移（例: `AVAILABLE -> RESERVED -> CONSUMED -> WIPED`）、遮断ルール同期結果、およびハッシュ連鎖監査ログの検証結果を即座に構造化出力します。

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: XDP / TC eBPF プログラムの実コード実装とユーザー空間エミュレーション検証器の併用**
  - *Chosen Approach*: CO-RE / `libbpf` 準拠の完全な eBPF C ソース（ヘッダ・XDP Ingress・TC Egress・ローダー）を実装するとともに、特権カーネルを持たないコンテナ環境でも同一のパケット境界検査・Port 22 レート制限・IPv6拡張ヘッダ追跡・Dead-Man Switch ハートビート判定をバイト単位で決定論的に検証できる Python XDP/TC ベリファイア＆マップ同期エンジンを実装します。
  - *Why*: 実機 Linux カーネル配備用の C コードを完備しつつ、CI/コンテナ環境でも 100% 単体テストでロジックの正しさ（旧ドラフトの4欠陥が解消されていること）を証明するためです。
  - *Alternatives Considered*: C コードのみを作成してテストをスキップする案は、パケット解析バグの再発を検知できないため却下しました。
- **Decision 2: DPI サンプリングスキップの完全撤廃と高確信 AI 異常スコアの遮断統合**
  - *Chosen Approach*: フローキャッシュの6パケット目以降を確率的にスキップしていた `_should_force_full_scan()` のバイパス経路を廃止し、すべてのペイロード付きパケットに対して正規化DPIを実行します。また、`inspect_packet_pipeline()` の最終 `block` 判定式に `ai_anomaly`（高信頼度閾値超過時または `ONI_MODE` 時）と `parse_error`（非先頭フラグメント・未知L2 EtherType）を組み込みます。
  - *Why*: 「先頭5パケットを無害にし6パケット目にエクスプロイトを送る」回避攻撃や、未知ゼロデイ攻撃が `block=False` で通過する P1-02 / P1-03 / P1-04 の脆弱性を根絶するためです。
- **Decision 3: 外部暗号パッケージ不在時でも完全動作する RFC 準拠 Pure-Python 暗号エンジンの内蔵**
  - *Chosen Approach*: 外部 C 拡張（`cryptography`, `pqcrypto`, `argon2-cffi`, `shamir-mnemonic`）が導入されている場合はそれを利用し、未導入環境では RFC 8032 (Ed25519)、RFC 7748 (X25519)、FIPS 203 互換格子 KEM (ML-KEM-768 / ML-KEM-1024)、RFC 9106 / PBKDF2-HMAC-SHA512、SLIP-0039 GF(256) シャミア秘密分散、および NIST SP 800-38D AES-256-GCM の Pure-Python 実装へシームレスに結合します。
  - *Why*: コンテナ環境で `BLOCKED` となっていた11個の暗号・クォーラム・鍵管理テストスイートをすべて実暗号演算で `PASS` させ、アルゴリズムの整合性とゼロ化動作を完全に保証するためです。

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                     MK1Ai Unified Sovereign-Airgap Architecture                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                           │
       ┌───────────────────────────────────┼───────────────────────────────────┐
       ▼                                   ▼                                   ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐  ┌──────────────────────────────┐
│  L0/L1: XDP & TC eBPF Guard  │  │  L2/L3: Core AI & DPI Engine │  │  QKD & PQC Crypto Subsystem  │
│  ┌────────────────────────┐  │  │  ┌────────────────────────┐  │  │  ┌────────────────────────┐  │
│  │ XDP Ingress Filter     │  │  │  │ Strict Packet Parser   │  │  │  │ 9-State QKD Policy &   │  │
│  │ - VLAN VID Whitelist   │  │  │  │ - Frag Offset>0 Block  │  │  │  │ ETSI 014/004 KMI       │  │
│  │ - IPv4/v6 LPM Blocklist│  │  │  │ - IPv6 ESP Stop/8B Chk │  │  │  └───────────┬────────────┘  │
│  │ - Port 22 Rate-Limited │  │  │  │ - Unknown L2 FailClose │  │  │              ▼               │
│  │ - Dead-Man Heartbeat   │  │  │  └───────────┬────────────┘  │  │  ┌────────────────────────┐  │
│  └───────────┬────────────┘  │  │              ▼               │  │  │ 9-Zone Key Registry    │  │
│              ▼               │  │  ┌────────────────────────┐  │  │  │ (HONMARU / INNER 1..4  │  │
│  ┌────────────────────────┐  │  │  │ Full-Packet Norm DPI   │  │  │  │  / OUTER 1..4)         │  │
│  │ TC clsact Egress/wg0   │◄─┼──┼──┤ + 3-Head AI RiskNet    │  │  │  │ - One-Time Consume     │  │
│  │ - Post-decrypt Check   │  │  │  │ - Zero Sampled-Skip    │  │  │  │ - Immediate Key Wipe   │  │
│  │ - Exfil TC_ACT_SHOT    │  │  │  │ - AI Anomaly -> Block  │  │  │  └───────────┬────────────┘  │
│  └────────────────────────┘  │  │  └───────────┬────────────┘  │  │              ▼               │
└──────────────┬───────────────┘  └──────────────┼───────────────┘  │  ┌────────────────────────┐  │
               │                                 │                  │  │ 2-Stage HKDF-SHA384    │  │
               ▼                                 ▼                  │  │ (QKD + ML-KEM + X25519)│  │
┌──────────────────────────────────────────────────────────────┐    │  │ + SessionRatchet Purge │  │
│     Unified Enforcement & Event-Bound Quorum Controller      │◄───┘  └────────────────────────┘  │
│  - Syncs `_IP_BLACKLIST` -> `inet mk1_airgap` & XDP LPM Maps │                                   │
│  - Event-Bound M-of-N Ed25519 Approval for Kill Switch       │◄──────────────────────────────────┘
└──────────────────────────────────────────────────────────────┘
```

### Data Model & State

1. **XDP / TC eBPF Control & Map State**:
   - `mk1_control_map`: `heartbeat_ns` (uint64), `heartbeat_ttl_ns` (デフォルト5秒), `lockdown_mode` (uint32), `oni_mode` (uint32), `allowed_vlan_bitmap` (uint64), `safe_harbor_ipv4` / `safe_harbor_port`.
   - `mk1_blocklist_v4` / `mk1_blocklist_v6`: LPM Trie 構造（プレフィックス長＋アドレス → 遮断時刻・理由コード）。
   - `mk1_src_rate_v4` / `mk1_src_rate_v6`: 送信元IP単位のトークンバケット（Port 22 を含む全ポートに例外なく適用）。
2. **QKD 9-State & 9-Zone Key Lifecycle Model**:
   - `QKDState`: `QKD_UNAVAILABLE`, `QKD_SIMULATED`, `QKD_CONNECTING`, `QKD_READY`, `QKD_DEGRADED`, `QKD_KEY_EXHAUSTED`, `QKD_AUTH_FAILED`, `QKD_REVOKED`, `QKD_ERROR`。`QKD_SIMULATED` から `QKD_READY` への遷移はハードウェア証明書チェーン検証なしでは構造的に不可能な不変条件を持つ。
   - `QKDKeyRecord`: `key_id` (UUIDv4), `zone_id` (`HONMARU` / `INNER_1..4` のみ許可、`OUTER_1..4` はQKD取得全面禁止), `sae_pair`, `purpose` (`kek-wrapping` / `transport-seed`), `acquired_at_ns`, `expires_at_ns`, `state` (`AVAILABLE -> RESERVED -> CONSUMED -> WIPED / REVOKED`)。
3. **Unified PQC & SessionRatchet Memory State**:
   - ハイブリッド KEM スイートとして `ML-KEM-1024 + X25519` と `ML-KEM-768 + X25519` の双方をアジャイルにサポートしつつデフォルト整合性を統一。
   - `SessionRatchet.destroy()` 実行時に必ず `_ACTIVE_RATCHETS.discard(self)` と鍵バッファの `wipe_buffer()` を実行し、`set_memory_guard_enabled(False)` や `ONI_MODE` 発動時には `purge_all_ratchets()` で全アクティブセッションを一斉破棄。

### Interactive Component & State Mapping

| トリガー / 入力イベント | 対象サブシステム | 状態遷移・検証ロジック | 最終出力・フェールクローズ保証 |
| :--- | :--- | :--- | :--- |
| **悪性パケット / スキャン到着** | PacketParser + DPI + AI + Firewall + XDP | 1. 非先頭断片・未知L2・ESP切り詰めを `parse_error=True` 判定<br>2. サンプリングスキップなしで正規化DPI＆AI推論実行<br>3. `block=True` 時に `_IP_BLACKLIST` 登録と同時に `mk1_firewall` (`inet mk1_airgap`) と XDP LPM マップへ即時反映 | 攻撃通信を即時遮断し、Python検知とカーネル遮断テーブルの不整合（P0-03）を解消 |
| **Kill Switch / 能動的隔離の要求** | AirGapController + Quorum Verifier | 1. 要求イベント固有の `event_id` と操作ダイジェストを生成<br>2. M-of-N Ed25519 署名付き `approval_token` の有無・期限・Nonce・署名を検証<br>3. 検証成功時のみ実隔離を実行、未承認時は拒否 | 未承認の誤発動・暴走を防ぎつつ、承認時の実遮断機能（P0-02 / R-12）を確立 |
| **QKD 鍵取得＆ハイブリッド導出** | QKD 8-Module Subsystem | 1. 要求元 `zone_id` が `OUTER_1..4` なら即拒否<br>2. KMI (`Get_key`) 取得後、32B長・非ゼロ・エントロピー検査<br>3. PQC+X25519 共有秘密と2段階 `HKDF-SHA384` で結合<br>4. `finally` で生QKD鍵を `wipe_buffer()` し `WIPED` へ更新 | 二重消費（再利用）の完全防止、影武者から本丸への鍵汚染阻止、生鍵のメモリ残留ゼロ化 |
| **セッション破棄 / Memory Guard 状態変化** | SessionRatchet + SecureTransport | 1. `ratchet.destroy()` で送受信チェイン鍵をゼロ化し `_ACTIVE_RATCHETS` から削除<br>2. `mlock` 失敗またはガード無効化時に `purge_all_ratchets()` を強制実行 | ヒープ上のラチェット参照リーク（P1-05）および未ロック状態の秘密鍵残存を完全排除 |
