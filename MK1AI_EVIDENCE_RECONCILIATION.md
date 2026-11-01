# MK1Ai — Independent Post-Remediation Evidence Reconciliation Report (`MK1AI_EVIDENCE_RECONCILIATION.md`)

**監査対象レポート**:
1. `MK1AI_REMEDIATION_REPORT.md`
2. `MK1AI_XDP_GAP_ANALYSIS.md`
3. `MK1AI_XDP_REDESIGN.md`
4. `MK1AI_XDP_ENFORCEMENT_MATRIX.md`
5. `MK1AI_REGRESSION_REPORT.md`
6. `MK1AI_PERFORMANCE_ROADMAP.md`

**監査モード**: 独立読み取り専用監査（ソースコード・テスト・ホスト設定の変更なし）

---

## 1. 修正済みと未実装の厳密な6分類（Section 1）

直近の報告書群（`MK1AI_REMEDIATION_REPORT.md` 等）で記載された項目を、実コード（`airgap_ai_defender.py`, `mk1_firewall.py`, `mk1_secure_transport.py`, `mk1_quorum.py`, `mk1_session_ratchet.py`, `mk1_key_registry.py`, `mk1_hybrid_kem.py`, `mk1_quarantine.py`）および実ファイルツリーと直接照合し、以下の **A〜F の6カテゴリ** に厳密に分離する。

### A. Python側で修正済みの欠陥（実コードおよび単体テストで検証完了）

| 項目ID | 対象ファイル・行番号 | 修正内容（実コード確認結果） |
|---|---|---|
| **A-01** | `airgap_ai_defender.py:5780` | `inspect_packet_pipeline()` の `dpi_suspicious` 判定式に `or dpi_result.get("scan_strategy") == "fail_closed"` を追加。`analyze_dpi_payload()` が `None`/非文字列/空バイト列や例外で `_build_fail_closed_dpi_result()` を返した場合に、`block=True, stage="dpi"` へ確実に伝播するよう修正済み。 |
| **A-02** | `airgap_ai_defender.py:1037–1068, 2070` | `_normalize_inspected_payload()` を実装し、UTF-16LE/BE（Nullバイト除去）、URLエンコード（`%XX` 最大2パス）、HTML数値文字参照（`&#xXX;`, `&#dd;`）、16進エスケープ（`\xXX`, `\u00XX`）をデコードした上で `_matches_enforcement_signature()` により検査するよう修正済み。併せて `_EVAL_CALL_RE` / `_BENIGN_DOC_EXT_RE` により `evaluation_report`、`medieval_history`、`passwd_policy.txt` 等の正常文字列での誤遮断を抑制済み。 |
| **A-03** | `airgap_ai_defender.py:2114–2120` | `analyze_dpi_payload()` において `suspicious=True` または `attack_signatures` 非空と判定されたパケットについて、`_FLOW_STATE_CACHE.pop(flow_key, None)` を実行し、悪性スコアがキャッシュに保存されて後続パケットの `sampled_skip` に悪用される状態汚染を防止済み。 |
| **A-04** | `airgap_ai_defender.py:627–678, 740–1003` | `PacketParser` に `_unwrap_l2_ether_type()`（IEEE 802.1Q `0x8100` / 802.1ad QinQ `0x88A8` を最大2段アンラップ）、`_skip_ipv6_extension_headers()`（Hop-by-Hop, Routing, Fragment, ESP, AH, Destination Options を最大8ヘッダ走査）、ICMP/ICMPv6 8バイトヘッダ以降の `payload` 抽出（`lines 973–975, 1001–1003`）、および L2/IPv4/IPv6/TCP/UDP/ICMP 切り詰めパケットへの `parse_error=True` 付与を実装済み。 |
| **A-05** | `airgap_ai_defender.py:5824–5842` | `inspect_packet_pipeline()` の Progressive Defense 判定順序を修正し、`_is_ip_blacklisted(src_ip)` を `parse_error` 判定より先（`line 5824`）に評価するよう変更。また `prog_state.get("defer")` 時に `block=False` で通過していた欠陥を `block=True, stage="rate_limited"`（`line 5833`）へ修正済み。 |
| **A-06** | `airgap_ai_defender.py:441–457` | `toggle_oni_mode()` において公開変数 `ONI_MODE` と内部参照フラグ `_ONI_MODE_ACTIVE` の双方を同期更新するよう修正済み。 |
| **A-07** | `airgap_ai_defender.py:5861–5882` | `inspect_packet_pipeline()` に `feature_vector` バリデーションを追加し、長さ不足（`< 3`）、非数値型、`NaN`/`Inf`、負数を含む特徴量ベクトルに対して `block=True, stage="ai", reason="Invalid or corrupted AI feature vector (fail-closed)"` を返すよう修正済み。 |
| **A-08** | `mk1_quorum.py:13–26, 151, 237, 321` | `cryptography` ライブラリ未導入環境でもモジュール import がクラッシュしないよう `_CRYPTOGRAPHY_AVAILABLE` ガードを追加し、鍵生成・署名・検証呼び出し時には Fail-Closed で `QuorumError` を送出するよう修正済み。 |
| **A-09** | `mk1_firewall.py:143, 210–214` | `render_nft_transaction()` の `input`/`output` チェインに `ct state invalid drop` と `iifname "lo" accept` / `oifname "lo" accept` を追加。また `remove_nft_policy()` が非 root 実行で拒否された際に `_fail()` を呼んで `last_nft_failure` に証跡を記録するよう修正済み。 |

---

### B. 単体テストのみPASSした機能（モック・スタブ・文字列検証のみであり、実OS／実暗号／実モデル推論は未実行）

| 項目ID | 対象機能・ファイル | 単体テストでの検証範囲 | 未実施の実環境検証（混同禁止） |
|---|---|---|---|
| **B-01** | `mk1_firewall.py` の `nftables` ルール生成・適用 (`tests/test_firewall_nft.py` 7/7 PASS) | `render_nft_transaction()` の出力文字列検証、および `unittest.mock.patch("subprocess.run")` によるモック呼び出し検証のみ。 | 実カーネルの `nft -f -` による構文解析・アトミックテーブル置換・パケット遮断は **未検証（`NOT_TESTED`）**。 |
| **B-02** | `mk1_secure_transport.py` の `SessionRatchet` / `RevocationManifest` 統合 | `SessionRatchet` 配線コードと失効チェック分岐の単体ロジック確認のみ。 | 本環境に `cryptography` および `pqcrypto` が未導入のため、`SecureTransport` の実ハンドシェイク（ML-KEM + AES-256-GCM + HKDF ラチェット + Ed25519 失効リスト検証）の結合実行は **未検証（`SKIPPED` / `NOT_TESTED`）**。 |
| **B-03** | `airgap_ai_defender.py` の AI 特徴量バリデーションと推論統合 | `_TorchStub`（`TORCH_AVAILABLE = False`）環境下での `feature_vector` 境界値チェックと決定論的フォールバック確認のみ。 | 実 PyTorch テンソル演算・学習済みモデル重みを用いた実推論パイプラインは **未検証（`NOT_TESTED`）**。 |

---

### C. 実通信で未検証の機能（Live Traffic / Multi-NIC / Tunnel 未検証）

| 項目ID | 対象機能 | 未検証の理由・内容 |
|---|---|---|
| **C-01** | `AF_PACKET` (`SOCK_RAW`) ライブキャプチャ (`airgap_ai_defender.py:3903`) | 非特権コンテナであり外部通信・NIC操作禁止のため、実NIC（物理NIC、Proxmox `vmbr0`、VLAN トランク、WireGuard `wg0`）を流れる実トラフィックに対するパケット捕捉・解析は **実通信未検証**。 |
| **C-02** | `nftables` 実パケット遮断および `mk1-wireguard-egress.nft.template` 適用 | `table inet mk1_airgap` および `table inet mk1ai_egress` を実カーネルにロードした状態でのデータプレーン遮断・フェイルセーフ動作は **実通信未検証**。 |
| **C-03** | WireGuard フルトンネル経路検証 (`_verify_wireguard_full_tunnel()`, `airgap_ai_defender.py:3862`) | 実ホストの `/proc/net/route` / `ip route` 上で `wg0` インターフェースを検証するライブテストは **実通信未検証**。 |

---

### D. XDPの設計のみ完了した機能（`xdp_design_only` — 実コード・バイナリは未実装）

| 項目ID | 設計ドキュメント箇所 | 内容（設計書上の記載のみでありリポジトリ内に実装ファイルは存在しない） |
|---|---|---|
| **D-01** | `MK1AI_XDP_REDESIGN.md:91–289` | `security/ebpf/mk1_xdp_ingress.bpf.c` の C ソース設計案（`mk1_control_map`, `mk1_blocklist_v4`, `mk1_src_rate_v4`, `mk1_verdict_stats` BPF マップ定義と XDP セクション）。 |
| **D-02** | `MK1AI_XDP_REDESIGN.md:14–87` | 4層防御アーキテクチャ設計（L0: Native XDP Ingress、L1: TC `clsact` Egress/Ingress、L2: `nftables` ステートフル検査、L3: `AF_XDP` ゼロコピー User-Space AI/DPI）。 |
| **D-03** | `MK1AI_XDP_ENFORCEMENT_MATRIX.md:17–43` | 19種類の攻撃ベクターに対する XDP / TC / `nftables` / Python DPI の役割分担マトリクス。 |

---

### E. 実装自体が存在しない機能（リポジトリ内にコード 0 行）

| 項目ID | 未実装コンポーネント | 実コード調査結果 |
|---|---|---|
| **E-01** | XDP / TC eBPF ソースファイルおよびオブジェクト (`*.bpf.c`, `*.bpf.o`) | リポジトリ内に `.bpf.c` / `.bpf.o` ファイルは **0個**。`security/ebpf/` ディレクトリ自体が存在しない。 |
| **E-02** | `libbpf` ローダーおよび BPF マップ Pinning 連携 | `Makefile`、`mk1_tunnel.c`、Python コードのいずれにも `bpf_prog_load`、`bpf_xdp_attach`、`/sys/fs/bpf/mk1_*` マップ操作コードは **0行**。 |
| **E-03** | `AF_XDP` (`XSKMAP`) ゼロコピーソケット受信 | `airgap_ai_defender.py:3903` は `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))` による受動コピー監視のままであり、パケットを `XDP_DROP` する能力を持たない。 |
| **E-04** | XDP IPv6 LPM ブロックリストおよび IPv6 拡張ヘッダ BPF パーサー | `MK1AI_XDP_REDESIGN.md` の設計コード内でも IPv6 は `ETH_P_IPV6` 判定後に L4 オフセットを固定加算するのみで、IPv6 用 LPM Trie マップや拡張ヘッダ走査は設計コードにすら含まれていない。 |
| **E-05** | `airgap_ai_defender.py` と `mk1_quarantine.py` の統合ブリッジ | リポジトリ内に実際に `nft add element` 等を呼び出す `mk1_quarantine.py` が存在するが、`airgap_ai_defender.py` からは import も呼び出しも一切行われていない（完全未接続）。 |

---

### F. 修正を保留している機能（意図的据え置き・Dry-Run 固定）

| 項目ID | 対象箇所 | 保留状態の詳細 |
|---|---|---|
| **F-01** | Kill Switch / 能動的隔離の常時無効化 (`airgap_ai_defender.py:417, 5573, 5984, 6226, 6933, 6988`) | 4重の安全ゲート（① `_DRY_RUN = True` 初期値、② CLI `--no-dry-run` 指定時の `parser.error` 拒否、③ `evaluate_threat_state()` の `_ISOLATION_APPROVAL_PENDING = True` 保留、④ `execute_kill_switch()` の `if not dry_run: return False` ハードコード拒否）により、**ランタイムでの実遮断・NICシャットダウンは一切実行されない状態のまま据え置かれている**。 |
| **F-02** | `mk1_path_trust.c` の POSIX マクロ不足 (`#define _XOPEN_SOURCE 700`) | `Makefile` の `-std=c11` 単体コンパイル時に `O_NOFOLLOW` / `O_CLOEXEC` / `S_IFMT` が未定義となる問題。C ソース変更禁止条件に従い、`MK1AI_XDP_REDESIGN.md:295` に 1行パッチ案として記載するのみで実ファイルは未変更。 |

---

## 2. 変更ファイルの完全な証拠確認（Section 2）

### 2.1 Git メタデータの有無に関する明示的報告
- 当該ワークスペース（`/app/applet`）には **`.git` ディレクトリおよび Git メタデータが存在しない**（`os.path.exists("/app/applet/.git") == False`）。
- したがって、「Git 状態を保存した」「`git status` / `git diff` による追跡」と表現することは不正確であり、実際の監査証跡は **初期ファイルツリー（128ファイル）のバイトサイズおよび SHA-256 ハッシュ値と、現在のファイルシステムのバイトサイズおよび SHA-256 ハッシュ値の直接比較** に基づく。
- 前回の `MK1AI_REMEDIATION_REPORT.md`（Section 1.2）では、変更前ハッシュ一覧に6つの主要ファイルしか記載されていなかったため、以下に **変更された全6ファイル＋新規作成された全10ファイル（計16ファイル）および未変更の重要C/モデルファイル** の変更前後サイズ・SHA-256・区分・変更理由・作業範囲整合性を完全に整理する。

### 2.2 全変更・追加ファイルのサイズおよび SHA-256 完全対照表

| # | ファイルパス | 変更前サイズ (Bytes) | 変更前 SHA-256 | 変更後サイズ (Bytes) | 変更後 SHA-256 | 区分 | 変更理由 | 今回の作業範囲との一致 |
|---|---|---:|---|---:|---|---|---|---:|
| 1 | `/airgap_ai_defender.py` | 310,790 | `bfd461677f2983e09b01b7ac7b451fe12ff3c24a32324313022f8163dcc63127` | 325,645 | `6a23e7f61dc9961fa7dc2ebbcbb9b57862538572b483f9ebb03033afbee55f61` | **変更 (Modified)** | DPI `fail_closed` 伝播、多段エンコード正規化、誤検知抑制、フローキャッシュ汚染防止、VLAN/IPv6拡張ヘッダ/ICMP解析、Progressive Defense 順序・`defer` 修正、`ONI_MODE` 同期、`feature_vector` 検証 | **一致**（Python判定処理の修正） |
| 2 | `/mk1_firewall.py` | 8,555 | `f3a0ad76feef712137c80b8b285db8ad1732b8a122af2aee68171951b87ba9b7` | 8,958 | `53e5d1c174ea95b2e13dab4026ae80893d1d89750ab7c60b3c2f6b4f566b4e9d` | **変更 (Modified)** | `render_nft_transaction()` への `ct state invalid drop`・`lo` 許可追加、`remove_nft_policy()` の非root失敗記録 (`_fail()`) | **一致**（nftables ソース修正） |
| 3 | `/mk1_secure_transport.py` | 23,776 | `609c5cc01b92632442febec4a3dbeeb7a981f6cc15d1e8ec56b4ace2db4ebd31` | 25,799 | `26c9ef1043de204c20d4a786edd14bd6fb46c8f7cd1db1678a844481026b011c` | **変更 (Modified)** | `SessionRatchet` によるメッセージ毎の鍵導出統合、`RevocationManifest` によるピア失効検証フック追加 | **一致**（Python暗号トランスポート修正） |
| 4 | `/mk1_quorum.py` | 15,826 | `9a8c3252a70760c3b6fb91c918ca138bc229238b12a080886bc0584c7c92a225` | 15,648 | `a6e115cba3f014a55a35b53fd65658e4dfa7cb7177f59eeff20e49de7ac9f61f` | **変更 (Modified)** | `cryptography` 未導入時の `_CRYPTOGRAPHY_AVAILABLE` ガードと Fail-Closed `QuorumError` 送出（冗長なラッパー関数を簡潔化したため -178 Bytes） | **一致**（Pythonゼロトラスト判定修正） |
| 5 | `/tests/test_airgap_ai_defender.py` | 143,580 | `3534e9a055f983b99788716fe7d13cd665e1b2528fc7046f3bd9bf4251b2ee6a` | 150,886 | `b111a000753479a47959e8ceefffbdd37e95a6110a1eedacc0de60e5035ae469` | **変更 (Modified)** | `TestSecurityRemediationRegressions`（REG-01〜REG-09 の12テストメソッド）の追加 | **一致**（Python単体テストの追加） |
| 6 | `/tests/test_firewall_nft.py` | 2,330 | `3e7d53d10a1a5f4271819cc3b642df53c485560ca8958f1567bd17b722f4cf4c` | 2,938 | `6b9c42e8608f56db77205dfe5f4c94ae8f49bf3926625134fc1dc814b00d51fd` | **変更 (Modified)** | `ct state invalid drop`、`lo` ルール、非root時の `remove_nft_policy()` 失敗記録のアサーション追加 | **一致**（Python単体テストの追加） |
| 7 | `/app.py` | — (存在せず) | `N/A (新規作成)` | 15,658 | `74eed9740ed8330d46e84ec5f809fbda84fa55d4fc9bf0011b3f61407a0d5303` | **追加 (Added)** | Turn 2（「The dev server didn't start, please fix it」）で AI Studio プレビュー環境（Port 3000）起動用に作成された Web ダッシュボード | **範囲外（Out-of-Scope）** ※Turn 3のセキュリティ指示前に作成されたプレビュー用ファイル。削除禁止ルールに従い保持 |
| 8 | `/MK1AI_REMEDIATION_REPORT.md` | — (存在せず) | `N/A (新規作成)` | 21,641 | `0fd6c7627f292e641d34ef4fb9670ff0c1824891439ce4420069e01857415730` | **追加 (Added)** | PART 10 成果物1（セキュリティ修正報告書） | **一致**（要求成果物） |
| 9 | `/MK1AI_XDP_GAP_ANALYSIS.md` | — (存在せず) | `N/A (新規作成)` | 12,843 | `d28cb68173be5285a06674986d60e3745557941ef67d57b8876430164a3022a1` | **追加 (Added)** | PART 10 成果物2（XDPすり抜け原因・ギャップ分析） | **一致**（要求成果物） |
| 10 | `/MK1AI_XDP_REDESIGN.md` | — (存在せず) | `N/A (新規作成)` | 15,834 | `b1a93bf48fb70fa6ff88bc838e3d6ca98be2cb5ba131144df214796473380115` | **追加 (Added)** | PART 10 成果物3（XDP/TC/AF_XDP 再設計仕様書） | **一致**（要求成果物） |
| 11 | `/MK1AI_XDP_ENFORCEMENT_MATRIX.md` | — (存在せず) | `N/A (新規作成)` | 8,663 | `c496215dc9d7c580f12bd4db67cf1d61663414189b55c77bc0da4cc2ef16cd4f` | **追加 (Added)** | PART 10 成果物4（多層防御エンフォースメントマトリクス） | **一致**（要求成果物） |
| 12 | `/MK1AI_REGRESSION_REPORT.md` | — (存在せず) | `N/A (新規作成)` | 9,629 | `8b7ab13548fc13c95f0398140bb5d988eb7bb9341288ce2d3931c8391068fd0b` | **追加 (Added)** | PART 10 成果物5（回帰テスト報告書） | **一致**（要求成果物） |
| 13 | `/MK1AI_PERFORMANCE_ROADMAP.md` | — (存在せず) | `N/A (新規作成)` | 7,950 | `d993fd14b4f5169135190cc464a5b2016c1b308e36fb80c3de7f5d2df4ce28b5` | **追加 (Added)** | PART 10 成果物6（性能改善ロードマップ） | **一致**（要求成果物） |
| 14 | `/MK1AI_POSTFIX_VERIFICATION.md` | — (存在せず) | `N/A (新規作成)` | 20,747 | `fd973eb8328640b0bd79dbda6cf23d1371a7cd4214b426dbec0e1f885a123214` | **追加 (Added)** | 前ターンで作成された独立検証レポート | **一致**（監査成果物） |
| 15 | `/MK1AI_GIT_CHANGE_AUDIT.md` | — (存在せず) | `N/A (新規作成)` | 12,188 | `3ee9b6774fd42c99d918bd672c02c207cf8213eb41cdca17965dfcf81101d378` | **追加 (Added)** | 前ターンで作成された変更ファイル監査レポート | **一致**（監査成果物） |
| 16 | `/MK1AI_REGRESSION_EVIDENCE_MATRIX.md` | — (存在せず) | `N/A (新規作成)` | 14,538 | `327eb048fbebffae24bb33bf499bdba2cb08a7e5c5baae9e88c3196c87382735` | **追加 (Added)** | 前ターンで作成された回帰テスト証拠マトリクス | **一致**（監査成果物） |

### 2.3 未変更が義務付けられている主要ファイル（Cソース・テンプレート・ノートブック等）の不変性確認
以下のファイルは初期状態から **1バイトも変更されていない** ことを確認した：
- `/mk1_memory_guard.c` (`3,005 Bytes`, SHA-256: `e741f9538c8ff1df23a6f33eb1b8b4ca770bd7b3d177dc559a32f5fb53d87a42`) — **未変更**
- `/mk1_path_trust.c` (`6,812 Bytes`, SHA-256: `c526fa3700e89eb82cb947fb3473a13dcab343f7122debe9ffbe79bf6c88cb7e`) — **未変更**
- `/mk1_tunnel.c` (`18,939 Bytes`, SHA-256: `5360a0d6931f5f167f6841c00ff2de199df31bc3a930315a2ec612fb1d4bfca6`) — **未変更**
- `/mk1-wireguard-egress.nft.template` (`2,213 Bytes`, SHA-256: `7de276369b86ab8c2732ff59bf006944ec901d635d4282b8d5bf0ef41ab1c50f`) — **未変更**
- `/colab_training.ipynb` (`18,864 Bytes`, SHA-256: `7e70ee3f6b33cb205543ef6f1dc5d5ba053272be856301b93fbba9d467505166`) — **未変更**

---

## 3. 回帰テスト 248件 の内訳照合および REG-01〜REG-09 監査（Section 3）

### 3.1 「248 PASS」表記の不正確さと正確な内訳
- `MK1AI_REMEDIATION_REPORT.md` のサマリ等で「248件のテストを実行」と記載されていたが、実際の `python3 -m unittest discover -s tests -v` の厳密な内訳は以下の通りである：
  - **総テスト数 (`Ran`)**: **248 件**
  - **成功 (`PASS`)**: **226 件**
  - **スキップ (`SKIPPED`)**: **22 件**（すべて `cryptography` または `pqcrypto` ライブラリ未導入による環境スキップ）
  - **失敗 (`FAIL` / `ERROR`)**: **0 件**
- したがって、「248 PASS」ではなく **「248件中 226 PASS / 22 SKIPPED / 0 FAIL」** が正確なテスト結果である。

### 3.2 スキップされた 22 件の全リストと理由

| テストファイル | スキップ件数 | テストクラス・メソッド | スキップ理由 |
|---|---:|---|---|
| `tests/test_hybrid_kem.py` | 5 | `TestHybridKEM` 全5メソッド (`test_derive_wg_psk_deterministic`, `test_encapsulate_decapsulate_roundtrip` 等) | `pqcrypto` (`ml_kem_1024`) および `cryptography` (`X25519`, `HKDF`) 未導入 |
| `tests/test_key_backup.py` | 4 | `TestKeyBackup` 全4メソッド | `cryptography` (`AESGCM`, `Scrypt`) 未導入 |
| `tests/test_key_registry.py` | 5 | `TestKeyRegistry` 全5メソッド | `cryptography` (`Ed25519`) 未導入 |
| `tests/test_quorum.py` | 4 | `TestQuorum` 全4メソッド | `cryptography` (`Ed25519`) 未導入 |
| `tests/test_session_ratchet.py` | 4 | `TestSessionRatchet` 全4メソッド | `cryptography` (`HKDF`) 未導入 |

### 3.3 REG-01〜REG-09（欠番指摘のあった REG-04 / REG-06 を含む）の全件照合
- **REG-04 および REG-06 の調査結果**:
  - `app.py`（Webプレビュー画面の `run_live_verification_checks()`）のテーブル表示では `REG-01`, `REG-02`, `REG-03`, `REG-05`, `REG-07`, `REG-08`, `REG-09` の7行のみが表示されており、**Web UI 上では `REG-04` と `REG-06` が欠番となっていた**。
  - 一方、実テストコード `tests/test_airgap_ai_defender.py`（`TestSecurityRemediationRegressions` クラス、`lines 2823–3012`）および `MK1AI_REGRESSION_REPORT.md`（`lines 16–27`）には **`REG-01` から `REG-09` までの全9項目（12テストメソッド）がすべて定義・実装されており、実測で全件 PASS している**。

| 項目ID | 検証対象 | 対応テストメソッド (`tests/test_airgap_ai_defender.py`) | 行番号 | 実行結果 | 実コード照合結果 |
|---|---|---|---|---|---|
| **REG-01** | DPI `fail_closed` の最終判定（`block=True`）への伝播 | `test_reg01_dpi_fail_closed_propagates_to_pipeline` | `2826–2840` | **PASS** | `airgap_ai_defender.py:5780` で `scan_strategy == "fail_closed"` を `dpi_suspicious=True` に伝播。 |
| **REG-02** | UTF-16LE/BE、URLエンコード、HTMLエンティティ、Hex、Nullバイトの検知 | `test_reg02_dpi_obfuscated_encodings_detected` | `2842–2869` | **PASS** | `_normalize_inspected_payload()` (`lines 1043–1059`) でデコード後にシグネチャ一致を確認。 |
| **REG-03** | 正常な技術文書・識別子・ファイル名の誤遮断防止 | `test_reg03_dpi_benign_text_not_false_positive` | `2871–2886` | **PASS** | `evaluation_report`, `medieval_history`, `passwd_policy.txt`, `system_administration.pdf` が全て `suspicious=False` となることを確認。 |
| **REG-04** | フローキャッシュの悪性スコア保存防止（サンプリングバイパス防止） | `test_reg04_flow_cache_does_not_cache_malicious_verdict` | `2888–2903` | **PASS** *(Web UI表示では欠落)* | `airgap_ai_defender.py:2114–2115` で悪性判定時に `_FLOW_STATE_CACHE.pop(flow_key, None)` を実行しキャッシュ汚染を阻止。 |
| **REG-05** | L2 802.1Q VLAN / 802.1ad QinQ、IPv6拡張ヘッダ、ICMPペイロード抽出、切り詰めパケット検知 | `test_reg05_parser_8021q_vlan_and_qinq`<br>`test_reg05_parser_ipv6_extension_headers`<br>`test_reg05_parser_icmp_payload_extracted`<br>`test_reg05_parser_truncated_headers_flagged` | `2905–2949` | **PASS** (4メソッド) | `_unwrap_l2_ether_type()`, `_skip_ipv6_extension_headers()`, ICMP `payload` 抽出、切り詰め時 `parse_error=True` を確認。 |
| **REG-06** | Progressive Defense の判定順序（ブラックリスト優先）および `defer=True` 時の遮断 | `test_reg06_progressive_defense_order_and_defer_block` | `2951–2958` | **PASS** *(Web UI表示では欠落)* | `airgap_ai_defender.py:5824` でブラックリスト判定を最優先化し、`line 5833` で `defer=True` を `block=True, stage="rate_limited"` に修正。 |
| **REG-07** | `toggle_oni_mode()` の `ONI_MODE` / `_ONI_MODE_ACTIVE` 同期 | `test_reg07_toggle_oni_mode_synchronizes_flags` | `2960–2969` | **PASS** | `airgap_ai_defender.py:441–457` で両変数が一致して切り替わることを確認。 |
| **REG-08** | 破損特徴量ベクトル（要素不足、`NaN`、負数）の AI Fail-Closed 遮断 | `test_reg08_corrupted_feature_vector_fails_closed` | `2971–2986` | **PASS** | `airgap_ai_defender.py:5861–5882` で `[1.0]`, `[float("nan"), 1.0, 1.0]`, `[-5.0, 1.0, 1.0]` が全て `block=True, stage="ai"` となることを確認。 |
| **REG-09** | `SessionRatchet` トランスポート統合と `nftables` `ct state invalid drop` / `lo` 出力 | `test_reg09_secure_transport_wires_session_ratchet`<br>`test_reg09_firewall_renders_ct_invalid_and_loopback` | `2988–3012` | **PASS** (2メソッド) | `mk1_secure_transport.py` のラチェット配線と `mk1_firewall.py` の出力文字列を確認。 |

### 3.4 追加確認項目（Section 3 末尾の5項目）の実コード照合結果
1. **フローキャッシュの異常スコア保存防止**: `airgap_ai_defender.py:2114–2120` にて `if not suspicious and not matched_signatures:` の場合のみ `_FLOW_STATE_CACHE[flow_key]` に保存し、悪性時は `pop()` する実装を実コードで確認済み。ただし、先頭5パケットを良性通信として送信し6パケット目以降に攻撃を送る「遅延攻撃」への構造的限界が残る（詳細は `MK1AI_POSTFIX_GAP_REPORT.md` 参照）。
2. **802.1Q / QinQ の解析**: `airgap_ai_defender.py:627–643` の `_unwrap_l2_ether_type()` で `0x8100` / `0x88A8` / `0x9100` を最大2タグ（8バイト）までアンラップする実装を確認済み。
3. **IPv6拡張ヘッダーの解析**: `airgap_ai_defender.py:646–678` の `_skip_ipv6_extension_headers()` で `0, 43, 44, 50, 51, 60` を最大8ヘッダまで走査する実装を確認済み。ただし Non-first fragment（`frag_offset > 0`）時の扱いに残存課題がある（`MK1AI_POSTFIX_GAP_REPORT.md` 参照）。
4. **ICMPペイロード検査**: `airgap_ai_defender.py:973–975`（IPv4 ICMP）および `1001–1003`（IPv6 ICMPv6）で8バイトヘッダ以降のスライスを `result["payload"]` に格納する実装を確認済み。
5. **`ONI_MODE` と `_ONI_MODE_ACTIVE` の同期**: `airgap_ai_defender.py:441–457` の `toggle_oni_mode()` で同期されることを確認済み。ただし他箇所から `airgap_ai_defender.ONI_MODE = True` と属性直接代入された場合は `_ONI_MODE_ACTIVE` が更新されない点に注意が必要。
