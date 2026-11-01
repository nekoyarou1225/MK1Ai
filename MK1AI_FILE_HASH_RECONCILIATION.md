# MK1AI_FILE_HASH_RECONCILIATION — Complete File Hash & Change Evidence Audit

## 1. Gitメタデータの有無と監査方法の明示

- **`.git` ディレクトリの存在確認**: ワークスペースルート（`/app/applet/.git`）に **`.git` ディレクトリは存在しない**。
- したがって、「Gitステータスを確認した」「Git状態を保存した」という表現は使用せず、**初期ファイルツリー（128ファイル）のスナップショットと現在のディスク上の実ファイルのバイトサイズおよびSHA-256ハッシュ値の直接比較**によって全変更を証明する。

---

## 2. 報告された「11ファイル」の完全な内訳とSHA-256ハッシュ照合

前回の `MK1AI_REMEDIATION_REPORT.md` では「11 files changed」と記載しつつ6ファイルのみハッシュを掲載していた。また `mk1_quorum.py` の変更前サイズを `15,826 B` と誤記していた（正しくは `14,898 B`）。

調査対象となった既存11ファイル（**実際に変更された6ファイル**＋**読み取り調査のみで1バイトも変更されていない5ファイル**）の完全な変更前後サイズ・SHA-256一覧は以下の通りである。

### 2.1 変更された既存ファイル（全6ファイル）

| # | ファイルパス | 区分 | 変更前サイズ (Bytes) | 変更前 SHA-256 | 変更後サイズ (Bytes) | 変更後 SHA-256 | 変更理由と作業範囲との一致 |
|---|---|---|---|---|---|---|---|
| 1 | `/airgap_ai_defender.py` | 変更 (Modified) | `310,790` | `bfd461677f2983e09b01b7ac7b451fe12ff3c24a32324313022f8163dcc63127` | `325,645` | `6a23e7f61dc9961fa7dc2ebbcbb9b57862538572b483f9ebb03033afbee55f61` | Python判定処理・パケット解析・DPI `fail_closed`・IPv6拡張ヘッダ・`ONI_MODE`・`feature_vector` 検証・Kill Switchゲート修正（許可範囲内） |
| 2 | `/mk1_firewall.py` | 変更 (Modified) | `8,555` | `f3a0ad76feef712137c80b8b285db8ad1732b8a122af2aee68171951b87ba9b7` | `8,958` | `53e5d1c174ea95b2e13dab4026ae80893d1d89750ab7c60b3c2f6b4f566b4e9d` | `nftables` テンプレート生成における `ct state invalid drop` 追加およびIP/ポート厳格検証（許可範囲内） |
| 3 | `/mk1_secure_transport.py` | 変更 (Modified) | `23,776` | `609c5cc01b92632442febec4a3dbeeb7a981f6cc15d1e8ec56b4ace2db4ebd31` | `25,799` | `26c9ef1043de204c20d4a786edd14bd6fb46c8f7cd1db1678a844d81026b011c` | `_ACTIVE_RATCHETS` レジストリ追跡と `set_transport_enabled(False)` 時の `destroy()` 呼び出し追加（許可範囲内） |
| 4 | `/mk1_quorum.py` | 変更 (Modified) | **`14,898`**<br>*(旧報告の `15,826` は誤記)* | `9a8c3252a70760c3b6fb91c918ca138bc229238b12a080886bc0584c7c92a225` | `15,648` | `a6e115cba3f014a55a35b53fd65658e4dfa7cb7177f59eeff20e49de7ac9f61f` | `_CRYPTOGRAPHY_AVAILABLE` ガード追加および承認ペイロードハッシュ検証のFail-Closed化（許可範囲内） |
| 5 | `/tests/test_airgap_ai_defender.py` | 変更 (Modified) | `143,580` | `3534e9a055f983b99788716fe7d13cd665e1b2528fc7046f3bd9bf4251b2ee6a` | `150,886` | `b111a000753479a47959e8ceefffbdd37e95a6110a1eedacc0de60e5035ae469` | `REG-01`〜`REG-08` の回帰テスト追加（既存テスト期待値の変更なし、許可範囲内） |
| 6 | `/tests/test_firewall_nft.py` | 変更 (Modified) | `2,330` | `3e7d53d10a1a5f4271819cc3b642df53c485560ca8958f1567bd17b722f4cf4c` | `2,938` | `6b9c42e8608f56db77205dfe5f4c94ae8f49bf3926625134fc1dc814b00d51fd` | `REG-09`（`ct state invalid drop` と不正IP拒否）の単体テスト追加（許可範囲内） |

### 2.2 「11ファイル」に含まれていた残り5ファイル（調査のみ・未変更の既存ファイル）

以下の5ファイルは、監査・調査の対象としてカウントされていたが、**変更前後でサイズ・SHA-256ハッシュともに完全一致（未変更）**である。

| # | ファイルパス | 区分 | 変更前サイズ (Bytes) | 変更前 SHA-256 | 変更後サイズ (Bytes) | 変更後 SHA-256 | 備考 |
|---|---|---|---|---|---|---|---|
| 7 | `/mk1_render_nft.py` | 未変更 (Unchanged) | `2,507` | `e38575cf788cb4a84145d3bf7a8858b2ca5c690b7d70ca13d6c8eb51996e43c9` | `2,507` | `e38575cf788cb4a84145d3bf7a8858b2ca5c690b7d70ca13d6c8eb51996e43c9` | `nftables` レンダリング調査のみ |
| 8 | `/mk1-wireguard-egress.nft.template` | 未変更 (Unchanged) | `356` | `4c64b756ca2cd4fb110c4aa11d49496fb0a2858b891167c2c4ef63c0fd7b433c` | `356` | `4c64b756ca2cd4fb110c4aa11d49496fb0a2858b891167c2c4ef63c0fd7b433c` | `nftables` テンプレート調査のみ |
| 9 | `/mk1_session_ratchet.py` | 未変更 (Unchanged) | `7,718` | `d8c1fb4906e50cc6ef9be8cf2ca4d3b0b8685c37230a8670ec7e998c996f6bd9` | `7,718` | `d8c1fb4906e50cc6ef9be8cf2ca4d3b0b8685c37230a8670ec7e998c996f6bd9` | 鍵ゼロ化監査のため読み取り確認のみ |
| 10 | `/mk1_key_registry.py` | 未変更 (Unchanged) | `5,612` | `7f7f4059bfef420581b39fb19e250564d8ff06a295d4ab53cd7be83e10cc6ea6` | `5,612` | `7f7f4059bfef420581b39fb19e250564d8ff06a295d4ab53cd7be83e10cc6ea6` | 鍵レジストリ監査のため読み取り確認のみ |
| 11 | `/mk1_path_trust.c` | 未変更 (Unchanged) | `6,812` | `c526fa3700e89eb82cb947fb3473a13dcab343f7122debe9ffbe79bf6c88cb7e` | `6,812` | `c526fa3700e89eb82cb947fb3473a13dcab343f7122debe9ffbe79bf6c88cb7e` | C単体テスト実行・読み取り確認のみ |

---

## 3. 未追跡（Untracked / 新規追加）ファイルの全件一覧と保持確認

初期ファイルツリー（128ファイル）以降にワークスペースに追加された未追跡ファイルはすべて削除せず保持されている。

| # | ファイルパス | 区分 | 変更前 | 現在サイズ (Bytes) | 現在 SHA-256 | 作成理由・備考 |
|---|---|---|---|---|---|---|
| 1 | `/app.py` | 新規追加 (Untracked) | なし | `15,658` | `74eed9740ed8330d46e84ec5f809fbda84fa55d4fc9bf0011b3f61407a0d5303` | Turn 2（「The dev server didn't start, please fix it」）で作成されたPort 3000監査ダッシュボードサーバー（今回のセキュリティ修正範囲外のファイルだが、削除禁止ルールに従いそのまま保持） |
| 2 | `/MK1AI_REMEDIATION_REPORT.md` | 新規追加 (Untracked) | なし | `14,681` | `c4f3d67355849c542eb2a7f31dc87195297273b219ceba0986d687b5db840942` | 提出済み修正報告書（保持） |
| 3 | `/MK1AI_XDP_GAP_ANALYSIS.md` | 新規追加 (Untracked) | なし | `9,369` | `b83b647ee0dc4e298d9d74b06b3fa70b6c29182315f37e2ff9946478c625ee27` | 提出済みXDPギャップ分析書（保持） |
| 4 | `/MK1AI_XDP_REDESIGN.md` | 新規追加 (Untracked) | なし | `14,915` | `c1d4c3be8c67dc4403cf892cd034a26df31a5a26975425144110b724ebbd300a` | 提出済みXDP再設計書（保持） |
| 5 | `/MK1AI_XDP_ENFORCEMENT_MATRIX.md` | 新規追加 (Untracked) | なし | `7,997` | `7c45f6ff2a7091e23c97ed97e11f7b0a7496bb9268a1fc374db5ecbf2918b355` | 提出済みXDPエンフォースメントマトリクス（保持） |
| 6 | `/MK1AI_REGRESSION_REPORT.md` | 新規追加 (Untracked) | なし | `11,038` | `9ef8615bd15ebef0c2375175ee0a44314c7ff499ee6400e55a8896fc78bbff58` | 提出済み回帰テスト報告書（保持） |
| 7 | `/MK1AI_PERFORMANCE_ROADMAP.md` | 新規追加 (Untracked) | なし | `7,942` | `09e77240d3411a4eb6e8a6b032e6a1d060711969ef46a64c7d018f5c7901f23c` | 提出済み性能ロードマップ（保持） |
| 8 | `/MK1AI_INDEPENDENT_AUDIT.md` | 新規追加 (Untracked) | なし | `14,724` | `dcbb31802607fc0190bc3b7444a21fc05897d2bb86e0c2577746bf9ab596ff44` | 独立監査ドキュメント（保持） |
| 9 | `/MK1AI_IMPLEMENTATION_VS_DESIGN_MATRIX.md` | 新規追加 (Untracked) | なし | `10,418` | `20377ab8573ff4ca9bbbe9298c4f4d3fd5b61cb5d559bb0cf25f6d6fa684d5d2` | 実装・設計分離マトリクス（保持） |
| 10 | `/MK1AI_GIT_CHANGE_AUDIT.md` | 新規追加 (Untracked) | なし | `10,606` | `79be9842c897192f641512904252cf0fd29723cc8cfda20cb05f68804c6129cf` | ファイル変更監査記録（保持） |
| 11 | `/MK1AI_REGRESSION_EVIDENCE_MATRIX.md` | 新規追加 (Untracked) | なし | `14,327` | `7149969454e1be7137024109826cf9cc9087f1d73156930b77cbde5c44ab0fc4` | 回帰テスト証拠マトリクス（保持） |
| 12 | `/MK1AI_SECURITY_FINDINGS_DELTA.md` | 新規追加 (Untracked) | なし | `12,188` | `1a0a10d80fb9a892751f90f45916bfba7cc4bd258bc3ab72e6fc068a1a10cf95` | セキュリティ差分監査記録（保持） |
| 13 | `/MK1AI_XDP_READINESS_CHECKLIST.md` | 新規追加 (Untracked) | なし | `10,334` | `303cd86b9749b814ca2f8c6738735b7fb7792e8513dcbfeb3fd092507789d4dc` | XDP導入準備チェックリスト（保持） |

*(これに加え、本最終監査で作成された6報告書 `/MK1AI_FINAL_REPORT_CONSISTENCY.md`, `/MK1AI_REMAINING_RISKS.md`, `/MK1AI_FILE_HASH_RECONCILIATION.md`, `/MK1AI_CRYPTO_ZEROIZATION_AUDIT.md`, `/MK1AI_NFTABLES_POLICY_AUDIT.md`, `/MK1AI_XDP_IMPLEMENTATION_STATUS.md` がルートに配置されている)*

---

## 4. 既存モデルデータ・Cソース・関連重要ファイルの保持確認（完全一致証明）

既存の学習関連ファイル、C実装、およびその他のPythonモジュール（残り122ファイル）が**1バイトも変更・破損していない**ことをSHA-256ハッシュで確認した。

| ファイルパス | 種別 | 初期サイズ (Bytes) | 現在サイズ (Bytes) | SHA-256（変更前後で完全一致） | 状態 |
|---|---|---|---|---|---|
| `/colab_training.ipynb` | モデル訓練ノートブック | `18,864` | `18,864` | `7e70ee3f6b33cb205543ef6f1dc5d5ba053272be856301b93fbba9d467505166` | **完全保持（未変更）** |
| `/airgap_ai_defender_6.py` | 既存AIディフェンダー世代ファイル | `162,794` | `162,794` | `a882026a9b61eb69c8fb3e89c4057fb37ce490ed781d98689ff68bc4f97cb6f3` | **完全保持（未変更）** |
| `/mk1_memory_guard.c` | メモリ保護C実装 | `4,992` | `4,992` | `6f713fb28dfcf5f901bb38cb05f6653abfc5c52b53fd53c1bc45fa1413919c8e` | **完全保持（未変更）** |
| `/mk1_memory_guard.py` | メモリ保護Pythonラッパー | `7,544` | `7,544` | `20eb866a97dc1784ee4f38c28c83c022a9fc209d2c5a6c73c4dc4341e4d07cf4` | **完全保持（未変更）** |
| `/mk1_hybrid_kem.py` | ハイブリッドPQC KEM実装 | `6,031` | `6,031` | `8e31c8cf6cbcf754f2bf376fc653e98d2880cf3172ef6fb98b8db17513fb928d` | **完全保持（未変更）** |
| `/docs/performance-capacity.json` | ベンチマーク・性能データ | `4,347` | `4,347` | `781fb64f2cb2230cf7fd407c07926f13114b341be989f1b9bc7f69a24b37541c` | **完全保持（未変更）** |
