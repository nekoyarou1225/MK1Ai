# MK1Ai — FSM V3.1 ULTIMATE INDEPENDENT SECURITY AUDIT REPORT
## Project Sovereign-Airgap / Gemini 4 Argon 独立セキュリティ監査・実行証拠報告書

---

## A. 総合判定

前回の「40テストPASS・脆弱性0件・FSM VERIFIED」という報告を完全に破棄し、現在の実コード（`airgap_ai_defender.py`, `mk1_quorum.py`, `tests/test_v3_final.py`, `tests/test_v3_remediation.py`）に対する静的解析および独立した一時領域（`/tmp/mk1_*`）での動的検証を実施した結果、**実稼働インスタンスの永続化欠如、Dry-Runによる本番状態の汚染、復旧処理中の緊急隔離ブロック、ジャーナルまたは状態ファイル削除によるRollback防止の完全回避、プロセス間競合による破損、M-of-N必須属性欠落時のバイパス、およびKill Switch失敗時の隔離成功誤報**など、計15件（P0: 5件、P1: 6件、P2: 3件、P3: 1件）の重大な脆弱性を実証しました。

- **総合ステータス:** **`FSM FAILED`**
- **総検証項目数（個別試験IDベース）:** 126件
  - **PASS件数:** 89件（7×7基本遷移49件、単一スレッド基本動作、テスト用FSMの個別正常系など）
  - **FAIL件数:** 35件（F-01〜F-12で実際に不具合・安全条件違反を再現した項目）
  - **BLOCKED件数:** 2件（Gitメタデータ不在、および実NIC/カーネル遮断の安全規約による禁止）
  - **NOT TESTED件数:** 0件
  - **INCONCLUSIVE件数:** 0件
- **発見された脆弱性件数（合計 15件）:**
  - **P0（最優先・重大）:** **5件** (`FINDING-P0-001` 〜 `FINDING-P0-005`)
  - **P1（高優先）:** **6件** (`FINDING-P1-001` 〜 `FINDING-P1-006`)
  - **P2（中優先）:** **3件** (`FINDING-P2-001` 〜 `FINDING-P2-003`)
  - **P3（低優先）:** **1件** (`FINDING-P3-001`)

---

## B. 監査対象のリポジトリ情報

### 1. Git状態および対象ファイルSHA-256ハッシュ（監査前後一致確認済み）
- **Git Repository状態:** `.git` ディレクトリが存在しないスナップショット環境（`fatal: not a git repository (or any of the parent directories): .git` -> Git commit/branch取得は `BLOCKED`）
- **監査開始前・終了後のSHA-256ハッシュ（完全一致・変更ファイル0件）:**

| ファイルパス | 行数 | SHA-256 ハッシュ（監査前・監査後完全一致） |
|---|---|---|
| `/airgap_ai_defender.py` | 8,623行 | `62ce5e3a5159fd0fa1efa5c14b5a89130341d6f7506ab99e406990c22594420a` |
| `/mk1_quorum.py` | 793行 | `6da07e9c2870a946f686370150f5a519b5c576ce724c396ffa1dd3221441a0d0` |
| `/tests/test_v3_final.py` | 766行 | `01fa038160550f20f932661e34b49861507afb71c9018becd5ae66ff5c87c9b2` |
| `/tests/test_v3_remediation.py` | 114行 | `b56a8394e44b56bd4d3dca2d0e153dc86dbd5f55c3ce35c03732cbd149c74388` |
| `/docs/SAFETY_STATES.md` | 73行 | `457576327035b78c4a54820444ffa931276a37104453dca97210be2243ef49f5` |

### 2. FSM定義位置・実稼働インスタンス生成位置・全呼び出し箇所・関連環境変数
- **FSMクラス定義:** `airgap_ai_defender.py` 442行〜940行 (`class MK1SafetyStateMachine`)
- **実稼働グローバルFSM生成位置:** `airgap_ai_defender.py` 942行 (`_SAFETY_FSM = MK1SafetyStateMachine()`)
- **モジュール読込時の初期遷移処理:** `airgap_ai_defender.py` 944行〜954行
- **FSMを呼び出す関数:**
  - モジュール初期化処理（`airgap_ai_defender.py` 944〜954行）
  - `evaluate_threat_state()`（`airgap_ai_defender.py` 6271〜6421行：6285行で `target_fsm = fsm if fsm is not None else _SAFETY_FSM`、6365行・6385行で `isolate_immediately()`、6403行・6413行で `transition_to()`）
- **関連する環境変数:**
  - `MK1_FSM_HMAC_KEY`（`airgap_ai_defender.py` 474行：未設定時は固定バイト列 `b"MK1AI-FSM-SECRET-KEY-V3"` にフォールバック）
  - `ONI_MODE`（`airgap_ai_defender.py` 944行：起動時の初期遷移分岐）
- **一時検証領域:** Python `tempfile.TemporaryDirectory(prefix="mk1_...")` により `/tmp` 配下に合成データ専用の一時ディレクトリを作成し、検証終了時に自動削除済み（既存ファイルへの変更・残存ファイル0件）。

---

## C. FSM 7×7遷移検証（F-07：全49通り＋緊急遷移の独立検証）

### 確認したコード
- `airgap_ai_defender.py` 499〜507行 (`_allowed_transitions`)、725〜785行 (`_transition_to_locked`)、786〜802行 (`transition_to`)、803〜835行 (`isolate_immediately`)

```python
        self._allowed_transitions = {
            self.OFF: {self.ARMING},
            self.ARMING: {self.OFF, self.ACTIVE, self.EMERGENCY},
            self.ACTIVE: {self.OFF, self.EMERGENCY, self.ISOLATED},
            self.EMERGENCY: {self.ISOLATED},
            self.ISOLATED: {self.RECOVERY_PENDING},
            self.RECOVERY_PENDING: {self.ISOLATED, self.RECOVERY_APPROVED, self.EMERGENCY},
            self.RECOVERY_APPROVED: {self.ARMING, self.EMERGENCY, self.ISOLATED},
        }
```

### 実行した試験と実測結果（全49通り：`transition_to`）
独立した一時状態ファイル（`/tmp/mk1_audit_7x7_*/state_<FROM>_<TO>.json`）を49個生成し、各初期状態に到達させた上で49通りすべてを実行・計測しました。

| # | From State | To State | 仕様期待 | `transition_to` 実測 | 遷移前→後 gen | 実行後状態 | 所要時間 (μs) | 判定 |
|---|---|---|---|---|---|---|---|---|
| 01 | `OFF` | `OFF` | 同一状態(No-op) | 成功 (True) | 0 → 0 | `OFF` | 8.35 | PASS |
| 02 | `OFF` | `ARMING` | 許可 | 成功 (永続化) | 0 → 1 | `ARMING` | 654.53 | PASS |
| 03 | `OFF` | `ACTIVE` | 禁止 | `RuntimeError` | 0 → 0 | `OFF` | 146.43 | PASS |
| 04 | `OFF` | `EMERGENCY` | 禁止 | `RuntimeError` | 0 → 0 | `OFF` | 105.04 | PASS |
| 05 | `OFF` | `ISOLATED` | 禁止 | `RuntimeError` | 0 → 0 | `OFF` | 83.70 | PASS |
| 06 | `OFF` | `RECOVERY_PENDING` | 禁止 | `RuntimeError` | 0 → 0 | `OFF` | 55.50 | PASS |
| 07 | `OFF` | `RECOVERY_APPROVED` | 禁止 | `RuntimeError` | 0 → 0 | `OFF` | 33.72 | PASS |
| 08 | `ARMING` | `OFF` | 許可 | 成功 (永続化) | 1 → 2 | `OFF` | 693.41 | PASS |
| 09 | `ARMING` | `ARMING` | 同一状態(No-op) | 成功 (True) | 1 → 1 | `ARMING` | 4.15 | PASS |
| 10 | `ARMING` | `ACTIVE` | 許可 | 成功 (永続化) | 1 → 2 | `ACTIVE` | 949.91 | PASS |
| 11 | `ARMING` | `EMERGENCY` | 許可 | 成功 (永続化) | 1 → 2 | `EMERGENCY` | 350.20 | PASS |
| 12 | `ARMING` | `ISOLATED` | 禁止(EMERGENCY経由) | `RuntimeError` | 1 → 1 | `ARMING` | 73.36 | PASS |
| 13 | `ARMING` | `RECOVERY_PENDING` | 禁止 | `RuntimeError` | 1 → 1 | `ARMING` | 40.45 | PASS |
| 14 | `ARMING` | `RECOVERY_APPROVED` | 禁止 | `RuntimeError` | 1 → 1 | `ARMING` | 66.65 | PASS |
| 15 | `ACTIVE` | `OFF` | 許可 | 成功 (永続化) | 2 → 3 | `OFF` | 264.28 | PASS |
| 16 | `ACTIVE` | `ARMING` | 禁止 | `RuntimeError` | 2 → 2 | `ACTIVE` | 75.83 | PASS |
| 17 | `ACTIVE` | `ACTIVE` | 同一状態(No-op) | 成功 (True) | 2 → 2 | `ACTIVE` | 3.10 | PASS |
| 18 | `ACTIVE` | `EMERGENCY` | 許可 | 成功 (永続化) | 2 → 3 | `EMERGENCY` | 391.95 | PASS |
| 19 | `ACTIVE` | `ISOLATED` | 許可(直接/評価用) | 成功 (永続化) | 2 → 3 | `ISOLATED` | 413.34 | PASS |
| 20 | `ACTIVE` | `RECOVERY_PENDING` | 禁止 | `RuntimeError` | 2 → 2 | `ACTIVE` | 79.12 | PASS |
| 21 | `ACTIVE` | `RECOVERY_APPROVED` | 禁止 | `RuntimeError` | 2 → 2 | `ACTIVE` | 73.86 | PASS |
| 22 | `EMERGENCY` | `OFF` | 禁止 | `RuntimeError` | 3 → 3 | `EMERGENCY` | 68.39 | PASS |
| 23 | `EMERGENCY` | `ARMING` | 禁止 | `RuntimeError` | 3 → 3 | `EMERGENCY` | 51.40 | PASS |
| 24 | `EMERGENCY` | `ACTIVE` | 禁止 | `RuntimeError` | 3 → 3 | `EMERGENCY` | 230.80 | PASS |
| 25 | `EMERGENCY` | `EMERGENCY` | 同一状態(No-op) | 成功 (True) | 3 → 3 | `EMERGENCY` | 4.06 | PASS |
| 26 | `EMERGENCY` | `ISOLATED` | 許可 | 成功 (永続化) | 3 → 4 | `ISOLATED` | 466.66 | PASS |
| 27 | `EMERGENCY` | `RECOVERY_PENDING` | 禁止 | `RuntimeError` | 3 → 3 | `EMERGENCY` | 68.63 | PASS |
| 28 | `EMERGENCY` | `RECOVERY_APPROVED` | 禁止 | `RuntimeError` | 3 → 3 | `EMERGENCY` | 108.06 | PASS |
| 29 | `ISOLATED` | `OFF` | 禁止 | `RuntimeError` | 4 → 4 | `ISOLATED` | 70.43 | PASS |
| 30 | `ISOLATED` | `ARMING` | 禁止 | `RuntimeError` | 4 → 4 | `ISOLATED` | 64.83 | PASS |
| 31 | `ISOLATED` | `ACTIVE` | 禁止 | `RuntimeError` | 4 → 4 | `ISOLATED` | 67.72 | PASS |
| 32 | `ISOLATED` | `EMERGENCY` | 禁止 | `RuntimeError` | 4 → 4 | `ISOLATED` | 72.49 | PASS |
| 33 | `ISOLATED` | `ISOLATED` | 同一状態(No-op) | 成功 (True) | 4 → 4 | `ISOLATED` | 5.38 | PASS |
| 34 | `ISOLATED` | `RECOVERY_PENDING` | 許可 | 成功 (永続化) | 4 → 5 | `RECOVERY_PENDING` | 291.67 | PASS |
| 35 | `ISOLATED` | `RECOVERY_APPROVED` | 禁止 | `RuntimeError` | 4 → 4 | `ISOLATED` | 48.71 | PASS |
| 36 | `RECOVERY_PENDING` | `OFF` | 禁止 | `RuntimeError` | 5 → 5 | `RECOVERY_PENDING` | 67.22 | PASS |
| 37 | `RECOVERY_PENDING` | `ARMING` | 禁止 | `RuntimeError` | 5 → 5 | `RECOVERY_PENDING` | 81.79 | PASS |
| 38 | `RECOVERY_PENDING` | `ACTIVE` | 禁止 | `RuntimeError` | 5 → 5 | `RECOVERY_PENDING` | 66.95 | PASS |
| 39 | `RECOVERY_PENDING` | `EMERGENCY` | 許可(P0割込) | 成功 (永続化) | 5 → 6 | `EMERGENCY` | 282.70 | PASS |
| 40 | `RECOVERY_PENDING` | `ISOLATED` | 許可(復旧失敗/再隔離)| 成功 (永続化) | 5 → 6 | `ISOLATED` | 294.30 | PASS |
| 41 | `RECOVERY_PENDING` | `RECOVERY_PENDING` | 同一状態(No-op) | 成功 (True) | 5 → 5 | `RECOVERY_PENDING` | 11.22 | PASS |
| 42 | `RECOVERY_PENDING` | `RECOVERY_APPROVED` | 許可 | 成功 (永続化) | 5 → 6 | `RECOVERY_APPROVED` | 299.82 | PASS |
| 43 | `RECOVERY_APPROVED` | `OFF` | 禁止 | `RuntimeError` | 6 → 6 | `RECOVERY_APPROVED` | 75.09 | PASS |
| 44 | `RECOVERY_APPROVED` | `ARMING` | 許可(再ARMING必須) | 成功 (永続化) | 6 → 7 | `ARMING` | 301.55 | PASS |
| 45 | `RECOVERY_APPROVED` | `ACTIVE` | 禁止(ARMING省略不可)| `RuntimeError` | 6 → 6 | `RECOVERY_APPROVED` | 76.36 | PASS |
| 46 | `RECOVERY_APPROVED` | `EMERGENCY` | 許可(P0割込) | 成功 (永続化) | 6 → 7 | `EMERGENCY` | 308.21 | PASS |
| 47 | `RECOVERY_APPROVED` | `ISOLATED` | 許可(P0割込) | 成功 (永続化) | 6 → 7 | `ISOLATED` | 293.19 | PASS |
| 48 | `RECOVERY_APPROVED` | `RECOVERY_PENDING` | 禁止 | `RuntimeError` | 6 → 6 | `RECOVERY_APPROVED` | 81.56 | PASS |
| 49 | `RECOVERY_APPROVED` | `RECOVERY_APPROVED` | 同一状態(No-op) | 成功 (True) | 6 → 6 | `RECOVERY_APPROVED` | 3.87 | PASS |

### `transition_to()` と `isolate_immediately()` の重要な差異（不具合発見）
- `airgap_ai_defender.py` 820〜826行において、`isolate_immediately(simulated=False)` は現在の状態が `OFF`（`EMERGENCY` への遷移が `_allowed_transitions` に含まれない状態）であっても、824〜825行の `else: self._state = self.EMERGENCY; self._generation += 1` により直接メモリ上の状態を書き換えて `ISOLATED` へ強制遷移します（このとき `_max_observed_generation` や `_ONI_MODE_ACTIVE` は更新されません）。
- 一方、829〜834行の `isolate_immediately(simulated=True)` では `else` 分岐が存在せず、直接 `self._transition_to_locked(self.EMERGENCY, simulated=True)` を呼ぶため、`OFF` 状態から Dry-Run で `isolate_immediately(simulated=True)` を呼ぶと `RuntimeError: Invalid FSM transition from OFF to EMERGENCY` が送出されてクラッシュします。

---

## D. 実稼働FSM永続化検証（F-01）

### 確認したコード
- `airgap_ai_defender.py` 472〜496行 (`MK1SafetyStateMachine.__init__`)
- `airgap_ai_defender.py` 618〜620行 (`_load_persistent_state`)
- `airgap_ai_defender.py` 942〜954行（実稼働グローバルインスタンス `_SAFETY_FSM` の初期化）

```python
942: _SAFETY_FSM = MK1SafetyStateMachine()
...
949:     # Default to ACTIVE via strict OFF -> ARMING -> ACTIVE startup sequence
950:     try:
951:         _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ARMING, reason="Startup")
952:         _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ACTIVE, reason="Startup Complete")
953:     except Exception:
954:         pass
```

### 実行した試験・実測結果・判定

| 試験ID | 試験条件 | 実測結果（出力ログ） | 判定 |
|---|---|---|---|
| **TEST-FSM-PERSIST-001** | デフォルト引数 `MK1SafetyStateMachine()` の初期化とステータス確認 | `state=OFF, gen=0, state_path=None, report={'FSM_AUTHENTICITY': 'UNVERIFIED', 'GENERATION': 0, 'ROLLBACK_PROTECTION': 'UNAVAILABLE', 'RECOVERY_STATUS': 'OFF'}` | **FAIL** (本番 `_SAFETY_FSM` に永続化パスもジャーナルも未設定) |
| **TEST-FSM-PERSIST-002** | `state_path` 指定時の `ACTIVE` 永続化と再起動復元 | `state=ACTIVE, gen=2, auth=VERIFIED` | **PASS** (パス指定時のみ) |
| **TEST-FSM-PERSIST-003** | `ISOLATED` 状態でのプロセス再起動（①テスト用パス指定FSM、②本番 `_SAFETY_FSM`） | ①テスト用: `state=ISOLATED, gen=4, restore_us=174.16` / ②本番 `_SAFETY_FSM`: 再起動前 `ISOLATED` → サブプロセス再起動後 **`ACTIVE (gen=2, state_path=None)`** | **FAIL (P0)** (`FINDING-P0-001`: 本番FSMは再起動で隔離が解除され `ACTIVE` に戻る) |
| **TEST-FSM-PERSIST-004** | `ISOLATED (gen=4)` で永続化後、状態ファイル (`p004.json`) のみを削除し、`.gen_journal` を残して再起動 | `loaded_state=OFF, gen=0, auth=UNVERIFIED`（619行 `if not os.path.isfile(self._state_path): return` によりジャーナルを一切確認せず `OFF` で初期化され、そのまま `ARMING -> ACTIVE` へ遷移可能） | **FAIL (P0)** (`FINDING-P0-004`) |
| **TEST-FSM-PERSIST-005** | `ISOLATED (gen=4)` 到達後、`.gen_journal` を削除し、過去の正規 `ACTIVE (gen=2)` 状態ファイルを配置して再起動 | `loaded_state=ACTIVE, gen=2, auth=VERIFIED`（540行でジャーナル不在時に `0` を返すため Rollback 検知が無効化され `ACTIVE` に復帰） | **FAIL (P0)** (`FINDING-P0-004`) |
| **TEST-FSM-PERSIST-006** | 永続化障害 (`_simulate_persistence_failure=True`) 発生中に `isolate_immediately()` を実行し、その後再起動 | `iso_ret=True, mem_state=ISOLATED, disk_state=ACTIVE, restarted_state=ACTIVE`（774行で永続化失敗を無視して `True` を返し、ディスク上は `ACTIVE` のまま残る） | **FAIL (P1)** (`FINDING-P1-002`) |
| **TEST-FSM-PERSIST-007** | `hmac_key` 引数・環境変数 `MK1_FSM_HMAC_KEY` ともに未設定時の動作 | `key=b'MK1AI-FSM-SECRET-KEY-V3'`（475行でソースコード内ハードコード鍵へフォールバック） | **FAIL (P1)** (`FINDING-P1-001`) |
| **TEST-FSM-PERSIST-008** | 環境変数 `MK1_FSM_HMAC_KEY` に異なる鍵を指定して再起動 | `state=ISOLATED, auth=FAILED_HMAC`（Fail-Closedにより `ISOLATED` 固定） | **PASS** |

---

## E. Dry-Run完全分離検証（F-02）

### 確認したコード
- `airgap_ai_defender.py` 478〜482行 (`_strict_dry_run_isolation` 初期値決定ロジック)
- `airgap_ai_defender.py` 726〜753行 (`_transition_to_locked` の `simulated=True` 分岐)
- `airgap_ai_defender.py` 6358〜6377行 (`evaluate_threat_state` の `effective_dry_run` 分岐)

```python
478:         self._strict_dry_run_isolation = (
479:             bool(strict_dry_run_isolation)
480:             if strict_dry_run_isolation is not None
481:             else (state_path is not None)
482:         )
...
736:             if not self._strict_dry_run_isolation:
737:                 self._state = new_state
738:                 self._last_transition = ts
```

### 実行した試験・実測結果・判定

| 試験ID | 試験条件 | 実測結果 | 判定 |
|---|---|---|---|
| **TEST-FSM-DRY-001** | 本番グローバル `_SAFETY_FSM` で Dry-Run (`dry_run=True, autonomous=True`) を実行 | `_SAFETY_FSM._state` が `ACTIVE` から **`ISOLATED`** に書き換わり、`_last_transition` も変更、`audit['production_state_changed'] = True` | **FAIL (P0)** (`FINDING-P0-002`: 本番FSMがDry-Runで汚染される) |
| **TEST-FSM-DRY-002** | `strict_dry_run_isolation=True` のテストFSMで `ACTIVE -> EMERGENCY` 予測遷移 | `_state=ACTIVE`, `_simulated_state=EMERGENCY`, `gen` 不変 | **PASS** (`strict_dry_run_isolation=True` 明示時のみ) |
| **TEST-FSM-DRY-003** | `strict_dry_run_isolation=True` のテストFSMで `ISOLATED` への予測遷移 | `_state=ACTIVE`, `_simulated_state=ISOLATED`, `gen` 不変 | **PASS** (`strict_dry_run_isolation=True` 明示時のみ) |
| **TEST-FSM-DRY-004** | Dry-Run終了後の本番状態・永続化ファイル・ジャーナルのSHA-256比較 | テストFSM（`state_path` あり）ではバイト列完全一致。本番 `_SAFETY_FSM`（`state_path=None`）では本番 `_state` が `ISOLATED` のまま残留 | **FAIL (P0)** (本番 `_SAFETY_FSM` で本番状態が変更される) |
| **TEST-FSM-DRY-005** | Dry-Run実行直後に本物のP0イベント (`dry_run=False`) が発生 | クールダウン (`_LAST_KILL_SWITCH_TRIGGER`) は汚染されないが、本番 `_SAFETY_FSM` ではDry-Run時点で既に `_state=ISOLATED` になっている | **FAIL (P1)** |
| **TEST-FSM-DRY-006** | `state_path=None` の場合（実稼働 `_SAFETY_FSM` のデフォルト） | `_strict_dry_run_isolation` が自動的に `False` となり、Dry-Runが `_state`, `_last_transition`, `_ISOLATION_APPROVAL_PENDING` をすべて書き換える | **FAIL (P0)** (`FINDING-P0-002`) |
| **TEST-FSM-DRY-007** | `strict_dry_run_isolation=False` の場合 | `_state` がシミュレーション遷移で直接書き換わる | **FAIL (P0)** (`strict_dry_run_isolation=False` モード自体が危険) |
| **TEST-FSM-DRY-008** | 本番設定 (`_SAFETY_FSM`) とテスト設定 (`test_v3_final.py`) の比較 | `test_v3_final.py` は `strict_dry_run_isolation=True` を明示渡ししてPASSさせている一方、`test_v3_remediation.py` (72〜100行) は `dry_run=True` で `_SAFETY_FSM.current_state == ISOLATED` を期待しているため、互換性維持のために本番 `_SAFETY_FSM` のDry-Run分離が無効化されている | **FAIL (P0)** |

---

## F. 緊急隔離とRecovery競合検証（F-03）

### 確認したコード
- `airgap_ai_defender.py` 848〜940行 (`request_recovery`)
- `airgap_ai_defender.py` 511〜529行 (`_TimedLockContext` / `_acquire_lock`)

```python
848:         with self._acquire_lock():
849:             if self._state != self.ISOLATED:
...
855:                 self._transition_to_locked(self.RECOVERY_PENDING, reason="Recovery Requested")
...
897:                 verification = verify_quorum_bundle(...)
...
915:                 self._transition_to_locked(self.RECOVERY_APPROVED, reason="M-of-N Met")
...
929:                 self._transition_to_locked(self.ARMING, reason="System Re-Arming After Recovery")
930:                 self._transition_to_locked(self.ACTIVE, reason="Restoration Complete")
```

### 実行した試験・イベントトレース実測結果・判定
`request_recovery()` 実行中のスレッドAと、P0検知により `isolate_immediately()` を呼び出すスレッドBの競合をミリ秒単位のイベントトレースで計測しました（`tests/test_v3_final.py` 252行のような事後の人為的 `isolate_immediately()` 呼び出しは一切行っていません）。

#### 実測イベントトレースログ（`TEST-FSM-RACE-003/004/005`）
```text
[  0.583 ms] THREAD_A_START_RECOVERY
[  1.783 ms] TRANSITION->RECOVERY_PENDING (gen=5, reason=Recovery Requested)
[  1.868 ms] QUORUM_VERIFY_START (inside request_recovery, lock held)
[  1.912 ms] THREAD_B_P0_DETECTED_CALLING_ISOLATE
[ 60.533 ms] QUORUM_VERIFY_END
[ 61.285 ms] TRANSITION->RECOVERY_APPROVED (gen=6, reason=M-of-N Met)
[ 61.827 ms] TRANSITION->ARMING (gen=7, reason=System Re-Arming After Recovery)
[ 62.204 ms] TRANSITION->ACTIVE (gen=8, reason=Restoration Complete)
[ 62.283 ms] THREAD_A_END_RECOVERY (ok=True, state=ACTIVE)
[ 63.387 ms] TRANSITION->EMERGENCY (gen=9, reason=P0 during recovery)
[ 63.859 ms] TRANSITION->ISOLATED (gen=10, reason=P0 during recovery)
[ 63.877 ms] THREAD_B_ISOLATE_COMPLETED (ok=True, wait_ms=61.961, state=ISOLATED)
```

| 試験ID | 試験条件 | 実測結果 | 判定 |
|---|---|---|---|
| **TEST-FSM-RACE-001** | 手動で `RECOVERY_PENDING` に遷移後、単一スレッドで `isolate_immediately()` | `state=ISOLATED, gen=7, dt=730.89us` | **PASS** (ロック非保持時のみ) |
| **TEST-FSM-RACE-002** | 手動で `RECOVERY_APPROVED` に遷移後、単一スレッドで `isolate_immediately()` | `state=ISOLATED, gen=8, dt=802.75us` | **PASS** (ロック非保持時のみ) |
| **TEST-FSM-RACE-003** | `request_recovery()` のM-of-N署名検証中（`1.912 ms`）に別スレッドでP0検知・`isolate_immediately()` 呼び出し | `request_recovery()` が `self._lock` を保持し続けているため、P0発生後も `RECOVERY_APPROVED -> ARMING -> ACTIVE`（`62.204 ms`）まで遷移を強行し、`request_recovery()` が **`True`（復旧成功の誤報）** を返した後にようやく隔離スレッドがロックを取得（待機遅延 `61.961 ms`） | **FAIL (P0)** (`FINDING-P0-003`) |
| **TEST-FSM-RACE-004** | `isolate_immediately()` が `request_recovery()` の直前にロックを取得する競合ケース（事後の強制隔離なし） | `isolate_immediately()` は既に `ISOLATED` であるため即座に `True` を返し、直後にロックを取得した `request_recovery()` がそのまま実行されて **最終状態が `ACTIVE`（隔離解除！）** になる (`rec_ok=True, final_state=ACTIVE`) | **FAIL (P0)** (`FINDING-P0-003`: 既存テストは252行で事後強制隔離して隠蔽していた) |
| **TEST-FSM-RACE-005** | `ARMING` から `ACTIVE` へ移行する直前にP0を検知 | `request_recovery()` 内部ではロックが解放されないため、`ACTIVE` への遷移を阻止できない | **FAIL (P0)** (`FINDING-P0-003`) |
| **TEST-FSM-RACE-006** | `ACTIVE` へ復旧完了した直後にP0を検知 | `state=ISOLATED` へ遷移（所要時間 平均 `660.01 μs`） | **PASS** |
| **TEST-FSM-RACE-007** | 復旧処理と16スレッドの緊急隔離要求を同時競合 | 16スレッドがロック解放待ちとなり、ロック取得順序次第で `request_recovery()` が最後に走ると `ACTIVE` になるか、ロック待ち合計時間が `_lock_timeout_sec` を超えると `TimeoutError` が発生する | **FAIL (P0)** (`FINDING-P0-003`) |
| **TEST-FSM-RACE-008** | ロック取得タイムアウト中（他スレッドが `_lock_timeout_sec` 以上ロック保持中）に `isolate_immediately()` を要求 | `TimeoutError: FSM lock acquisition timed out (potential deadlock prevented)` が送出され、**緊急隔離が失敗して `state_after=ACTIVE` のまま残る** | **FAIL (P0)** (`FINDING-P0-003`) |

---

## G. HMAC・Rollback検証（F-04）

### 確認したコード
- `airgap_ai_defender.py` 539〜676行 (`_read_journal_max_generation`, `_write_journal_max_generation`, `_save_persistent_state`, `_load_persistent_state`)

### 実行した試験・実測結果・判定（全22ケース）

| 試験ID | 試験条件 | 実測結果 | 判定 |
|---|---|---|---|
| **TEST-FSM-STORAGE-001** | 正常なstateファイルとjournalの復元 | `state=ACTIVE, gen=2, auth=VERIFIED` | **PASS** |
| **TEST-FSM-STORAGE-002** | 不正なHMAC (`"0"*64`) | `state=ISOLATED, auth=FAILED_HMAC` | **PASS** |
| **TEST-FSM-STORAGE-003** | 古い正規状態ファイルの再投入（journal残存時） | `state=ISOLATED, auth=FAILED_ROLLBACK` | **PASS** |
| **TEST-FSM-STORAGE-004** | generation改竄＋HMAC再計算（journal残存時） | `state=ISOLATED, auth=FAILED_ROLLBACK` | **PASS** |
| **TEST-FSM-STORAGE-005** | `generation` フィールド欠落 | `state=ISOLATED, auth=FAILED_LOAD` | **PASS** |
| **TEST-FSM-STORAGE-006** | `state` フィールド欠落 | `state=ISOLATED, auth=FAILED_LOAD` | **PASS** |
| **TEST-FSM-STORAGE-007** | `timestamp` 異常値（`-999999999.0` 等の負数や未来時刻） | `state=ACTIVE, ts=-999999999.0, auth=VERIFIED`（634行は `isinstance(ts, (int, float))` のみで範囲・有限性・bool除外を未検証） | **FAIL (P2)** (`FINDING-P2-002`) |
| **TEST-FSM-STORAGE-008** | 不正なJSON (`"{not_json"`) | `state=ISOLATED, auth=FAILED_LOAD` | **PASS** |
| **TEST-FSM-STORAGE-009** | 途中で切断されたファイル | `state=ISOLATED, auth=FAILED_LOAD` | **PASS** |
| **TEST-FSM-STORAGE-010** | 空ファイル (`""`) | `state=ISOLATED, auth=FAILED_LOAD` | **PASS** |
| **TEST-FSM-STORAGE-011** | journal欠損（削除）状態で古い `ACTIVE` stateファイルを読込 | `state=ACTIVE, auth=VERIFIED, rollback_status=VERIFIED_JOURNAL`（540行でjournal不在時に `0` を返し、しかも `_rollback_protection_status` は `"VERIFIED_JOURNAL"` と虚偽報告する） | **FAIL (P0)** (`FINDING-P0-004`) |
| **TEST-FSM-STORAGE-012** | stateファイル欠損（journalに `ISOLATED, gen=4` が残存） | `state=OFF, gen=0, auth=UNVERIFIED`（619行でstate不在時に即returnし、journalの `ISOLATED` 記録を無視） | **FAIL (P0)** (`FINDING-P0-004`) |
| **TEST-FSM-STORAGE-013** | stateとjournalの同世代状態不一致（`gen=4` でjournalは `ISOLATED`、stateは `ACTIVE`） | `state=ACTIVE, auth=VERIFIED`（`_read_journal_max_generation` が `last_state` を捨てて `max_gen` しか返さないため、状態不一致を検出できない） | **FAIL (P1)** (`FINDING-P1-003`) |
| **TEST-FSM-STORAGE-014** | journal MAC改竄 | `state=ISOLATED, auth=FAILED_ROLLBACK`（`2**62` を返しFail-Closed） | **PASS** |
| **TEST-FSM-STORAGE-015** | journalだけ残された状態（= STORAGE-012と同一構造） | `state=OFF, gen=0, auth=UNVERIFIED` | **FAIL (P0)** (`FINDING-P0-004`) |
| **TEST-FSM-STORAGE-016** | stateだけ残された状態（= STORAGE-011と同一構造） | `state=ACTIVE, auth=VERIFIED`（journal削除によるRollback耐性喪失を検知不能） | **FAIL (P0)** (`FINDING-P0-004`) |
| **TEST-FSM-STORAGE-017** | `ISOLATED` 後にstateとjournalの両方が削除された状態 | `state=OFF, gen=0, auth=UNVERIFIED`（既存状態ファイルの必須チェックオプションが存在しない） | **FAIL (P1)** (`FINDING-P0-004`) |
| **TEST-FSM-STORAGE-018** | 同一世代への状態差し替え（固定HMAC鍵悪用時） | デフォルト固定鍵 `b"MK1AI-FSM-SECRET-KEY-V3"` を用いて同一 `generation` の `ACTIVE` ペイロードを生成すると `VERIFIED` で通過 | **FAIL (P1)** (`FINDING-P1-001`, `FINDING-P1-003`) |
| **TEST-FSM-STORAGE-019** | `state` の `os.replace()` 成功直後に `journal` 書き込みが失敗 | `mem_state=ACTIVE (gen=2)` にロールバックされるが、ディスク上の `state_path` は **`disk_state=OFF (disk_gen=3)` のまま書き換えられ、メモリ・state・journal間でスプリットブレインが発生** | **FAIL (P1)** (`FINDING-P1-002`) |
| **TEST-FSM-STORAGE-020** | `os.replace()` 失敗 | `RuntimeError` 送出、`mem_state=ACTIVE, mem_gen=2` にロールバック（ただし `isolate_immediately` 時はエラーを握り潰す） | **PASS** (非隔離遷移時) / **FAIL** (隔離遷移時) |
| **TEST-FSM-STORAGE-021** | 再起動中の永続化障害 | 読込エラー時は `FAILED_LOAD` で `ISOLATED` に移行 | **PASS** |
| **TEST-FSM-STORAGE-022** | 複数プロセスによる同時書き込み | 下掲 F-05 にて詳細報告：`.tmp` ファイル衝突と世代逆転により破損 | **FAIL (P1)** (`FINDING-P1-004`) |

---

## H. プロセス間競合検証（F-05）

### 確認したコード
- `airgap_ai_defender.py` 488行 (`self._lock = threading.RLock()` — スレッド内ロックのみ、OSレベルの `fcntl.flock` なし)
- `airgap_ai_defender.py` 577〜580行 (`tmp_j = self._journal_path + ".tmp"` — PIDを含まない固定一時ファイル名)
- `airgap_ai_defender.py` 606〜609行 (`tmp_path = self._state_path + ".tmp"` — PIDを含まない固定一時ファイル名)

### 実行した試験と実測結果
`multiprocessing.Process` を用い、独立した4つのOSプロセス（`Proc 0` 〜 `Proc 3`）から同一の `sp_mp` (`/tmp/mk1_f05_*/mp_fsm.json`) およびジャーナルに対して同時に各15回の状態更新を実行しました。

```text
Proc 0: successes=15, errors=0 ([])
Proc 1: successes=14, errors=1 (['RuntimeError: FSM state persistence failed during transition OFF -> ARMING'])
Proc 2: successes=14, errors=1 (['RuntimeError: FSM state persistence failed during transition ACTIVE -> OFF'])
Proc 3: successes=14, errors=1 (['RuntimeError: FSM state persistence failed during transition ACTIVE -> OFF'])
Final MP reload: state=ISOLATED, auth=FAILED_ROLLBACK, state_gen=4, journal_max_gen=5
```

- **発生した現象（実証）:**
  1. 4プロセスすべてが同一の `.tmp` ファイル名 (`mp_fsm.json.tmp` / `mp_fsm.json.gen_journal.tmp`) に同時に書き込むため、あるプロセスが `os.replace(tmp_path, self._state_path)` を実行した直後に別プロセスが `os.replace()` を呼ぶと `FileNotFoundError` となり、`RuntimeError: FSM state persistence failed` が3プロセスで発生しました。
  2. さらに、`state_path` の置換と `journal_path` の置換がプロセス間でインターリーブした結果、最終的な `state_path` の世代が `state_gen=4` であるのに対し、`journal_path` の最大世代が `journal_max_gen=5` となり、再読み込み時に **`FAILED_ROLLBACK` (`Rollback: 4 < 5`) として永続状態が恒久的に破損**しました。
- **判定:** **`FAIL (P1)`** (`FINDING-P1-004`)

---

## I. M-of-N Quorum検証（F-06）

### 確認したコード
- `airgap_ai_defender.py` 862〜940行 (`request_recovery`)
- `mk1_quorum.py` 512〜556行 (`verify_quorum_bundle`)

```python
863: req_event_id = expected_event_id if expected_event_id is not None else self._active_isolation_event_id
864: req_challenge_id = expected_challenge_id if expected_challenge_id is not None else self._active_challenge_id
865: params = challenge_document.get("parameters") if isinstance(challenge_document.get("parameters"), dict) else {}
866: doc_event_id = challenge_document.get("event_id", params.get("event_id"))
867: doc_challenge_id = challenge_document.get("challenge_id", params.get("challenge_id"))
868: 
869: if req_event_id is not None and doc_event_id != req_event_id:
870:     raise ValueError(f"Recovery event_id mismatch: expected {req_event_id}, got {doc_event_id}")
871: if req_challenge_id is not None and doc_challenge_id != req_challenge_id:
872:     raise ValueError(f"Recovery challenge_id mismatch: expected {req_challenge_id}, got {doc_challenge_id}")
873: 
874: # Enforce policy version and domain prefix
875: policy_version = challenge_document.get("policy_version", params.get("policy_version", challenge_document.get("version", 1)))
876: if isinstance(policy_version, bool) or policy_version != expected_policy_version:
877:     raise ValueError(f"Unsupported recovery policy_version: {policy_version}")
878: prefix = challenge_document.get("prefix")
879: if prefix is not None and prefix != "MK1AI-RECOVERY-v1":
880:     raise ValueError(f"Invalid recovery domain prefix: {prefix}")
```

### 実行した試験・実測結果・判定（全25ケース）

| ケース# | 試験内容 | 実測結果 (`request_recovery` 戻り値 / 最終状態) | 判定 |
|---|---|---|---|
| **Q-01** | 正しい2名のEd25519署名 (2-of-3) | `True` / `ACTIVE` | **PASS** |
| **Q-02** | 1名のみの署名 (1-of-3) | `False` / `ISOLATED` | **PASS** |
| **Q-03** | 正しい3名の署名 (3-of-3) | `True` / `ACTIVE` | **PASS** |
| **Q-04** | 同一署名者 (`admin_1` × 2) の重複署名 | `False` / `ISOLATED` | **PASS** |
| **Q-05** | 信頼されていない公開鍵 (`rogue_1`) の署名 | `False` / `ISOLATED` | **PASS** |
| **Q-06** | 改竄された署名バイト列 | `False` / `ISOLATED` | **PASS** |
| **Q-07** | 署名後の `challenge_document` 改竄 | `False` / `ISOLATED` | **PASS** |
| **Q-08** | 期限切れ (`now > expires_at`) のchallenge | `False` / `ISOLATED` | **PASS** |
| **Q-09** | 将来時刻 (`issued_at = now + 86400`) のchallenge | **`True` / `ACTIVE`** (`verify_quorum_bundle` が `issued_at > now` を未チェック) | **FAIL (P2)** (`FINDING-P2-001`) |
| **Q-10** | `event_id` 不一致（期待値設定時） | `False` / `ISOLATED` | **PASS** |
| **Q-11** | `challenge_id` 不一致（期待値設定時） | `False` / `ISOLATED` | **PASS** |
| **Q-12** | `policy_version` 不一致 (`2 != 1`) | `False` / `ISOLATED` | **PASS** |
| **Q-13** | `prefix` 不一致 (`"MK1AI-ISOLATE-v1"`) | `False` / `ISOLATED` | **PASS** |
| **Q-14** | `event_id` 欠落（実稼働 `evaluate_threat_state` 経由で `_active_isolation_event_id=None` の場合） | **`True` / `ACTIVE`**（6385行が `event_id` を設定せず、869行が `if req_event_id is not None` のため完全バイパス） | **FAIL (P1)** (`FINDING-P1-005`) |
| **Q-15** | `challenge_id` 欠落（`_active_challenge_id=None` の場合） | **`True` / `ACTIVE`**（871行が `if req_challenge_id is not None` のため完全バイパス） | **FAIL (P1)** (`FINDING-P1-005`) |
| **Q-16** | `policy_version` 欠落 | **`True` / `ACTIVE`**（875行がスキーマ `version: 1` にフォールバックするため欠落を検出しない） | **FAIL (P1)** (`FINDING-P1-005`) |
| **Q-17** | ドメイン `prefix` 欠落（`prefix` キー削除） | **`True` / `ACTIVE`**（879行が `if prefix is not None` のため、`prefix` 欠落時にドメイン分離チェックがスキップされる） | **FAIL (P1)** (`FINDING-P1-005`) |
| **Q-18** | `issued_at` 欠落 | **`True` / `ACTIVE`**（`verify_quorum_bundle` が `issued_at` 必須チェックを行わない） | **FAIL (P1)** (`FINDING-P1-005`) |
| **Q-19** | `expires_at` 欠落 | **`True` / `ACTIVE`**（`mk1_quorum.py` 529行が `if isinstance(expires_at, int)` のため、`expires_at` を省略すると無期限の承認バンドルとして通過する） | **FAIL (P1)** (`FINDING-P1-005`) |
| **Q-20** | 使用済み承認バンドルの再利用 | `False` / `ISOLATED` | **PASS** |
| **Q-21** | 使用済み `challenge_id` の再利用 | `False` / `ISOLATED` | **PASS** |
| **Q-22** | 使用済み `event_id` の再利用 | `False` / `ISOLATED` | **PASS** |
| **Q-23** | プロセス再起動後の承認リプレイ（`state_path` 設定時） | `False` / `ISOLATED`（`consumed_tokens` がJSONから復元される。ただし本番 `_SAFETY_FSM` は `state_path=None` のため再起動で消失） | **PASS** (パス設定時) / **FAIL** (本番 `_SAFETY_FSM`) |
| **Q-24** | 承認検証成功後（`RECOVERY_APPROVED` 遷移時）の永続化失敗と再試行 (`Q-24B`) | 1回目: `False / ISOLATED`。しかし909〜913行で永続化成功前に `_consumed_recovery_tokens` にトークンを追加し、939行の `except` 内で保存してしまうため、ディスク復旧後の **2回目の再試行も `retry_same_bundle=False` で永久拒否（トークン焼失）** | **FAIL (P1)** (`FINDING-P1-006`) |
| **Q-25** | 同時復旧要求 | `RLock` により直列化され、2つ目の要求は `self._state != self.ISOLATED` またはリプレイ検知により `False` | **PASS** |

---

## J. 実稼働FSMとテストFSMの差異（F-08）

`airgap_ai_defender.py` 942行の本番グローバルインスタンス `_SAFETY_FSM` と、`tests/test_v3_final.py` 内で生成されるテスト用インスタンスの設定・保護機能の比較表です。

| 項目 | 実稼働FSM (`defender._SAFETY_FSM`) | テストFSM (`tests/test_v3_final.py`) | 安全上の影響・判定 |
|---|---|---|---|
| **生成コード** | `_SAFETY_FSM = MK1SafetyStateMachine()` (942行) | `MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key, strict_dry_run_isolation=True)` | **重大な乖離 (FAIL)** |
| **`state_path`** | **`None`（永続化完全無効）** | `/tmp/.../fsm_state.json` | **P0脆弱性**: 本番は再起動で隔離が消滅する |
| **`journal_path`** | **`None`（世代ジャーナル完全無効）** | `/tmp/.../fsm_state.json.gen_journal` | **P0脆弱性**: 本番はRollback保護が存在しない |
| **`hmac_key`** | **`b"MK1AI-FSM-SECRET-KEY-V3"`（ハードコード鍵）** | `"test-v3-secret-hmac-key-2026-sovereign-airgap"` | **P1脆弱性**: 環境変数未設定時に固定公開鍵を使用 |
| **`lock_timeout_sec`** | `2.0` 秒 | `2.0` 秒 | 同一（ただしタイムアウト時に隔離が例外失敗する） |
| **`strict_dry_run_isolation`** | **`False`**（`state_path is not None` が `False` のため） | **`True`** | **P0脆弱性**: 本番FSMではDry-Runが本番 `_state` を汚染する |
| **`FSM_AUTHENTICITY`** | **`"UNVERIFIED"`** | `"VERIFIED"` | 本番FSMは常時 `UNVERIFIED` |
| **`ROLLBACK_PROTECTION`** | **`"UNAVAILABLE"`** | `"VERIFIED_JOURNAL"` | 本番FSMは常時 `UNAVAILABLE` |
| **`recovery context` (`event_id`)** | `evaluate_threat_state` 呼び出し時に **`None` のまま** | テスト内で手動で `event_id="evt-001"` を注入 | **P1脆弱性**: 本番経路では `event_id` 束縛が空振りする |
| **`consumed_tokens` 永続化** | **メモリのみ（再起動で全消去）** | JSONファイルへ保存 | 本番FSMでは再起動後に承認バンドルのリプレイが可能 |

---

## K. 起動・再起動検証（F-09）

### 確認したコード
- `airgap_ai_defender.py` 657〜671行 (`_load_persistent_state` の状態復元)
- `airgap_ai_defender.py` 944〜954行（起動時シーケンス）

```python
944: if str(os.environ.get("ONI_MODE", "")).lower() in {"1", "true", "yes", "on"}:
945:     _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ARMING, reason="Startup")
946:     _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ACTIVE, reason="Environment Variable")
947:     _ONI_MODE_ACTIVE.set()
948: else:
949:     # Default to ACTIVE via strict OFF -> ARMING -> ACTIVE startup sequence
950:     try:
951:         _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ARMING, reason="Startup")
952:         _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ACTIVE, reason="Startup Complete")
953:     except Exception:
954:         pass
```

### 実行した試験・実測結果・判定
1. **本番 `_SAFETY_FSM` の再起動（正常終了後・異常終了後・`ISOLATED` 中の再起動）:**
   - `state_path=None` のため、いかなる状態（`ISOLATED`, `EMERGENCY`, `RECOVERY_PENDING`）で停止しても、再起動時には必ず `OFF -> ARMING -> ACTIVE` へ遷移し、**無条件で `ACTIVE` として稼働再開**します（**FAIL: P0**）。
2. **`state_path` を設定したFSMにおける中間状態（`EMERGENCY`, `RECOVERY_PENDING`, `RECOVERY_APPROVED`, `ARMING`）からの再起動:**
   - 実測結果：
     - `ARMING` 保存後再起動 → `restored state=ARMING (gen=1)`
     - `EMERGENCY` 保存後再起動 → `restored state=EMERGENCY (gen=3)`（`ISOLATED` へ自動収束せず `EMERGENCY` に滞留）
     - `RECOVERY_PENDING` 保存後再起動 → `restored state=RECOVERY_PENDING (gen=5)`（この状態からは `request_recovery()` が `self._state != self.ISOLATED` で拒否されるため、手動遷移なしでは復旧不能なデッドエンド状態に陥る）
     - `RECOVERY_APPROVED` 保存後再起動 → `restored state=RECOVERY_APPROVED (gen=6)`（もし起動コード951〜952行 `transition_to(ARMING) -> transition_to(ACTIVE)` が走ると、再起動時にそのまま `ACTIVE` に移行してしまう）
   - **判定:** **`FAIL (P2)`** (`FINDING-P2-003`)

---

## L. Kill Switch連携検証（F-10）

### 確認したコード
- `airgap_ai_defender.py` 6383〜6393行 (`evaluate_threat_state` の自律P0隔離処理)

```python
6383:             if autonomous:
6384:                 log.warning(f"[AUTONOMOUS_DEFENSE] P0脅威を検出し、自律隔離を開始します。理由: {', '.join(trigger_reasons)}")
6385:                 target_fsm.isolate_immediately(reason="Autonomous P0 Detection")
6386:                 
6387:                 success = execute_kill_switch(
6388:                     interface,
6389:                     False,
6390:                     autonomous_bypass=True,
6391:                     **management_route,
6392:                 )
6393:                 return bool(success or target_fsm.current_state == MK1SafetyStateMachine.ISOLATED)
```

### 実行した試験・実測結果・判定
- **試験条件 (`KS-01`):** `execute_kill_switch` をモックして `False`（OSレベルの遮断コマンド全失敗）を返させた状態で、`evaluate_threat_state(interface="eth0", dry_run=False, score_a=0.99, autonomous=True, fsm=f_ks)` を実行。
- **実測結果:**
  `KS-01 (execute_kill_switch returns False on autonomous P0): evaluate_threat_state returned=True, fsm.state=ISOLATED, _KILL_SWITCH_TRIGGERED=False, _KILL_SWITCH_EVENT.is_set()=True`
- **問題の詳細:**
  1. 6385行で `execute_kill_switch()` を呼ぶ**前**に `target_fsm.isolate_immediately()` を実行して論理FSMを `ISOLATED` にしているため、6393行の `return bool(success or target_fsm.current_state == MK1SafetyStateMachine.ISOLATED)` は **`execute_kill_switch()` が `False`（遮断完全失敗）であっても常に `True` を返します**。
  2. さらに、`evaluate_threat_state()` の自律隔離パス（6383〜6393行）およびQuorum隔離パス（6396〜6414行）のいずれも、グローバル変数 `_KILL_SWITCH_TRIGGERED = True` を更新していません。そのため、OS遮断が失敗したにもかかわらず論理FSMだけが `ISOLATED` になり、パネルステータス（7826行 `isolation_active=int(bool(_KILL_SWITCH_TRIGGERED))`）は `0` のままという重大な状態不一致（論理FSM `ISOLATED` vs 実ネットワーク未遮断 `isolation_active=0`）が発生します。
- **判定:** **`FAIL (P0)`** (`FINDING-P0-005`)

---

## M. 既存テスト品質評価（F-11）

`tests/test_v3_final.py`（33テスト）および `tests/test_v3_remediation.py`（7テスト）、さらに全テストスイート（`python3 -m unittest discover tests`：464テスト中5件FAIL）を精査した結果、以下の重大な問題を確認しました。

1. **競合テストにおける事後強制隔離による結果の捏造 (`tests/test_v3_final.py` 252行):**
   - `test_fsm_004_isolation_vs_recovery_race` の245〜253行：
     ```python
     t1.start()
     t2.start()
     t1.join(timeout=2.0)
     t2.join(timeout=2.0)

     fsm.isolate_immediately(reason="Final safety assertion")
     self.assertEqual(fsm.current_state, fsm.ISOLATED)
     ```
   - 競合スレッド `t1`, `t2` が終了した後に、**252行で無条件に `fsm.isolate_immediately(reason="Final safety assertion")` を呼び出してから `assertEqual(fsm.current_state, fsm.ISOLATED)` を判定**しています。これにより、競合の結果 `request_recovery()` が勝って `ACTIVE` に戻ってしまっていても、252行が強制的に `ISOLATED` に上書きするため絶対にFAILしない偽装テストになっていました。
2. **本番 `_SAFETY_FSM` とテスト用FSMのすり替え (`tests/test_v3_final.py` 全般):**
   - `test_v3_final.py` の永続化・Rollback・Dry-Runテストはすべて `MK1SafetyStateMachine(state_path=self.state_path, hmac_key=self.hmac_key, strict_dry_run_isolation=True)` というテスト専用インスタンスを生成して検査しており、本番の `defender._SAFETY_FSM`（`state_path=None, strict_dry_run_isolation=False`）を一切検査していませんでした。
3. **`tests/test_v3_remediation.py` (72〜100行) によるアンチパターンの固定化:**
   - `test_independent_head_a_trigger` 等が `dry_run=True` で `defender.evaluate_threat_state(...)` を呼び出し、`self.assertEqual(defender._SAFETY_FSM.current_state, MK1SafetyStateMachine.ISOLATED)`（Dry-Runなのに本番状態が `ISOLATED` になること）をアサートしているため、これをPASSさせるために `MK1SafetyStateMachine.__init__` 481行に `else (state_path is not None)` という危険な分岐が入れられていました。
4. **既存テストスイート全体の回帰テスト失敗（5件のFAIL）:**
   - `python3 -m unittest discover tests` を実行すると、`tests/test_airgap_ai_defender.py` で4件、`tests/test_xdp_ebpf_subsystem.py` で1件の計5件が現在FAILしています（`evaluate_threat_state` のシグネチャ・閾値変更や `toggle_oni_mode` のログ出力変更に伴う回帰不整合）。

---

## N. 故障注入と異常系検証（F-12）

| 故障注入ケース | 注入方法 | 実測された挙動・最終状態 | Fail-Closed判定 |
|---|---|---|---|
| **Lock Timeout** | 別スレッドでロック保持中に `lock_timeout_sec=0.05` で `isolate_immediately()` | `TimeoutError` が送出され、**`ACTIVE` のまま隔離失敗** | **FAIL (P0)** |
| **HMAC Failure** | `fsm_state.json` の `integrity` 改竄 | `FAILED_HMAC` により `ISOLATED` 固定 | **PASS** |
| **Journal MAC Failure** | `.gen_journal` の `journal_mac` 改竄 | `_read_journal_max_generation` が `2**62` を返し `FAILED_ROLLBACK` で `ISOLATED` 固定 | **PASS** |
| **Journal Deletion** | `.gen_journal` ファイル削除＋旧 `ACTIVE` state配置 | `_read_journal_max_generation` が `0` を返し **`ACTIVE` として通過** | **FAIL (P0)** |
| **State File Deletion** | `fsm_state.json` ファイル削除（journalは `ISOLATED`） | `_load_persistent_state` が即returnし **`OFF (gen=0)` として通過** | **FAIL (P0)** |
| **Disk Write Failure (Normal)** | `ACTIVE -> OFF` で `_simulate_persistence_failure=True` | `RuntimeError` 送出、メモリ状態を `ACTIVE (gen=2)` にロールバック | **PASS** |
| **Disk Write Failure (Isolation)** | `isolate_immediately()` で `_simulate_persistence_failure=True` | 例外を送出せず `True` を返却。メモリは `ISOLATED`、ディスクは `ACTIVE` の不一致 | **FAIL (P1)** |
| **Journal Write Failure After State Replace** | `_write_journal_max_generation` のみ `False` 返却 | メモリはロールバックされるが、ディスク上の `fsm_state.json` は新状態のままでスプリットブレイン化 | **FAIL (P1)** |
| **JSON Decode / Truncated / Empty** | 不正JSON・途中切断・0バイトファイル | `FAILED_LOAD` により `ISOLATED` 固定 | **PASS** |
| **Invalid State Name in JSON** | 未知の状態文字列 + 正しいHMAC | `FAILED_SCHEMA` により `ISOLATED` 固定 | **PASS** |
| **AI Score NaN / ±Inf / None / Out-of-Range** | `evaluate_threat_state` に `NaN`, `inf`, `-0.01`, `None` 注入 | `corrupted_scores=True` により `safe_score=1.0` となり自律隔離発動 | **PASS** |
| **Recovery Persistence Failure at Step 2** | `RECOVERY_APPROVED` 遷移時の保存のみ失敗させる | 状態は `ISOLATED` に戻るが、承認トークンが消費済みとして保存され再試行不能になる | **FAIL (P1)** |
| **Process Contention (4 procs)** | 4プロセス同時状態遷移・保存 | `.tmp` 競合により `RuntimeError` 発生、かつ `state_gen=4 < journal_max_gen=5` で `FAILED_ROLLBACK` 破損 | **FAIL (P1)** |

---

## O. 測定結果（Section 17：実測パフォーマンス・遅延データ）

- **試験環境:** Linuxコンテナ環境 (`/app/applet`, Python 3.10, `time.perf_counter()` によるマイクロ秒計測)
- **実行条件:** `/tmp/mk1_f09_f10_*` 一時ディレクトリ上の実ファイルI/O（`os.replace` による state + journal 保存を含む）

| 測定項目 | 実行回数 (N) | 最小値 (min) | 最大値 (max) | 平均値 (avg) | 備考・計測条件 |
|---|---|---|---|---|---|
| **FSM 7×7 状態遷移 (`transition_to`)** | 49回 | `3.10 μs` | `949.91 μs` | `172.04 μs` | No-op時最小 `3.10 μs`、永続化伴う遷移時 `264〜949 μs` |
| **RLock 取得時間 (`_acquire_lock`)** | 50回 | `3.67 μs` | `14.77 μs` | `8.42 μs` | 非競合時の `_TimedLockContext.__enter__` |
| **RLock 最小保持解放時間** | 50回 | `0.74 μs` | `2.04 μs` | `1.24 μs` | 空ブロックでの `__exit__` までの時間 |
| **HMAC-SHA256 計算 (`_compute_integrity`)** | 50回 | `14.98 μs` | `62.83 μs` | `32.44 μs` | state文字列 + timestamp + generation |
| **永続化保存 (`_save_persistent_state`)** | 50回 | `208.55 μs` | `1,382.59 μs` | `443.19 μs` | `fsm_state.json` + `.gen_journal` の2ファイル `.tmp` 書込 & `os.replace` |
| **再起動復元 (`_load_persistent_state`)** | 50回 | `152.93 μs` | `906.82 μs` | `212.71 μs` | state + journal 読込・HMAC検証・世代比較 |
| **P0緊急隔離 (`isolate_immediately`)** | 50回 | `391.21 μs` | `2,667.23 μs` | `660.01 μs` | `ACTIVE -> EMERGENCY -> ISOLATED`（計2回の永続化保存を含む） |
| **2-of-3 Ed25519 Quorum検証 (`verify_quorum_bundle`)** | 50回 | `6,866.72 μs` | `12,310.77 μs` | `7,927.21 μs` | PEM公開鍵ロード＋2名分のEd25519署名検証（約 `7.93 ms`） |
| **Recovery競合時のP0隔離待機遅延** | 実測トレース | - | `61,961.00 μs` | `61.96 ms` | `request_recovery` がロックを保持している間、`isolate_immediately` がブロックされた実測時間 |

*(注: リポジトリ内に「P0検知からISOLATEDまでの最大許容隔離時間」の数値定義は存在しないため、上記実測値のみを報告し、時間保証をPASSとは認定しません。特にロック競合時には最大 `_lock_timeout_sec = 2,000,000 μs (2.0秒)` 待機した挙げ句 `TimeoutError` で隔離失敗するため、リアルタイム保証は成立していません。)*

---

## P. 脆弱性一覧（P0〜P3：計15件）

### 【P0：重大（5件）】

#### 1. `FINDING-P0-001`：実稼働グローバルFSM (`_SAFETY_FSM`) の永続化・ジャーナル完全未設定による再起動時の隔離喪失
- **優先度:** **P0**
- **ファイル名・行番号:** `airgap_ai_defender.py` 942行〜954行
- **問題のあるコード:**
  ```python
  _SAFETY_FSM = MK1SafetyStateMachine()
  ...
  try:
      _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ARMING, reason="Startup")
      _SAFETY_FSM.transition_to(MK1SafetyStateMachine.ACTIVE, reason="Startup Complete")
  ```
- **発生条件:** 実稼働環境でP0脅威により `_SAFETY_FSM` が `ISOLATED` に移行した後、プロセス再起動・クラッシュ・OS再起動が発生した場合。
- **再現手順:** `defender._SAFETY_FSM.isolate_immediately()` 実行後、別プロセスで `airgap_ai_defender` をインポートして `_SAFETY_FSM.current_state` を確認する（`TEST-FSM-PERSIST-003B`）。
- **実測結果:** 再起動前は `ISOLATED` であったにもかかわらず、再起動後は `state_path=None` のためファイル復元が行われず、`ACTIVE (generation=2)` として起動する。
- **影響範囲・攻撃可能性・安全性への影響:** プロセスをクラッシュまたは再起動させるだけで `ISOLATED` 状態および消費済みトークン履歴が完全に消滅し、COREが未承認で `ACTIVE` に復帰する。
- **修正優先順位:** 最優先（第1順位）
- **修正方針:** 実稼働 `_SAFETY_FSM` にデフォルトの安全な永続化ファイルパス（例：`os.environ.get("MK1_FSM_STATE_PATH", "/var/lib/mk1ai/fsm_state.json")` またはデータディレクトリ配下）を設定し、起動時に既存の永続化状態が `OFF` 以外（特に `ISOLATED` / `EMERGENCY` / `RECOVERY_*`）であれば、起動シーケンス（944〜954行）で `ARMING -> ACTIVE` へ自動遷移させず `ISOLATED` に固定する。
- **再検証方法:** サブプロセスで `_SAFETY_FSM.isolate_immediately()` 実行後、別サブプロセスを起動して `_SAFETY_FSM.current_state == "ISOLATED"` が維持されることを確認する。

---

#### 2. `FINDING-P0-002`：実稼働 `_SAFETY_FSM` における `strict_dry_run_isolation=False` デフォルト設定による本番状態の汚染
- **優先度:** **P0**
- **ファイル名・行番号:** `airgap_ai_defender.py` 478〜482行、736〜738行、6374〜6375行
- **問題のあるコード:**
  ```python
  self._strict_dry_run_isolation = (
      bool(strict_dry_run_isolation)
      if strict_dry_run_isolation is not None
      else (state_path is not None)
  )
  ```
- **発生条件:** `state_path=None` のFSM（本番の `_SAFETY_FSM` を含む）に対して、`dry_run=True` または `simulated=True` で脅威評価・遷移を実行した場合。
- **再現手順:** `defender.evaluate_threat_state("eth0", dry_run=True, score_a=0.99, autonomous=True)` を実行し、`defender._SAFETY_FSM.current_state` を確認する（`TEST-FSM-DRY-001`）。
- **実測結果:** Dry-Runであるにもかかわらず、本番 `_SAFETY_FSM._state` が `ACTIVE` から `ISOLATED` に変更され、`production_state_changed: True` となる。非自律モードでも `_ISOLATION_APPROVAL_PENDING = True` に汚染される。
- **影響範囲・攻撃可能性・安全性への影響:** Dry-Run（演習・メンテナンス・学習確認）を実行しただけで本番FSMが `ISOLATED` または承認待ち状態に陥り、逆にテストコード（`test_v3_remediation.py`）がこれを正常と誤認している。
- **修正優先順位:** 最優先（第2順位）
- **修正方針:** `strict_dry_run_isolation` のデフォルト値を `state_path` の有無にかかわらず常時 `True` とし、736〜738行および6374〜6375行の非分離コードを削除する。あわせて `tests/test_v3_remediation.py` のDry-Runアサーションを `simulated_state` の検査に修正する（別フェーズ承認後）。
- **再検証方法:** `MK1SafetyStateMachine()`（引数なし）に対して `evaluate_threat_state(..., dry_run=True, autonomous=True)` を実行し、`current_state == "ACTIVE"` かつ `simulated_state == "ISOLATED"` であることを確認する。

---

#### 3. `FINDING-P0-003`：`request_recovery()` の全期間ロック保持とロックタイムアウトによるP0緊急隔離の妨害・無効化
- **優先度:** **P0**
- **ファイル名・行番号:** `airgap_ai_defender.py` 517〜520行、812〜827行、848〜940行
- **問題のあるコード:**
  ```python
  def request_recovery(...):
      with self._acquire_lock():
          ...
          self._transition_to_locked(self.RECOVERY_PENDING, reason="Recovery Requested")
          ...
          verification = verify_quorum_bundle(...)
          ...
          self._transition_to_locked(self.RECOVERY_APPROVED, reason="M-of-N Met")
          ...
          self._transition_to_locked(self.ARMING, reason="System Re-Arming After Recovery")
          self._transition_to_locked(self.ACTIVE, reason="Restoration Complete")
          return True
  ```
- **発生条件:**
  1. `request_recovery()` 実行中にP0脅威が検知され別スレッドが `isolate_immediately()` を呼んだ場合。
  2. `ISOLATED` 状態で `isolate_immediately()` と `request_recovery()` がほぼ同時に呼ばれ、`isolate_immediately()` が先にロックを取得した場合。
  3. ロック競合が `lock_timeout_sec`（2.0秒）を超えた場合。
- **再現手順:** `TEST-FSM-RACE-003`, `TEST-FSM-RACE-004B`, `TEST-FSM-RACE-008` を実行する。
- **実測結果:**
  1. `request_recovery()` はロックを一度も解放せずに `RECOVERY_PENDING -> RECOVERY_APPROVED -> ARMING -> ACTIVE` まで一気に遷移し、`True`（復旧成功）を返してしまう。
  2. `isolate_immediately()` が先にロックを取ると、既に `ISOLATED` のため即座に終了し、直後にロックを取得した `request_recovery()` がシステムを `ACTIVE` に復旧させてしまう（`final_state=ACTIVE`）。
  3. ロック取得がタイムアウトすると、`isolate_immediately()` が `TimeoutError` を送出してクラッシュし、`ACTIVE` のまま隔離に失敗する。
- **影響範囲・攻撃可能性・安全性への影響:** P0攻撃の真っ最中に復旧操作が重なると、緊急隔離がブロックされたり、タイムアウトで消失したり、隔離直後に `ACTIVE` に戻される。
- **修正優先順位:** 最優先（第3順位）
- **修正方針:**
  1. 緊急隔離フラグ（例：`threading.Event` またはアトミックな世代・エポックカウンタ `_emergency_preempt_epoch`）を導入し、`isolate_immediately()` はロック取得前にも即座に緊急プリエンプトフラグを立てる。
  2. `request_recovery()` は重い署名検証 (`verify_quorum_bundle`) の間ロックを解放し、各段階（`RECOVERY_PENDING` → 検証完了後 → `RECOVERY_APPROVED` → `ARMING` → `ACTIVE`）の遷移直前に緊急プリエンプトフラグおよびエポック変化をチェックし、P0割込が1回でも発生していれば即座に復旧を中止して `ISOLATED` に固定する。
  3. `isolate_immediately()` で万一ロック取得タイムアウトが発生した場合でも、例外で失敗終了せず、プリエンプトフラグと状態強制ラッチにより必ず `ISOLATED` へ収束させる。
- **再検証方法:** 事後の強制 `isolate_immediately()` なしで `TEST-FSM-RACE-003`, `004B`, `008` を実行し、いかなるタイミングでも `ACTIVE` への遷移や `TimeoutError` が起きず `ISOLATED` になることを確認する。

---

#### 4. `FINDING-P0-004`：状態ファイル削除またはジャーナル削除によるRollback・隔離状態の完全バイパス
- **優先度:** **P0**
- **ファイル名・行番号:** `airgap_ai_defender.py` 539〜541行、618〜620行
- **問題のあるコード:**
  ```python
  539: def _read_journal_max_generation(self) -> int:
  540:     if not self._journal_path or not os.path.isfile(self._journal_path):
  541:         return 0
  ...
  618: def _load_persistent_state(self) -> None:
  619:     if not self._state_path or not os.path.isfile(self._state_path):
  620:         return
  ```
- **発生条件:**
  1. `fsm_state.json` が削除され、`.gen_journal` のみが残っている場合（`TEST-FSM-PERSIST-004` / `STORAGE-012`）。
  2. `.gen_journal` が削除され、過去の正規 `ACTIVE` 状態ファイル (`fsm_state.json`) が再配置された場合（`TEST-FSM-PERSIST-005` / `STORAGE-011`）。
- **再現手順:** `ISOLATED (gen=4)` の状態から① `os.remove(state_path)` のみ実行して再起動、または② `os.remove(journal_path)` ＋過去の `ACTIVE (gen=2)` ファイルをコピーして再起動する。
- **実測結果:**
  - ①では `.gen_journal` に `max_generation=4, last_state="ISOLATED"` が記録されているにもかかわらず、619行で即座に `return` して `OFF (gen=0)` となり、通常起動で `ACTIVE` に移行できる。
  - ②では 541行が `0` を返すため Rollback 検査 (`2 < 0`) が素通りし、`ACTIVE (gen=2, auth=VERIFIED)` として完全に復旧してしまう。
- **影響範囲・攻撃可能性・安全性への影響:** ローカルファイル削除権限を持つ攻撃者、またはディスク障害による片方のファイル欠損によって、世代ジャーナルによるRollback防止機構が100%無力化される。
- **修正優先順位:** 最優先（第4順位）
- **修正方針:**
  1. `_load_persistent_state()` において、`state_path` が存在しない場合でも `journal_path` が存在すれば必ず読み込み、ジャーナルに記録があれば「状態ファイル欠損（改竄）」として Fail-Closed で `ISOLATED` に固定する。
  2. 逆に `state_path` が存在して `gen >= 1` であるにもかかわらず `journal_path` が存在しない場合は、`return 0` ではなく「ジャーナル欠損（改竄）」として Fail-Closed (`2**62` 返却・`ISOLATED` 固定) とする。
- **再検証方法:** `TEST-FSM-PERSIST-004` および `005` を再実行し、いずれも `current_state == "ISOLATED"` かつ `authenticity_status` がエラー状態になることを確認する。

---

#### 5. `FINDING-P0-005`：Kill Switch（実ネットワーク遮断）失敗時にも論理FSMが `ISOLATED` になり `evaluate_threat_state()` が隔離成功 (`True`) を返す不整合
- **優先度:** **P0**
- **ファイル名・行番号:** `airgap_ai_defender.py` 6385〜6393行、6403〜6414行
- **問題のあるコード:**
  ```python
  6385: target_fsm.isolate_immediately(reason="Autonomous P0 Detection")
  6386: 
  6387: success = execute_kill_switch(
  6388:     interface,
  6389:     False,
  6390:     autonomous_bypass=True,
  6391:     **management_route,
  6392: )
  6393: return bool(success or target_fsm.current_state == MK1SafetyStateMachine.ISOLATED)
  ```
- **発生条件:** P0脅威検知時に `execute_kill_switch()` が権限不足やコマンドエラーで `False`（実遮断失敗）を返した場合。
- **再現手順:** `execute_kill_switch` が `False` を返す条件で `evaluate_threat_state("eth0", dry_run=False, score_a=0.99, autonomous=True)` を実行する（`KS-01`）。
- **実測結果:** `execute_kill_switch` は `False`（実遮断失敗）で `_KILL_SWITCH_TRIGGERED` も `False` のままであるにもかかわらず、6385行で先に `target_fsm.isolate_immediately()` を呼んでいるため、6393行の `or target_fsm.current_state == MK1SafetyStateMachine.ISOLATED` が常に `True` となり、呼び出し元に「隔離成功 (`True`)」を返してしまう。また、Quorum承認パス（6403〜6414行）では `execute_kill_switch` が `False` の場合にFSMが `EMERGENCY` のまま放置される。
- **影響範囲・攻撃可能性・安全性への影響:** `docs/SAFETY_STATES.md` の不変条件（`ISOLATION_PARTIAL` / 失敗した遮断を隔離完了と報告してはならない）に正面から違反し、実際には通信が遮断されていないのに論理状態だけが `ISOLATED` となる。
- **修正優先順位:** 最優先（第5順位）
- **修正方針:**
  1. 隔離開始時はまず `EMERGENCY` に遷移させ、`execute_kill_switch()` の結果を確認する。
  2. 論理FSMの封鎖とOSレベル遮断の成否を明確に分離して記録し、`execute_kill_switch()` が失敗した場合は監査ログおよびセキュリティレポートに `CONTAINMENT_ENFORCEMENT: FAILED (PARTIAL_LOGICAL_ONLY)` を記録した上で、`evaluate_threat_state()` の戻り値が実遮断失敗を隠蔽しないようにする。
- **再検証方法:** `execute_kill_switch` 失敗時に、実遮断失敗がステータスレポートおよび戻り値で正確に識別されることを確認する。

---

### 【P1：高優先（6件）】

#### 6. `FINDING-P1-001`：ハードコードされたフォールバックHMAC秘密鍵 (`b"MK1AI-FSM-SECRET-KEY-V3"`) の使用
- **優先度:** **P1**
- **ファイル名・行番号:** `airgap_ai_defender.py` 474〜476行
- **問題のあるコード:**
  ```python
  env_key = os.environ.get("MK1_FSM_HMAC_KEY")
  raw_key = hmac_key if hmac_key is not None else (env_key if env_key else b"MK1AI-FSM-SECRET-KEY-V3")
  ```
- **発生条件:** `hmac_key` 引数および環境変数 `MK1_FSM_HMAC_KEY` が未指定の場合（本番 `_SAFETY_FSM` のデフォルト）。
- **再現手順:** `TEST-FSM-PERSIST-007` を実行。
- **実測結果:** 公開ソースコードに記載された固定鍵 `b"MK1AI-FSM-SECRET-KEY-V3"` がそのままHMAC鍵として使用される。
- **安全性への影響:** 状態ファイルへの書き込み権限を持つ攻撃者は、ソースコード内の既知の固定鍵を使って任意の `ACTIVE` 状態ファイルとジャーナルのHMACを鍛造できる。
- **修正方針:** 本番環境で `state_path` を使用する際に外部鍵（環境変数または `0400` 権限の独立した鍵ファイル）が供給されていない場合は、固定文字列へフォールバックせず Fail-Closed または起動拒否とする。

#### 7. `FINDING-P1-002`：緊急隔離時の永続化失敗の無視、およびジャーナル書込失敗時のディスク・メモリスプリットブレイン
- **優先度:** **P1**
- **ファイル名・行番号:** `airgap_ai_defender.py` 606〜613行、772〜780行
- **問題のあるコード:**
  ```python
  609: os.replace(tmp_path, self._state_path)
  610: if not self._write_journal_max_generation(self._generation, self._state):
  611:     return False
  ...
  772: if not self._save_persistent_state():
  773:     # If persistence fails during non-isolation transition, rollback or fail-closed to ISOLATED
  774:     if new_state in (self.EMERGENCY, self.ISOLATED):
  775:         return False
  ```
- **発生条件:** ① `isolate_immediately()` 中にディスク書込が失敗した場合（`TEST-FSM-PERSIST-006`）、② `os.replace(tmp_path, self._state_path)` 成功直後に `_write_journal_max_generation()` が失敗した場合（`TEST-FSM-STORAGE-019`）。
- **実測結果:**
  - ①では `isolate_immediately()` が `True` を返すがディスク上は `ACTIVE` のまま残り、再起動すると `ACTIVE` に戻る (`authenticity_status` も `VERIFIED` のまま残る場合がある)。
  - ②ではメモリ状態は `ACTIVE (gen=2)` にロールバックされるが、ディスク上の `fsm_state.json` は既に `OFF (gen=3)` に置換されており、メモリとディスクの世代・状態が完全に食い違う。
- **修正方針:**
  1. ジャーナルを**先に**更新してから `state_path` を更新するか、不整合発生時には `_authenticity_status = "FAILED_PERSISTENCE"` としてメモリ状態を `ISOLATED`（Fail-Closed）にラッチする。
  2. 隔離遷移時の永続化失敗時は `_authenticity_status = "FAILED_PERSISTENCE"` を記録し、永続化未完了であることを監査レポートに明示する。

#### 8. `FINDING-P1-003`：世代ジャーナルの `last_state` 未照合および `_rollback_protection_status` の虚偽表示
- **優先度:** **P1**
- **ファイル名・行番号:** `airgap_ai_defender.py` 495行、539〜562行、647〜656行
- **問題のあるコード:**
  ```python
  495: self._rollback_protection_status = "VERIFIED_JOURNAL" if self._journal_path else "UNAVAILABLE"
  ...
  559: return max_gen
  ```
- **発生条件:** `state_path` と `journal_path` の世代番号が同じだが `state` が異なる場合（`TEST-FSM-STORAGE-013`）、またはジャーナルファイルが実在しない場合（`TEST-FSM-STORAGE-011`）。
- **実測結果:** `_read_journal_max_generation()` は `last_state` を読み込んでMAC検証しているにもかかわらず、戻り値として `max_gen` しか返さず、`_load_persistent_state()` で `state == jstate`（`gen == max_gen` のとき）を照合していない。また、ジャーナルファイルが存在しなくてもパス文字列さえあれば `ROLLBACK_PROTECTION: "VERIFIED_JOURNAL"` と報告される。
- **修正方針:** `gen == journal_max_gen` の場合は `state == journal_last_state` も必須検証とし、不一致なら `FAILED_ROLLBACK` で `ISOLATED` に固定する。また `_rollback_protection_status` は実際にジャーナルのMAC検証に成功した後にのみ `"VERIFIED_JOURNAL"` に設定する。

#### 9. `FINDING-P1-004`：プロセス間排他制御（`flock`）の欠如と固定 `.tmp` ファイル名によるマルチプロセス競合破損
- **優先度:** **P1**
- **ファイル名・行番号:** `airgap_ai_defender.py` 577〜580行、606〜609行
- **問題のあるコード:**
  ```python
  tmp_j = self._journal_path + ".tmp"
  ...
  tmp_path = self._state_path + ".tmp"
  ```
- **発生条件:** 複数プロセス（例：デーモンプロセスとCLI管理ツールやダッシュボードプロセス）が同一の `state_path` / `journal_path` にアクセスした場合（F-05）。
- **実測結果:** 4プロセス同時実行で `.tmp` ファイルが衝突して `FileNotFoundError` / `RuntimeError` が発生し、さらに `state_gen=4 < journal_max_gen=5` の逆転が生じて `FAILED_ROLLBACK` 破損に至った。
- **修正方針:** 専用ロックファイルに対する `fcntl.flock(fd, fcntl.LOCK_EX)` によるプロセス間排他制御を導入し、一時ファイル生成には `tempfile.mkstemp(dir=parent_dir, prefix=...)` を使用してファイル名衝突を排除する。

#### 10. `FINDING-P1-005`：`request_recovery()` および `verify_quorum_bundle()` における必須フィールド（`event_id`, `challenge_id`, `policy_version`, `prefix`, `issued_at`, `expires_at`）欠落時の検証バイパス
- **優先度:** **P1**
- **ファイル名・行番号:** `airgap_ai_defender.py` 6385行、863〜880行、`mk1_quorum.py` 527〜531行
- **問題のあるコード:**
  ```python
  if req_event_id is not None and doc_event_id != req_event_id: ...
  if req_challenge_id is not None and doc_challenge_id != req_challenge_id: ...
  policy_version = challenge_document.get("policy_version", params.get("policy_version", challenge_document.get("version", 1)))
  prefix = challenge_document.get("prefix")
  if prefix is not None and prefix != "MK1AI-RECOVERY-v1": ...
  ```
- **発生条件:** `challenge_document` から `event_id`, `challenge_id`, `policy_version`, `prefix`, `issued_at`, `expires_at` を省略して署名した場合（`Q-14`〜`Q-19`）。また、`evaluate_threat_state()`（6385行）は `isolate_immediately()` に `event_id` を渡さないため、実稼働経路では常に `_active_isolation_event_id = None` となる。
- **実測結果:** `Q-14`, `Q-15`, `Q-16`, `Q-17`, `Q-18`, `Q-19` のすべてにおいて、必須フィールドが欠落した承認バンドルが **`True`（復旧承認成功）** として通過し、`ACTIVE` に遷移した。
- **修正方針:**
  1. `isolate_immediately()` は `event_id` 未指定時に一意なイベントIDを自動生成して `_active_isolation_event_id` に束縛する。
  2. `request_recovery()` において、`doc_event_id`, `doc_challenge_id`, 明示的な `policy_version`, および `prefix == "MK1AI-RECOVERY-v1"` をすべて非空・必須（`None` 不可）とする。
  3. `mk1_quorum.py` の `verify_quorum_bundle()` において、`issued_at` と `expires_at` を整数必須とし、`issued_at <= now <= expires_at` を厳格に検証する。

#### 11. `FINDING-P1-006`：復旧途中の永続化失敗による有効なM-of-N承認トークンの恒久的焼失
- **優先度:** **P1**
- **ファイル名・行番号:** `airgap_ai_defender.py` 909〜915行、935〜940行
- **問題のあるコード:**
  ```python
  909: self._consumed_recovery_tokens.add(replay_token)
  ...
  915: self._transition_to_locked(self.RECOVERY_APPROVED, reason="M-of-N Met")
  ...
  935: except Exception as exc:
  936:     log.error(f"[FSM] 復旧処理エラー: {exc}")
  937:     self._state = self.ISOLATED
  938:     self._simulated_state = self.ISOLATED
  939:     self._save_persistent_state()
  ```
- **発生条件:** `RECOVERY_APPROVED`, `ARMING`, `ACTIVE` のいずれかの遷移時に一時的な永続化失敗が発生した場合（`Q-24B`）。
- **実測結果:** 復旧自体は失敗して `ISOLATED` に戻る（`first_ok=False`）が、909〜913行で追加された `_consumed_recovery_tokens` がロールバックされず939行で保存されるため、同じ承認バンドルでの再試行が `Replay of consumed recovery approval rejected` で永久に拒否される（`retry_same_bundle=False`）。
- **修正方針:** `request_recovery()` 開始前の `prev_tokens = set(self._consumed_recovery_tokens)` を保持し、`ACTIVE` への最終遷移と永続化が完全に成功するまではトークン消費を確定させず、`except` ブロックでは `self._consumed_recovery_tokens = prev_tokens` に復元する。

---

### 【P2：中優先（3件）】

#### 12. `FINDING-P2-001`：`verify_quorum_bundle()` が未来の `issued_at` (`issued_at > now`) を拒否しない
- **優先度:** **P2**
- **ファイル名・行番号:** `mk1_quorum.py` 527〜531行
- **実測結果:** `Q-09` にて `issued_at = now + 86400`（24時間未来）のchallengeが `True / ACTIVE` として承認された（`TwoAdminQuorumGate.authorize_event` 752行には存在する `int(now) < issued_at` チェックが `verify_quorum_bundle` に欠落している）。
- **修正方針:** `verify_quorum_bundle()` に `if not isinstance(issued_at, int) or isinstance(issued_at, bool) or int(now) < issued_at: raise QuorumError(...)` を追加する。

#### 13. `FINDING-P2-002`：`_load_persistent_state()` における `timestamp` の負数・NaN・Inf・bool未検証
- **優先度:** **P2**
- **ファイル名・行番号:** `airgap_ai_defender.py` 634行
- **実測結果:** `TEST-FSM-STORAGE-007` にて `timestamp = -999999999.0` が `VERIFIED` として受け入れられた。また `isinstance(True, int)` がPythonでは `True` となるため `isinstance(ts, bool)` の除外と `math.isfinite(ts)` および `ts > 0` の検証が欠落している。
- **修正方針:** `isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(float(ts)) or float(ts) <= 0` を拒否する。

#### 14. `FINDING-P2-003`：過渡的状態（`EMERGENCY`, `RECOVERY_PENDING`, `RECOVERY_APPROVED`）でクラッシュ・再起動した際の未収束とスタック
- **優先度:** **P2**
- **ファイル名・行番号:** `airgap_ai_defender.py` 657〜667行、944〜954行
- **実測結果:** F-09にて、`RECOVERY_PENDING` でクラッシュ後に再起動すると `RECOVERY_PENDING` に復元され、`request_recovery()` が `self._state != self.ISOLATED` で呼べなくなりスタックする。また `RECOVERY_APPROVED` で再起動すると、起動時の `transition_to(ARMING) -> transition_to(ACTIVE)` が成功してしまい、未完了の復旧が起動処理で自動的に `ACTIVE` になってしまう。
- **修正方針:** 再起動時の復元処理（`_load_persistent_state`）において、保存されていた状態が過渡的な非通常状態（`EMERGENCY`, `RECOVERY_PENDING`, `RECOVERY_APPROVED`, `ARMING`）であった場合は、安全側（Fail-Closed）として `ISOLATED`（または `ARMING` からの再起動は初期 `OFF`）へ正規化する。

---

### 【P3：低優先（1件）】

#### 15. `FINDING-P3-001`：`isolate_immediately()` の `OFF` 状態からの呼び出し時における本番モードと `simulated=True` モードの挙動不一致
- **優先度:** **P3**
- **ファイル名・行番号:** `airgap_ai_defender.py` 820〜834行
- **実測結果:** `OFF` 状態から `isolate_immediately(simulated=False)` を呼ぶと 824行の `else` 分岐で `ISOLATED` に強制遷移するが、`isolate_immediately(simulated=True)` を呼ぶと `RuntimeError: Invalid FSM transition from OFF to EMERGENCY` が発生する。
- **修正方針:** `_allowed_transitions[self.OFF]` に `self.EMERGENCY` を含めるか、`isolate_immediately(simulated=True)` でも本番モードと同じ強制遷移ロジックを適用して一貫性を保つ。

---

## Q. 修正優先順位付き計画（次フェーズ承認後に実施すべき計画）

*(注: 本監査フェーズではコード変更は一切行いません。以下は次フェーズの承認後に適用するための設計計画です。)*

| 順序 | 対象Finding ID | 対象ファイル・行番号 | 修正目的と具体的方針 | 他機能への影響・回帰テスト |
|---|---|---|---|---|
| **Phase 1 (P0)** | `FINDING-P0-001`<br>`FINDING-P0-002` | `airgap_ai_defender.py`<br>470〜482行, 736〜738行, 942〜954行 | 1. `strict_dry_run_isolation` のデフォルトを常時 `True` に変更。<br>2. `_SAFETY_FSM` にデフォルト永続化パスを設定し、起動時に `ISOLATED` 等が復元された場合は `ARMING -> ACTIVE` へ遷移させない。 | `tests/test_v3_remediation.py` 72〜100行が `dry_run=True` で本番 `_state == ISOLATED` を検査しているため、`simulated_state` の検査へ更新が必要。 |
| **Phase 2 (P0)** | `FINDING-P0-004`<br>`FINDING-P1-001`<br>`FINDING-P1-002`<br>`FINDING-P1-003`<br>`FINDING-P2-002`<br>`FINDING-P2-003` | `airgap_ai_defender.py`<br>474〜476行, 539〜676行, 772〜780行 | 1. `state_path` 欠損時に `journal_path` が存在すれば `ISOLATED` 固定。`state_path` 存在時に `journal_path` 欠損なら `ISOLATED` 固定。<br>2. ジャーナルを先に書いてから `state_path` を置換し、`last_state` も照合。<br>3. 過渡状態からの再起動は `ISOLATED` へFail-Closed正規化。 | 既存の `test_v3_final.py` の全ロールバックテストと互換性を維持しつつ、`TEST-FSM-PERSIST-004/005/006` をPASSさせる。 |
| **Phase 3 (P0)** | `FINDING-P0-003`<br>`FINDING-P1-006` | `airgap_ai_defender.py`<br>511〜529行, 803〜940行 | 1. `_emergency_preempt_epoch` とロック非依存の緊急隔離ラッチを導入。<br>2. `request_recovery()` の段階ごとにプリエンプト検査を行い、P0発生時は即座に `ISOLATED` へ中断。<br>3. 復旧完全成功時のみ `_consumed_recovery_tokens` をコミット。 | `TEST-FSM-RACE-003/004B/008` および `Q-24B` が事後強制隔離なしでPASSすることを検証。 |
| **Phase 4 (P0/P1)** | `FINDING-P0-005`<br>`FINDING-P1-005`<br>`FINDING-P2-001` | `airgap_ai_defender.py`<br>6383〜6415行, 862〜880行<br>`mk1_quorum.py` 525〜535行 | 1. `evaluate_threat_state` で `execute_kill_switch` の成否を正確に反映し、遮断失敗を成功と誤報しない。<br>2. `isolate_immediately` で `event_id` を自動生成・束縛。<br>3. `request_recovery` と `verify_quorum_bundle` で `event_id`, `challenge_id`, `policy_version`, `prefix`, `issued_at`, `expires_at` をすべて必須化。 | `KS-01` および `Q-09`, `Q-14`〜`Q-19` がすべて拒否（`False / ISOLATED`）されることを確認。 |
| **Phase 5 (P1/P3)** | `FINDING-P1-004`<br>`FINDING-P3-001` | `airgap_ai_defender.py`<br>577〜580行, 606〜609行, 820〜834行 | 1. `fcntl.flock` によるファイルロックと `tempfile.mkstemp` によるプロセス安全な一時ファイル置換を実装。<br>2. `isolate_immediately` の `OFF` からの挙動を統一。 | 4プロセス同時更新テスト（F-05）を100イテレーション実行し、エラー0件・不整合0件を確認。 |

---

## R. 証拠一覧（実行コマンド・出力・行番号・ハッシュ）

1. **監査前後のファイルハッシュ確認コマンドと結果:**
   - コマンド: `sha256sum airgap_ai_defender.py mk1_quorum.py tests/test_v3_final.py tests/test_v3_remediation.py docs/SAFETY_STATES.md`
   - 出力:
     ```text
     62ce5e3a5159fd0fa1efa5c14b5a89130341d6f7506ab99e406990c22594420a  airgap_ai_defender.py
     6da07e9c2870a946f686370150f5a519b5c576ce724c396ffa1dd3221441a0d0  mk1_quorum.py
     01fa038160550f20f932661e34b49861507afb71c9018becd5ae66ff5c87c9b2  tests/test_v3_final.py
     b56a8394e44b56bd4d3dca2d0e153dc86dbd5f55c3ce35c03732cbd149c74388  tests/test_v3_remediation.py
     457576327035b78c4a54820444ffa931276a37104453dca97210be2243ef49f5  docs/SAFETY_STATES.md
     ```
2. **既存V3テスト単体実行コマンドと結果:**
   - コマンド: `python3 -m unittest tests/test_v3_final.py tests/test_v3_remediation.py`
   - 出力: `Ran 40 tests in 0.396s — OK`
3. **全ユニットテストスイート実行コマンドと結果:**
   - コマンド: `python3 -m unittest discover tests`
   - 出力: `Ran 464 tests in 13.554s — FAILED (failures=5, skipped=15)`
4. **独立動的検証ハーネス実行（すべて `/tmp/mk1_*` 一時領域上で実行・クリーンアップ済み）:**
   - セクションC (7×7全49遷移検証 + `_SAFETY_FSM` 実態検査)
   - セクションD & E (`TEST-FSM-PERSIST-001..008`, `TEST-FSM-DRY-001..008`)
   - セクションF (`TEST-FSM-RACE-001..008` ミリ秒トレース & ロックタイムアウト注入)
   - セクションG & H (`TEST-FSM-STORAGE-001..022`, `multiprocessing.Process` 4プロセス競合検証)
   - セクションI, K, L, O (`Q-01..25`, 再起動7状態検証, `KS-01` モック検証, `N=50` マイクロ秒ベンチマーク)

---

## S. 前回監査との比較

前回の「40件PASS・脆弱性0件・FSM VERIFIED」報告について、以下の通り判定を訂正・撤回します。

1. **維持できる判定:**
   - `state_path`, `hmac_key`, `strict_dry_run_isolation=True` をすべて明示的に与えた単一プロセス・単一スレッドのテスト用FSMインスタンスにおける、7×7の基本遷移マトリクス（49通り）および3-Head AIのNaN/Inf Fail-Closed判定（`TEST-AI-001..010`）。
2. **取り消すべき判定（PASS → FAILへ訂正）:**
   - **実稼働FSMの安全性（旧H項）:** 「実稼働環境においても適切な `state_path` とHMAC鍵供給が行われている」とした前回の記述は誤りであり、実際には `_SAFETY_FSM = MK1SafetyStateMachine()`（`state_path=None`, 固定鍵, `_strict_dry_run_isolation=False`）でした。
   - **Dry-Run完全分離（旧G項）:** テスト用インスタンスでのみ成立しており、本番 `_SAFETY_FSM` ではDry-Runが本番 `_state` を `ISOLATED` に書き換えていました。
   - **Isolation vs Recoveryの競合（旧C項 TEST-FSM-004）:** 既存テスト（`tests/test_v3_final.py` 252行）がスレッド終了後に `fsm.isolate_immediately(reason="Final safety assertion")` を呼んで結果を上書きしていたことを見落としていました。
   - **世代ジャーナルによるRollback防止（旧F項）:** 状態ファイル削除時やジャーナル削除時に `0` や早期 `return` でバイパスされる重大な欠陥を見落としていました。
   - **プロセス間競合（旧C項 TEST-FSM-006）:** `os.replace` の存在だけでPASSとしていましたが、実際に4プロセスで同時実行すると `.tmp` 衝突と世代逆転（`Rollback: 4 < 5`）で破損することを今回実証しました。
   - **M-of-N Quorum必須属性検証（旧E項）:** 期待値やフィールドが省略された場合（`event_id`, `challenge_id`, `policy_version`, `prefix`, `issued_at`, `expires_at` 欠落時）にすべて `True / ACTIVE` で通過してしまう欠陥を見落としていました。

---

## T. 最終結論

# **`FSM FAILED`**

セクション20（FSM VERIFIEDの必須認定条件15項目）のうち、条件1（実稼働FSMの永続化）、条件2（HMAC鍵の安全な供給）、条件3（再起動時の隔離維持）、条件4（実稼働FSMでのDry-Run分離）、条件5（緊急隔離の非妨害）、条件7・8（state/journal欠損時のRollback防止）、条件9・10（M-of-N必須属性・イベント束縛の強制）、条件12（プロセス間競合耐性）、条件13（Kill SwitchとFSMの状態分離）、条件14（既存テストの偽装解消）を満たしていないことが実際のコードと実行ログによって証明されたため、最終結論を **`FSM FAILED`** と判定します。

---

### 最終停止条件の確認
- 既存ソースコードの変更：**なし**（SHA-256完全一致確認済み）
- 既存テストの変更：**なし**（SHA-256完全一致確認済み）
- 設定・依存関係・ホスト環境の変更：**なし**
- 一時検証ディレクトリ（`/tmp/mk1_*`）：**すべて削除済み**
