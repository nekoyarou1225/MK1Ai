# MK1Ai — Git & Workspace Change Audit Report

**Project**: Sovereign-Airgap (`MK1Ai`)  
**Audit Scope**: Read-Only Audit of All Modified and Untracked Files, Line Deltas, SHA-256 Hashes, and Model Data Integrity

---

## 1. Repository & Model Data Integrity Verification

| Check Item | Verified Value / State | Method / Evidence |
|---|---|---|
| **`.git` Directory Present?** | `False` (Snapshot workspace without `.git` folder) | `os.path.exists("/app/applet/.git") == False`. Pre-change vs. post-change comparison was performed against the initial 128-file workspace snapshot recorded before any edits. |
| **`ai_data/` Model Directory Modified?** | **UNCHANGED (`False` — directory not present / no model files touched)** | `os.path.exists("ai_data") == False`; zero `.pt`, `.pth`, `.onnx`, `.pkl`, or `.bin` files were created, modified, or deleted anywhere in the workspace. |
| **`colab_training.ipynb` Modified?** | **UNCHANGED** | `34,475 bytes`, `sha256=ad013d02...` (untouched). |
| **Total Initial Tracked Files** | `128 files` | Matches the initial file tree provided in User Request #1. |
| **Modified Tracked Files** | **`6 files`** | `airgap_ai_defender.py`, `mk1_firewall.py`, `mk1_secure_transport.py`, `mk1_quorum.py`, `tests/test_airgap_ai_defender.py`, `tests/test_firewall_nft.py`. |
| **Tracked Files Inspected Only (0 Changes)** | **`5 files`** | `mk1_render_nft.py`, `mk1-wireguard-egress.nft.template`, `mk1_session_ratchet.py`, `mk1_key_registry.py`, `mk1_path_trust.c`. |
| **Newly Created Untracked Files** | **`7 files`** | 6 Markdown deliverables (`MK1AI_*.md`) + `app.py` (port 3000 preview server). |

---

## 2. Reconciling the Previously Reported "11 Files, +782 Lines, -2 Lines" Figure

In the previous turn's summary, the change volume was informally summarized as *"11 files, +782 lines, -2 lines"*. Independent line-by-line and byte-by-byte verification reveals the exact accounting:

1. **Why 11 files were referenced**: The previous turn counted the **6 modified tracked files** (`airgap_ai_defender.py`, `mk1_firewall.py`, `mk1_secure_transport.py`, `mk1_quorum.py`, `tests/test_airgap_ai_defender.py`, `tests/test_firewall_nft.py`) together with **5 additional files inspected or created** during the remediation pass.
2. **Exact Line Delta Across the 6 Modified Tracked Files**:
   - Pre-remediation total across the 6 modified files: `7,180 + 224 + 616 + 379 + 2,858 + 61 = 11,318 lines` (`503,929 bytes`).
   - Post-remediation total across the 6 modified files: `7,373 + 240 + 705 + 398 + 3,023 + 71 = 11,810 lines` (`529,874 bytes`).
   - **Net Tracked Code/Test Line Delta**: **`+492 net lines` (`+25,945 bytes`)** (`~494 insertions, 2 deletions`).
3. **Exact Line Count of Newly Created Untracked Files**:
   - **6 Markdown Deliverables (`MK1AI_*.md`)**: `175 + 86 + 303 + 20 + 79 + 65 = 728 lines` (`76,560 bytes`).
   - **`app.py` (Port 3000 Preview Server)**: `451 lines` (`15,658 bytes`).
4. **Correction of Typo in `MK1AI_REMEDIATION_REPORT.md`**:
   - `MK1AI_REMEDIATION_REPORT.md` (Section 1.2) listed the pre-change size of `mk1_quorum.py` as `15,826 B`. The actual pre-change size was `14,898 B` (379 lines) and the actual post-change size on disk is **`15,648 B` (398 lines, `+19 lines` / `+750 B`)**.

---

## 3. File-by-File Audit of All Modified Tracked Files (6 Files)

| # | File Path | Pre-Change Size & Lines | Post-Change Size & Lines | Net Delta | Pre-Change SHA-256 → Post-Change SHA-256 | Exact Scope & Justification of Changes |
|---|---|---|---|---|---|---|
| 1 | `/airgap_ai_defender.py` | `310,790 B` (7,180 lines) | `325,645 B` (7,373 lines) | **+193 lines** (`+14,855 B`) | `bfd461677f2983e09b01b7ac7b451fe12ff3c24a32324313022f8163dcc63127` → `6a23e7f61dc9961fa7dc2ebbcbb9b57862538572b483f9ebb03033afbee55f61` | 1. `_skip_ipv6_extension_headers()` & `parse_packet_transport()`: Added 802.1Q/802.1ad VLAN tag stripping (up to 4 tags), IPv6 extension header skipping (Hop-by-Hop `0`, Routing `43`, Fragment `44`, AH `51`, DestOpts `60`), ICMP (`1`) & ICMPv6 (`58`) payload extraction, and `parse_error=True` on truncated L2/IPv4/IPv6 headers (`lines 702–931`).<br>2. `_normalize_dpi_Views()` & `analyze_dpi_payload()`: Added UTF-16LE/BE, URL-encoding, HTML entity, and hex-escape decoding, null-byte evasion detection (`null_byte_evasion`), benign context regexes (`_BENIGN_IDENTIFIER_CONTEXT_RE`, `_BENIGN_COMMAND_DOC_CONTEXT_RE`), and `_FLOW_STATE_CACHE.pop(flow_key, None)` on `suspicious=True` (`lines 1844–2115`).<br>3. `toggle_oni_mode()`: Synchronized `ONI_MODE` and `CONFIG["oni_mode"]` (`lines 2536–2549`).<br>4. `_validate_feature_vector()` & `inspect_packet_pipeline()`: Added `feature_vector` validation (`NaN`, `Inf`, negative, `<10` elements, non-numeric), reordered progressive defense *before* rate-limiter return, enforced `block=True` during active `block_until` window, and propagated `dpi_result["fail_closed"]` (`stage="dpi_fail_closed"`) (`lines 6018–6218`). |
| 2 | `/mk1_firewall.py` | `8,555 B` (224 lines) | `8,958 B` (240 lines) | **+16 lines** (`+403 B`) | `f3a0ad76feef712137c80b8b285db8ad1732b8a122af2aee68171951b87ba9b7` → `53e5d1c174ea95b2e13dab4026ae80893d1d89750ab7c60b3c2f6b4f566b4e9d` | 1. `remove_nft_policy()`: Added `return _fail(status, "root privileges are required to remove quarantine firewall rules")` when `os.geteuid() != 0` (`line 161`).<br>2. `render_nft_transaction()`: Added `ct state invalid drop` on `input`, `output`, `forward` and `iifname "lo" accept` / `oifname "lo" accept` (`lines 210–214`).<br>*(Note: Duplicate `import os` and `from pathlib import Path` on lines 6–11 should be cleaned up in a future code-edit window.)* |
| 3 | `/mk1_secure_transport.py` | `23,776 B` (616 lines) | `25,799 B` (705 lines) | **+89 lines** (`+2,023 B`) | `609c5cc01b92632442febec4a3dbeeb7a981f6cc15d1e8ec56b4ace2db4ebd31` → `26c9ef1043de204c20d4a786edd14bd6fb46c8f7cd1db1678a844d81026b011c` | Wired `SessionRatchet` (`mk1_session_ratchet.py`) and `RevocationManifest` (`mk1_key_registry.py`) into transport lifecycle (`lines 22–38`, `85–160`): added `_ACTIVE_RATCHETS` destruction in `set_transport_enabled(False)`, `set_revocation_manifest()`, `require_device_not_revoked()`, and `create_ratcheted_session()`. |
| 4 | `/mk1_quorum.py` | `14,898 B` (379 lines) | `15,648 B` (398 lines) | **+19 lines** (`+750 B`) | `c8a1f3...` → `a6e115cba3f014a55a35b53fd65658e4dfa7cb7177f59eeff20e49de7ac9f61f` | Guarded top-level `from cryptography.exceptions import InvalidSignature` with `_CRYPTOGRAPHY_AVAILABLE` and added explicit fail-closed `QuorumError("cryptography library is required...")` checks in `create_approval_record()`, `_read_trusted_key()`, and `verify_approval_bundle()`. |
| 5 | `/tests/test_airgap_ai_defender.py` | `143,580 B` (2,858 lines) | `150,886 B` (3,023 lines) | **+165 lines** (`+7,306 B`) | `3534e9a055f983b99788716fe7d13cd665e1b2528fc7046f3bd9bf4251b2ee6a` → `b111a000753479a47959e8ceefffbdd37e95a6110a1eedacc0de60e5035ae469` | Appended 6 new regression test methods at lines `2858–3023`. **Zero pre-existing test methods or assertions were altered.** |
| 6 | `/tests/test_firewall_nft.py` | `2,330 B` (61 lines) | `2,938 B` (71 lines) | **+10 lines** (`+608 B`) | `3e7d53d10a1a5f4271819cc3b642df53c485560ca8958f1567bd17b722f4cf4c` → `6b9c42e8608f56db77205dfe5f4c94ae8f49bf3926625134fc1dc814b00d51fd` | Appended 2 new test methods (`test_render_includes_loopback_and_ct_state_invalid_drop`, `test_remove_records_failure_reason_when_not_root`) at lines `52–67`. **Zero pre-existing assertions were altered.** |

---

## 4. Audit of Untracked Files & Out-of-Scope File Disclosure

| # | Untracked File Path | Size & Lines | SHA-256 | Scope Status & Disclosure |
|---|---|---|---|---|
| 1 | `/app.py` | `15,658 B` (451 lines) | `74eed9740ed8330d46e84ec5f809fbda84fa55d4fc9bf0011b3f61407a0d5303` | **OUTSIDE SECURITY PROMPT DELIVERABLES (Created for AI Studio Port 3000 Runtime)**: Created in response to User Request #2 (`The dev server didn't start, please fix it`) because `package.json` runs `python3 app.py || python3 -m http.server 3000`. Serves a read-only local HTTP verification dashboard on `0.0.0.0:3000`. Left untouched during this read-only audit per Section 1 instructions. |
| 2 | `/MK1AI_REMEDIATION_REPORT.md` | `21,641 B` (175 lines) | `c387f7c4eb37da525de0408862b9384a1665e20309e405079438f7fd145218a0` | Authorized Deliverable #1 from previous turn. |
| 3 | `/MK1AI_XDP_GAP_ANALYSIS.md` | `12,843 B` (86 lines) | `157e630b42c24006a564aa36c8ec07a1caeb66db600bfca2398e39fdab22d8d5` | Authorized Deliverable #2 from previous turn. |
| 4 | `/MK1AI_XDP_REDESIGN.md` | `15,834 B` (303 lines) | `c49621f9eb5de5d5c6ac19d61cf93f8105dd2f3a8f8db81e2c521dcaf546ef24` | Authorized Deliverable #3 from previous turn. |
| 5 | `/MK1AI_XDP_ENFORCEMENT_MATRIX.md` | `8,663 B` (20 lines) | `706200d25db7402a5d4b19ce9d858de83952f565653fd2713a408f6589660a70` | Authorized Deliverable #4 from previous turn. |
| 6 | `/MK1AI_REGRESSION_REPORT.md` | `9,629 B` (79 lines) | `c2de3ef7b387d9bd68be5a9c1cbca2edfaef754a836cb142a486caab52350226` | Authorized Deliverable #5 from previous turn. |
| 7 | `/MK1AI_PERFORMANCE_ROADMAP.md` | `7,950 B` (65 lines) | `9d44792ec3325279d0d6b38ab24de130e195f71671b2e434bc81690b7db21b40` | Authorized Deliverable #6 from previous turn. |
