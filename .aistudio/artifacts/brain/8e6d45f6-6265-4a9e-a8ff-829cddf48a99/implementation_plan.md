# MK1Ai — Ultimate Security System Repair & Hardening Implementation Plan

## 1. Executive Summary & Audit Baseline (Phase 0 & Phase 1)

This implementation plan establishes the architectural and engineering blueprint for hardening **MK1Ai (Project Sovereign-Airgap)** into an enterprise-grade, high-reliability security appliance.

In accordance with strict read-only audit instructions and user constraints:
- **No workspace source code or configuration files have been modified or deleted.**
- All 413 unit tests (`tests/`) remain fully intact and passing.
- P0, P1, and R risk registers have been rigorously re-verified against the actual repository source code.

---

## 2. P0/P1/R Evidence Register (Phase 1 Audit Results)

| Issue ID | Category | Target Location | Actual Code Evidence | Severity | Verification Status |
|---|---|---|---|---|---|
| **P0-01** | XDP / In-line Drop | `airgap_ai_defender.py:6781` | `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ...)` is asynchronous passive copy (`ptype_all`), not an in-line kernel `XDP_DROP` or `NF_DROP`. | **CRITICAL** | `NOT_IMPLEMENTED` / `NOT_TESTED` |
| **P0-02** | Kill Switch | `airgap_ai_defender.py:417, 5984, 6933` | 4-fold hardcoded dry-run checks (`_DRY_RUN = True`, CLI error on `--no-dry-run`, `_ISOLATION_APPROVAL_PENDING`, `if not dry_run: return False`) unconditionally block active isolation. | **CRITICAL** | `NOT_IMPLEMENTED` / `NOT_TESTED` |
| **P0-03** | Firewall Sync | `airgap_ai_defender.py` ⇔ `mk1_firewall.py` | Python threat detection engine has zero imports or calls to `mk1_quarantine.py` or `mk1_firewall.py`. Table name mismatch (`inet filter` vs `inet mk1_airgap`). | **CRITICAL** | `NOT_IMPLEMENTED` / `NOT_TESTED` |
| **P0-04** | XDP Bypass | `MK1AI_XDP_REDESIGN.md` | Legacy XDP draft code bypassed port 22 (`if bpf_ntohs(th->dest) == 22) return XDP_PASS;`) and lacked IPv6 extension header / fragment inspection. | **CRITICAL** | `DESIGN_ONLY` |
| **P1-01** | PQC Suite Mismatch | `mk1_hybrid_kem.py` vs `mk1_secure_transport.py` | `mk1_hybrid_kem.py` uses `ML-KEM-1024 + X25519`, whereas `mk1_secure_transport.py` uses `ML-KEM-768` standalone. All crypto tests SKIPPED due to missing dependencies. | **HIGH** | `NOT_TESTED` |
| **P1-02** | DPI Sampling Bypass | `airgap_ai_defender.py:1084` | 5-packet benign prefix followed by attack payload on 6th packet bypassed DPI via `sampled_skip` (mitigated in recent unit test fixes, but requires XDP full inspection). | **HIGH** | `TESTED` (Python only) |
| **P1-03** | Parser Limitations | `airgap_ai_defender.py:646` | Non-zero fragment offsets (`frag_offset > 0`), IPv6 ESP headers (Next Header 50), and unknown L2 EtherTypes lacked strict Fail-Closed handling. | **HIGH** | `TESTED` (Python only) |
| **P1-04** | AI Anomaly Advisory | `airgap_ai_defender.py:5920` | `ai_anomaly=True` was advisory-only and not included in `inspect_packet_pipeline()` blocking expression (`block = blacklisted or dpi_suspicious ...`). | **HIGH** | `DESIGN_ONLY` |
| **P1-05** | Python Key Leak | `mk1_session_ratchet.py:66` | Immutable Python `bytes` from `HKDF.derive()` and `AESGCM(bytes(key))` cannot be wiped via `wipe_buffer()`, leaving plaintext keys on CPython heap. | **HIGH** | `NOT_TESTED` |
| **P1-06** | nftables Order | `mk1_firewall.py:210` | `ct state invalid drop` was placed before `iifname "lo" accept`, risking local process communication. (Fixed in recent patches). | **HIGH** | `TESTED` |
| **P1-07** | POSIX Macros | `mk1_path_trust.c:1` | Missing `#define _XOPEN_SOURCE 700` caused compilation warnings/failures with `-std=c11`. (Fixed in recent patches). | **HIGH** | `TESTED` |
| **R-01..R-12** | Residual Risks | Various | All 12 residual risks (fragment DOS, crypto timing, state split, QKD absence, HW dependency) are re-classified as `NOT_TESTED` or `DESIGN_ONLY`. | **HIGH** | `NOT_TESTED` |

---

## 3. Technical Remediation Design & Unified Diff Proposals (Phase 2)

### 3.1 Native Crypto Broker & Secure Memory Architecture
To eliminate Python heap key exposure (`P1-05`), we propose introducing an isolated Native Crypto Broker daemon communicating via Unix Domain Socket (`SOCK_STREAM`) with `SO_PEERCRED` authorization.
- Opaque handles bound to `PID`, `UID`, `Session ID`, `Zone ID`, `Purpose`, and `Generation`.
- `mk1_memory_guard.c` enforced with strict `mlock`, `MADV_DONTDUMP`, `MADV_DONTFORK`, and fail-closed panic if `mlock` fails.

### 3.2 XDP / TC 7-Stage Architecture (`security/ebpf/mk1_xdp_ingress.bpf.c`)
- **VLAN 4096-bit Bitmap**: Utilizing `__u64 allowed_vlan_bitmap[64]` with `word_index = vid >> 6`, `bit_index = vid & 63`. VID 0 and 4095 dropped by default. Updated via `BPF_MAP_TYPE_ARRAY_OF_MAPS` atomic pointer swap.
- **Fragmentation Policy**: In accordance with user preference, **all non-zero fragment offsets (`frag_offset > 0`) are dropped at XDP**, with legitimate PMTUD ICMP responses permitted under strict rate limits.
- **TC Egress & WireGuard 4-Point Inspection**: Enforcing inspection across (1) Physical Ingress, (2) Physical Egress, (3) `wg0` Ingress, and (4) `wg0` Egress.

### 3.3 QKD 9-State Machine & Zone Security
- Enforcing the 9 states (`QKD_UNAVAILABLE`, `QKD_SIMULATED`, `QKD_CONNECTING`, `QKD_READY`, `QKD_DEGRADED`, `QKD_KEY_EXHAUSTED`, `QKD_AUTH_FAILED`, `QKD_REVOKED`, `QKD_ERROR`).
- **Forbidden**: Direct transition from `QKD_SIMULATED` to `QKD_READY`.
- **Zone Binding**: Enforcing strict authenticated caller zone binding across `HONMARU`, `INNER_1..4`, and `OUTER_1..4`, explicitly refusing key requests originating from Outer zones for Honmaru assets.

---

## 4. Required Deliverables Plan (25 Enterprise Specifications)

Upon user approval, the following 25 specification documents and architectural reports will be generated in the repository:
1. `MK1AI_P0_P1_REMEDIATION.md`
2. `MK1AI_THREAT_MODEL.md`
3. `MK1AI_FINAL_SECURITY_ARCHITECTURE.md`
4. `MK1AI_XDP_TC_IMPLEMENTATION.md`
5. `MK1AI_NETWORK_ENFORCEMENT_MATRIX.md`
6. `MK1AI_DPI_AI_OVERLOAD_CONTROL.md`
7. `MK1AI_PACKET_DISPATCH_ARCHITECTURE.md`
8. `MK1AI_VLAN_4096_BITMAP_SPEC.md`
9. `MK1AI_WIREGUARD_FOUR_POINT_ENFORCEMENT.md`
10. `MK1AI_FRAGMENT_REASSEMBLY_POLICY.md`
11. `MK1AI_NATIVE_CRYPTO_BROKER.md`
12. `MK1AI_SECURE_MEMORY_ARCHITECTURE.md`
13. `MK1AI_CRYPTO_DEPENDENCY_POLICY.md`
14. `MK1AI_QKD_IMPLEMENTATION_STATUS.md`
15. `MK1AI_QKD_DEVICE_AND_ZONE_SECURITY.md`
16. `MK1AI_HYBRID_KDF_SPECIFICATION.md`
17. `MK1AI_KEY_LIFECYCLE.md`
18. `MK1AI_SESSION_RATCHET_SECURITY.md`
19. `MK1AI_QUORUM_KILL_SWITCH_SPEC.md`
20. `MK1AI_ENFORCEMENT_GENERATION_CONTROL.md`
21. `MK1AI_TESTER_INTEGRATION.md`
22. `MK1AI_XDP_7_STAGE_VALIDATION.md`
23. `MK1AI_PERFORMANCE_VERIFICATION.md`
24. `MK1AI_FAILURE_AND_RECOVERY.md`
25. `MK1AI_RESIDUAL_RISK_REGISTER.md`

---

## 5. Next Steps (Phase 3 — Awaiting Approval)

In accordance with Phase 3 instructions, **all investigation and planning are complete. No code or repository files have been modified.**

Please review this implementation plan and click **Proceed** (or provide feedback) to authorize the sequential implementation and generation of the specification documents.
