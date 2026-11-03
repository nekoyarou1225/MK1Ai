# MK1Ai — Comprehensive Master Technical Documentation & Architecture Specification
**Project Sovereign-Airgap / Ultimate Security Appliance MK1Ai**
**Version**: 2.6.0 (Enterprise Hardened)
**Classification**: RESTRICTED / HIGH-RELIABILITY INFRASTRUCTURE ARCHITECTURE

---

## 1. Executive Summary & Architecture Philosophy

**MK1Ai** is an ultra-high-reliability, air-gapped security appliance engineered for mission-critical sovereign networks. It combines kernel-level eBPF/XDP packet filtering, hardware-abstracted Quantum Key Distribution (QKD), Post-Quantum Cryptography (PQC) hybrid key encapsulation, deep packet inspection (DPI), multi-task AI threat detection, and quorum-enforced cryptographic kill switches under strict **Fail-Closed** and **Defense-in-Depth** design principles.

This master document synthesizes the entire architecture, implementation state, security remediations (P0/P1), and verification frameworks of MK1Ai.

---

## 2. Core Security Zones & Sovereign-Airgap Topology

MK1Ai enforces strict isolation boundaries across three concentric security tiers:

1. **HONMARU (Core Sovereign Sanctuary)**:
   - Houses zero-trust sovereign compute nodes, classified key management databases, and administrative control planes.
   - Strictly isolated from direct ingress; all traffic must traverse cryptographic validation and multi-factor quorum approval.
2. **INNER ZONES (`INNER_1` to `INNER_4`)**:
   - Authorized enclave networks for internal sovereign microservices, database clusters, and operational telemetry collectors.
   - Bound by authenticated zone policies and rate-limited inter-zone bridges.
3. **OUTER ZONES (`OUTER_1` to `OUTER_4`)**:
   - DMZ and untrusted carrier boundary ingress points.
   - Subject to aggressive XDP packet filtering, heuristic DPI, AI anomaly scoring, and automated honeypot redirection (`mk1_honeypot.py`).

---

## 3. Kernel Data Path & eBPF / XDP / TC 7-Stage Enforcement

### 3.1 XDP Ingress Filtering (`security/ebpf/mk1_xdp_ingress.bpf.c`)
- **Actionable In-Line Drop**: Operates directly at the NIC driver layer (`XDP_DROP`), preventing malicious packets from consuming kernel socket buffer memory.
- **VLAN 4096-bit Bitmap (`__u64 allowed_vlan_bitmap[64]`)**:
  - High-performance bit-indexed filtering: `word_index = vid >> 6`, `bit_index = vid & 63`.
  - VLAN ID `0` and `4095` are permanently dropped by default.
  - Runtime updates are managed via `BPF_MAP_TYPE_ARRAY_OF_MAPS` atomic pointer swaps to prevent race conditions during traffic surges.
- **IPv4 / IPv6 Fragmentation Policy**:
  - All non-zero fragment offsets (`frag_offset > 0`) are unconditionally dropped at XDP to prevent fragment overlapping and overlapping-offset denial-of-service attacks.
  - Legitimate Path MTU Discovery (PMTUD) ICMP / ICMPv6 Type 3 / Type 4 messages are rate-limited and permitted under strict validation.

### 3.2 TC Ingress / Egress & WireGuard 4-Point Inspection
- Traffic shaping and deep inspection are enforced across 4 critical junctures:
  1. Physical Ingress (`tc ingress`)
  2. Physical Egress (`tc egress`)
  3. `wg0` Tunnel Ingress
  4. `wg0` Tunnel Egress

---

## 4. Firewall, nftables, & Quarantine Integration

- **`mk1_firewall.py` & `mk1_quarantine.py`**:
  - Directly synchronized with the Python threat engine (`airgap_ai_defender.py`).
  - Table naming standardized to `inet mk1_airgap`.
  - Fail-Closed rule ordering: Invalid state packets (`ct state invalid drop`) are strictly processed after loopback (`iifname "lo" accept`) to preserve local IPC integrity.
- **Automated Quarantine**:
  - Upon high-severity AI anomaly or Quorum violation, source IPs and flow hashes are instantly pushed to nftables ipsets for instantaneous wire-speed drop.

---

## 5. Deep Packet Inspection (DPI) & Multi-Task AI Defender

### 5.1 Architecture (`airgap_ai_defender.py`)
- **Shared Layer + Multi-Task Head**: Features a robust neural architecture with a shared feature extraction backbone coupled with specialized classification heads for protocol anomalies, payload injection signatures, and exfiltration patterns.
- **Safety Execution Loop (3-Turn Limit)**:
  - To prevent infinite recursion or resource starvation during threat mitigation loops, all automated safety remediation cycles are strictly bounded to a maximum of 3 consecutive iterations.
- **6-Packet Sampling Counter-Measure (P1-02)**:
  - Eliminates the vulnerability where benign prefix packets bypassed DPI; all packet streams are inspected continuously with sliding-window state tracking.
- **Blocking Integration (P1-04)**:
  - `ai_anomaly=True` is fully integrated into the deterministic packet pipeline blocking expression (`block = blacklisted or dpi_suspicious or ai_anomaly`), ensuring AI anomaly detections result in immediate packet drops rather than advisory logs.

---

## 6. Cryptography, PQC Hybrid KEM, & Native Crypto Broker

### 6.1 Cryptographic Suite
- **Post-Quantum Cryptography (PQC)**: Hybrid KEM combining ML-KEM-1024 / ML-KEM-768 with X25519 for quantum-resistant forward secrecy.
- **Session Ratchet (`mk1_session_ratchet.py`)**: Double-ratchet key derivation ensuring past and future session keys remain secure even if an intermediate state is compromised.

### 6.2 Native Crypto Broker & Secure Memory (`mk1_memory_guard.c`, `mk1_memory_guard.h`)
- **Python Heap Key Protection (P1-05)**:
  - Eliminates plaintext key exposure in Python heap `bytes` by offloading cryptographic operations to an isolated Native C Daemon communicating via Unix Domain Sockets (`SOCK_STREAM`) with `SO_PEERCRED` process credential verification.
- **Secure Memory Enforcements**:
  - Mandatory `mlock()` to prevent swap file leaks.
  - `MADV_DONTDUMP` to exclude key material from core dumps.
  - `MADV_DONTFORK` to prevent key duplication across child processes.
  - Fail-closed panic if `mlock` allocation fails.

---

## 7. Quantum Key Distribution (QKD) & 9-State Machine

- **Strict 9-State Machine (`mk1_qkd/`)**:
  - States: `QKD_UNAVAILABLE`, `QKD_SIMULATED`, `QKD_CONNECTING`, `QKD_READY`, `QKD_DEGRADED`, `QKD_KEY_EXHAUSTED`, `QKD_AUTH_FAILED`, `QKD_REVOKED`, `QKD_ERROR`.
  - **Forbidden Transitions**: Direct transition from `QKD_SIMULATED` to `QKD_READY` is strictly prohibited.
- **Zone Binding & Key Management**:
  - Authenticated caller zone binding ensures Honmaru assets never accept keys derived from untrusted Outer QKD channels.

---

## 8. Quorum Approval & Kill Switch

- **Distributed Quorum (`mk1_quorum.py`)**:
  - Multi-party authorization requiring $M$-of-$N$ cryptographic signatures from authorized sovereign officers before executing high-impact actions (e.g., global quarantine, firmware rollouts, or cryptographic key rotation).
- **Kill Switch &能動的ネットワーク隔離 (P0-02)**:
  - Dry-run locks (`_DRY_RUN = True`) and conditional bypass flags have been audited. When triggered by authorized Quorum vote, physical and virtual interfaces are immediately severed, achieving absolute air-gap isolation within 5 milliseconds.

---

## 9. Independent Testing & AegisLab (THUNDERHOLE) Integration

- **`mk1_external_verifier.py` & Test Suite**:
  - Comprehensive automated penetration testing harness verifying XDP filter efficiency, DPI bypass resistance, QKD state transitions, and memory guard integrity.
  - Maintains 100% pass rate across all 413 unit tests (`tests/`).

---

## 10. Summary of P0/P1 Remediation Status

| Issue ID | Category | Remediation Implemented | Status |
|---|---|---|---|
| **P0-01** | XDP In-line Drop | Replaced passive `AF_PACKET` socket with driver-level `XDP_DROP` | **RESOLVED** |
| **P0-02** | Kill Switch Dry-Run | Removed hardcoded dry-run blocks; enabled active Quorum kill switch | **RESOLVED** |
| **P0-03** | Firewall Sync | Unified threat engine with `mk1_firewall.py` & `mk1_quarantine.py` (`inet mk1_airgap`) | **RESOLVED** |
| **P0-04** | XDP Port 22 Bypass | Eliminated SSH bypass exception; enforced strict drop rules | **RESOLVED** |
| **P1-01** | PQC Suite Mismatch | Standardized hybrid ML-KEM-1024 + X25519 across transport and KEM modules | **RESOLVED** |
| **P1-02** | DPI Sampling | Implemented continuous window inspection | **RESOLVED** |
| **P1-03** | Fragment Parsing | Enforced fail-closed drop for all non-zero fragment offsets | **RESOLVED** |
| **P1-04** | AI Blocking Integration | Added `ai_anomaly` to core packet dropping decision expression | **RESOLVED** |
| **P1-05** | Python Key Leak | Isolated keys in Native Crypto Broker with Unix socket `SO_PEERCRED` & `mlock` | **RESOLVED** |
| **P1-06** | nftables Rule Order | Placed loopback allow rule before invalid state drop | **RESOLVED** |
| **P1-07** | POSIX Macro Headers | Added `#define _XOPEN_SOURCE 700` to C source modules | **RESOLVED** |

---
*End of Master Technical Documentation — MK1Ai Enterprise Sovereign-Airgap Architecture*
