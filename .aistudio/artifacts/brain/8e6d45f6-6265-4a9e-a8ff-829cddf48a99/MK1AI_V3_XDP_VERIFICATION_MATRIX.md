# MK1Ai V3 XDP/TC Verification Matrix
## Data-Plane Parity and Kernel/NIC Status Reporting

**Status**: STAGES 1-4 VERIFIED (Userspace)

### 1. Matrix Definition (9-Stage)

| Stage | Name | Status | Method |
|---|---|---|---|
| **1** | Source & Syntax | **VERIFIED** | Static C Inspection |
| **2** | BPF Map Schema | **VERIFIED** | Static C Inspection |
| **3** | Bounded Proofs | **VERIFIED** | Static C Inspection |
| **4** | Userspace Parity | **VERIFIED** | `MK1XDPController` Unit Tests |
| **5** | Kernel Verifier | **NOT_TESTED** | Requires `CAP_BPF` |
| **6** | veth Attach | **NOT_TESTED** | Requires Root/NetNS |
| **7** | TC Qdisc Attach | **NOT_TESTED** | Requires Root |
| **8** | Native XDP (NIC) | **NOT_CONNECTED**| Requires Hardware |
| **9** | Line-Rate Stress | **NOT_CONNECTED**| Requires Hardware |

### 2. Implementation Audit (`mk1_xdp_controller.py`)

#### 2.1 Userspace Parity (Stage 4)
- **Engine**: `MK1XDPController.evaluate_xdp_ingress()` implements a Python-based clone of the eBPF C logic.
- **Accuracy**: It handles VLAN tags, IPv4/IPv6 LPM lookups, TCP flag validation, and Dead-Man Switch heartbeat checks with byte-level accuracy.
- **Verification**: `tests/test_xdp_controller.py` verifies that the Python shadow logic correctly drops packets when `ONI_MODE` or `DEADMAN_LOCKDOWN` is active.

#### 2.2 Honesty Guardrail
- The system explicitly distinguishes between "Shadow Mode" (unprivileged/no NIC) and "Native Mode".
- `MK1XDPController.attach_mode` defaults to `XDP_USERSPACE_SHADOW_ONLY` (line 135) to prevent false security claims in virtualized or unprivileged environments.

### 3. V3 Feature: Dead-Man Switch (Requirement 17)
- **Mechanism**: eBPF map `mk1_ctrl_map` stores `last_heartbeat_ns`.
- **Enforcement**: If `now - last_heartbeat_ns > 5.0s`, the XDP/TC program triggers `XDP_DROP` / `TC_ACT_SHOT`.
- **Sync**: `airgap_ai_defender` must call `DEFAULT_XDP_CONTROLLER.send_heartbeat()` in its primary capture loop.

### 4. Identified Gaps
- **Heartbeat Connection**: While the `MK1XDPController` has `send_heartbeat()`, the main loop in `airgap_ai_defender.py` needs to be audited to ensure it calls this heartbeat even when under high CPU load or during model inference.
