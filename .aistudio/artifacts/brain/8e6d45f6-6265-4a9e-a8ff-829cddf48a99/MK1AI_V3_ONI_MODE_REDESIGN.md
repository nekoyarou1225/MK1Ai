# MK1Ai V3 ONI MODE Redesign Report
## Formal Defense State Management and Data-Plane Synchronization

**Status**: IMPLEMENTED

### 1. ONI MODE Definition (V3)
ONI MODE (鬼モード) is no longer just a sensitivity flag. In V3, it is integrated into the 7-state FSM as a high-alert operational status that synchronizes userspace AI thresholds with the eBPF/XDP data-plane.

### 2. Synchronization Points

#### 2.1 FSM Integration
- When the FSM enters `EMERGENCY` or `ISOLATED` state, `_ONI_MODE_ACTIVE.set()` is triggered (line 491).
- This ensures that a system in isolation is also in its highest sensitivity state if it is ever partially restored for maintenance.

#### 2.2 XDP Data-Plane Sync
- `toggle_oni_mode(True)` calls `DEFAULT_XDP_CONTROLLER.set_oni_mode(True)` (line 567).
- In `MK1XDPController.evaluate_xdp_ingress`, `oni_mode` presence triggers `VerdictReason.ONI_LOCKDOWN` (line 304), which enforces an immediate `XDP_DROP` for all non-management traffic (line 661, 736).

#### 2.3 AI Pipeline Sync
- In `inspect_packet_pipeline`, `ONI_MODE_is_active()` is checked at the very beginning (line 6061).
- If active, it returns a `block=True` verdict with `reason="ONI_MODE enabled"`, bypassing heavier AI inference to save cycles for mitigation.

### 3. Verification of "Safe Even When OFF"
The requirement states that ONI MODE should remain effective if the system is compromised. 
- **Implementation**: The eBPF data-plane (`mk1_xdp_ingress.bpf.c`) reads from `mk1_ctrl_map`. 
- **Integrity**: Since eBPF runs in kernel space, even if the userspace `airgap_ai_defender` process is killed, the `oni_mode` bit in the BPF map remains `1`, maintaining the blocklist until a persistent reset or M-of-N recovery occurs.

### 4. Remaining Tasks
- **Persistence**: Ensure `oni_mode` bit is persisted in `/.ai_data/fsm_state.json` to survive hardware reboots.
