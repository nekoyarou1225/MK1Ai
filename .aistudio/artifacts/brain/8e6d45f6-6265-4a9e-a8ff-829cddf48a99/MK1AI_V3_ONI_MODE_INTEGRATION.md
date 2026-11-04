# MK1Ai V3 ONI MODE Integration Report
## Integration of ONI MODE (鬼モード) into FSM and Packet Pipeline

**Target Variables & Functions**: `_ONI_MODE_ACTIVE`, `toggle_oni_mode()`, `ONI_MODE_is_active()`

### 1. Integration Architecture
- **FSM Synchronization**: When the system transitions to `EMERGENCY` state, `_ONI_MODE_ACTIVE.set()` is automatically triggered, raising threat sensitivity to maximum.
- **Data-Plane Sync**: `toggle_oni_mode()` updates the eBPF control map (`mk1_ctrl_map`), causing the kernel-side XDP ingress program to drop all unauthorized traffic instantly.
- **Pipeline Early Exit**: `inspect_packet_pipeline()` checks `ONI_MODE_is_active()` at entry (line 6061). If active, packets are evaluated against strict lockdown rules without expensive inference overhead.

### 2. Safety Bounds
- Turning ONI MODE OFF does **not** disable the core security posture or allow unverified traffic; it merely returns threat thresholds to standard operational parameters (`_NORMAL_MODE_COMPOSITE_THRESHOLD = 0.88`).
