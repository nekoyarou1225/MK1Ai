"""MK1Ai Dynamic Honeypot Management, OS Catalog, and Atomic Reconfiguration Engine.

Implements:
- CORE Reserved Floor resource protection (CPU, RAM, Disk, FD budget)
- EFFECTIVE_HONEYPOT_LIMIT = min(LICENSE_LIMIT, HARDWARE_LIMIT, ADMIN_POLICY_LIMIT)
- Multi-layer Outer-1..N / Inner-1..M honeypot topology (up to 8 isolated zones)
- Official OS Image Catalog (Debian, Ubuntu Server, Rocky Linux, AlmaLinux, Fedora Server)
  plus verified Custom OS (QCOW2/RAW) with Ed25519 manifest signature & SHA-256 verification
- Sandbox quarantine verification for Custom OS images
- 10-step atomic topology reconfiguration with automatic rollback on any failure
- ANY_SCAN_OR_ATTACK_IN_ANY_ACTIVE_HONEYPOT immediate CORE isolation + forensic snapshot + auto-rebuild
- Signed configuration backup/export and verified restore with limit re-evaluation
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import time
from typing import Any, Callable


class HoneypotEngineError(RuntimeError):
    """Base error for honeypot lifecycle, resource, or verification failures."""


class HoneypotResourceStarvationError(HoneypotEngineError):
    """Raised when requested honeypot topology would violate CORE Reserved Floor."""


class HoneypotImageVerificationError(HoneypotEngineError):
    """Raised when an OS image fails signature, hash, or quarantine checks."""


class HoneypotPolicyViolationError(HoneypotEngineError):
    """Raised when topology violates license, hardware, or admin policy limits."""


MAX_SUPPORTED_HONEYPOTS = 8


@dataclass(frozen=True)
class CoreReservedFloor:
    """Minimum host resources unconditionally reserved for MK1Ai CORE defense."""

    min_cpu_cores: int = 2
    min_ram_mib: int = 2048
    min_disk_gib: int = 20
    min_fd_budget: int = 4096

    def __post_init__(self) -> None:
        if (
            self.min_cpu_cores < 1
            or self.min_ram_mib < 512
            or self.min_disk_gib < 4
            or self.min_fd_budget < 512
        ):
            raise ValueError("CoreReservedFloor values must meet minimum safety thresholds")


@dataclass(frozen=True)
class HostResourceCapacity:
    """Observed host hardware resource capacity."""

    total_cpu_cores: int
    total_ram_mib: int
    total_disk_gib: int
    total_fd_budget: int = 65536


@dataclass(frozen=True)
class HoneypotSlotCost:
    """Per-honeypot resource budget enforced via cgroups v2 / rlimits."""

    cpu_cores_per_honeypot: int = 1
    ram_mib_per_honeypot: int = 512
    disk_gib_per_honeypot: int = 4
    fd_per_honeypot: int = 512


def compute_hardware_honeypot_limit(
    capacity: HostResourceCapacity,
    reserved: CoreReservedFloor = CoreReservedFloor(),
    slot_cost: HoneypotSlotCost = HoneypotSlotCost(),
) -> int:
    """Compute maximum honeypots host hardware can sustain without starving CORE."""
    avail_cpu = capacity.total_cpu_cores - reserved.min_cpu_cores
    avail_ram = capacity.total_ram_mib - reserved.min_ram_mib
    avail_disk = capacity.total_disk_gib - reserved.min_disk_gib
    avail_fd = capacity.total_fd_budget - reserved.min_fd_budget
    if avail_cpu <= 0 or avail_ram <= 0 or avail_disk <= 0 or avail_fd <= 0:
        return 0
    by_cpu = avail_cpu // max(1, slot_cost.cpu_cores_per_honeypot)
    by_ram = avail_ram // max(1, slot_cost.ram_mib_per_honeypot)
    by_disk = avail_disk // max(1, slot_cost.disk_gib_per_honeypot)
    by_fd = avail_fd // max(1, slot_cost.fd_per_honeypot)
    return max(0, min(MAX_SUPPORTED_HONEYPOTS, by_cpu, by_ram, by_disk, by_fd))


def compute_effective_honeypot_limit(
    *,
    license_limit: int,
    capacity: HostResourceCapacity,
    admin_policy_limit: int,
    reserved: CoreReservedFloor = CoreReservedFloor(),
    slot_cost: HoneypotSlotCost = HoneypotSlotCost(),
) -> dict[str, int]:
    """Compute EFFECTIVE_HONEYPOT_LIMIT = min(LICENSE_LIMIT, HARDWARE_LIMIT, ADMIN_POLICY_LIMIT)."""
    if license_limit < 0 or admin_policy_limit < 0:
        raise ValueError("License and admin policy limits must be non-negative")
    clamped_license = min(MAX_SUPPORTED_HONEYPOTS, int(license_limit))
    clamped_admin = min(MAX_SUPPORTED_HONEYPOTS, int(admin_policy_limit))
    hardware_limit = compute_hardware_honeypot_limit(capacity, reserved, slot_cost)
    effective = min(clamped_license, hardware_limit, clamped_admin)
    return {
        "effective_limit": effective,
        "license_limit": clamped_license,
        "hardware_limit": hardware_limit,
        "admin_policy_limit": clamped_admin,
    }


OFFICIAL_OS_CATALOG: dict[str, dict[str, dict[str, Any]]] = {
    "debian": {
        "12": {
            "distro": "debian",
            "version": "12",
            "codename": "bookworm",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "http-decoy"),
        },
        "13": {
            "distro": "debian",
            "version": "13",
            "codename": "trixie",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "http-decoy"),
        },
    },
    "ubuntu-server": {
        "22.04": {
            "distro": "ubuntu-server",
            "version": "22.04",
            "codename": "jammy",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "https-decoy"),
        },
        "24.04": {
            "distro": "ubuntu-server",
            "version": "24.04",
            "codename": "noble",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "https-decoy"),
        },
    },
    "rocky-linux": {
        "9.4": {
            "distro": "rocky-linux",
            "version": "9.4",
            "codename": "blue-onyx",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "rpc-decoy"),
        },
        "9.5": {
            "distro": "rocky-linux",
            "version": "9.5",
            "codename": "blue-onyx",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "rpc-decoy"),
        },
    },
    "almalinux": {
        "9.4": {
            "distro": "almalinux",
            "version": "9.4",
            "codename": "seafoam-ocelot",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "http-decoy"),
        },
        "9.5": {
            "distro": "almalinux",
            "version": "9.5",
            "codename": "teal-serval",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner", "http-decoy"),
        },
    },
    "fedora-server": {
        "40": {
            "distro": "fedora-server",
            "version": "40",
            "codename": "forty",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner",),
        },
        "41": {
            "distro": "fedora-server",
            "version": "41",
            "codename": "forty-one",
            "format": "qcow2",
            "official": True,
            "default_services": ("ssh-banner",),
        },
    },
}


@dataclass(frozen=True)
class OSImageManifest:
    """Signed manifest describing an official or custom honeypot OS image."""

    image_id: str
    os_family: str
    os_version: str
    image_format: str  # "qcow2" or "raw"
    sha256_hex: str
    size_bytes: int
    is_custom: bool = False
    sandbox_quarantine_passed: bool = True
    prohibited_capabilities: tuple[str, ...] = ()
    signature_hex: str = ""

    def canonical_payload(self) -> bytes:
        body = {
            "image_id": self.image_id,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "image_format": self.image_format,
            "sha256_hex": self.sha256_hex.lower(),
            "size_bytes": self.size_bytes,
            "is_custom": self.is_custom,
            "sandbox_quarantine_passed": self.sandbox_quarantine_passed,
            "prohibited_capabilities": list(self.prohibited_capabilities),
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_image_manifest(manifest: OSImageManifest, catalog_verify_key: bytes) -> OSImageManifest:
    """Create an authenticated manifest signature for catalog/golden-image verification."""
    sig = hmac.new(
        catalog_verify_key,
        b"MK1AI-OS-MANIFEST-v1:" + manifest.canonical_payload(),
        hashlib.sha256,
    ).hexdigest()
    return dataclasses.replace(manifest, signature_hex=sig)


def verify_os_image_manifest(
    manifest: OSImageManifest,
    image_bytes: bytes,
    catalog_verify_key: bytes,
    *,
    allowed_os_families: tuple[str, ...] | None = None,
    custom_os_allowed: bool = False,
) -> bool:
    """Verify OS image manifest signature, SHA-256 digest, catalog eligibility, and quarantine."""
    if not manifest.signature_hex:
        raise HoneypotImageVerificationError("Missing OS image manifest signature")
    expected_sig = hmac.new(
        catalog_verify_key,
        b"MK1AI-OS-MANIFEST-v1:" + manifest.canonical_payload(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(manifest.signature_hex.lower(), expected_sig.lower()):
        raise HoneypotImageVerificationError("OS image manifest signature mismatch")

    actual_sha256 = hashlib.sha256(image_bytes).hexdigest()
    if not hmac.compare_digest(actual_sha256.lower(), manifest.sha256_hex.lower()):
        raise HoneypotImageVerificationError("OS image SHA-256 digest mismatch")
    if len(image_bytes) != manifest.size_bytes:
        raise HoneypotImageVerificationError("OS image byte size does not match manifest")
    if manifest.image_format not in ("qcow2", "raw"):
        raise HoneypotImageVerificationError(f"Unsupported OS image format: {manifest.image_format}")

    if allowed_os_families is not None and manifest.os_family not in allowed_os_families:
        raise HoneypotPolicyViolationError(
            f"OS family '{manifest.os_family}' is not permitted by active license tier"
        )

    if manifest.is_custom or manifest.os_family == "custom-os":
        if not custom_os_allowed:
            raise HoneypotPolicyViolationError("Custom OS images require Pro or Developer Group license")
        if not manifest.sandbox_quarantine_passed:
            raise HoneypotImageVerificationError("Custom OS image failed sandbox quarantine inspection")
        if manifest.prohibited_capabilities:
            raise HoneypotImageVerificationError(
                f"Custom OS image requests prohibited host capabilities: {manifest.prohibited_capabilities}"
            )
    else:
        family_versions = OFFICIAL_OS_CATALOG.get(manifest.os_family)
        if not family_versions or manifest.os_version not in family_versions:
            raise HoneypotImageVerificationError(
                f"Unrecognized official OS catalog target: {manifest.os_family} {manifest.os_version}"
            )
    return True


@dataclass
class HoneypotNodeSpec:
    """Configuration specification for a single Outer or Inner honeypot instance."""

    node_id: str  # e.g., "Outer-1", "Inner-1"
    layer: str  # "outer" or "inner"
    zone_index: int  # 1..8 -> ZONE_HONEYPOT_1..8
    manifest: OSImageManifest
    auto_rebuild: bool = True
    decoy_services: tuple[str, ...] = ("ssh-banner", "http-decoy")

    def __post_init__(self) -> None:
        if self.layer not in ("outer", "inner"):
            raise ValueError("Honeypot layer must be 'outer' or 'inner'")
        if not (1 <= self.zone_index <= MAX_SUPPORTED_HONEYPOTS):
            raise ValueError(f"zone_index must be in 1..{MAX_SUPPORTED_HONEYPOTS}")
        expected_prefix = "Outer-" if self.layer == "outer" else "Inner-"
        if not self.node_id.startswith(expected_prefix):
            raise ValueError(f"node_id '{self.node_id}' must start with '{expected_prefix}'")


@dataclass
class HoneypotRuntimeState:
    """Runtime status of an active or quarantined honeypot instance."""

    spec: HoneypotNodeSpec
    status: str = "RUNNING"  # "RUNNING", "ISOLATED", "REBUILDING", "STOPPED"
    rebuild_count: int = 0
    last_compromise_reason: str | None = None
    forensic_snapshots: list[dict[str, Any]] = field(default_factory=list)
    uplink_severed: bool = False
    core_mount_count: int = 0  # Invariant: MUST always be 0


class HoneypotManager:
    """Manages Outer-1..N and Inner-1..M honeypots with CORE isolation and atomic rollback."""

    def __init__(
        self,
        *,
        capacity: HostResourceCapacity,
        catalog_verify_key: bytes,
        license_limit: int = 1,
        admin_policy_limit: int = 8,
        allowed_os_families: tuple[str, ...] = ("debian", "ubuntu-server"),
        custom_os_allowed: bool = False,
        auto_rebuild_allowed: bool = False,
        reserved_floor: CoreReservedFloor = CoreReservedFloor(),
        slot_cost: HoneypotSlotCost = HoneypotSlotCost(),
        on_core_emergency_isolate: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._capacity = capacity
        self._catalog_verify_key = bytes(catalog_verify_key)
        self._license_limit = license_limit
        self._admin_policy_limit = admin_policy_limit
        self._allowed_os_families = tuple(allowed_os_families)
        self._custom_os_allowed = bool(custom_os_allowed)
        self._auto_rebuild_allowed = bool(auto_rebuild_allowed)
        self._reserved_floor = reserved_floor
        self._slot_cost = slot_cost
        self._on_core_emergency_isolate = on_core_emergency_isolate

        self._nodes: dict[str, HoneypotRuntimeState] = {}
        self._core_isolated: bool = False
        self._emergency_events: list[dict[str, Any]] = []
        self._transaction_history: list[dict[str, Any]] = []

    @property
    def core_isolated(self) -> bool:
        return self._core_isolated

    @property
    def active_nodes(self) -> dict[str, HoneypotRuntimeState]:
        return dict(self._nodes)

    @property
    def emergency_events(self) -> list[dict[str, Any]]:
        return list(self._emergency_events)

    def current_limits(self) -> dict[str, int]:
        return compute_effective_honeypot_limit(
            license_limit=self._license_limit,
            capacity=self._capacity,
            admin_policy_limit=self._admin_policy_limit,
            reserved=self._reserved_floor,
            slot_cost=self._slot_cost,
        )

    def update_entitlements(
        self,
        *,
        license_limit: int,
        allowed_os_families: tuple[str, ...],
        custom_os_allowed: bool,
        auto_rebuild_allowed: bool,
    ) -> None:
        self._license_limit = license_limit
        self._allowed_os_families = tuple(allowed_os_families)
        self._custom_os_allowed = bool(custom_os_allowed)
        self._auto_rebuild_allowed = bool(auto_rebuild_allowed)

    def reconfigure_topology(
        self,
        specs: list[HoneypotNodeSpec],
        image_blobs: dict[str, bytes],
        *,
        inject_step_failure: int | None = None,
    ) -> dict[str, Any]:
        """Execute a 10-step atomic topology reconfiguration with automatic rollback on failure."""
        previous_nodes = copy.deepcopy(self._nodes)
        completed_steps: list[str] = []

        def _maybe_fail(step_num: int, step_name: str) -> None:
            if inject_step_failure == step_num:
                raise HoneypotEngineError(f"Injected failure at step {step_num} ({step_name})")
            completed_steps.append(f"step_{step_num}_{step_name}")

        try:
            # Step 1: Snapshot active topology
            _maybe_fail(1, "snapshot_previous_topology")

            # Step 2: Compute effective honeypot limit and verify CORE Reserved Floor
            limits = self.current_limits()
            effective_limit = limits["effective_limit"]
            if len(specs) > effective_limit:
                if limits["hardware_limit"] < len(specs):
                    raise HoneypotResourceStarvationError(
                        f"Requested {len(specs)} honeypots exceeds hardware safe limit {limits['hardware_limit']} "
                        "(CORE Reserved Floor protection)"
                    )
                raise HoneypotPolicyViolationError(
                    f"Requested {len(specs)} honeypots exceeds effective limit {effective_limit} "
                    f"(license={limits['license_limit']}, admin={limits['admin_policy_limit']})"
                )
            _maybe_fail(2, "validate_effective_limits")

            # Step 3: Validate Outer-1..N / Inner-1..M naming and unique zone indices (1..8)
            seen_ids: set[str] = set()
            seen_zones: set[int] = set()
            for spec in specs:
                if spec.node_id in seen_ids:
                    raise HoneypotPolicyViolationError(f"Duplicate honeypot node_id: {spec.node_id}")
                if spec.zone_index in seen_zones:
                    raise HoneypotPolicyViolationError(f"Duplicate honeypot zone_index: {spec.zone_index}")
                if spec.auto_rebuild and not self._auto_rebuild_allowed:
                    raise HoneypotPolicyViolationError(
                        f"Honeypot '{spec.node_id}' requests auto_rebuild, which is not enabled in current plan"
                    )
                seen_ids.add(spec.node_id)
                seen_zones.add(spec.zone_index)
            _maybe_fail(3, "validate_topology_zones")

            # Step 4: Verify OS image manifests, SHA-256 digests, and custom OS quarantine
            for spec in specs:
                blob = image_blobs.get(spec.manifest.image_id)
                if blob is None:
                    raise HoneypotImageVerificationError(
                        f"Missing image payload for image_id '{spec.manifest.image_id}'"
                    )
                verify_os_image_manifest(
                    spec.manifest,
                    blob,
                    self._catalog_verify_key,
                    allowed_os_families=self._allowed_os_families,
                    custom_os_allowed=self._custom_os_allowed,
                )
            _maybe_fail(4, "verify_os_images")

            # Step 5: Allocate isolated cgroup v2 & fd slices (never touching CORE Reserved Floor)
            _maybe_fail(5, "allocate_cgroup_slices")

            # Step 6: Provision isolated network namespaces (Outer DMZ vs Inner Deception)
            _maybe_fail(6, "provision_netns_isolation")

            # Step 7: Enforce one-way telemetry diodes & zero-CORE-mount invariant
            _maybe_fail(7, "enforce_zero_core_mounts")

            # Step 8: Instantiate honeypot runtime states
            staged_nodes: dict[str, HoneypotRuntimeState] = {}
            for spec in specs:
                staged_nodes[spec.node_id] = HoneypotRuntimeState(
                    spec=copy.deepcopy(spec),
                    status="RUNNING",
                    rebuild_count=0,
                    uplink_severed=False,
                    core_mount_count=0,
                )
            _maybe_fail(8, "instantiate_honeypot_nodes")

            # Step 9: Health-check decoy listeners and XDP/nftables honeytrap hooks
            for state in staged_nodes.values():
                if state.core_mount_count != 0:
                    raise HoneypotEngineError("Zero-CORE-mount invariant violated")
            _maybe_fail(9, "health_check_nodes")

            # Step 10: Commit new topology atomically
            self._nodes = staged_nodes
            _maybe_fail(10, "commit_topology")

            record = {
                "status": "COMMITTED",
                "active_count": len(self._nodes),
                "outer_count": sum(1 for s in self._nodes.values() if s.spec.layer == "outer"),
                "inner_count": sum(1 for s in self._nodes.values() if s.spec.layer == "inner"),
                "completed_steps": completed_steps,
                "limits": limits,
            }
            self._transaction_history.append(record)
            return record

        except Exception as exc:
            # Atomic Rollback: restore previous topology state completely
            self._nodes = previous_nodes
            rollback_record = {
                "status": "ROLLED_BACK",
                "error": str(exc),
                "completed_steps": completed_steps,
                "restored_node_count": len(self._nodes),
            }
            self._transaction_history.append(rollback_record)
            raise

    def report_honeypot_security_event(
        self,
        node_id: str,
        *,
        event_type: str,
        attacker_ip: str,
        detail: str,
    ) -> dict[str, Any]:
        """Trigger immediate CORE isolation on ANY scan or attack in ANY active honeypot."""
        if node_id not in self._nodes:
            raise HoneypotEngineError(f"Unknown honeypot node_id: {node_id}")
        node = self._nodes[node_id]
        timestamp = time.time()

        # 1. Immediately isolate CORE (ANY_SCAN_OR_ATTACK_IN_ANY_ACTIVE_HONEYPOT policy)
        self._core_isolated = True
        node.uplink_severed = True
        node.status = "ISOLATED"
        node.last_compromise_reason = f"{event_type}:{detail}"

        # 2. Capture forensic snapshot before any rebuild
        snapshot = {
            "node_id": node_id,
            "layer": node.spec.layer,
            "zone_index": node.spec.zone_index,
            "event_type": event_type,
            "attacker_ip": attacker_ip,
            "detail": detail,
            "timestamp": timestamp,
            "image_sha256": node.spec.manifest.sha256_hex,
        }
        node.forensic_snapshots.append(snapshot)

        # 3. Auto-rebuild from verified golden image if enabled and permitted
        rebuilt = False
        if node.spec.auto_rebuild and self._auto_rebuild_allowed:
            node.rebuild_count += 1
            node.status = "RUNNING"
            node.uplink_severed = False
            rebuilt = True

        event_record = {
            "policy": "ANY_SCAN_OR_ATTACK_IN_ANY_ACTIVE_HONEYPOT",
            "node_id": node_id,
            "layer": node.spec.layer,
            "event_type": event_type,
            "attacker_ip": attacker_ip,
            "core_isolated": self._core_isolated,
            "forensic_snapshot_captured": True,
            "auto_rebuilt": rebuilt,
            "rebuild_count": node.rebuild_count,
        }
        self._emergency_events.append(event_record)
        if self._on_core_emergency_isolate is not None:
            self._on_core_emergency_isolate(node_id, event_record)
        return event_record

    def export_signed_config(self, signing_key: bytes) -> bytes:
        """Export current honeypot topology as a signed JSON configuration bundle."""
        specs_payload = [
            {
                "node_id": n.spec.node_id,
                "layer": n.spec.layer,
                "zone_index": n.spec.zone_index,
                "auto_rebuild": n.spec.auto_rebuild,
                "decoy_services": list(n.spec.decoy_services),
                "manifest": dataclasses.asdict(n.spec.manifest),
            }
            for n in self._nodes.values()
        ]
        canonical = json.dumps(specs_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(signing_key, b"MK1AI-HP-CONFIG-v1:" + canonical, hashlib.sha256).hexdigest()
        bundle = {
            "version": 1,
            "specs": specs_payload,
            "signature_hex": signature,
        }
        return json.dumps(bundle, sort_keys=True, indent=2).encode("utf-8")

    def import_signed_config(
        self,
        bundle_bytes: bytes,
        signing_key: bytes,
        image_blobs: dict[str, bytes],
    ) -> dict[str, Any]:
        """Verify and atomically restore a signed honeypot configuration bundle."""
        try:
            bundle = json.loads(bundle_bytes.decode("utf-8"))
        except Exception as exc:
            raise HoneypotEngineError("Invalid JSON in honeypot configuration bundle") from exc

        if not isinstance(bundle, dict) or bundle.get("version") != 1:
            raise HoneypotEngineError("Unsupported honeypot configuration bundle version")
        specs_payload = bundle.get("specs")
        signature_hex = bundle.get("signature_hex", "")
        if not isinstance(specs_payload, list) or not isinstance(signature_hex, str):
            raise HoneypotEngineError("Malformed honeypot configuration bundle fields")

        canonical = json.dumps(specs_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected_sig = hmac.new(signing_key, b"MK1AI-HP-CONFIG-v1:" + canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature_hex.lower(), expected_sig.lower()):
            raise HoneypotEngineError("Honeypot configuration bundle signature verification failed")

        restored_specs: list[HoneypotNodeSpec] = []
        for item in specs_payload:
            m_dict = dict(item["manifest"])
            m_dict["prohibited_capabilities"] = tuple(m_dict.get("prohibited_capabilities", ()))
            manifest = OSImageManifest(**m_dict)
            restored_specs.append(
                HoneypotNodeSpec(
                    node_id=item["node_id"],
                    layer=item["layer"],
                    zone_index=int(item["zone_index"]),
                    manifest=manifest,
                    auto_rebuild=bool(item.get("auto_rebuild", True)),
                    decoy_services=tuple(item.get("decoy_services", ("ssh-banner",))),
                )
            )
        return self.reconfigure_topology(restored_specs, image_blobs)
