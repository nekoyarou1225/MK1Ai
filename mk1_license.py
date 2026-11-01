"""MK1Ai Enterprise License, Offline Asymmetric Verification, and Developer Group Engine.

Implements:
- Pure-Python RFC 8032 Ed25519 asymmetric signature verification so the client verifier
  stores ONLY the 32-byte public root key (no private signing key or shared HMAC secret
  in the client verifier).
- 4 License Tiers: Community / Basic, Standard, Pro, Developer Group / Enterprise.
- Non-negotiable Security Invariant: CORE isolation, attack detection, emergency kill switch,
  and emergency control plane bandwidth remain 100% enabled across ALL tiers and in
  Safe Degraded Mode (when license is expired, tampered, hardware-mismatched, or revoked).
- Monotonic License Ledger preventing system clock rollback and old-sequence license replay.
- Signed Offline Certificate Revocation List (CRL).
- Traffic Policer enforcing data-plane bandwidth/PPS/session limits while unconditionally
  exempting emergency control plane traffic.
- Developer Group Administration (group creation, member addition/removal, zero-trust
  rejection of self-asserted developer flags, and SHA-256 hash-chained audit log).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import os
from typing import Any


class LicensePlatformError(RuntimeError):
    """Base error for license validation, anti-rollback, or group administration failures."""


class LicenseVerificationError(LicensePlatformError):
    """Raised when a license token fails signature, fingerprint, or CRL checks."""


class LicenseRollbackError(LicensePlatformError):
    """Raised when clock rollback or license sequence downgrade is detected."""


class DeveloperGroupPrivilegeError(LicensePlatformError):
    """Raised when an unauthorized or self-asserted Developer Group operation is attempted."""


# ── Pure-Python RFC 8032 Ed25519 Asymmetric Implementation ──────────────────
# Ensures offline asymmetric public-key verification works in all environments
# without storing any signing secret inside the client verifier.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


_D = (-121665 * _inv(121666)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * _inv(5)) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q, 1, (_BX * _BY) % _Q)
_IDENT = (0, 1, 1, 0)


def _edwards_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (t1 * 2 * _D * t2) % _Q
    d = (z1 * 2 * z2) % _Q
    e = (b - a) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return (e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q


def _scalarmult(pt: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    res = _IDENT
    cur = pt
    scalar = e
    while scalar > 0:
        if scalar & 1:
            res = _edwards_add(res, cur)
        cur = _edwards_add(cur, cur)
        scalar >>= 1
    return res


def _encodepoint(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = _inv(z)
    xp = (x * zi) % _Q
    yp = (y * zi) % _Q
    bits = bytearray(yp.to_bytes(32, "little"))
    bits[31] |= (xp & 1) << 7
    return bytes(bits)


def _decodepoint(s: bytes) -> tuple[int, int, int, int]:
    if len(s) != 32:
        raise ValueError("Invalid Ed25519 point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("Ed25519 y-coordinate out of range")
    x_sign = (s[31] >> 7) & 1
    u = (y * y - 1) % _Q
    v = (_D * y * y + 1) % _Q
    xx = (u * _inv(v)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q != 0:
        raise ValueError("Point is not on Ed25519 curve")
    if x == 0 and x_sign == 1:
        raise ValueError("Invalid x=0 with negative sign bit")
    if (x & 1) != x_sign:
        x = _Q - x
    return x, y, 1, (x * y) % _Q


def ed25519_public_key_from_seed(seed32: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from 32-byte private seed (used by offline issuer)."""
    if len(seed32) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encodepoint(_scalarmult(_B, a))


def ed25519_sign(seed32: bytes, msg: bytes) -> bytes:
    """Sign message using 32-byte Ed25519 private seed (issuer-only helper)."""
    if len(seed32) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _encodepoint(_scalarmult(_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    r_pt = _encodepoint(_scalarmult(_B, r))
    k = int.from_bytes(hashlib.sha512(r_pt + pub + msg).digest(), "little") % _L
    s = (r + k * a) % _L
    return r_pt + s.to_bytes(32, "little")


def ed25519_verify(public_key32: bytes, msg: bytes, signature64: bytes) -> bool:
    """Verify 64-byte Ed25519 signature using ONLY the 32-byte public key."""
    if len(public_key32) != 32 or len(signature64) != 64:
        return False
    try:
        a_pt = _decodepoint(public_key32)
        r_bytes = signature64[:32]
        r_pt = _decodepoint(r_bytes)
        s = int.from_bytes(signature64[32:], "little")
        if s >= _L:
            return False
        k = int.from_bytes(hashlib.sha512(r_bytes + public_key32 + msg).digest(), "little") % _L
        lhs = _scalarmult(_B, s)
        rhs = _edwards_add(r_pt, _scalarmult(a_pt, k))
        return _encodepoint(lhs) == _encodepoint(rhs)
    except Exception:
        return False


class PlanTier(str, Enum):
    COMMUNITY_BASIC = "community_basic"
    STANDARD = "standard"
    PRO = "pro"
    DEVELOPER_GROUP = "developer_group"


@dataclass(frozen=True)
class PlanEntitlements:
    """Entitlements for a license tier. Core protection flags are unconditionally True."""

    tier: PlanTier
    max_honeypots: int
    allowed_os_families: tuple[str, ...]
    custom_os_allowed: bool
    auto_rebuild_allowed: bool
    developer_group_admin_allowed: bool
    bandwidth_mbps: int
    pps_limit: int
    max_concurrent_sessions: int
    degraded_mode: bool = False
    degraded_reason: str | None = None
    # Non-negotiable security invariants across all tiers and degraded states:
    core_isolation_enabled: bool = True
    attack_detection_enabled: bool = True
    emergency_kill_switch_enabled: bool = True
    emergency_control_plane_unlimited: bool = True
    audit_log_integrity_enabled: bool = True

    def __post_init__(self) -> None:
        if not (
            self.core_isolation_enabled
            and self.attack_detection_enabled
            and self.emergency_kill_switch_enabled
            and self.emergency_control_plane_unlimited
            and self.audit_log_integrity_enabled
        ):
            raise ValueError("Security invariant violation: CORE protection cannot be disabled in any tier")


TIER_CATALOG: dict[PlanTier, PlanEntitlements] = {
    PlanTier.COMMUNITY_BASIC: PlanEntitlements(
        tier=PlanTier.COMMUNITY_BASIC,
        max_honeypots=1,
        allowed_os_families=("debian", "ubuntu-server"),
        custom_os_allowed=False,
        auto_rebuild_allowed=False,
        developer_group_admin_allowed=False,
        bandwidth_mbps=100,
        pps_limit=20_000,
        max_concurrent_sessions=1_024,
    ),
    PlanTier.STANDARD: PlanEntitlements(
        tier=PlanTier.STANDARD,
        max_honeypots=2,
        allowed_os_families=("debian", "ubuntu-server", "rocky-linux", "almalinux"),
        custom_os_allowed=False,
        auto_rebuild_allowed=True,
        developer_group_admin_allowed=False,
        bandwidth_mbps=1_000,
        pps_limit=150_000,
        max_concurrent_sessions=8_192,
    ),
    PlanTier.PRO: PlanEntitlements(
        tier=PlanTier.PRO,
        max_honeypots=4,
        allowed_os_families=("debian", "ubuntu-server", "rocky-linux", "almalinux", "fedora-server", "custom-os"),
        custom_os_allowed=True,
        auto_rebuild_allowed=True,
        developer_group_admin_allowed=False,
        bandwidth_mbps=2_500,
        pps_limit=500_000,
        max_concurrent_sessions=32_768,
    ),
    PlanTier.DEVELOPER_GROUP: PlanEntitlements(
        tier=PlanTier.DEVELOPER_GROUP,
        max_honeypots=8,
        allowed_os_families=("debian", "ubuntu-server", "rocky-linux", "almalinux", "fedora-server", "custom-os"),
        custom_os_allowed=True,
        auto_rebuild_allowed=True,
        developer_group_admin_allowed=True,
        bandwidth_mbps=10_000,
        pps_limit=2_000_000,
        max_concurrent_sessions=131_072,
    ),
}


def compute_device_fingerprint(
    *,
    machine_id: str,
    cpu_model: str,
    primary_mac: str,
    root_fs_uuid: str,
) -> str:
    """Compute deterministic SHA-256 hardware/host binding fingerprint."""
    payload = f"MK1AI-HW-FP-v1|{machine_id.strip()}|{cpu_model.strip()}|{primary_mac.strip().lower()}|{root_fs_uuid.strip()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SignedLicenseToken:
    """Offline license document signed by the MK1Ai License Authority Ed25519 private key."""

    license_id: str
    customer_org: str
    tier: PlanTier
    device_fingerprint: str
    issued_at_utc: int
    expires_at_utc: int
    sequence_number: int
    max_honeypots_override: int | None = None
    group_id: str | None = None
    signature_hex: str = ""

    def canonical_bytes(self) -> bytes:
        doc = {
            "license_id": self.license_id,
            "customer_org": self.customer_org,
            "tier": self.tier.value,
            "device_fingerprint": self.device_fingerprint.lower(),
            "issued_at_utc": int(self.issued_at_utc),
            "expires_at_utc": int(self.expires_at_utc),
            "sequence_number": int(self.sequence_number),
            "max_honeypots_override": self.max_honeypots_override,
            "group_id": self.group_id,
        }
        return b"MK1AI-OFFLINE-LICENSE-v1:" + json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_signed_license(token: SignedLicenseToken, issuer_private_seed32: bytes) -> SignedLicenseToken:
    """Authority-side helper to sign an offline license token with Ed25519."""
    sig = ed25519_sign(issuer_private_seed32, token.canonical_bytes()).hex()
    return SignedLicenseToken(
        license_id=token.license_id,
        customer_org=token.customer_org,
        tier=token.tier,
        device_fingerprint=token.device_fingerprint,
        issued_at_utc=token.issued_at_utc,
        expires_at_utc=token.expires_at_utc,
        sequence_number=token.sequence_number,
        max_honeypots_override=token.max_honeypots_override,
        group_id=token.group_id,
        signature_hex=sig,
    )


@dataclass(frozen=True)
class SignedLicenseCRL:
    """Ed25519-signed offline Certificate Revocation List for revoked licenses/devices."""

    crl_sequence: int
    issued_at_utc: int
    revoked_license_ids: tuple[str, ...]
    revoked_device_fingerprints: tuple[str, ...] = ()
    signature_hex: str = ""

    def canonical_bytes(self) -> bytes:
        doc = {
            "crl_sequence": int(self.crl_sequence),
            "issued_at_utc": int(self.issued_at_utc),
            "revoked_license_ids": sorted(self.revoked_license_ids),
            "revoked_device_fingerprints": sorted(fp.lower() for fp in self.revoked_device_fingerprints),
        }
        return b"MK1AI-OFFLINE-CRL-v1:" + json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_signed_crl(crl: SignedLicenseCRL, issuer_private_seed32: bytes) -> SignedLicenseCRL:
    sig = ed25519_sign(issuer_private_seed32, crl.canonical_bytes()).hex()
    return SignedLicenseCRL(
        crl_sequence=crl.crl_sequence,
        issued_at_utc=crl.issued_at_utc,
        revoked_license_ids=crl.revoked_license_ids,
        revoked_device_fingerprints=crl.revoked_device_fingerprints,
        signature_hex=sig,
    )


class MonotonicLicenseLedger:
    """Tracks monotonic timestamp and sequence numbers to defeat clock rollback & replay."""

    def __init__(self, *, max_clock_skew_sec: int = 30) -> None:
        self._max_observed_utc: int = 0
        self._highest_sequence_by_device: dict[str, int] = {}
        self._highest_crl_sequence: int = 0
        self._max_clock_skew_sec = max_clock_skew_sec

    @property
    def max_observed_utc(self) -> int:
        return self._max_observed_utc

    def check_and_advance_clock(self, current_utc: int) -> None:
        if self._max_observed_utc > 0 and current_utc + self._max_clock_skew_sec < self._max_observed_utc:
            raise LicenseRollbackError(
                f"System clock rollback detected: current_utc={current_utc} < max_observed_utc={self._max_observed_utc}"
            )
        if current_utc > self._max_observed_utc:
            self._max_observed_utc = current_utc

    def check_and_record_license_sequence(self, device_fingerprint: str, sequence_number: int) -> None:
        fp = device_fingerprint.lower()
        prev_seq = self._highest_sequence_by_device.get(fp, 0)
        if sequence_number < prev_seq:
            raise LicenseRollbackError(
                f"License sequence rollback rejected: seq={sequence_number} < highest_seen={prev_seq}"
            )
        self._highest_sequence_by_device[fp] = sequence_number

    def check_and_record_crl_sequence(self, crl_sequence: int) -> None:
        if crl_sequence < self._highest_crl_sequence:
            raise LicenseRollbackError(
                f"CRL sequence rollback rejected: crl_seq={crl_sequence} < highest_seen={self._highest_crl_sequence}"
            )
        self._highest_crl_sequence = crl_sequence


class OfflineLicenseVerifier:
    """Client-side offline license verifier holding ONLY the 32-byte Ed25519 root public key."""

    def __init__(
        self,
        *,
        authority_public_key32: bytes,
        local_device_fingerprint: str,
        ledger: MonotonicLicenseLedger | None = None,
    ) -> None:
        if len(authority_public_key32) != 32:
            raise ValueError("authority_public_key32 must be a 32-byte Ed25519 public key")
        self._authority_public_key32 = bytes(authority_public_key32)
        self._local_device_fingerprint = local_device_fingerprint.lower()
        self._ledger = ledger if ledger is not None else MonotonicLicenseLedger()
        self._active_crl: SignedLicenseCRL | None = None

    @property
    def has_private_key_material(self) -> bool:
        """Client verifier never holds any private signing seed."""
        return False

    def install_crl(self, crl: SignedLicenseCRL) -> None:
        try:
            sig_bytes = bytes.fromhex(crl.signature_hex)
        except ValueError as exc:
            raise LicenseVerificationError("Malformed CRL signature hex") from exc
        if not ed25519_verify(self._authority_public_key32, crl.canonical_bytes(), sig_bytes):
            raise LicenseVerificationError("CRL Ed25519 signature verification failed")
        self._ledger.check_and_record_crl_sequence(crl.crl_sequence)
        self._active_crl = crl

    def safe_degraded_entitlements(self, reason: str) -> PlanEntitlements:
        """Return Community/Basic Safe Degraded Mode while keeping CORE security 100% active."""
        base = TIER_CATALOG[PlanTier.COMMUNITY_BASIC]
        return PlanEntitlements(
            tier=PlanTier.COMMUNITY_BASIC,
            max_honeypots=base.max_honeypots,
            allowed_os_families=base.allowed_os_families,
            custom_os_allowed=False,
            auto_rebuild_allowed=False,
            developer_group_admin_allowed=False,
            bandwidth_mbps=base.bandwidth_mbps,
            pps_limit=base.pps_limit,
            max_concurrent_sessions=base.max_concurrent_sessions,
            degraded_mode=True,
            degraded_reason=reason,
            core_isolation_enabled=True,
            attack_detection_enabled=True,
            emergency_kill_switch_enabled=True,
            emergency_control_plane_unlimited=True,
            audit_log_integrity_enabled=True,
        )

    def evaluate_license(
        self,
        token: SignedLicenseToken,
        *,
        current_utc: int,
        strict: bool = False,
    ) -> PlanEntitlements:
        """Verify license offline; return tier entitlements or transition to Safe Degraded Mode."""
        try:
            # Reject environment-variable privilege bypass attempts
            if os.environ.get("MK1AI_FORCE_DEV_LICENSE") or os.environ.get("MK1AI_BYPASS_LICENSE"):
                raise LicenseVerificationError("Environment variable license override is prohibited")

            try:
                sig_bytes = bytes.fromhex(token.signature_hex)
            except ValueError as exc:
                raise LicenseVerificationError("Invalid license signature hex encoding") from exc

            if not ed25519_verify(self._authority_public_key32, token.canonical_bytes(), sig_bytes):
                raise LicenseVerificationError("Ed25519 license signature verification failed")

            if not hmac.compare_digest(token.device_fingerprint.lower(), self._local_device_fingerprint):
                raise LicenseVerificationError("License device_fingerprint does not match host hardware")

            self._ledger.check_and_advance_clock(current_utc)
            if current_utc < token.issued_at_utc:
                raise LicenseVerificationError("License issued_at_utc is in the future")
            if current_utc > token.expires_at_utc:
                raise LicenseVerificationError("License has expired")

            if self._active_crl is not None:
                if token.license_id in self._active_crl.revoked_license_ids:
                    raise LicenseVerificationError(f"License '{token.license_id}' is revoked by CRL")
                if token.device_fingerprint.lower() in [
                    fp.lower() for fp in self._active_crl.revoked_device_fingerprints
                ]:
                    raise LicenseVerificationError("Device fingerprint is revoked by CRL")

            self._ledger.check_and_record_license_sequence(token.device_fingerprint, token.sequence_number)
            if token.tier == PlanTier.DEVELOPER_GROUP and not token.group_id:
                raise LicenseVerificationError("Developer Group tier requires a bound group_id")

            base = TIER_CATALOG[token.tier]
            max_hp = base.max_honeypots
            if token.max_honeypots_override is not None:
                max_hp = max(1, min(base.max_honeypots, int(token.max_honeypots_override)))

            return PlanEntitlements(
                tier=base.tier,
                max_honeypots=max_hp,
                allowed_os_families=base.allowed_os_families,
                custom_os_allowed=base.custom_os_allowed,
                auto_rebuild_allowed=base.auto_rebuild_allowed,
                developer_group_admin_allowed=base.developer_group_admin_allowed,
                bandwidth_mbps=base.bandwidth_mbps,
                pps_limit=base.pps_limit,
                max_concurrent_sessions=base.max_concurrent_sessions,
                degraded_mode=False,
                degraded_reason=None,
            )
        except LicensePlatformError as exc:
            if strict:
                raise
            return self.safe_degraded_entitlements(str(exc))


class TrafficPolicer:
    """Enforces plan data-plane traffic limits while unconditionally exempting emergency control plane."""

    def __init__(self, entitlements: PlanEntitlements) -> None:
        self._entitlements = entitlements

    def evaluate_traffic(
        self,
        *,
        observed_mbps: float,
        observed_pps: int,
        active_sessions: int,
        is_emergency_control_plane: bool = False,
    ) -> dict[str, Any]:
        # Emergency control plane (kill switch, quarantine, forensic alert, local IPC) is NEVER throttled
        if is_emergency_control_plane:
            return {
                "allowed": True,
                "throttled": False,
                "exempt_reason": "EMERGENCY_CONTROL_PLANE_UNLIMITED",
            }
        exceeded: list[str] = []
        if observed_mbps > self._entitlements.bandwidth_mbps:
            exceeded.append("bandwidth_mbps")
        if observed_pps > self._entitlements.pps_limit:
            exceeded.append("pps_limit")
        if active_sessions > self._entitlements.max_concurrent_sessions:
            exceeded.append("max_concurrent_sessions")
        return {
            "allowed": len(exceeded) == 0,
            "throttled": len(exceeded) > 0,
            "exceeded_metrics": exceeded,
        }


@dataclass
class DeveloperGroupRecord:
    group_id: str
    group_name: str
    owner_id: str
    max_seats: int
    members: dict[str, dict[str, Any]] = field(default_factory=dict)
    revoked: bool = False


class DeveloperGroupAdminEngine:
    """Zero-trust Developer Group lifecycle manager with Ed25519 verification & hash-chained audit log."""

    def __init__(self, *, authority_public_key32: bytes) -> None:
        if len(authority_public_key32) != 32:
            raise ValueError("authority_public_key32 must be 32 bytes")
        self._authority_public_key32 = bytes(authority_public_key32)
        self._groups: dict[str, DeveloperGroupRecord] = {}
        self._audit_chain: list[dict[str, Any]] = []

    @property
    def audit_chain(self) -> list[dict[str, Any]]:
        return list(self._audit_chain)

    def _append_audit_entry(self, action: str, actor_id: str, details: dict[str, Any]) -> dict[str, Any]:
        prev_hash = self._audit_chain[-1]["entry_hash"] if self._audit_chain else "0" * 64
        entry_body = {
            "index": len(self._audit_chain),
            "action": action,
            "actor_id": actor_id,
            "details": details,
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(entry_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(canonical).hexdigest()
        record = {**entry_body, "entry_hash": entry_hash}
        self._audit_chain.append(record)
        return record

    def verify_audit_chain(self) -> bool:
        prev_hash = "0" * 64
        for idx, entry in enumerate(self._audit_chain):
            if entry.get("index") != idx or entry.get("prev_hash") != prev_hash:
                return False
            body = {
                "index": entry["index"],
                "action": entry["action"],
                "actor_id": entry["actor_id"],
                "details": entry["details"],
                "prev_hash": entry["prev_hash"],
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected_hash = hashlib.sha256(canonical).hexdigest()
            if not hmac.compare_digest(entry.get("entry_hash", ""), expected_hash):
                return False
            prev_hash = expected_hash
        return True

    def create_group(
        self,
        *,
        group_id: str,
        group_name: str,
        owner_id: str,
        max_seats: int,
        entitlements: PlanEntitlements,
        authority_signature_hex: str,
        self_asserted_developer: bool = False,
    ) -> DeveloperGroupRecord:
        if self_asserted_developer:
            self._append_audit_entry(
                "REJECT_SELF_ASSERTED_DEV_PRIVILEGE",
                owner_id,
                {"group_id": group_id, "reason": "self_asserted_developer_flag_rejected"},
            )
            raise DeveloperGroupPrivilegeError("Self-asserted developer flag is rejected under Zero-Trust")

        if entitlements.tier != PlanTier.DEVELOPER_GROUP or not entitlements.developer_group_admin_allowed:
            self._append_audit_entry(
                "REJECT_UNAUTHORIZED_GROUP_CREATE",
                owner_id,
                {"group_id": group_id, "tier": entitlements.tier.value},
            )
            raise DeveloperGroupPrivilegeError("Active verified Developer Group license is required")

        msg = f"MK1AI-DEV-GROUP-CREATE-v1|{group_id}|{group_name}|{owner_id}|{max_seats}".encode("utf-8")
        try:
            sig_bytes = bytes.fromhex(authority_signature_hex)
        except ValueError as exc:
            raise DeveloperGroupPrivilegeError("Invalid authority signature hex") from exc
        if not ed25519_verify(self._authority_public_key32, msg, sig_bytes):
            self._append_audit_entry(
                "REJECT_INVALID_GROUP_SIGNATURE",
                owner_id,
                {"group_id": group_id},
            )
            raise DeveloperGroupPrivilegeError("Developer Group creation authority signature invalid")

        record = DeveloperGroupRecord(
            group_id=group_id,
            group_name=group_name,
            owner_id=owner_id,
            max_seats=max(1, int(max_seats)),
            members={owner_id: {"role": "owner", "device_fingerprint": "owner-device"}},
        )
        self._groups[group_id] = record
        self._append_audit_entry(
            "CREATE_DEVELOPER_GROUP",
            owner_id,
            {"group_id": group_id, "group_name": group_name, "max_seats": max_seats},
        )
        return record

    def add_member(
        self,
        *,
        group_id: str,
        actor_id: str,
        member_id: str,
        role: str,
        device_fingerprint: str,
    ) -> dict[str, Any]:
        group = self._groups.get(group_id)
        if group is None or group.revoked:
            raise DeveloperGroupPrivilegeError("Developer group does not exist or is revoked")
        actor_info = group.members.get(actor_id)
        if actor_info is None or actor_info.get("role") not in ("owner", "admin"):
            self._append_audit_entry(
                "REJECT_ADD_MEMBER_UNAUTHORIZED",
                actor_id,
                {"group_id": group_id, "target_member": member_id},
            )
            raise DeveloperGroupPrivilegeError("Only group owner or admin can add members")
        if member_id not in group.members and len(group.members) >= group.max_seats:
            raise DeveloperGroupPrivilegeError("Developer group seat limit reached")
        if role not in ("admin", "developer", "auditor"):
            raise ValueError(f"Unsupported member role: {role}")

        group.members[member_id] = {
            "role": role,
            "device_fingerprint": device_fingerprint.lower(),
        }
        return self._append_audit_entry(
            "ADD_GROUP_MEMBER",
            actor_id,
            {"group_id": group_id, "member_id": member_id, "role": role},
        )

    def remove_member(
        self,
        *,
        group_id: str,
        actor_id: str,
        member_id: str,
    ) -> dict[str, Any]:
        group = self._groups.get(group_id)
        if group is None or group.revoked:
            raise DeveloperGroupPrivilegeError("Developer group does not exist or is revoked")
        actor_info = group.members.get(actor_id)
        if actor_info is None or actor_info.get("role") not in ("owner", "admin"):
            raise DeveloperGroupPrivilegeError("Only group owner or admin can remove members")
        if member_id == group.owner_id:
            raise DeveloperGroupPrivilegeError("Cannot remove group owner")
        group.members.pop(member_id, None)
        return self._append_audit_entry(
            "REMOVE_GROUP_MEMBER",
            actor_id,
            {"group_id": group_id, "member_id": member_id},
        )
