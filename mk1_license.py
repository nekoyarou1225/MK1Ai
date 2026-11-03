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


class LicenseCategory(str, Enum):
    GENERAL = "GENERAL"
    BUSINESS = "BUSINESS"
    RESEARCH = "RESEARCH"
    GENESIS_GROUP = "GENESIS_GROUP"


class LicenseSubTier(str, Enum):
    PLUS = "PLUS"
    PLUS_PRO = "PLUS_PRO"
    PLUS_PRO_MAX = "PLUS_PRO_MAX"
    PRO = "PRO"
    PRO_MAX = "PRO_MAX"
    ULTRA = "ULTRA"
    ULTRA_PRO = "ULTRA_PRO"
    ULTRA_MAX = "ULTRA_MAX"


import re as _re

_SHA256_HEX_RE = _re.compile(r"^[0-9a-fA-F]{64}$")
_MY_NUMBER_12DIGIT_RE = _re.compile(r"(?<!\d)\d{12}(?!\d)")
_RAW_IMAGE_MARKERS = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"BM",
    b"data:image/",
)


def validate_kyc_biometric_hashes(
    *,
    kyc_identity_hash: str | bytes,
    biometric_3d_mesh_hash: str | bytes,
    device_fingerprint: str | bytes,
) -> dict[str, str]:
    """Validate that KYC identity, 3D facial mesh, and device fingerprint are irreversible SHA-256 hashes.

    Strictly rejects raw facial images, base64 image URIs, or 12-digit My Number strings.
    """
    validated: dict[str, str] = {}
    for field_name, raw_val in (
        ("kyc_identity_hash", kyc_identity_hash),
        ("biometric_3d_mesh_hash", biometric_3d_mesh_hash),
        ("device_fingerprint", device_fingerprint),
    ):
        if isinstance(raw_val, (bytes, bytearray)):
            for marker in _RAW_IMAGE_MARKERS:
                if bytes(raw_val).startswith(marker) or marker in bytes(raw_val)[:64]:
                    raise LicenseVerificationError(
                        f"FAIL_CLOSED_BLOCK: Raw image binary prohibited in {field_name}"
                    )
            try:
                text_val = bytes(raw_val).decode("ascii")
            except UnicodeDecodeError as exc:
                raise LicenseVerificationError(
                    f"FAIL_CLOSED_BLOCK: Non-ASCII binary blob prohibited in {field_name}"
                ) from exc
        elif isinstance(raw_val, str):
            text_val = raw_val.strip()
        else:
            raise LicenseVerificationError(f"FAIL_CLOSED_BLOCK: Invalid type for {field_name}")

        if text_val.lower().startswith("data:image/"):
            raise LicenseVerificationError(
                f"FAIL_CLOSED_BLOCK: Raw image data URI prohibited in {field_name}"
            )
        if len(text_val) == 12 and text_val.isdigit():
            raise LicenseVerificationError(
                f"FAIL_CLOSED_BLOCK: Raw 12-digit My Number string prohibited in {field_name}"
            )
        if not _SHA256_HEX_RE.fullmatch(text_val):
            if _MY_NUMBER_12DIGIT_RE.search(text_val):
                raise LicenseVerificationError(
                    f"FAIL_CLOSED_BLOCK: Unhashed 12-digit My Number pattern prohibited in {field_name}"
                )
            raise LicenseVerificationError(
                f"FAIL_CLOSED_BLOCK: {field_name} must be an irreversible 64-hex SHA-256 digest"
            )
        validated[field_name] = text_val.lower()
    return validated


def compute_watermark_digest(
    *,
    license_id: str,
    kyc_identity_hash: str,
    biometric_3d_mesh_hash: str,
    device_fingerprint: str,
) -> str:
    """Compute deterministic cryptographic watermark digest for 30-day trial leak attribution."""
    checked = validate_kyc_biometric_hashes(
        kyc_identity_hash=kyc_identity_hash,
        biometric_3d_mesh_hash=biometric_3d_mesh_hash,
        device_fingerprint=device_fingerprint,
    )
    payload = (
        f"MK1AI-WATERMARK-v1|{license_id.strip()}|"
        f"{checked['kyc_identity_hash']}|"
        f"{checked['biometric_3d_mesh_hash']}|"
        f"{checked['device_fingerprint']}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def embed_packet_watermark(packet_bytes: bytes, watermark_digest: str) -> bytes:
    """Embed cryptographic trial watermark into an outbound packet trailer."""
    if not _SHA256_HEX_RE.fullmatch(watermark_digest):
        raise LicenseVerificationError("watermark_digest must be a 64-hex SHA-256 digest")
    tag = f"|MK1WM:{watermark_digest.lower()}|".encode("ascii")
    return bytes(packet_bytes) + tag


def embed_audit_log_watermark(audit_record: dict[str, Any], watermark_digest: str) -> dict[str, Any]:
    """Embed cryptographic trial watermark into an audit log entry."""
    if not _SHA256_HEX_RE.fullmatch(watermark_digest):
        raise LicenseVerificationError("watermark_digest must be a 64-hex SHA-256 digest")
    enriched = dict(audit_record)
    enriched["watermark_digest"] = watermark_digest.lower()
    return enriched


def trace_leak_owner(
    leaked_artifact: bytes | str | dict[str, Any],
    issued_tokens: list[SignedLicenseToken],
) -> dict[str, Any] | None:
    """Reverse-trace a leaked packet or audit log to the exact licensed trial owner."""
    extracted_digest: str | None = None
    if isinstance(leaked_artifact, dict):
        wm = leaked_artifact.get("watermark_digest")
        if isinstance(wm, str) and _SHA256_HEX_RE.fullmatch(wm):
            extracted_digest = wm.lower()
    else:
        text = (
            leaked_artifact.decode("utf-8", errors="ignore")
            if isinstance(leaked_artifact, (bytes, bytearray))
            else str(leaked_artifact)
        )
        match = _re.search(r"MK1WM:([0-9a-fA-F]{64})", text)
        if match:
            extracted_digest = match.group(1).lower()
        elif _SHA256_HEX_RE.fullmatch(text.strip()):
            extracted_digest = text.strip().lower()

    if not extracted_digest:
        return None

    for token in issued_tokens:
        token_wm = token.effective_watermark_digest()
        if token_wm and hmac.compare_digest(token_wm.lower(), extracted_digest):
            return {
                "license_id": token.license_id,
                "customer_org": token.customer_org,
                "plan_code": token.plan_code,
                "kyc_identity_hash": token.kyc_identity_hash,
                "biometric_3d_mesh_hash": token.biometric_3d_mesh_hash,
                "device_fingerprint": token.device_fingerprint,
                "watermark_digest": token_wm.lower(),
            }
    return None


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
    plan_code: str = "GENERAL.PLUS"
    category: LicenseCategory = LicenseCategory.GENERAL
    sub_tier: LicenseSubTier = LicenseSubTier.PLUS
    watermark_required: bool = False
    watermark_digest: str | None = None
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
        plan_code="GENERAL.PLUS",
        category=LicenseCategory.GENERAL,
        sub_tier=LicenseSubTier.PLUS,
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
        plan_code="GENERAL.PRO",
        category=LicenseCategory.GENERAL,
        sub_tier=LicenseSubTier.PRO,
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
        plan_code="BUSINESS.PRO_MAX",
        category=LicenseCategory.BUSINESS,
        sub_tier=LicenseSubTier.PRO_MAX,
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
        plan_code="GENESIS_GROUP.ULTRA_MAX",
        category=LicenseCategory.GENESIS_GROUP,
        sub_tier=LicenseSubTier.ULTRA_MAX,
    ),
}


def _build_thunderhole_32_plan_catalog() -> dict[str, PlanEntitlements]:
    """Construct all 32 THUNDERHOLE plans (4 categories x 8 sub-tiers)."""
    catalog: dict[str, PlanEntitlements] = {}
    sub_tier_order = list(LicenseSubTier)
    for cat in LicenseCategory:
        for idx, sub in enumerate(sub_tier_order):
            plan_code = f"{cat.value}.{sub.value}"
            if idx == 0 and cat == LicenseCategory.GENERAL:
                legacy_tier = PlanTier.COMMUNITY_BASIC
            elif idx <= 2:
                legacy_tier = PlanTier.STANDARD
            elif cat == LicenseCategory.GENESIS_GROUP or idx >= 6:
                legacy_tier = PlanTier.DEVELOPER_GROUP if cat == LicenseCategory.GENESIS_GROUP else PlanTier.PRO
            else:
                legacy_tier = PlanTier.PRO

            max_hp = min(8, max(1, idx + 1))
            if cat == LicenseCategory.GENESIS_GROUP:
                max_hp = min(8, max(4, idx + 1))
            custom_os = idx >= 3 or cat in (LicenseCategory.RESEARCH, LicenseCategory.GENESIS_GROUP)
            auto_rebuild = idx >= 1 or cat != LicenseCategory.GENERAL
            dev_group_admin = cat == LicenseCategory.GENESIS_GROUP
            os_fams = (
                ("debian", "ubuntu-server")
                if idx == 0 and cat == LicenseCategory.GENERAL
                else (
                    ("debian", "ubuntu-server", "rocky-linux", "almalinux")
                    if not custom_os
                    else ("debian", "ubuntu-server", "rocky-linux", "almalinux", "fedora-server", "custom-os")
                )
            )
            bw_mbps = 100 * (idx + 1) * (2 if cat in (LicenseCategory.RESEARCH, LicenseCategory.GENESIS_GROUP) else 1)
            pps = 25_000 * (idx + 1) * (2 if cat in (LicenseCategory.RESEARCH, LicenseCategory.GENESIS_GROUP) else 1)
            sessions = 1_024 * (2**idx)
            catalog[plan_code] = PlanEntitlements(
                tier=legacy_tier,
                max_honeypots=max_hp,
                allowed_os_families=os_fams,
                custom_os_allowed=custom_os,
                auto_rebuild_allowed=auto_rebuild,
                developer_group_admin_allowed=dev_group_admin,
                bandwidth_mbps=bw_mbps,
                pps_limit=pps,
                max_concurrent_sessions=sessions,
                plan_code=plan_code,
                category=cat,
                sub_tier=sub,
                watermark_required=(cat == LicenseCategory.RESEARCH and sub == LicenseSubTier.ULTRA_MAX),
            )
    return catalog


THUNDERHOLE_PLAN_CATALOG: dict[str, PlanEntitlements] = _build_thunderhole_32_plan_catalog()


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
    plan_code: str | None = None
    kyc_identity_hash: str | None = None
    biometric_3d_mesh_hash: str | None = None
    watermark_digest: str | None = None
    is_offline_trial: bool = False
    signature_hex: str = ""

    @property
    def monotonic_seq(self) -> int:
        return self.sequence_number

    def effective_watermark_digest(self) -> str | None:
        if self.watermark_digest:
            return self.watermark_digest.lower()
        if self.kyc_identity_hash and self.biometric_3d_mesh_hash:
            return compute_watermark_digest(
                license_id=self.license_id,
                kyc_identity_hash=self.kyc_identity_hash,
                biometric_3d_mesh_hash=self.biometric_3d_mesh_hash,
                device_fingerprint=self.device_fingerprint,
            )
        return None

    def canonical_bytes(self) -> bytes:
        doc: dict[str, Any] = {
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
        if self.plan_code is not None:
            doc["plan_code"] = self.plan_code
        if self.kyc_identity_hash is not None:
            doc["kyc_identity_hash"] = self.kyc_identity_hash.lower()
        if self.biometric_3d_mesh_hash is not None:
            doc["biometric_3d_mesh_hash"] = self.biometric_3d_mesh_hash.lower()
        if self.watermark_digest is not None:
            doc["watermark_digest"] = self.watermark_digest.lower()
        if self.is_offline_trial:
            doc["is_offline_trial"] = True
        return b"MK1AI-OFFLINE-LICENSE-v1:" + json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_signed_license(token: SignedLicenseToken, issuer_private_seed32: bytes) -> SignedLicenseToken:
    """Authority-side helper to sign an offline license token with Ed25519."""
    wm_digest = token.watermark_digest
    if (
        token.is_offline_trial
        or token.plan_code == "RESEARCH.ULTRA_MAX"
        or token.kyc_identity_hash is not None
        or token.biometric_3d_mesh_hash is not None
    ):
        if not token.kyc_identity_hash or not token.biometric_3d_mesh_hash:
            raise LicenseVerificationError(
                "Offline trial / KYC-bound license requires kyc_identity_hash and biometric_3d_mesh_hash"
            )
        validate_kyc_biometric_hashes(
            kyc_identity_hash=token.kyc_identity_hash,
            biometric_3d_mesh_hash=token.biometric_3d_mesh_hash,
            device_fingerprint=token.device_fingerprint,
        )
        if wm_digest is None:
            wm_digest = compute_watermark_digest(
                license_id=token.license_id,
                kyc_identity_hash=token.kyc_identity_hash,
                biometric_3d_mesh_hash=token.biometric_3d_mesh_hash,
                device_fingerprint=token.device_fingerprint,
            )
    unsigned_token = SignedLicenseToken(
        license_id=token.license_id,
        customer_org=token.customer_org,
        tier=token.tier,
        device_fingerprint=token.device_fingerprint,
        issued_at_utc=token.issued_at_utc,
        expires_at_utc=token.expires_at_utc,
        sequence_number=token.sequence_number,
        max_honeypots_override=token.max_honeypots_override,
        group_id=token.group_id,
        plan_code=token.plan_code,
        kyc_identity_hash=token.kyc_identity_hash,
        biometric_3d_mesh_hash=token.biometric_3d_mesh_hash,
        watermark_digest=wm_digest,
        is_offline_trial=token.is_offline_trial,
        signature_hex="",
    )
    sig = ed25519_sign(issuer_private_seed32, unsigned_token.canonical_bytes()).hex()
    return SignedLicenseToken(
        license_id=unsigned_token.license_id,
        customer_org=unsigned_token.customer_org,
        tier=unsigned_token.tier,
        device_fingerprint=unsigned_token.device_fingerprint,
        issued_at_utc=unsigned_token.issued_at_utc,
        expires_at_utc=unsigned_token.expires_at_utc,
        sequence_number=unsigned_token.sequence_number,
        max_honeypots_override=unsigned_token.max_honeypots_override,
        group_id=unsigned_token.group_id,
        plan_code=unsigned_token.plan_code,
        kyc_identity_hash=unsigned_token.kyc_identity_hash,
        biometric_3d_mesh_hash=unsigned_token.biometric_3d_mesh_hash,
        watermark_digest=unsigned_token.watermark_digest,
        is_offline_trial=unsigned_token.is_offline_trial,
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
        """Return GENERAL.PLUS (Community/Basic) Safe Degraded Mode while keeping CORE security 100% active."""
        base = THUNDERHOLE_PLAN_CATALOG["GENERAL.PLUS"]
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
            plan_code="GENERAL.PLUS",
            category=LicenseCategory.GENERAL,
            sub_tier=LicenseSubTier.PLUS,
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
        """Verify license offline; return tier entitlements or transition to Safe Degraded Mode (GENERAL.PLUS)."""
        try:
            # Reject environment-variable privilege bypass attempts
            if os.environ.get("MK1AI_FORCE_DEV_LICENSE") or os.environ.get("MK1AI_BYPASS_LICENSE"):
                raise LicenseVerificationError("Environment variable license override is prohibited")

            if (
                token.is_offline_trial
                or token.plan_code == "RESEARCH.ULTRA_MAX"
                or token.kyc_identity_hash is not None
                or token.biometric_3d_mesh_hash is not None
            ):
                if not token.kyc_identity_hash or not token.biometric_3d_mesh_hash:
                    raise LicenseVerificationError(
                        "Offline trial license requires kyc_identity_hash and biometric_3d_mesh_hash"
                    )
                validate_kyc_biometric_hashes(
                    kyc_identity_hash=token.kyc_identity_hash,
                    biometric_3d_mesh_hash=token.biometric_3d_mesh_hash,
                    device_fingerprint=token.device_fingerprint,
                )
                expected_wm = compute_watermark_digest(
                    license_id=token.license_id,
                    kyc_identity_hash=token.kyc_identity_hash,
                    biometric_3d_mesh_hash=token.biometric_3d_mesh_hash,
                    device_fingerprint=token.device_fingerprint,
                )
                if token.watermark_digest and not hmac.compare_digest(
                    token.watermark_digest.lower(), expected_wm.lower()
                ):
                    raise LicenseVerificationError("Trial watermark_digest mismatch")

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

            if token.plan_code is not None:
                if token.plan_code not in THUNDERHOLE_PLAN_CATALOG:
                    raise LicenseVerificationError(f"Unknown THUNDERHOLE plan_code: {token.plan_code}")
                base = THUNDERHOLE_PLAN_CATALOG[token.plan_code]
            else:
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
                plan_code=base.plan_code,
                category=base.category,
                sub_tier=base.sub_tier,
                watermark_required=base.watermark_required or token.is_offline_trial,
                watermark_digest=token.effective_watermark_digest(),
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
