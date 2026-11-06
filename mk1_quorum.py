"""Strict multi-signer Ed25519 approval verification for sensitive operations."""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from pathlib import Path
from typing import Mapping

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _CRYPTOGRAPHY_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - minimal environment fallback
    InvalidSignature = Exception  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = object  # type: ignore[assignment,misc]
    Ed25519PublicKey = object  # type: ignore[assignment,misc]
    _CRYPTOGRAPHY_AVAILABLE = False


MAX_APPROVAL_BUNDLE_BYTES = 32 * 1024
MAX_APPROVALS = 3
SIGNATURE_BYTES = 64
PUBLIC_KEY_BYTES = 32
MAX_CHALLENGE_BYTES = 4096


class QuorumError(RuntimeError):
    """Raised when trusted quorum approval cannot be established."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise QuorumError("Approval bundle contains a duplicate JSON key")
        result[key] = value
    return result


def _validate_signer_id(signer_id: object) -> str:
    if (
        not isinstance(signer_id, str)
        or not signer_id
        or len(signer_id) > 64
        or not signer_id.isascii()
        or not signer_id.replace("-", "").replace("_", "").isalnum()
    ):
        raise QuorumError("Quorum roster contains an invalid signer identity")
    return signer_id


def _parse_challenge(raw: bytes) -> tuple[dict[str, object], bytes]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_CHALLENGE_BYTES:
        raise QuorumError("Release challenge is invalid or exceeds its size limit")
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError, QuorumError) as exc:
        if isinstance(exc, QuorumError):
            raise
        raise QuorumError("Release challenge is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "version", "generation", "challenge", "message_base64",
    }:
        raise QuorumError("Release challenge does not match the closed schema")
    generation = document["generation"]
    challenge = document["challenge"]
    if (
        isinstance(document["version"], bool)
        or document["version"] != 1
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= 2**63 - 1
        or not isinstance(challenge, str)
        or len(challenge) != 64
        or any(character not in "0123456789abcdef" for character in challenge)
    ):
        raise QuorumError("Release challenge fields are invalid")
    message = (
        f"MK1AI-QUARANTINE-RELEASE-v1\n{generation}\n{challenge}\n"
    ).encode("ascii")
    try:
        provided_message = base64.b64decode(
            document["message_base64"],
            validate=True,
        )
    except (binascii.Error, TypeError, ValueError) as exc:
        raise QuorumError("Release challenge message is invalid base64") from exc
    if provided_message != message:
        raise QuorumError("Release challenge message does not match its fields")
    if base64.b64encode(provided_message).decode("ascii") != document["message_base64"]:
        raise QuorumError("Release challenge message encoding is not canonical")
    return document, message


def _read_bounded_file(
    path: Path,
    *,
    maximum_bytes: int,
    require_private_owner: bool = False,
) -> bytes:
    try:
        file_descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise QuorumError("Input file could not be opened safely") from exc
    try:
        file_stat = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_size <= 0
            or file_stat.st_size > maximum_bytes
        ):
            raise QuorumError("Input file is invalid or exceeds its size limit")
        if require_private_owner and (
            file_stat.st_uid != os.geteuid() or file_stat.st_mode & 0o077
        ):
            raise QuorumError("Private signing key ownership or mode is invalid")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        if len(contents) > maximum_bytes:
            raise QuorumError("Input file exceeds its size limit")
        return contents
    finally:
        os.close(file_descriptor)


def create_approval_record(
    signer_id: str,
    challenge_document: bytes,
    private_key_pem: bytes,
) -> bytes:
    """Sign only a well-formed, fresh release challenge using an Ed25519 key."""
    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise QuorumError("cryptography library is required for Ed25519 quorum operations")
    signer_id = _validate_signer_id(signer_id)
    _, message = _parse_challenge(challenge_document)
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise QuorumError("Approver private key is not valid unencrypted PEM") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise QuorumError("Approver private key must use Ed25519")
    signature = private_key.sign(message)
    record = {
        "version": 1,
        "signer_id": signer_id,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def create_approval_record_from_files(
    signer_id: str,
    challenge_path: Path,
    private_key_path: Path,
) -> bytes:
    challenge = _read_bounded_file(
        challenge_path,
        maximum_bytes=MAX_CHALLENGE_BYTES,
    )
    private_key = _read_bounded_file(
        private_key_path,
        maximum_bytes=16_384,
        require_private_owner=True,
    )
    return create_approval_record(signer_id, challenge, private_key)


def combine_approval_records(records: list[bytes]) -> bytes:
    """Combine independent signer records; cryptographic checks occur at target."""
    if not 2 <= len(records) <= MAX_APPROVALS:
        raise QuorumError("At least two and at most three approval records are required")
    approvals: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in records:
        if not isinstance(raw, bytes) or len(raw) > 2048:
            raise QuorumError("Approval record is invalid or exceeds its size limit")
        try:
            record = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, UnicodeDecodeError, QuorumError) as exc:
            if isinstance(exc, QuorumError):
                raise
            raise QuorumError("Approval record is not valid UTF-8 JSON") from exc
        if not isinstance(record, dict) or set(record) != {
            "version", "signer_id", "signature",
        }:
            raise QuorumError("Approval record does not match the closed schema")
        if isinstance(record["version"], bool) or record["version"] != 1:
            raise QuorumError("Approval record version is unsupported")
        signer_id = _validate_signer_id(record["signer_id"])
        if signer_id in seen:
            raise QuorumError("Approval records repeat a signer")
        if not isinstance(record["signature"], str):
            raise QuorumError("Approval record signature must be base64 text")
        try:
            signature = base64.b64decode(record["signature"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise QuorumError("Approval record signature is not valid base64") from exc
        if len(signature) != SIGNATURE_BYTES:
            raise QuorumError("Approval signature has an invalid length")
        seen.add(signer_id)
        approvals.append({
            "signer_id": signer_id,
            "signature": record["signature"],
        })
    return json.dumps(
        {"version": 1, "approvals": approvals},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _read_trusted_key(
    path: Path,
    *,
    expected_uid: int,
    strict_ancestors: bool,
) -> Ed25519PublicKey:
    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise QuorumError("cryptography library is required for Ed25519 quorum operations")
    try:
        file_descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise QuorumError("A trusted quorum public key could not be opened") from exc
    try:
        key_stat = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(key_stat.st_mode)
            or key_stat.st_uid != expected_uid
            or key_stat.st_mode & 0o022
            or key_stat.st_size <= 0
            or key_stat.st_size > 16_384
        ):
            raise QuorumError("Quorum public key ownership, mode, or size is invalid")
        if strict_ancestors:
            for parent in path.parents:
                parent_stat = parent.stat()
                if parent_stat.st_uid != expected_uid or parent_stat.st_mode & 0o022:
                    raise QuorumError("Quorum public key has an untrusted parent directory")
        chunks: list[bytes] = []
        remaining = 16_385
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded_key = b"".join(chunks)
        if len(encoded_key) > 16_384:
            raise QuorumError("Quorum public key exceeds its size limit")
    finally:
        os.close(file_descriptor)

    try:
        public_key = serialization.load_pem_public_key(encoded_key)
    except (ValueError, TypeError) as exc:
        raise QuorumError("Quorum public key is not valid PEM") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise QuorumError("Quorum public key must use Ed25519")
    return public_key


def load_trusted_quorum_keys(
    key_paths: Mapping[str, Path],
    *,
    expected_uid: int,
    strict_ancestors: bool = True,
) -> dict[str, Ed25519PublicKey]:
    """Load a closed roster of two or three independently enrolled signers."""
    if not 2 <= len(key_paths) <= MAX_APPROVALS:
        raise QuorumError("Quorum roster must contain two or three signers")
    for signer_id in key_paths:
        _validate_signer_id(signer_id)

    loaded = {
        signer_id: _read_trusted_key(
            Path(key_path),
            expected_uid=expected_uid,
            strict_ancestors=strict_ancestors,
        )
        for signer_id, key_path in key_paths.items()
    }
    fingerprints = {
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for key in loaded.values()
    }
    if len(fingerprints) != len(loaded):
        raise QuorumError("Quorum public keys must be distinct")
    return loaded


def verify_approval_bundle(
    message: bytes,
    bundle: bytes,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    *,
    threshold: int = 2,
) -> tuple[str, ...]:
    """Require distinct, known signer IDs and valid signatures over one message."""
    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise QuorumError("cryptography library is required for Ed25519 quorum operations")
    if not isinstance(message, bytes) or not message:
        raise QuorumError("Quorum message must be non-empty bytes")
    if not isinstance(bundle, bytes) or len(bundle) > MAX_APPROVAL_BUNDLE_BYTES:
        raise QuorumError("Approval bundle is invalid or exceeds its size limit")
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold < 2
        or threshold > len(trusted_keys)
    ):
        raise QuorumError("Quorum threshold must be at least two and fit the roster")
    if not 2 <= len(trusted_keys) <= MAX_APPROVALS:
        raise QuorumError("Quorum roster must contain two or three signers")
    encoded_keys: set[bytes] = set()
    for signer_id, key in trusted_keys.items():
        _validate_signer_id(signer_id)
        if not isinstance(key, Ed25519PublicKey):
            raise QuorumError("Quorum roster contains a non-Ed25519 key")
        encoded_keys.add(key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ))
    if len(encoded_keys) != len(trusted_keys):
        raise QuorumError("Quorum public keys must be distinct")

    try:
        document = json.loads(
            bundle,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, QuorumError) as exc:
        if isinstance(exc, QuorumError):
            raise
        raise QuorumError("Approval bundle is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {"version", "approvals"}:
        raise QuorumError("Approval bundle does not match the closed schema")
    if (
        isinstance(document["version"], bool)
        or document["version"] != 1
        or not isinstance(document["approvals"], list)
    ):
        raise QuorumError("Approval bundle schema version or approvals field is invalid")
    if not threshold <= len(document["approvals"]) <= len(trusted_keys):
        raise QuorumError("Approval bundle quorum count is invalid")

    accepted: list[str] = []
    seen: set[str] = set()
    for approval in document["approvals"]:
        if (
            not isinstance(approval, dict)
            or set(approval) != {"signer_id", "signature"}
            or not isinstance(approval["signer_id"], str)
            or not isinstance(approval["signature"], str)
        ):
            raise QuorumError("Approval entry does not match the closed schema")
        signer_id = approval["signer_id"]
        if signer_id in seen:
            raise QuorumError("Approval bundle repeats a signer")
        key = trusted_keys.get(signer_id)
        if key is None:
            raise QuorumError("Approval bundle contains an unknown signer")
        try:
            signature = base64.b64decode(approval["signature"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise QuorumError("Approval signature is not valid base64") from exc
        if base64.b64encode(signature).decode("ascii") != approval["signature"]:
            raise QuorumError("Approval signature encoding is not canonical")
        if len(signature) != SIGNATURE_BYTES:
            raise QuorumError("Approval signature has an invalid length")
        try:
            key.verify(signature, message)
        except InvalidSignature as exc:
            raise QuorumError("An approval signature is invalid") from exc
        seen.add(signer_id)
        accepted.append(signer_id)
    return tuple(accepted)


def generate_operator_keypair(operator_id: str) -> dict[str, bytes | str]:
    """Generate an Ed25519 operator keypair for quorum signing and verification."""
    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise QuorumError("cryptography library is required for Ed25519 quorum operations")
    signer_id = _validate_signer_id(operator_id)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return {
        "operator_id": signer_id,
        "private_key_pem": private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "public_key_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    }


MAX_VALID_EPOCH = 4_102_444_800  # 2100-01-01T00:00:00Z
MAX_CHALLENGE_TTL_SEC = 86_400


def generate_secure_event_id(prefix: str = "evt") -> str:
    """Generate a cryptographically random 128-bit event or challenge identifier."""
    import secrets
    clean_prefix = prefix.strip() if isinstance(prefix, str) and prefix.strip().isalnum() else "id"
    return f"{clean_prefix}-{secrets.token_hex(16)}"


def _validate_finite_int_timestamp(value: object, field_name: str) -> int:
    """Validate that a timestamp is a finite, positive integer (rejecting bool, float NaN/Inf, negative, None)."""
    import math
    if value is None or isinstance(value, bool):
        raise QuorumError(f"Quorum timestamp '{field_name}' must be an integer (got {type(value).__name__})")
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise QuorumError(f"Quorum timestamp '{field_name}' must be a finite integer")
        value = int(value)
    if not isinstance(value, int):
        raise QuorumError(f"Quorum timestamp '{field_name}' must be an integer")
    if value <= 0 or value > MAX_VALID_EPOCH:
        raise QuorumError(f"Quorum timestamp '{field_name}' is out of valid epoch range: {value}")
    return value


def _validate_identifier_token(value: object, field_name: str) -> str:
    """Validate challenge_id / event_id is a non-empty bounded ASCII identifier."""
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
        or not value.isascii()
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)
    ):
        raise QuorumError(f"Quorum field '{field_name}' must be a non-empty printable ASCII string (1..128 chars)")
    return value


def create_quorum_challenge(
    operation: str,
    parameters: Mapping[str, object] | None = None,
    *,
    required_m: int = 2,
    total_n: int = 2,
    ttl_sec: int = 300,
    now: int = 1_700_000_000,
    challenge_id: str = "chg-default",
    policy_version: int = 1,
) -> dict[str, object]:
    """Build a canonical M-of-N operational quorum challenge document.
    
    Now adds domain-specific prefixes based on operation:
    - ISOLATE_NETWORK -> MK1AI-ISOLATE-v1
    - RELEASE_QUARANTINE -> MK1AI-RECOVERY-v1
    """
    if not isinstance(operation, str) or not operation.strip():
        raise QuorumError("Quorum challenge operation must be a non-empty string")
    if (
        isinstance(required_m, bool)
        or not isinstance(required_m, int)
        or isinstance(total_n, bool)
        or not isinstance(total_n, int)
        or required_m < 2
        or total_n < required_m
        or total_n > MAX_APPROVALS
    ):
        raise QuorumError("Quorum challenge threshold must satisfy 2 <= M <= N <= 3")
    if isinstance(ttl_sec, bool) or not isinstance(ttl_sec, int) or ttl_sec < 1 or ttl_sec > MAX_CHALLENGE_TTL_SEC:
        raise QuorumError(f"Quorum challenge ttl_sec must be an integer in 1..{MAX_CHALLENGE_TTL_SEC}")
    if isinstance(policy_version, bool) or not isinstance(policy_version, int) or policy_version < 1:
        raise QuorumError("Quorum challenge policy_version must be a positive integer")
    clean_challenge_id = _validate_identifier_token(challenge_id, "challenge_id")
    issued_at = _validate_finite_int_timestamp(now, "now")
    expires_at = _validate_finite_int_timestamp(issued_at + ttl_sec, "expires_at")

    # Operation-specific prefixing (CORE vs Decoy / Isolation vs Recovery domain separation)
    prefix = "MK1AI-QUARANTINE-RELEASE-v1"
    if operation == "ISOLATE_NETWORK":
        prefix = "MK1AI-ISOLATE-v1"
    elif "RELEASE" in operation or "RECOVERY" in operation:
        prefix = "MK1AI-RECOVERY-v1"

    params_dict = dict(parameters or {})
    if "policy_version" in params_dict:
        pv = params_dict["policy_version"]
        if isinstance(pv, bool) or not isinstance(pv, int) or pv < 1:
            raise QuorumError("Quorum challenge parameters.policy_version must be a positive integer")
        policy_version = pv

    # Include prefix and policy_version in the signed document for strict cryptographic binding
    doc: dict[str, object] = {
        "version": 1,
        "policy_version": policy_version,
        "challenge_id": clean_challenge_id,
        "operation": operation,
        "prefix": prefix,
        "parameters": params_dict,
        "required_m": int(required_m),
        "total_n": int(total_n),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    return doc


def _canonical_challenge_bytes(challenge_document: Mapping[str, object]) -> bytes:
    return json.dumps(dict(challenge_document), sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_quorum_challenge(
    challenge_document: Mapping[str, object],
    *,
    operator_id: str,
    private_key_pem: bytes,
    signed_at: int | None = None,
) -> dict[str, object]:
    """Sign a structured quorum challenge document with an operator Ed25519 private key."""
    del signed_at
    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise QuorumError("cryptography library is required for Ed25519 quorum operations")
    signer_id = _validate_signer_id(operator_id)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise QuorumError("Operator private key must use Ed25519")
    sig = private_key.sign(_canonical_challenge_bytes(challenge_document))
    return {
        "signer_id": signer_id,
        "signature": base64.b64encode(sig).decode("ascii"),
    }


def build_quorum_bundle(
    challenge_document: Mapping[str, object],
    signatures: list[Mapping[str, object]],
) -> dict[str, object]:
    """Assemble a canonical approval bundle from operator signatures."""
    del challenge_document
    return {
        "version": 1,
        "approvals": [
            {
                "signer_id": str(entry["signer_id"]),
                "signature": str(entry["signature"]),
            }
            for entry in signatures
        ],
    }


def verify_quorum_bundle(
    approval_bundle: Mapping[str, object] | bytes,
    *,
    challenge_document: Mapping[str, object],
    trusted_keys: Mapping[str, bytes | Ed25519PublicKey],
    expected_operation: str | None = None,
    now: int | None = None,
) -> dict[str, object]:
    """Verify a structured M-of-N Ed25519 quorum approval bundle against challenge_document."""
    import time as _time_mod

    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise QuorumError("cryptography library is required for Ed25519 quorum operations")
    if not isinstance(challenge_document, Mapping):
        raise QuorumError("challenge_document must be a mapping")

    operation = challenge_document.get("operation")
    if not isinstance(operation, str) or not operation.strip():
        raise QuorumError("Quorum challenge is missing mandatory 'operation' field")
    if expected_operation is not None and operation != expected_operation:
        raise QuorumError("Quorum challenge operation mismatch")

    # Mandatory challenge_id validation
    _validate_identifier_token(challenge_document.get("challenge_id"), "challenge_id")

    # Mandatory domain prefix validation (CORE vs Decoy / operation separation)
    prefix = challenge_document.get("prefix")
    if not isinstance(prefix, str) or not prefix.strip():
        raise QuorumError("Quorum challenge is missing mandatory 'prefix' field")
    if operation == "ISOLATE_NETWORK" and prefix != "MK1AI-ISOLATE-v1":
        raise QuorumError(f"Invalid domain prefix '{prefix}' for ISOLATE_NETWORK")
    if operation == "RELEASE_QUARANTINE" and prefix != "MK1AI-RECOVERY-v1":
        raise QuorumError(f"Invalid domain prefix '{prefix}' for RELEASE_QUARANTINE")

    # Mandatory event_id and policy_version when releasing quarantine
    params = challenge_document.get("parameters")
    if params is not None and not isinstance(params, Mapping):
        raise QuorumError("Quorum challenge 'parameters' must be a mapping")
    params_map = params if isinstance(params, Mapping) else {}
    if operation == "RELEASE_QUARANTINE":
        raw_evt = challenge_document.get("event_id", params_map.get("event_id"))
        _validate_identifier_token(raw_evt, "event_id")
        if "policy_version" in challenge_document:
            raw_pv = challenge_document.get("policy_version")
        elif "policy_version" in params_map:
            raw_pv = params_map.get("policy_version")
        else:
            raise QuorumError("Quorum challenge for RELEASE_QUARANTINE is missing mandatory 'policy_version'")
        if isinstance(raw_pv, bool) or not isinstance(raw_pv, int) or raw_pv < 1:
            raise QuorumError("Quorum challenge 'policy_version' must be a positive integer")
        domain_tag = params_map.get("domain")
        if domain_tag is not None and domain_tag != "MK1AI-RECOVERY-v1":
            raise QuorumError(f"Quorum challenge domain mismatch (Decoy/foreign domain rejected): {domain_tag}")

    # Mandatory timestamp and expiration / future issuance checks (issued_at <= now <= expires_at)
    issued_at = _validate_finite_int_timestamp(challenge_document.get("issued_at"), "issued_at")
    expires_at = _validate_finite_int_timestamp(challenge_document.get("expires_at"), "expires_at")
    if expires_at < issued_at:
        raise QuorumError("Quorum challenge expires_at precedes issued_at")
    if expires_at - issued_at > MAX_CHALLENGE_TTL_SEC:
        raise QuorumError("Quorum challenge TTL exceeds maximum allowed window")

    current_ts = _validate_finite_int_timestamp(int(_time_mod.time()) if now is None else now, "now")
    if current_ts < issued_at:
        raise QuorumError("Quorum challenge issued_at is in the future")
    if current_ts > expires_at:
        raise QuorumError("Quorum challenge has expired")

    raw_req_m = challenge_document.get("required_m", 2)
    if isinstance(raw_req_m, bool) or not isinstance(raw_req_m, int) or raw_req_m < 2:
        raise QuorumError("Quorum challenge required_m must be an integer >= 2")
    threshold = raw_req_m
    loaded_keys: dict[str, Ed25519PublicKey] = {}
    for signer_id, raw_key in trusted_keys.items():
        if isinstance(raw_key, Ed25519PublicKey):
            loaded_keys[signer_id] = raw_key
        elif isinstance(raw_key, (bytes, bytearray)):
            pub = serialization.load_pem_public_key(bytes(raw_key))
            if not isinstance(pub, Ed25519PublicKey):
                raise QuorumError("Trusted key is not Ed25519")
            loaded_keys[signer_id] = pub
        else:
            raise QuorumError("Unsupported trusted key format")

    bundle_bytes = (
        approval_bundle
        if isinstance(approval_bundle, bytes)
        else json.dumps(dict(approval_bundle), sort_keys=True, separators=(",", ":")).encode("ascii")
    )
    accepted = verify_approval_bundle(
        _canonical_challenge_bytes(challenge_document),
        bundle_bytes,
        loaded_keys,
        threshold=threshold,
    )
    return {"verified": True, "signers": accepted}


REQUIRED_ADMIN_QUORUM = 2


class TwoAdminQuorumGate:
    """Enforces Quorum = 2 distinct administrator Ed25519 approvals per event_id.

    Protects critical operations (kill_switch, quarantine_release) against:
    - Single-administrator execution or duplicate admin_id signing
    - event_id replay (both in-memory and across process restarts via atomic ledger)
    - Expired approval bundles
    - Post-restart state tampering or corruption (fail-closed QuorumError)
    """

    def __init__(
        self,
        trusted_admin_keys: Mapping[str, bytes | Ed25519PublicKey],
        *,
        state_path: Path | str | None = None,
    ) -> None:
        if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
            raise QuorumError("cryptography library is required for Ed25519 quorum operations")
        if len(trusted_admin_keys) < REQUIRED_ADMIN_QUORUM:
            raise QuorumError("TwoAdminQuorumGate requires at least 2 distinct administrators")
        self._trusted_keys: dict[str, Ed25519PublicKey] = {}
        raw_pub_set: set[bytes] = set()
        for admin_id, key_obj in trusted_admin_keys.items():
            clean_id = _validate_signer_id(admin_id)
            if isinstance(key_obj, Ed25519PublicKey):
                pub = key_obj
            elif isinstance(key_obj, (bytes, bytearray)):
                loaded = serialization.load_pem_public_key(bytes(key_obj))
                if not isinstance(loaded, Ed25519PublicKey):
                    raise QuorumError("Administrator public key must be Ed25519")
                pub = loaded
            else:
                raise QuorumError("Unsupported administrator public key type")
            raw_bytes = pub.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if raw_bytes in raw_pub_set:
                raise QuorumError("Administrator Ed25519 public keys must be distinct")
            raw_pub_set.add(raw_bytes)
            self._trusted_keys[clean_id] = pub

        self._state_path = Path(state_path) if state_path is not None else None
        self._consumed_events: dict[str, dict[str, object]] = {}
        self._max_observed_time: int = 0
        if self._state_path is not None and self._state_path.exists():
            self._load_persistent_state()

    @staticmethod
    def _compute_state_digest(consumed: Mapping[str, object], max_time: int) -> str:
        import hashlib

        body = json.dumps(
            {"consumed_events": dict(consumed), "max_observed_time": int(max_time)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(b"MK1AI-QUORUM-STATE-v1:" + body).hexdigest()

    def _load_persistent_state(self) -> None:
        if self._state_path is None:
            return
        try:
            raw = self._state_path.read_text(encoding="utf-8")
            doc = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except Exception as exc:
            raise QuorumError("FAIL_CLOSED_BLOCK: Persistent quorum state is corrupted") from exc
        if not isinstance(doc, dict) or set(doc) != {
            "version",
            "consumed_events",
            "max_observed_time",
            "integrity_sha256",
        }:
            raise QuorumError("FAIL_CLOSED_BLOCK: Persistent quorum state schema mismatch")
        if doc.get("version") != 1 or not isinstance(doc.get("consumed_events"), dict):
            raise QuorumError("FAIL_CLOSED_BLOCK: Persistent quorum state version/type invalid")
        max_time = doc.get("max_observed_time")
        if isinstance(max_time, bool) or not isinstance(max_time, int) or max_time < 0:
            raise QuorumError("FAIL_CLOSED_BLOCK: Persistent quorum max_observed_time invalid")
        expected_digest = self._compute_state_digest(doc["consumed_events"], max_time)
        if doc.get("integrity_sha256") != expected_digest:
            raise QuorumError("FAIL_CLOSED_BLOCK: Persistent quorum state integrity check failed")
        self._consumed_events = dict(doc["consumed_events"])
        self._max_observed_time = max_time

    def _save_persistent_state(self) -> None:
        if self._state_path is None:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        digest = self._compute_state_digest(self._consumed_events, self._max_observed_time)
        payload = json.dumps(
            {
                "version": 1,
                "consumed_events": self._consumed_events,
                "max_observed_time": self._max_observed_time,
                "integrity_sha256": digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        tmp_path = self._state_path.with_suffix(".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        os.replace(tmp_path, self._state_path)

    @staticmethod
    def build_event_challenge(
        *,
        event_id: str,
        operation: str,
        issued_at: int,
        ttl_sec: int = 300,
        parameters: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        if not isinstance(event_id, str) or not event_id.strip() or len(event_id) > 128:
            raise QuorumError("event_id must be a non-empty string up to 128 chars")
        if operation not in ("kill_switch", "quarantine_release", "policy_override"):
            raise QuorumError(f"Unsupported critical quorum operation: {operation}")
        if ttl_sec <= 0 or ttl_sec > 86_400:
            raise QuorumError("ttl_sec must be between 1 and 86400 seconds")
        return {
            "version": 1,
            "event_id": event_id.strip(),
            "operation": operation,
            "parameters": dict(parameters or {}),
            "required_m": REQUIRED_ADMIN_QUORUM,
            "issued_at": int(issued_at),
            "expires_at": int(issued_at) + int(ttl_sec),
        }

    @staticmethod
    def sign_event_challenge(
        challenge: Mapping[str, object],
        *,
        admin_id: str,
        private_key: Ed25519PrivateKey | bytes,
    ) -> dict[str, str]:
        signer_id = _validate_signer_id(admin_id)
        if isinstance(private_key, (bytes, bytearray)):
            loaded_priv = serialization.load_pem_private_key(bytes(private_key), password=None)
            if not isinstance(loaded_priv, Ed25519PrivateKey):
                raise QuorumError("Admin private key must be Ed25519")
            priv = loaded_priv
        elif isinstance(private_key, Ed25519PrivateKey):
            priv = private_key
        else:
            raise QuorumError("Invalid admin private key")
        msg = _canonical_challenge_bytes(challenge)
        sig = priv.sign(msg)
        return {
            "signer_id": signer_id,
            "signature": base64.b64encode(sig).decode("ascii"),
        }

    def authorize_event(
        self,
        challenge: Mapping[str, object],
        approvals: list[Mapping[str, str]],
        *,
        expected_operation: str,
        now: int,
    ) -> dict[str, object]:
        """Verify Quorum >= 2 distinct admins, check expiration & event_id replay, and commit."""
        if self._state_path is not None and self._state_path.exists():
            self._load_persistent_state()

        if not isinstance(challenge, Mapping):
            raise QuorumError("Challenge must be a mapping")
        event_id = challenge.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise QuorumError("Challenge is missing a valid event_id")
        event_id = event_id.strip()

        if event_id in self._consumed_events:
            raise QuorumError(f"FAIL_CLOSED_BLOCK: Replay of consumed event_id '{event_id}' rejected")

        if challenge.get("operation") != expected_operation:
            raise QuorumError("Challenge operation does not match expected_operation")

        issued_at = challenge.get("issued_at")
        expires_at = challenge.get("expires_at")
        if (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
        ):
            raise QuorumError("Challenge timestamps must be integers")

        if int(now) < self._max_observed_time:
            raise QuorumError("FAIL_CLOSED_BLOCK: Monotonic clock rollback detected in quorum gate")
        if int(now) < issued_at:
            raise QuorumError("Challenge issued_at is in the future")
        if int(now) > expires_at:
            raise QuorumError("FAIL_CLOSED_BLOCK: Quorum approval challenge has expired")

        if not isinstance(approvals, list) or len(approvals) < REQUIRED_ADMIN_QUORUM:
            raise QuorumError("Quorum = 2 distinct administrator approvals required")

        bundle_bytes = json.dumps(
            {"version": 1, "approvals": approvals},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

        accepted_signers = verify_approval_bundle(
            _canonical_challenge_bytes(challenge),
            bundle_bytes,
            self._trusted_keys,
            threshold=REQUIRED_ADMIN_QUORUM,
        )
        if len(set(accepted_signers)) < REQUIRED_ADMIN_QUORUM:
            raise QuorumError("Quorum requires at least 2 distinct administrator identities")

        self._max_observed_time = max(self._max_observed_time, int(now))
        record = {
            "event_id": event_id,
            "operation": expected_operation,
            "approved_by": list(accepted_signers),
            "authorized_at": int(now),
        }
        self._consumed_events[event_id] = record
        self._save_persistent_state()
        return {
            "authorized": True,
            "quorum_met": True,
            "event_id": event_id,
            "operation": expected_operation,
            "signers": accepted_signers,
        }


