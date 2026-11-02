"""Key serialization formats, encodings, and PEM/DER loaders (RFC 8410)."""

from __future__ import annotations

import base64
from enum import Enum

ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_OID_DER = bytes.fromhex("06032b6570")

X25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")
X25519_SPKI_PREFIX = bytes.fromhex("302a300506032b656e032100")
X25519_OID_DER = bytes.fromhex("06032b656e")


class Encoding(Enum):
    PEM = "PEM"
    DER = "DER"
    Raw = "Raw"


class PrivateFormat(Enum):
    PKCS8 = "PKCS8"
    Raw = "Raw"
    TraditionalOpenSSL = "TraditionalOpenSSL"


class PublicFormat(Enum):
    SubjectPublicKeyInfo = "SubjectPublicKeyInfo"
    Raw = "Raw"
    PKCS1 = "PKCS1"


class KeySerializationEncryption:
    pass


class NoEncryption(KeySerializationEncryption):
    pass


def encode_pem(der_bytes: bytes, label: str) -> bytes:
    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode("ascii")


def decode_pem(pem_bytes: bytes, expected_label: str) -> bytes:
    if not isinstance(pem_bytes, (bytes, bytearray)):
        raise TypeError("PEM data must be bytes.")
    try:
        text = bytes(pem_bytes).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid PEM ASCII encoding.") from exc
    begin_marker = f"-----BEGIN {expected_label}-----"
    end_marker = f"-----END {expected_label}-----"
    if begin_marker not in text or end_marker not in text:
        raise ValueError(f"Unable to load PEM file; missing {expected_label} markers.")
    start = text.index(begin_marker) + len(begin_marker)
    end = text.index(end_marker, start)
    b64_payload = "".join(text[start:end].split())
    if not b64_payload:
        raise ValueError("Empty PEM payload.")
    try:
        return base64.b64decode(b64_payload, validate=True)
    except Exception as exc:
        raise ValueError("Malformed base64 inside PEM block.") from exc


def load_pem_private_key(
    data: bytes,
    password: bytes | None = None,
    backend: object = None,
) -> object:
    if password is not None:
        raise TypeError("Encrypted private keys are not supported with password!=None.")
    der = decode_pem(data, "PRIVATE KEY")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    if der.startswith(ED25519_PKCS8_PREFIX) and len(der) == len(ED25519_PKCS8_PREFIX) + 32:
        return Ed25519PrivateKey.from_private_bytes(der[len(ED25519_PKCS8_PREFIX) :])
    if ED25519_OID_DER in der:
        idx = der.index(ED25519_OID_DER) + len(ED25519_OID_DER)
        tail = der[idx:]
        marker = b"\x04\x20"
        if marker in tail:
            seed_start = tail.index(marker) + 2
            seed = tail[seed_start : seed_start + 32]
            if len(seed) == 32:
                return Ed25519PrivateKey.from_private_bytes(seed)

    if der.startswith(X25519_PKCS8_PREFIX) and len(der) == len(X25519_PKCS8_PREFIX) + 32:
        return X25519PrivateKey.from_private_bytes(der[len(X25519_PKCS8_PREFIX) :])
    if X25519_OID_DER in der:
        idx = der.index(X25519_OID_DER) + len(X25519_OID_DER)
        tail = der[idx:]
        marker = b"\x04\x20"
        if marker in tail:
            seed_start = tail.index(marker) + 2
            seed = tail[seed_start : seed_start + 32]
            if len(seed) == 32:
                return X25519PrivateKey.from_private_bytes(seed)

    raise ValueError("Unsupported or malformed PKCS#8 private key.")


def load_pem_public_key(data: bytes, backend: object = None) -> object:
    der = decode_pem(data, "PUBLIC KEY")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    if der.startswith(ED25519_SPKI_PREFIX) and len(der) == len(ED25519_SPKI_PREFIX) + 32:
        return Ed25519PublicKey.from_public_bytes(der[len(ED25519_SPKI_PREFIX) :])
    if der.startswith(X25519_SPKI_PREFIX) and len(der) == len(X25519_SPKI_PREFIX) + 32:
        return X25519PublicKey.from_public_bytes(der[len(X25519_SPKI_PREFIX) :])

    raise ValueError("Unsupported or malformed SubjectPublicKeyInfo public key.")
