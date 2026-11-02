"""RFC 8032 Ed25519 Edwards-Curve Digital Signature Algorithm implementation."""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

# Ed25519 curve constants (RFC 8032 Section 5.1)
_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)
_ZERO = (0, 1, 1, 0)


def _point_add(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P


def _point_double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = (x1 * x1) % _P
    b = (y1 * y1) % _P
    c = (2 * z1 * z1) % _P
    h = (a + b) % _P
    e = (h - ((x1 + y1) * (x1 + y1) % _P)) % _P
    g = (a - b) % _P
    f = (c + g) % _P
    return (e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P


def _scalar_mult(
    scalar: int,
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    result = _ZERO
    addend = point
    s = scalar
    while s > 0:
        if s & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        s >>= 1
    return result


def _point_encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    z_inv = pow(z, _P - 2, _P)
    x_aff = (x * z_inv) % _P
    y_aff = (y * z_inv) % _P
    encoded = y_aff | ((x_aff & 1) << 255)
    return encoded.to_bytes(32, "little")


def _point_decode(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise InvalidSignature("Invalid Ed25519 point length.")
    val = int.from_bytes(encoded, "little")
    y = val & ((1 << 255) - 1)
    x_sign = (val >> 255) & 1
    if y >= _P:
        raise InvalidSignature("Ed25519 point y coordinate out of range.")
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    v3 = (v * v % _P) * v % _P
    v7 = (v3 * v3 % _P) * v % _P
    x = (u * v3 % _P) * pow(u * v7 % _P, (_P - 5) // 8, _P) % _P
    v_x2 = (v * x * x) % _P
    if v_x2 == u:
        pass
    elif v_x2 == (-u) % _P:
        x = (x * _I) % _P
    else:
        raise InvalidSignature("Point is not on Ed25519 curve.")
    if x == 0 and x_sign == 1:
        raise InvalidSignature("Invalid negative zero x coordinate.")
    if (x & 1) != x_sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


class Ed25519PublicKey:
    def __init__(self, public_bytes: bytes) -> None:
        if not isinstance(public_bytes, (bytes, bytearray)) or len(public_bytes) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes.")
        self._raw = bytes(public_bytes)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "Ed25519PublicKey":
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("An Ed25519 public key is 32 bytes long")
        return cls(bytes(data))

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        if encoding is serialization.Encoding.Raw or format is serialization.PublicFormat.Raw:
            if (
                encoding is not serialization.Encoding.Raw
                or format is not serialization.PublicFormat.Raw
            ):
                raise ValueError("Raw encoding and Raw format must be used together.")
            return self._raw
        if format is not serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError("Ed25519 public keys require SubjectPublicKeyInfo or Raw format.")
        der = serialization.ED25519_SPKI_PREFIX + self._raw
        if encoding is serialization.Encoding.DER:
            return der
        if encoding is serialization.Encoding.PEM:
            return serialization.encode_pem(der, "PUBLIC KEY")
        raise ValueError(f"Unsupported encoding: {encoding}")

    def verify(self, signature: bytes, data: bytes) -> None:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            raise InvalidSignature("Ed25519 signature must be 64 bytes.")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like.")
        r_bytes = bytes(signature[:32])
        s_int = int.from_bytes(signature[32:], "little")
        if s_int >= _L:
            raise InvalidSignature("Ed25519 scalar S out of canonical bounds.")
        a_point = _point_decode(self._raw)
        r_point = _point_decode(r_bytes)
        k_digest = hashlib.sha512(r_bytes + self._raw + bytes(data)).digest()
        k_int = int.from_bytes(k_digest, "little") % _L
        lhs = _scalar_mult(s_int, _B)
        rhs = _point_add(r_point, _scalar_mult(k_int, a_point))
        if not hmac.compare_digest(_point_encode(lhs), _point_encode(rhs)):
            raise InvalidSignature("Ed25519 signature verification failed.")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ed25519PublicKey):
            return False
        return hmac.compare_digest(self._raw, other._raw)


class Ed25519PrivateKey:
    def __init__(self, private_bytes: bytes) -> None:
        if not isinstance(private_bytes, (bytes, bytearray)) or len(private_bytes) != 32:
            raise ValueError("An Ed25519 private key is 32 bytes long")
        self._seed = bytes(private_bytes)
        digest = bytearray(hashlib.sha512(self._seed).digest())
        digest[0] &= 248
        digest[31] &= 127
        digest[31] |= 64
        self._scalar = int.from_bytes(digest[:32], "little")
        self._prefix = bytes(digest[32:64])
        self._public_raw = _point_encode(_scalar_mult(self._scalar, _B))

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        return cls(os.urandom(32))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "Ed25519PrivateKey":
        if not isinstance(data, (bytes, bytearray)) or len(data) != 32:
            raise ValueError("An Ed25519 private key is 32 bytes long")
        return cls(bytes(data))

    def public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey(self._public_raw)

    def sign(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like.")
        msg = bytes(data)
        r_digest = hashlib.sha512(self._prefix + msg).digest()
        r_int = int.from_bytes(r_digest, "little") % _L
        r_bytes = _point_encode(_scalar_mult(r_int, _B))
        k_digest = hashlib.sha512(r_bytes + self._public_raw + msg).digest()
        k_int = int.from_bytes(k_digest, "little") % _L
        s_int = (r_int + k_int * self._scalar) % _L
        return r_bytes + s_int.to_bytes(32, "little")

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        if not isinstance(encryption_algorithm, serialization.NoEncryption):
            raise ValueError("Only NoEncryption is supported.")
        if encoding is serialization.Encoding.Raw or format is serialization.PrivateFormat.Raw:
            if (
                encoding is not serialization.Encoding.Raw
                or format is not serialization.PrivateFormat.Raw
            ):
                raise ValueError("Raw encoding and Raw format must be used together.")
            return self._seed
        if format is not serialization.PrivateFormat.PKCS8:
            raise ValueError("Ed25519 private keys require PKCS8 or Raw format.")
        der = serialization.ED25519_PKCS8_PREFIX + self._seed
        if encoding is serialization.Encoding.DER:
            return der
        if encoding is serialization.Encoding.PEM:
            return serialization.encode_pem(der, "PRIVATE KEY")
        raise ValueError(f"Unsupported encoding: {encoding}")
