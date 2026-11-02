"""RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import HashAlgorithm


class HKDF:
    def __init__(
        self,
        algorithm: HashAlgorithm,
        length: int,
        salt: bytes | None,
        info: bytes | None,
        backend: object = None,
    ) -> None:
        if not isinstance(algorithm, HashAlgorithm):
            raise TypeError("Expected instance of hashes.HashAlgorithm.")
        if not isinstance(length, int) or length <= 0:
            raise ValueError("length must be a positive integer.")
        max_length = 255 * algorithm.digest_size
        if length > max_length:
            raise ValueError(f"Cannot derive keys larger than {max_length} bytes.")
        if salt is not None and not isinstance(salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes or None.")
        if info is not None and not isinstance(info, (bytes, bytearray)):
            raise TypeError("info must be bytes or None.")

        self._algorithm = algorithm
        self._length = length
        self._salt = bytes(salt) if salt is not None else (b"\x00" * algorithm.digest_size)
        self._info = bytes(info) if info is not None else b""
        self._used = False

    def _extract(self, key_material: bytes) -> bytes:
        salt = self._salt if self._salt else (b"\x00" * self._algorithm.digest_size)
        return hmac.new(salt, key_material, getattr(hashlib, self._algorithm.name)).digest()

    def _expand(self, prk: bytes) -> bytes:
        hash_fn = getattr(hashlib, self._algorithm.name)
        blocks: list[bytes] = []
        prev = b""
        counter = 1
        derived_len = 0
        while derived_len < self._length:
            prev = hmac.new(prk, prev + self._info + bytes([counter]), hash_fn).digest()
            blocks.append(prev)
            derived_len += len(prev)
            counter += 1
        return b"".join(blocks)[: self._length]

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise RuntimeError("HKDF instances can only be used once.")
        if not isinstance(key_material, (bytes, bytearray, memoryview)):
            raise TypeError("key_material must be bytes-like.")
        self._used = True
        prk = self._extract(bytes(key_material))
        return self._expand(prk)

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        derived = self.derive(key_material)
        if not hmac.compare_digest(derived, expected_key):
            raise InvalidSignature("Keys do not match.")
