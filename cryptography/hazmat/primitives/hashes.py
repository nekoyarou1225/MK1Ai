"""Cryptographic hash algorithms backed by Python standard library hashlib."""

from __future__ import annotations

import hashlib


class HashAlgorithm:
    name: str = ""
    digest_size: int = 0
    block_size: int = 0


class SHA256(HashAlgorithm):
    name = "sha256"
    digest_size = 32
    block_size = 64


class SHA384(HashAlgorithm):
    name = "sha384"
    digest_size = 48
    block_size = 128


class SHA512(HashAlgorithm):
    name = "sha512"
    digest_size = 64
    block_size = 128


class Hash:
    def __init__(self, algorithm: HashAlgorithm, backend: object = None) -> None:
        if not isinstance(algorithm, HashAlgorithm):
            raise TypeError("Expected instance of hashes.HashAlgorithm.")
        self._algorithm = algorithm
        self._ctx = hashlib.new(algorithm.name)

    @property
    def algorithm(self) -> HashAlgorithm:
        return self._algorithm

    def update(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        self._ctx.update(data)

    def finalize(self) -> bytes:
        return self._ctx.digest()

    def copy(self) -> "Hash":
        clone = Hash(self._algorithm)
        clone._ctx = self._ctx.copy()
        return clone
