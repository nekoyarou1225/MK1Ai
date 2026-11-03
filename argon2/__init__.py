"""Argon2id memory-hard key derivation package for airgapped sovereign deployments."""

from argon2.low_level import Type, hash_secret_raw

_MK1_PURE_PYTHON_FALLBACK = True

__all__ = ["Type", "hash_secret_raw", "_MK1_PURE_PYTHON_FALLBACK"]

