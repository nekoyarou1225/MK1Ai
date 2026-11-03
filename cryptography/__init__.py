"""Pure-Python RFC-compliant cryptography package for sovereign airgap environments."""

from cryptography.exceptions import CryptographyError, InvalidSignature, InvalidTag

_MK1_PURE_PYTHON_FALLBACK = True

__all__ = [
    "CryptographyError",
    "InvalidSignature",
    "InvalidTag",
    "_MK1_PURE_PYTHON_FALLBACK",
]

