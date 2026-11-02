"""Cryptographic exceptions matching pyca/cryptography API."""

from __future__ import annotations


class CryptographyError(Exception):
    """Base exception for cryptographic errors."""


class InvalidSignature(CryptographyError):
    """Raised when signature verification fails."""


class InvalidTag(CryptographyError):
    """Raised when AEAD authentication tag verification fails."""
