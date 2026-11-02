"""SLIP-0039 Shamir Mnemonic exceptions and utilities."""

from __future__ import annotations


class MnemonicError(Exception):
    """Raised when Shamir mnemonic generation or combination fails."""
