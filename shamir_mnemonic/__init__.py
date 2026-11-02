"""GF(256) Shamir's Secret Sharing mnemonic implementation (SLIP-0039 compatible API)."""

from __future__ import annotations

from collections.abc import Sequence
import hashlib
import hmac
import os

from shamir_mnemonic.utils import MnemonicError

__all__ = ["MnemonicError", "combine_mnemonics", "generate_mnemonics"]

# GF(256) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
_EXP = [0] * 512
_LOG = [0] * 256


def _init_gf256() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # Multiply by generator 0x03 in GF(2^8) / (x^8 + x^4 + x^3 + x + 1)
        x_times_2 = (x << 1) ^ (0x11B if (x & 0x80) else 0)
        x = x_times_2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_gf256()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero.")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    result = 0
    for c in reversed(coeffs):
        result = _gf_mul(result, x) ^ c
    return result


def _lagrange_interpolate_zero(points: Sequence[tuple[int, int]]) -> int:
    secret = 0
    k = len(points)
    for i in range(k):
        xi, yi = points[i]
        num = 1
        den = 1
        for j in range(k):
            if i == j:
                continue
            xj, _ = points[j]
            num = _gf_mul(num, xj)
            den = _gf_mul(den, xi ^ xj)
        term = _gf_mul(yi, _gf_div(num, den))
        secret ^= term
    return secret


def _split_bytes(secret: bytes, threshold: int, count: int) -> list[bytes]:
    shares = [bytearray(len(secret)) for _ in range(count)]
    for byte_idx, secret_byte in enumerate(secret):
        rand_coeffs = list(os.urandom(threshold - 1))
        coeffs = [secret_byte, *rand_coeffs]
        for share_idx in range(count):
            x = share_idx + 1
            shares[share_idx][byte_idx] = _eval_poly(coeffs, x)
    return [bytes(s) for s in shares]


def _recover_bytes(indexed_shares: Sequence[tuple[int, bytes]]) -> bytes:
    length = len(indexed_shares[0][1])
    out = bytearray(length)
    for byte_idx in range(length):
        points = [(x, share[byte_idx]) for x, share in indexed_shares]
        out[byte_idx] = _lagrange_interpolate_zero(points)
    return bytes(out)


def generate_mnemonics(
    group_threshold: int,
    groups: Sequence[tuple[int, int]],
    master_secret: bytes,
    passphrase: bytes = b"",
    iteration_exponent: int = 0,
    extendable: bool = True,
) -> list[list[str]]:
    if not isinstance(master_secret, (bytes, bytearray)) or len(master_secret) < 16 or len(master_secret) % 2 != 0:
        raise ValueError("master_secret must be an even number of bytes >= 16.")
    if group_threshold < 1 or group_threshold > len(groups):
        raise ValueError("Invalid group_threshold.")

    backup_id = os.urandom(8).hex()
    secret_bytes = bytes(master_secret)
    digest = hmac.new(
        hashlib.sha256(b"SLIP39-AUTH:" + bytes(passphrase)).digest(),
        backup_id.encode("ascii") + secret_bytes,
        hashlib.sha256,
    ).digest()[:16]
    payload = secret_bytes + digest

    result_groups: list[list[str]] = []
    for group_idx, (member_threshold, member_count) in enumerate(groups):
        if member_threshold < 1 or member_count < member_threshold or member_count > 16:
            raise ValueError("Invalid group member threshold/count.")
        raw_shares = _split_bytes(payload, member_threshold, member_count)
        group_mnemonics: list[str] = []
        for idx, share_bytes in enumerate(raw_shares, start=1):
            share_hex = share_bytes.hex()
            header = f"slip39:{backup_id}:{group_idx}:{member_threshold}:{idx}:{share_hex}"
            chk = hashlib.sha256(header.encode("ascii")).hexdigest()[:12]
            words = [
                "mk1share",
                backup_id,
                str(group_idx),
                str(member_threshold),
                str(idx),
                share_hex,
                chk,
            ]
            group_mnemonics.append(" ".join(words))
        result_groups.append(group_mnemonics)

    return result_groups


def combine_mnemonics(
    mnemonics: Sequence[str],
    passphrase: bytes = b"",
) -> bytes:
    if not mnemonics:
        raise MnemonicError("No mnemonics provided.")

    parsed: list[tuple[str, int, int, int, bytes]] = []
    seen_indices: set[int] = set()

    for item in mnemonics:
        if not isinstance(item, str) or not item.strip():
            raise MnemonicError("Empty or invalid mnemonic string.")
        parts = item.strip().split()
        if len(parts) != 7 or parts[0] != "mk1share":
            raise MnemonicError("Malformed mnemonic share format.")
        _, backup_id, group_str, threshold_str, idx_str, share_hex, chk = parts
        header = f"slip39:{backup_id}:{group_str}:{threshold_str}:{idx_str}:{share_hex}"
        expected_chk = hashlib.sha256(header.encode("ascii")).hexdigest()[:12]
        if not hmac.compare_digest(chk, expected_chk):
            raise MnemonicError("Mnemonic share checksum verification failed.")
        try:
            group_idx = int(group_str)
            threshold = int(threshold_str)
            member_idx = int(idx_str)
            share_bytes = bytes.fromhex(share_hex)
        except ValueError as exc:
            raise MnemonicError("Malformed numeric fields in mnemonic share.") from exc
        if member_idx in seen_indices:
            raise MnemonicError("Duplicate mnemonic share index.")
        seen_indices.add(member_idx)
        parsed.append((backup_id, group_idx, threshold, member_idx, share_bytes))

    first_backup_id, first_group, required_threshold, _, first_bytes = parsed[0]
    for backup_id, group_idx, threshold, _, share_bytes in parsed[1:]:
        if backup_id != first_backup_id or group_idx != first_group or threshold != required_threshold:
            raise MnemonicError("Shares belong to incompatible backup sets or groups.")
        if len(share_bytes) != len(first_bytes):
            raise MnemonicError("Share byte lengths do not match.")

    if len(parsed) < required_threshold:
        raise MnemonicError(
            f"Insufficient shares: got {len(parsed)}, require {required_threshold}."
        )

    selected = [(member_idx, share_bytes) for _, _, _, member_idx, share_bytes in parsed[:required_threshold]]
    recovered_payload = _recover_bytes(selected)
    if len(recovered_payload) < 32:
        raise MnemonicError("Recovered payload shorter than minimum secret + MAC.")

    secret_bytes = recovered_payload[:-16]
    recovered_mac = recovered_payload[-16:]
    expected_mac = hmac.new(
        hashlib.sha256(b"SLIP39-AUTH:" + bytes(passphrase)).digest(),
        first_backup_id.encode("ascii") + secret_bytes,
        hashlib.sha256,
    ).digest()[:16]
    if not hmac.compare_digest(recovered_mac, expected_mac):
        raise MnemonicError("Recovered secret integrity check failed.")
    return secret_bytes
