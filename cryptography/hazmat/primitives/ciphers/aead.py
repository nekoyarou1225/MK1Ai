"""NIST SP 800-38D AES-GCM Authenticated Encryption with Associated Data (AEAD)."""

from __future__ import annotations

import hmac
import os
import struct

from cryptography.exceptions import InvalidTag

# AES S-Box (FIPS 197)
_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON = (
    0x00000000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _sub_word(word: int) -> int:
    return (
        (_SBOX[(word >> 24) & 0xFF] << 24)
        | (_SBOX[(word >> 16) & 0xFF] << 16)
        | (_SBOX[(word >> 8) & 0xFF] << 8)
        | _SBOX[word & 0xFF]
    )


def _rot_word(word: int) -> int:
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)


def _expand_key(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = nk + 6
    total_words = 4 * (nr + 1)
    w = [0] * total_words
    for i in range(nk):
        w[i] = struct.unpack(">I", key[4 * i : 4 * i + 4])[0]
    for i in range(nk, total_words):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        w[i] = (w[i - nk] ^ temp) & 0xFFFFFFFF

    round_keys: list[list[int]] = []
    for r in range(nr + 1):
        rk_bytes: list[int] = []
        for c in range(4):
            word = w[4 * r + c]
            rk_bytes.extend(
                [
                    (word >> 24) & 0xFF,
                    (word >> 16) & 0xFF,
                    (word >> 8) & 0xFF,
                    word & 0xFF,
                ]
            )
        round_keys.append(rk_bytes)
    return round_keys


def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = list(block)
    nr = len(round_keys) - 1

    # AddRoundKey(0)
    rk0 = round_keys[0]
    for i in range(16):
        state[i] ^= rk0[i]

    for r in range(1, nr):
        # SubBytes + ShiftRows combined
        s0 = _SBOX[state[0]]
        s1 = _SBOX[state[5]]
        s2 = _SBOX[state[10]]
        s3 = _SBOX[state[15]]
        s4 = _SBOX[state[4]]
        s5 = _SBOX[state[9]]
        s6 = _SBOX[state[14]]
        s7 = _SBOX[state[3]]
        s8 = _SBOX[state[8]]
        s9 = _SBOX[state[13]]
        s10 = _SBOX[state[2]]
        s11 = _SBOX[state[7]]
        s12 = _SBOX[state[12]]
        s13 = _SBOX[state[1]]
        s14 = _SBOX[state[6]]
        s15 = _SBOX[state[11]]

        state = [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15]

        # MixColumns + AddRoundKey
        rk = round_keys[r]
        for c in range(0, 16, 4):
            a0, a1, a2, a3 = state[c], state[c + 1], state[c + 2], state[c + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            state[c] = a0 ^ t ^ _xtime(a0 ^ a1) ^ rk[c]
            state[c + 1] = a1 ^ t ^ _xtime(a1 ^ a2) ^ rk[c + 1]
            state[c + 2] = a2 ^ t ^ _xtime(a2 ^ a3) ^ rk[c + 2]
            state[c + 3] = a3 ^ t ^ _xtime(a3 ^ a0) ^ rk[c + 3]

    # Final round: SubBytes + ShiftRows + AddRoundKey
    rk_last = round_keys[nr]
    out = [
        _SBOX[state[0]] ^ rk_last[0],
        _SBOX[state[5]] ^ rk_last[1],
        _SBOX[state[10]] ^ rk_last[2],
        _SBOX[state[15]] ^ rk_last[3],
        _SBOX[state[4]] ^ rk_last[4],
        _SBOX[state[9]] ^ rk_last[5],
        _SBOX[state[14]] ^ rk_last[6],
        _SBOX[state[3]] ^ rk_last[7],
        _SBOX[state[8]] ^ rk_last[8],
        _SBOX[state[13]] ^ rk_last[9],
        _SBOX[state[2]] ^ rk_last[10],
        _SBOX[state[7]] ^ rk_last[11],
        _SBOX[state[12]] ^ rk_last[12],
        _SBOX[state[1]] ^ rk_last[13],
        _SBOX[state[6]] ^ rk_last[14],
        _SBOX[state[11]] ^ rk_last[15],
    ]
    return bytes(out)


def _gf128_mul(x: int, y: int) -> int:
    """Multiply two elements in GF(2^128) per NIST SP 800-38D."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _ghash(h_int: int, aad: bytes, ciphertext: bytes) -> int:
    y = 0
    for offset in range(0, len(aad), 16):
        chunk = aad[offset : offset + 16]
        if len(chunk) < 16:
            chunk = chunk + b"\x00" * (16 - len(chunk))
        y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), h_int)

    for offset in range(0, len(ciphertext), 16):
        chunk = ciphertext[offset : offset + 16]
        if len(chunk) < 16:
            chunk = chunk + b"\x00" * (16 - len(chunk))
        y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), h_int)

    len_block = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    y = _gf128_mul(y ^ int.from_bytes(len_block, "big"), h_int)
    return y


def _inc32(counter_block: bytes) -> bytes:
    prefix = counter_block[:12]
    ctr = (struct.unpack(">I", counter_block[12:16])[0] + 1) & 0xFFFFFFFF
    return prefix + struct.pack(">I", ctr)


def _gctr(round_keys: list[list[int]], icb: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray(len(data))
    cb = icb
    for offset in range(0, len(data), 16):
        keystream = _aes_encrypt_block(cb, round_keys)
        chunk = data[offset : offset + 16]
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ keystream[i]
        cb = _inc32(cb)
    return bytes(out)


class AESGCM:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like.")
        key_bytes = bytes(key)
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AESGCM key must be 128, 192, or 256 bits.")
        self._key = key_bytes
        self._round_keys = _expand_key(self._key)
        h_bytes = _aes_encrypt_block(b"\x00" * 16, self._round_keys)
        self._h_int = int.from_bytes(h_bytes, "big")

    @classmethod
    def generate_key(cls, bit_length: int) -> bytes:
        if bit_length not in (128, 192, 256):
            raise ValueError("bit_length must be 128, 192, or 256.")
        return os.urandom(bit_length // 8)

    def _compute_j0(self, nonce: bytes) -> bytes:
        if len(nonce) < 8 or len(nonce) > 128:
            raise ValueError("Nonce must be between 8 and 128 bytes.")
        if len(nonce) == 12:
            return nonce + b"\x00\x00\x00\x01"
        j0_int = _ghash(self._h_int, b"", nonce)
        return j0_int.to_bytes(16, "big")

    def encrypt(
        self,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
    ) -> bytes:
        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            raise TypeError("nonce must be bytes-like.")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like.")
        aad = b"" if associated_data is None else bytes(associated_data)
        nonce_bytes = bytes(nonce)
        plaintext = bytes(data)

        j0 = self._compute_j0(nonce_bytes)
        ciphertext = _gctr(self._round_keys, _inc32(j0), plaintext)
        s_int = _ghash(self._h_int, aad, ciphertext)
        tag = _gctr(self._round_keys, j0, s_int.to_bytes(16, "big"))
        return ciphertext + tag

    def decrypt(
        self,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
    ) -> bytes:
        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            raise TypeError("nonce must be bytes-like.")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like.")
        payload = bytes(data)
        if len(payload) < 16:
            raise InvalidTag("Ciphertext shorter than 16-byte GCM authentication tag.")
        aad = b"" if associated_data is None else bytes(associated_data)
        nonce_bytes = bytes(nonce)
        ciphertext = payload[:-16]
        received_tag = payload[-16:]

        j0 = self._compute_j0(nonce_bytes)
        s_int = _ghash(self._h_int, aad, ciphertext)
        expected_tag = _gctr(self._round_keys, j0, s_int.to_bytes(16, "big"))
        if not hmac.compare_digest(received_tag, expected_tag):
            raise InvalidTag("AESGCM authentication tag verification failed.")
        return _gctr(self._round_keys, _inc32(j0), ciphertext)
