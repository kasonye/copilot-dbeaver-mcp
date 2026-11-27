"""
Pure-Python FIPS-197 AES-128-CBC Decryptor (Zero C-Extension Dependencies).

Used by PythonDbBridge when JDK (java/javac) is not installed on the host machine,
enabling zero-dependency in-memory decryption of DBeaver's credentials-config.json
across Windows, macOS, and Linux.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

# DBeaver standard local credentials-config.json 16-byte key
DBEAVER_LOCAL_KEY = bytes.fromhex("babb4a9f774ab853c96c2d653dfe544a")

# Standard AES S-Box & Inverse S-Box (FIPS-197)
_SBOX = [
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
]

_INV_SBOX = [0] * 256
for _idx, _val in enumerate(_SBOX):
    _INV_SBOX[_val] = _idx

_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _expand_key_128(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes.")
    w: list[list[int]] = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = [_SBOX[temp[1]] ^ _RCON[i // 4], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(w[r * 4 : (r + 1) * 4], []) for r in range(11)]


def _decrypt_block_128(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[10][i] for i in range(16)]

    for rnd in range(9, 0, -1):
        # InvShiftRows (column-major state indexing: col*4 + row)
        s = [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3],
        ]
        # InvSubBytes & AddRoundKey
        rk = round_keys[rnd]
        s = [_INV_SBOX[s[i]] ^ rk[i] for i in range(16)]
        # InvMixColumns
        ns = [0] * 16
        for c in range(4):
            base = c * 4
            a0, a1, a2, a3 = s[base], s[base + 1], s[base + 2], s[base + 3]
            ns[base] = _gmul(a0, 0x0E) ^ _gmul(a1, 0x0B) ^ _gmul(a2, 0x0D) ^ _gmul(a3, 0x09)
            ns[base + 1] = _gmul(a0, 0x09) ^ _gmul(a1, 0x0E) ^ _gmul(a2, 0x0B) ^ _gmul(a3, 0x0D)
            ns[base + 2] = _gmul(a0, 0x0D) ^ _gmul(a1, 0x09) ^ _gmul(a2, 0x0E) ^ _gmul(a3, 0x0B)
            ns[base + 3] = _gmul(a0, 0x0B) ^ _gmul(a1, 0x0D) ^ _gmul(a2, 0x09) ^ _gmul(a3, 0x0E)
        s = ns

    # Final round: InvShiftRows -> InvSubBytes -> AddRoundKey(0)
    s = [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]
    rk0 = round_keys[0]
    return bytes(_INV_SBOX[s[i]] ^ rk0[i] for i in range(16))


def aes_128_cbc_decrypt_pkcs7(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16 or len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Invalid IV or ciphertext block alignment for AES-128-CBC.")
    round_keys = _expand_key_128(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(ciphertext), 16):
        blk = ciphertext[offset : offset + 16]
        dec = _decrypt_block_128(blk, round_keys)
        out.extend(dec[i] ^ prev[i] for i in range(16))
        prev = blk

    pad_len = out[-1]
    if pad_len < 1 or pad_len > 16 or any(b != pad_len for b in out[-pad_len:]):
        raise ValueError("Invalid PKCS#7 padding (wrong AES key or corrupted ciphertext).")
    return bytes(out[:-pad_len])


def _encrypt_block_128(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        ns = [0] * 16
        for c in range(4):
            base = c * 4
            a0, a1, a2, a3 = s[base], s[base + 1], s[base + 2], s[base + 3]
            ns[base] = _gmul(a0, 0x02) ^ _gmul(a1, 0x03) ^ a2 ^ a3
            ns[base + 1] = a0 ^ _gmul(a1, 0x02) ^ _gmul(a2, 0x03) ^ a3
            ns[base + 2] = a0 ^ a1 ^ _gmul(a2, 0x02) ^ _gmul(a3, 0x03)
            ns[base + 3] = _gmul(a0, 0x03) ^ a1 ^ a2 ^ _gmul(a3, 0x02)
        rk = round_keys[rnd]
        s = [ns[i] ^ rk[i] for i in range(16)]

    s = [_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    rk10 = round_keys[10]
    return bytes(s[i] ^ rk10[i] for i in range(16))


def aes_128_cbc_encrypt_pkcs7(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("AES-128-CBC IV must be 16 bytes.")
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    round_keys = _expand_key_128(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(padded), 16):
        xored = bytes(padded[offset + i] ^ prev[i] for i in range(16))
        enc = _encrypt_block_128(xored, round_keys)
        out.extend(enc)
        prev = enc
    return bytes(out)


_PY_CRED_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}


def decrypt_dbeaver_credentials_in_memory(cred_file_path: str) -> Dict[str, Any]:
    p = Path(cred_file_path)
    if not p.is_file():
        return {}
    st = p.stat()
    cached = _PY_CRED_CACHE.get(cred_file_path)
    if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]

    raw = p.read_bytes()
    if len(raw) <= 16:
        return {}
    iv = raw[:16]
    cipher_bytes = raw[16:]

    candidate_keys: list[bytes] = []
    custom_pw = os.environ.get("COPILOT_DBEAVER_MASTER_PASSWORD", "")
    if custom_pw:
        pw_bytes = custom_pw.encode("utf-8")
        candidate_keys.append(hashlib.md5(pw_bytes).digest())
        candidate_keys.append(hashlib.sha256(pw_bytes).digest()[:16])
    candidate_keys.append(DBEAVER_LOCAL_KEY)

    for key in candidate_keys:
        try:
            plain = aes_128_cbc_decrypt_pkcs7(cipher_bytes, key, iv)
            txt = plain.decode("utf-8").lstrip("\ufeff").strip()
            if txt.startswith("{"):
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    _PY_CRED_CACHE[cred_file_path] = (st.st_mtime_ns, st.st_size, parsed)
                    return parsed
        except Exception:
            continue

    raise RuntimeError(
        "Failed to decrypt DBeaver credentials-config.json in Python engine. "
        "If a custom Master Password is set in DBeaver, configure env COPILOT_DBEAVER_MASTER_PASSWORD."
    )
