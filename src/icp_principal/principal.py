# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

# principal type: https://internetcomputer.org/docs/references/ic-interface-spec/#principal

from __future__ import annotations

import base64
import hashlib
import math
import zlib
from enum import IntEnum
from typing import Union

# -----------------------------
# Constants
# -----------------------------

CRC_LENGTH_IN_BYTES = 4

# self-authenticating principal = sha224(SPKI_DER) || 0x02
_SA_SUFFIX = 0x02

# Known SPKI prefixes (hex) for validation.
# The IC accepts any DER-encoded public key for self-authenticating principals
# (Ed25519, ECDSA secp256k1, ECDSA P-256, BLS12-381). We validate a small
# allowlist of well-known prefixes to catch obviously malformed input early,
# but the algorithm itself is `sha224(DER) || 0x02` for any DER blob.

# Ed25519 (RFC 8410): 302a300506032b6570032100 || 32-byte raw key
_ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100"

# secp256k1 (id-ecPublicKey + secp256k1): common SPKI header with BIT STRING to follow
_SECP256K1_SPKI_PREFIX_HEX = "3056301006072a8648ce3d020106052b8104000a034200"

# ECDSA P-256 / secp256r1 (RFC 5480): id-ecPublicKey + prime256v1 + uncompressed BIT STRING
_P256_SPKI_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200"

# BLS12-381 G2 public key as used by IC subnet keys (DER-wrapped 96-byte compressed G2).
# Defined in the IC interface spec; the same prefix appears in IC_ROOT_KEY.
_BLS12_381_G2_SPKI_PREFIX_HEX = (
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
)

_ED25519_SPKI_PREFIX = bytes.fromhex(_ED25519_SPKI_PREFIX_HEX)
_SECP256K1_SPKI_PREFIX = bytes.fromhex(_SECP256K1_SPKI_PREFIX_HEX)
_P256_SPKI_PREFIX = bytes.fromhex(_P256_SPKI_PREFIX_HEX)
_BLS12_381_G2_SPKI_PREFIX = bytes.fromhex(_BLS12_381_G2_SPKI_PREFIX_HEX)

_KNOWN_SPKI_PREFIXES = (
    _ED25519_SPKI_PREFIX,
    _SECP256K1_SPKI_PREFIX,
    _P256_SPKI_PREFIX,
    _BLS12_381_G2_SPKI_PREFIX,
)


# -----------------------------
# Helpers
# -----------------------------

def _b32_group(s: str) -> str:
    """Group base32 text in 5-char chunks with dashes."""
    out = []
    while len(s) > 5:
        out.append(s[:5])
        s = s[5:]
    if s:
        out.append(s)
    return "-".join(out)


def _is_bytes_like(x) -> bool:
    return isinstance(x, (bytes, bytearray, memoryview))


# -----------------------------
# Principal class
# -----------------------------

class PrincipalClass(IntEnum):
    OpaqueId = 1
    SelfAuthenticating = 2
    DerivedId = 3
    Anonymous = 4


class Principal:
    def __init__(self, data: bytes = b"") -> None:
        # IMPORTANT: don't name this parameter "bytes" to avoid shadowing built-in bytes
        if not _is_bytes_like(data):
            raise TypeError("Principal expects bytes-like payload")
        b = bytes(data)
        self._bytes = b
        self._len = len(b)
        self._is_principal = True

    # Factories

    @staticmethod
    def management_canister() -> "Principal":
        """The management canister has empty bytes (text form 'aaaaa-aa')."""
        return Principal(b"")

    @staticmethod
    def anonymous() -> "Principal":
        """Anonymous principal (text form '2vxsx-fae')."""
        return Principal(b"\x04")

    @staticmethod
    def self_authenticating(spki_der: Union[bytes, bytearray, memoryview, str]) -> "Principal":
        """
        Derive a self-authenticating Principal from a DER-encoded public key.

        Per IC interface spec (section "Principal"):
            principal = sha224(DER-encoded public key) || 0x02 (29 bytes)

        The DER encoding is accepted for any supported scheme: Ed25519,
        ECDSA secp256k1, ECDSA P-256, or BLS12-381 G2 (subnet keys).

        The input must look like a SEQUENCE-wrapped SubjectPublicKeyInfo
        (i.e. start with 0x30 and be at least 40 bytes). Well-known prefixes
        are short-circuited; any other DER blob starting with 0x30 is also
        accepted, since the IC does not restrict the inner key algorithm.
        """
        if isinstance(spki_der, str):
            try:
                spki = bytes.fromhex(spki_der)
            except ValueError as e:
                raise ValueError("self_authenticating: string must be hex SPKI DER") from e
        elif _is_bytes_like(spki_der):
            spki = bytes(spki_der)
        else:
            raise TypeError("self_authenticating expects DER (bytes-like) or hex string")

        if len(spki) < 40:
            raise ValueError("self_authenticating: SPKI DER too short")

        # Accept any well-formed SubjectPublicKeyInfo (SEQUENCE-wrapped DER).
        # We don't crack the DER open; the IC accepts whatever DER the client
        # uses as long as the signature scheme is one of the supported ones.
        if spki[0] != 0x30 and not any(spki.startswith(p) for p in _KNOWN_SPKI_PREFIXES):
            raise ValueError("self_authenticating: input does not look like SPKI DER")

        digest = hashlib.sha224(spki).digest()
        return Principal(digest + bytes([PrincipalClass.SelfAuthenticating.value]))

    # Text/binary conversions

    @staticmethod
    def from_str(s: str) -> "Principal":
        """
        Parse a textual principal (with dash groups, no base32 padding) into bytes.

        Per IC spec, textual principals are parsed case-insensitively; the
        canonical form is lowercase. We compare the round-trip against the
        canonical lowercase form so that "AAAAA-AA" and "aaaaa-aa" both work.
        """
        if not isinstance(s, str):
            raise TypeError("from_str expects a string")
        s1 = s.replace("-", "")
        pad_len = math.ceil(len(s1) / 8) * 8 - len(s1)
        try:
            payload = base64.b32decode(s1.upper().encode() + b"=" * pad_len)
        except Exception as e:
            raise ValueError("invalid base32 principal string") from e
        if len(payload) < CRC_LENGTH_IN_BYTES:
            raise ValueError("principal too short")
        body = payload[CRC_LENGTH_IN_BYTES:]
        # Verify checksum
        chk = int.from_bytes(payload[:CRC_LENGTH_IN_BYTES], "big")
        if chk != (zlib.crc32(body) & 0xFFFFFFFF):
            raise ValueError("principal checksum mismatch")
        p = Principal(body)
        # Compare against canonical (lowercase) form so the parser is
        # case-insensitive but still rejects wrong grouping / extra chars.
        if p.to_str() != s.lower():
            raise ValueError("principal round-trip mismatch")
        return p

    @staticmethod
    def from_hex(s: str) -> "Principal":
        if not isinstance(s, str):
            raise TypeError("from_hex expects a hex string")
        try:
            raw = bytes.fromhex(s)
        except ValueError as e:
            raise ValueError("invalid hex for principal") from e
        return Principal(raw)

    def to_str(self) -> str:
        """Textual principal = base32( CRC32(bytes) || bytes ), grouped by 5 with dashes, lowercased."""
        checksum = zlib.crc32(self._bytes) & 0xFFFFFFFF
        payload = checksum.to_bytes(CRC_LENGTH_IN_BYTES, "big") + self._bytes
        s = base64.b32encode(payload).decode("utf-8").lower().replace("=", "")
        return _b32_group(s)

    # Account id helper (IC ledger)

    def to_account_id(self, sub_account: int = 0) -> "AccountIdentifier":
        return AccountIdentifier.new(self, sub_account)

    # Properties / magic methods

    @property
    def len(self) -> int:
        return self._len

    @property
    def bytes(self) -> bytes:
        return self._bytes

    @property
    def isPrincipal(self) -> bool:
        return self._is_principal

    def __repr__(self) -> str:
        return f"Principal({self.to_str()})"

    def __str__(self) -> str:
        return self.to_str()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Principal) and self._bytes == other._bytes

    def __hash__(self) -> int:
        return hash(self._bytes)


# -----------------------------
# AccountIdentifier
# -----------------------------

class AccountIdentifier:
    def __init__(self, data: bytes) -> None:
        if not _is_bytes_like(data):
            raise TypeError("AccountIdentifier expects bytes-like")
        b = bytes(data)
        if len(b) != 32:  # 4-byte CRC + 28-byte SHA-224 hash
            raise ValueError("AccountIdentifier must be 32 bytes (4 + 28)")
        self._hash = b

    def to_str(self) -> str:
        return "0x" + self._hash.hex()

    def __repr__(self) -> str:
        return f"Account({self.to_str()})"

    def __str__(self) -> str:
        return self.to_str()

    @property
    def bytes(self) -> bytes:
        return self._hash

    @staticmethod
    def new(principal: Principal, sub_account: int = 0) -> "AccountIdentifier":
        if not isinstance(sub_account, int) or sub_account < 0:
            raise ValueError("sub_account must be a non-negative integer")
        sha224 = hashlib.sha224()
        sha224.update(b"\x0Aaccount-id")
        sha224.update(principal.bytes)
        sha224.update(sub_account.to_bytes(32, "big"))
        h = sha224.digest()  # 28 bytes (SHA-224 produces 28-byte hash)
        checksum = zlib.crc32(h) & 0xFFFFFFFF
        return AccountIdentifier(checksum.to_bytes(CRC_LENGTH_IN_BYTES, "big") + h)