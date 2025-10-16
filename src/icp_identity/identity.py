from __future__ import annotations

import hashlib
import hmac
import json
import struct
import unicodedata
from typing import Optional, Tuple, List, Union

import ecdsa
from ecdsa.curves import Ed25519, SECP256k1
from ecdsa import util as ecdsa_util

from icp_principal import Principal


# =========================
# BIP-39 SEED DERIVATION
# =========================

def _mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Derive a 64-byte BIP-39 seed from mnemonic and optional passphrase.
    PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048).
    Using NFKD normalization as in the BIP-39 spec.
    """
    m = unicodedata.normalize("NFKD", mnemonic)
    s = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", m.encode(), s.encode(), 2048, dklen=64)


# =========================
# SLIP-0010 (Ed25519)
# =========================

_HARDENED_OFFSET = 0x80000000
_SLIP10_ED25519_SEED_KEY = b"ed25519 seed"


def _parse_path(path: str) -> List[int]:
    """
    Parse hardened derivation path like: m/44'/223'/0'/0'/0'
    For Ed25519 under SLIP-0010, ONLY hardened indices are valid.
    """
    if not path or not path.startswith("m/"):
        raise ValueError("Path must start with 'm/'")
    parts = path[2:].split("/")
    out: List[int] = []
    for seg in parts:
        if not seg.endswith("'"):
            raise ValueError("Ed25519 (SLIP-0010) supports hardened indices only: " + seg)
        n = seg[:-1]
        if not n.isdigit():
            raise ValueError("Invalid path segment: " + seg)
        out.append(int(n) | _HARDENED_OFFSET)
    return out


def _slip10_master_key_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """
    SLIP-0010 master key derivation for Ed25519.
    Returns (k, c) where k is 32-byte private key, c is 32-byte chain code.
    """
    I = hmac.new(_SLIP10_ED25519_SEED_KEY, seed, hashlib.sha512).digest()
    return I[:32], I[32:]


def _slip10_derive_child(key: bytes, chain: bytes, index: int) -> tuple[bytes, bytes]:
    """
    SLIP-0010 hardened child derivation:
      data = 0x00 || key(32) || index_be(4)
      I = HMAC-SHA512(chain, data)
      child_key = I[:32]; child_chain = I[32:]
    """
    if index < _HARDENED_OFFSET:
        raise ValueError("Non-hardened index not allowed for Ed25519 (SLIP-0010)")
    data = b"\x00" + key + struct.pack(">I", index)
    I = hmac.new(chain, data, hashlib.sha512).digest()
    return I[:32], I[32:]


def _slip10_derive_ed25519(seed: bytes, path: str) -> bytes:
    """
    Derive a 32-byte Ed25519 private key from BIP-39 seed using SLIP-0010 at the given path.
    Recommended ICP path: m/44'/223'/0'/0'/0'
    """
    key, chain = _slip10_master_key_from_seed(seed)
    for idx in _parse_path(path):
        key, chain = _slip10_derive_child(key, chain, idx)
    return key


# =========================
# Identity
# =========================

class Identity:
    """
    Ed25519 / secp256k1 identity for the Internet Computer.
    - Self-authenticating Principal derives from the SPKI DER public key.
    - Ed25519 signs the raw message (RFC 8032, no prehash).
    - secp256k1 signs/verify with SHA-256 and canonical DER(low-S) signatures.
    """

    def __init__(self, privkey: str = "", type: str = "ed25519", anonymous: bool = False) -> None:
        self.anonymous = bool(anonymous)
        if self.anonymous:
            self.key_type = "anonymous"
            self.sk = None
            self.vk = None
            self._privkey = ""
            self._pubkey = ""
            self._der_pubkey = b""
            return

        self.key_type = type
        pk_bytes = bytes.fromhex(privkey) if privkey else None

        if type == "secp256k1":
            self.sk = ecdsa.SigningKey.from_string(pk_bytes, curve=SECP256k1) if pk_bytes else \
                      ecdsa.SigningKey.generate(curve=SECP256k1)
            self.vk = self.sk.get_verifying_key()

        elif type == "ed25519":
            self.sk = ecdsa.SigningKey.from_string(pk_bytes, curve=Ed25519) if pk_bytes else \
                      ecdsa.SigningKey.generate(curve=Ed25519)
            self.vk = self.sk.get_verifying_key()
        else:
            raise ValueError("Unsupported identity type: " + type)

        # Raw hex keys (not DER)
        self._privkey = self.sk.to_string().hex()
        self._pubkey = self.vk.to_string().hex()

        # SPKI DER public key (used by self-authenticating principals)
        self._der_pubkey: bytes = self.vk.to_der()

    # ---- creation ----

    @staticmethod
    def from_seed(
        mnemonic: str,
        *,
        path: str = "m/44'/223'/0'/0'/0'",
        passphrase: str = ""
    ) -> "Identity":
        """
        Create an Ed25519 Identity from a BIP-39 mnemonic using SLIP-0010 (Ed25519).
        Default ICP path: m/44'/223'/0'/0'/0'
        """
        seed = _mnemonic_to_seed(mnemonic, passphrase)
        priv32 = _slip10_derive_ed25519(seed, path)
        return Identity(privkey=priv32.hex(), type="ed25519")

    @staticmethod
    def from_pem(pem: str) -> "Identity":
        """
        Load a private key from a PKCS#8 PEM (curve decides identity type).
        """
        key = ecdsa.SigningKey.from_pem(pem)
        curve = key.curve
        if curve == Ed25519:
            typ = "ed25519"
        elif curve == SECP256k1:
            typ = "secp256k1"
        else:
            raise ValueError("Unsupported PEM curve")
        return Identity(privkey=key.to_string().hex(), type=typ)

    # ---- conversion ----

    def to_pem(self) -> bytes:
        """Export the private key as PKCS#8 PEM."""
        return self.sk.to_pem(format="pkcs8") if self.sk is not None else b""

    # ---- signing ----

    def sender(self) -> Principal:
        """
        Return self-authenticating Principal derived from SPKI DER public key.
        """
        if self.anonymous:
            return Principal.anonymous()
        return Principal.self_authenticating(self._der_pubkey)

    def sign(self, msg: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Returns (der_pubkey, signature).
          - Ed25519: 64-byte signature over raw message.
          - secp256k1: DER-encoded ECDSA signature over SHA-256(message), canonical low-S.
        """
        if self.anonymous:
            return (None, None)

        if self.key_type == "ed25519":
            sig = self.sk.sign(msg)  # RFC 8032: no prehash
            return (self._der_pubkey, sig)

        if self.key_type == "secp256k1":
            sig = self.sk.sign(
                msg,
                hashfunc=hashlib.sha256,
                sigencode=ecdsa_util.sigencode_der_canonize,  # enforce low-S
            )
            return (self._der_pubkey, sig)

        raise ValueError("Unsupported identity type")

    def verify(self, msg: Union[bytes, str], sig: bytes) -> bool:
        """
        Local verification helper:
          - Ed25519: raw signature over raw message.
          - secp256k1: DER-encoded signature over SHA-256(message).
        """
        if isinstance(msg, str):
            msg = bytes.fromhex(msg)
        if self.anonymous or self.vk is None:
            return False

        try:
            if self.key_type == "ed25519":
                return self.vk.verify(sig, msg)
            if self.key_type == "secp256k1":
                return self.vk.verify(
                    sig, msg, hashfunc=hashlib.sha256, sigdecode=ecdsa_util.sigdecode_der
                )
        except Exception:
            return False
        return False

    # ---- props ----

    @property
    def privkey(self) -> str:
        """Hex-encoded raw private key (32 bytes for Ed25519)."""
        return self._privkey

    @property
    def pubkey(self) -> str:
        """Hex-encoded raw public key (no DER)."""
        return self._pubkey

    @property
    def der_pubkey(self) -> bytes:
        """X.509 SPKI DER public key (used by self-authenticating Principal)."""
        return self._der_pubkey

    def __repr__(self) -> str:
        return f"Identity({self.key_type}, {self._privkey}, {self._pubkey})"

    def __str__(self) -> str:
        return f"({self.key_type}, {self._privkey}, {self._pubkey})"


# =========================
# Delegation wrapper
# =========================

def _map_delegation(delegation: dict) -> dict:
    """
    Normalize a single delegation entry:
      - 'expiration' can be hex string or integer.
      - 'pubkey' and 'signature' accept hex strings or bytes-like.
    """
    exp = delegation["delegation"]["expiration"]
    if isinstance(exp, str):
        exp_val = int(exp, 16) if exp.lower().startswith("0x") else int(exp, 16)
    else:
        exp_val = int(exp)

    pubkey = delegation["delegation"]["pubkey"]
    pubkey_bytes = bytes.fromhex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)

    sig = delegation["signature"]
    sig_bytes = bytes.fromhex(sig) if isinstance(sig, str) else bytes(sig)

    return {
        "delegation": {
            "expiration": exp_val,
            "pubkey": pubkey_bytes,
        },
        "signature": sig_bytes,
    }


class DelegateIdentity:
    """
    Identity wrapper carrying delegations.
    - sender() uses the delegated 'publicKey' (SPKI DER) to form the Principal.
    - sign() delegates to the inner Identity.
    """
    def __init__(self, identity: Identity, delegation: dict) -> None:
        self.identity = identity
        self._delegations = [_map_delegation(d) for d in delegation["delegations"]]
        pk = delegation["publicKey"]
        self._der_pubkey: bytes = bytes.fromhex(pk) if isinstance(pk, str) else bytes(pk)

    def sign(self, msg: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        return self.identity.sign(msg)

    def sender(self) -> Principal:
        return Principal.self_authenticating(self._der_pubkey)

    @property
    def delegations(self) -> list[dict]:
        return self._delegations

    @property
    def der_pubkey(self) -> bytes:
        return self._der_pubkey

    @staticmethod
    def from_json(ic_identity: str, ic_delegation: str) -> "DelegateIdentity":
        """
        Adapter for exported formats:
          - ic_identity: JSON array where element[1] is a hex private key.
          - ic_delegation: JSON object with 'delegations' and 'publicKey'.
        """
        parsed_ic_identity = json.loads(ic_identity)
        parsed_ic_delegation = json.loads(ic_delegation)

        raw_hex = parsed_ic_identity[1]
        if not isinstance(raw_hex, str) or len(raw_hex) < 64:
            raise ValueError("invalid ic_identity format: expected hex private key")
        inner = Identity(privkey=raw_hex[:64], type="ed25519")
        return DelegateIdentity(inner, parsed_ic_delegation)

    def __repr__(self) -> str:
        return f"DelegateIdentity(identity={self.identity!r}, delegations={self._delegations!r})"

    def __str__(self) -> str:
        return f"(DelegateIdentity identity={self.identity}, delegations={self._delegations})"