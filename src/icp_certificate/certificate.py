# reference: https://smartcontracts.org/docs/interface-spec/index.html#certification

from __future__ import annotations

import hashlib
import time
from enum import IntEnum
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import cbor2
import leb128

from icp_principal.principal import Principal


# ----------------------------- Constants & helpers -----------------------------

def domain_sep(s: str) -> bytes:
    """Return a one-byte length prefix + UTF-8 bytes of the domain string."""
    b = s.encode("utf-8")
    if len(b) > 255:
        raise ValueError("domain separator too long")
    return bytes([len(b)]) + b


IC_STATE_ROOT_DOMAIN_SEPARATOR = domain_sep("ic-state-root")
IC_BLS_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
IC_ROOT_KEY = bytes.fromhex(
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
    "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd5"
    "46d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d1450"
    "5ffd7484b01291091c5f87b98883463f98091a0baaae"
)

DS_EMPTY = domain_sep("ic-hashtree-empty")
DS_FORK = domain_sep("ic-hashtree-fork")
DS_LABELED = domain_sep("ic-hashtree-labeled")
DS_LEAF = domain_sep("ic-hashtree-leaf")

# Fixed DER prefix for subnet BLS G2 pubkey
DER_PREFIX = bytes.fromhex(
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
)
KEY_LEN = 96  # compressed G2 key length in bytes


class NodeId(IntEnum):
    Empty = 0
    Fork = 1
    Labeled = 2
    Leaf = 3
    Pruned = 4


class BlstUnavailable(RuntimeError):
    """Raised when the official 'blst' Python binding is not available or mismatched."""


def ensure_blst_available():
    """
    Ensure the official supranational/blst SWIG binding is available and return the module.
    """
    try:
        import blst as _blst  # official supranational/blst SWIG binding
    except ModuleNotFoundError as e:
        raise BlstUnavailable(
            "BLS verification requires the official 'blst' Python binding, which was not found.\n\n"
            "Install (macOS/Linux):\n"
            "  1) git clone https://github.com/supranational/blst\n"
            "  2) cd blst/bindings/python && python3 run.me\n"
            "  3) Add that directory to PYTHONPATH, or copy blst.py and _blst*.so into site-packages\n\n"
            "For Apple Silicon (M1/M2): if you hit ABI issues, run with BLST_PORTABLE=1, e.g.\n"
            "  export BLST_PORTABLE=1 && python3 run.me"
        ) from e

    required = ("P1_Affine", "P2_Affine", "Pairing", "BLST_SUCCESS")
    if not all(hasattr(_blst, name) for name in required):
        raise BlstUnavailable(
            "A module named 'blst' was imported, but it does not expose the expected API.\n"
            "Ensure you are using the official supranational/blst SWIG binding."
        )
    return _blst


def verify_bls_signature_blst(signature: bytes, message: bytes, public_key_96: bytes) -> bool:
    """
    Verify BLS12-381 MinSig (G1 signature / G2 public key) using the official blst binding.
      - signature: compressed G1 (48 bytes)
      - public_key_96: compressed G2 (96 bytes)
      - DST: IC_BLS_DST (G1 ciphersuite)
    Returns True on success; False on failure.
    Raises BlstUnavailable if blst is not present.
    """
    _blst = ensure_blst_available()

    sig_bytes = bytes(signature)
    pk_bytes = bytes(public_key_96)
    msg_bytes = bytes(message)

    if len(sig_bytes) != 48 or len(pk_bytes) != 96:
        return False
    # quick compressed-format sanity (MSB should be set per IETF ciphersuite)
    if (sig_bytes[0] & 0x80) == 0 or (pk_bytes[0] & 0x80) == 0:
        return False

    try:
        p1_ctor = getattr(_blst.P1_Affine, "from_compressed", _blst.P1_Affine)
        p2_ctor = getattr(_blst.P2_Affine, "from_compressed", _blst.P2_Affine)
        sig_aff = p1_ctor(sig_bytes)
        pk_aff = p2_ctor(pk_bytes)
    except Exception:
        return False

    # A) fast path
    try:
        err = sig_aff.core_verify(pk_aff, True, msg_bytes, IC_BLS_DST, None)
        if err == _blst.BLST_SUCCESS:
            return True
    except Exception:
        return False

    # B) pairing fallback
    try:
        pairing = _blst.Pairing(True, IC_BLS_DST)
        pairing.aggregate(pk_aff, sig_aff, msg_bytes, None)
        return bool(pairing.finalverify())
    except Exception:
        return False


def extract_der(der: bytes) -> bytes:
    """Extract the raw 96-byte G2 public key from a DER-wrapped key with a fixed prefix."""
    if not isinstance(der, (bytes, bytearray, memoryview)):
        raise TypeError("der must be a bytes-like object")
    der = bytes(der)

    expected_len = len(DER_PREFIX) + KEY_LEN  # 37 + 96 = 133
    if len(der) != expected_len:
        raise ValueError(
            f"BLS DER-encoded public key must be {expected_len} bytes long (got {len(der)})"
        )

    if not der.startswith(DER_PREFIX):
        got = der[: len(DER_PREFIX)].hex()
        raise ValueError(
            f"BLS DER-encoded public key prefix mismatch: expected {DER_PREFIX.hex()}, got {got}"
        )

    return der[len(DER_PREFIX) :]  # 96 bytes


# ----------------------------- Certificate -----------------------------

class Certificate:
    """
    Certificate wrapper for IC hashtree + BLS verification.

    Typical usage:
        cert = Certificate(cbor_decoded_certificate_dict)
        # lookups
        reply = cert.lookup_reply(request_id)
        status = cert.lookup_request_status(request_id)
        rej    = cert.lookup_request_rejection(request_id)
        # verification
        cert.assert_certificate_valid(effective_canister_id)
    """

    def __init__(self, cert: Dict[str, Any]):
        # tree
        tree = cert.get("tree", cert.get(b"tree"))
        if tree is None:
            raise ValueError("certificate missing 'tree'")
        self.tree: Any = tree

        # signature
        sig_val = cert.get("signature", cert.get(b"signature"))
        self.signature: Optional[bytes] = bytes(sig_val) if sig_val is not None else None

        # delegation
        self.delegation: Optional[Dict[str, Any]] = cert.get(
            "delegation", cert.get(b"delegation")
        )

        # tiny cache for root hash
        self._root_hash_cache: Optional[bytes] = None

    def read_root_key(self) -> bytes:
        """Return the IC root DER-encoded public key."""
        return IC_ROOT_KEY

    # ---------------- HashTree lookup helpers ----------------

    def lookup_reply(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[bytes]:
        path = [b"request_status", self._to_bytes(request_id), b"reply"]
        return self.lookup(path)

    def lookup_request_status(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[bytes]:
        path = [b"request_status", self._to_bytes(request_id), b"status"]
        return self.lookup(path)

    def lookup_reject_code(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[str]:
        path = [b"request_status", self._to_bytes(request_id), b"reject_code"]
        value = self.lookup(path)
        if value is None:
            return None
        return bytes(value).decode("utf-8", "replace")

    def lookup_reject_message(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[str]:
        path = [b"request_status", self._to_bytes(request_id), b"reject_message"]
        value = self.lookup(path)
        if value is None:
            return None
        return bytes(value).decode("utf-8", "replace")

    def lookup_error_code(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[str]:
        path = [b"request_status", self._to_bytes(request_id), b"error_code"]
        value = self.lookup(path)
        if value is None:
            return None
        return bytes(value).decode("utf-8", "replace")

    def lookup_request_rejection(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Dict[str, Optional[str]]:
        return {
            "reject_code": self.lookup_reject_code(request_id),
            "reject_message": self.lookup_reject_message(request_id),
            "error_code": self.lookup_error_code(request_id),
        }

    def lookup(self, path: Sequence[Union[str, bytes, bytearray, memoryview]]) -> Optional[bytes]:
        """Resolve a path against the hash tree; return bytes at Leaf or None."""
        bpath = [self._to_bytes(x) for x in path]
        return self._lookup_path(bpath, self.tree)

    def _lookup_path(self, path: Sequence[bytes], node: Any) -> Optional[bytes]:
        """
        Spec-compliant traversal without flattening forks:
          - Empty: not found
          - Fork: try left, then right
          - Labeled: if label matches current path head, descend
          - Leaf: success only if path already consumed
          - Pruned: not traversable (digest only) => not found
        """
        tag = node[0]

        if tag == NodeId.Empty.value:
            return None

        if tag == NodeId.Pruned.value:
            return None

        if not path:
            # Only success if we are at a Leaf
            if tag == NodeId.Leaf.value:
                return bytes(node[1])
            return None

        if tag == NodeId.Fork.value:
            left = self._lookup_path(path, node[1])
            if left is not None:
                return left
            return self._lookup_path(path, node[2])

        if tag == NodeId.Labeled.value:
            want = path[0]
            have = bytes(node[1])
            if want == have:
                return self._lookup_path(path[1:], node[2])
            return None

        if tag == NodeId.Leaf.value:
            # path not empty but hit a leaf => not found
            return None

        raise RuntimeError("unreachable")

    # ---------------- HashTree digest helpers ----------------

    def tree_digest(self, node: Optional[Any] = None) -> bytes:
        """Compute the SHA-256 digest of a node according to the IC hashtree scheme."""
        if node is None:
            node = self.tree
        tag = node[0]

        if tag == NodeId.Empty.value:
            return hashlib.sha256(DS_EMPTY).digest()

        if tag == NodeId.Pruned.value:
            digest_bytes = bytes(node[1])
            if len(digest_bytes) != 32:
                raise ValueError("Pruned node must carry a 32-byte digest")
            return digest_bytes

        if tag == NodeId.Leaf.value:
            val = bytes(node[1])
            return hashlib.sha256(DS_LEAF + val).digest()

        if tag == NodeId.Labeled.value:
            label = bytes(node[1])
            sub_digest = self.tree_digest(node[2])
            return hashlib.sha256(DS_LABELED + label + sub_digest).digest()

        if tag == NodeId.Fork.value:
            left = self.tree_digest(node[1])
            right = self.tree_digest(node[2])
            return hashlib.sha256(DS_FORK + left + right).digest()

        raise RuntimeError("unreachable")

    def root_hash(self) -> bytes:
        """Compute and cache the hashtree root digest."""
        if self._root_hash_cache is None:
            self._root_hash_cache = self.tree_digest(self.tree)
        return self._root_hash_cache

    def signed_message(self) -> bytes:
        """Return domain separator + root hash (the message to be BLS-verified)."""
        return IC_STATE_ROOT_DOMAIN_SEPARATOR + self.root_hash()

    # ---------------- Delegation and verification ----------------

    def check_delegation(
        self,
        effective_canister_id: Union[bytes, bytearray, memoryview, str],
        *,
        must_verify: bool = True,
    ) -> bytes:
        """
        - No delegation: return the IC root DER public key.
        - With delegation: decode the parent certificate (CBOR),
            * The parent must NOT itself contain a delegation.
            * If must_verify=True: cryptographically verify the parent with blst.
            * Ensure effective_canister_id is within canister_ranges.
            * Return the subnet DER public_key.
        """
        eff = self._to_bytes(effective_canister_id)

        if self.delegation is None:
            return self.read_root_key()

        deleg = self.delegation
        subnet_id = bytes(deleg["subnet_id"])

        try:
            parent_cert_dict = cbor2.loads(deleg["certificate"])
        except Exception as e:
            raise ValueError("InvalidCborData: delegation.certificate") from e

        parent_cert = Certificate(parent_cert_dict)

        if parent_cert.delegation is not None:
            raise ValueError("CertificateHasTooManyDelegations")

        if must_verify:
            verified = parent_cert.verify_cert(eff, backend="blst")
            if verified is not True:
                raise ValueError("ParentCertificateVerificationFailed")

        # canister_ranges
        canister_range_path = [b"subnet", subnet_id, b"canister_ranges"]
        canister_range = parent_cert.lookup(canister_range_path)
        if canister_range is None:
            raise ValueError("Missing canister_ranges in delegation certificate")

        try:
            ranges_raw = cbor2.loads(canister_range)
        except Exception as e:
            raise ValueError("InvalidCborData: canister_ranges") from e

        try:
            ranges: List[Tuple[bytes, bytes]] = [(bytes(lo), bytes(hi)) for (lo, hi) in ranges_raw]
        except Exception as e:
            raise ValueError("InvalidCborData: ranges format") from e

        if not any(lo <= eff <= hi for (lo, hi) in ranges):
            raise ValueError("CertificateNotAuthorized")

        # subnet public key (DER)
        public_key_path = [b"subnet", subnet_id, b"public_key"]
        der_key = parent_cert.lookup(public_key_path)
        if der_key is None:
            raise ValueError("Missing public_key in delegation certificate")

        return der_key

    def verify_cert(self, effective_canister_id, *, backend: str = "auto"):
        """
        Verify the certificate against effective_canister_id.
        backend:
          - "auto" / "blst": verify with blst (raises if blst is unavailable)
          - "return_materials": return verification materials (skip crypto)
        """
        if self.signature is None:
            raise ValueError("certificate missing signature")

        sig_bytes = bytes(self.signature)
        if len(sig_bytes) != 48:
            raise ValueError("invalid signature length (expect 48 bytes for G1)")

        message = IC_STATE_ROOT_DOMAIN_SEPARATOR + self.root_hash()

        must_verify_chain = backend != "return_materials"
        der_key = self.check_delegation(effective_canister_id, must_verify=must_verify_chain)
        bls_pubkey_96 = extract_der(der_key)

        if backend == "return_materials":
            return {
                "signature": sig_bytes,
                "message": message,
                "der_public_key": der_key,
                "bls_public_key": bls_pubkey_96,
            }

        if backend in ("auto", "blst"):
            ok = verify_bls_signature_blst(sig_bytes, message, bls_pubkey_96)
            if not ok:
                raise ValueError("CertificateVerificationFailed")
            return True

        raise ValueError(f"Unknown backend: {backend}")

    def assert_certificate_valid(
        self, effective_canister_id: Union[str, bytes, bytearray, memoryview]
    ) -> None:
        """
        Validate that this Certificate is valid for the effective_canister_id (uses 'blst').
        - On success: return None.
        - On failure: raise ValueError/BlstUnavailable。
        """
        eid_bytes = _to_effective_canister_bytes(effective_canister_id)
        result = self.verify_cert(eid_bytes, backend="blst")
        if result is True:
            return
        raise RuntimeError("invalid certificate: BLS verification failed")

    # ---------------- Timestamp verification ----------------

    def verify_cert_timestamp(self, ingress_expiry_ns: int) -> None:
        """
        Verify the certificate timestamp:
          - read 'time' (nanoseconds) from the certificate
          - require both (now - time) <= ingress_expiry_ns and (time - now) <= ingress_expiry_ns
            (i.e., reject too-far future certs)
        Raise ValueError if the skew exceeds the allowed window.
        """
        cert_time_ns = self.lookup_time()
        now_ns = time.time_ns()
        limit = int(ingress_expiry_ns)

        if now_ns >= cert_time_ns:
            skew_past = now_ns - cert_time_ns
            if skew_past > limit:
                raise ValueError(
                    f"CertificateOutdated: skew_past={skew_past}ns > allowed={limit}ns"
                )
        else:
            skew_future = cert_time_ns - now_ns
            if skew_future > limit:
                raise ValueError(
                    f"CertificateFromFuture: skew_future={skew_future}ns > allowed={limit}ns"
                )

    def lookup_time(self) -> int:
        """Read and decode the 'time' label from the hashtree (ULEB128, nanoseconds)."""
        data = self.lookup([b"time"])
        if data is None:
            raise ValueError("Missing 'time' in certificate")
        try:
            return leb128.u.decode(bytes(data))
        except Exception as e:
            raise ValueError("Invalid 'time' encoding (expected ULEB128)") from e

    # ---------------- Utilities ----------------

    @staticmethod
    def _to_bytes(x: Union[str, bytes, bytearray, memoryview]) -> bytes:
        if isinstance(x, str):
            return x.encode("utf-8")
        if isinstance(x, (bytearray, memoryview)):
            return bytes(x)
        if isinstance(x, bytes):
            return x
        raise TypeError(f"expected bytes-like or str, got {type(x)}")


def _to_effective_canister_bytes(
    eid: Union[str, bytes, bytearray, memoryview]
) -> bytes:
    """
    Normalize an effective canister id into raw bytes:
      - str: parse IC textual format (with checksum) -> bytes
      - bytes/bytearray/memoryview: convert to bytes
    """
    if isinstance(eid, str):
        return Principal.from_str(eid).bytes
    if isinstance(eid, (bytes, bytearray, memoryview)):
        return bytes(eid)
    raise TypeError(f"unsupported effective_canister_id type: {type(eid)}")