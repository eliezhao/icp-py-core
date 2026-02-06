# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

"""
Internet Computer Agent implementation.

This module provides the core Agent class for interacting with the Internet Computer
protocol, including query and update operations, certificate verification, and
replica-signed query support.

Key Features:
- Query and update operations (sync and async)
- Certificate verification with BLS signatures
- Replica-signed query verification
- Node key caching for performance
- Automatic request signing and envelope construction
- Polling with exponential backoff for update calls
"""

from __future__ import annotations

from typing import Optional, Union, Any, Dict, List, Tuple
import hashlib
import time
import asyncio
import cbor2
import httpx
from httpx import Timeout, TimeoutException

from icp_candid import decode
from icp_certificate.certificate import IC_ROOT_KEY, Certificate
from icp_identity import DelegateIdentity
from icp_principal import Principal
from icp_candid.candid import encode, LEB128
from icp_core.errors import (
    ReplicaReject,
    PayloadEncodingError,
    NodeKeyNotFoundError,
    ReplicaSignatureVerificationFailed,
    IngressExpiryError,
    TimeoutWaitingForResponse,
    QuerySignatureVerificationFailed,
    MissingSignature,
    TooManySignatures,
    CertificateOutdated,
    CertificateNotAuthorized,
    DerKeyLengthMismatch,
    DerPrefixMismatch,
    MalformedPublicKey,
    MalformedSignature,
)

IC_REQUEST_DOMAIN_SEPARATOR = b"\x0Aic-request"
"""Domain separator for request signing (0x0A + "ic-request")."""

IC_RESPONSE_DOMAIN_SEPARATOR = b"\x0Bic-response"
"""Domain separator for response verification (0x0B + "ic-response")."""

# DER prefix for Ed25519 node public keys (12 bytes)
# [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0]
ED25519_DER_PREFIX = bytes([48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0])
"""DER prefix for Ed25519 node public keys (RFC 8410)."""

DEFAULT_POLL_TIMEOUT_SECS = 60.0
"""Default timeout for polling update call results in seconds."""

DEFAULT_QUERY_TIMEOUT_SEC = 30.0
"""Default timeout for query calls in seconds (30 seconds)."""

# Exponential backoff defaults
DEFAULT_INITIAL_DELAY = 0.5   # seconds
"""Default initial delay for exponential backoff in seconds."""

DEFAULT_MAX_INTERVAL  = 1.0   # seconds
"""Default maximum interval between polling attempts in seconds."""

DEFAULT_MULTIPLIER    = 1.4
"""Default multiplier for exponential backoff."""

NANOSECONDS = 1_000_000_000
"""Number of nanoseconds in one second."""

# Node key cache TTL (default 1 hour)
DEFAULT_NODE_KEY_CACHE_TTL_SEC = 3600
"""Default TTL for cached node public keys in seconds (1 hour)."""

def _safe_str(v: Any) -> Optional[str]:
    """
    Decode bytes-like objects to UTF-8 strings safely for error messages.
    
    This function safely converts various types to strings for use in error
    messages, handling encoding errors gracefully.
    
    Args:
        v: Value to convert to string. Can be None, str, bytes, bytearray, or memoryview.
    
    Returns:
        String representation of the value, or None if input is None.
    """
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode("utf-8", "replace")
    return str(v)


def sign_request(req: Dict[str, Any], iden: Any) -> Tuple[bytes, bytes]:
    """
    Build and CBOR-encode an envelope for an IC request.
    
    This function creates a signed request envelope by:
    1. Computing the request ID using Representation Independent Hash
    2. Signing the request ID with the provided identity
    3. Encoding the request, signature, and public key in CBOR format
    4. Including delegation information for delegated identities
    
    Args:
        req: Dictionary containing the request data (request_type, sender, etc.).
        iden: Identity object used to sign the request (must have a sign() method).
    
    Returns:
        A tuple of (request_id, signed_cbor_envelope):
        - request_id: 32-byte SHA-256 hash of the request
        - signed_cbor_envelope: CBOR-encoded signed request envelope
    
    Note:
        For delegated identities (DelegateIdentity), the envelope includes
        delegation chains and DER-encoded public keys.
    """
    request_id = to_request_id(req)
    message = IC_REQUEST_DOMAIN_SEPARATOR + request_id
    der_pubkey, sig = iden.sign(message)
    envelope = {
        "content": req,
        "sender_pubkey": der_pubkey,
        "sender_sig": sig,
    }
    if isinstance(iden, DelegateIdentity):
        envelope.update({
            "sender_pubkey": iden.der_pubkey,
            "sender_delegation": iden.delegations,
        })
    return request_id, cbor2.dumps(envelope)


def to_request_id(d: dict) -> bytes:
    """
    Compute the Representation Independent Hash (RIH) of a request dictionary.
    
    This function implements the canonical hashing algorithm used by the Internet
    Computer protocol to generate request IDs. It ensures that requests with
    the same content always produce the same hash, regardless of key ordering.
    
    This function recursively handles nested dictionaries and lists according to
    the Representation Independent Hash algorithm.
    
    Args:
        d: A dictionary representing the request. Keys and values are hashed
           according to the RIH algorithm. Supports nested dictionaries and lists.
    
    Returns:
        A 32-byte SHA-256 hash of the request.
    
    Raises:
        TypeError: If the input is not a dictionary.
    
    Note:
        This implements the Representation Independent Hash algorithm as specified
        in the IC protocol specification. It matches Rust's to_request_id implementation.
    """
    if not isinstance(d, dict):
        raise TypeError("request must be a dict")

    vec = []
    for k, v in d.items():
        # Hash the key (only str has .encode(); bytearray/memoryview use bytes())
        if isinstance(k, str):
            k = k.encode()
        elif not isinstance(k, bytes):
            k = bytes(k)
        h_k = hashlib.sha256(k).digest()
        
        # Hash the value (recursively handle nested structures)
        if isinstance(v, dict):
            # Recursively hash nested dictionaries
            h_v = to_request_id(v)
        elif isinstance(v, list):
            # Use encode_list for lists
            h_v = hashlib.sha256(encode_list(v)).digest()
        elif isinstance(v, int):
            # Encode integers as LEB128
            h_v = hashlib.sha256(LEB128.encode_u(v)).digest()
        elif isinstance(v, (bytes, bytearray, memoryview)):
            # Hash bytes directly
            h_v = hashlib.sha256(bytes(v)).digest()
        elif isinstance(v, str):
            # Hash strings as UTF-8 bytes
            h_v = hashlib.sha256(v.encode("utf-8")).digest()
        else:
            # Fallback: use CBOR encoding for other types
            h_v = hashlib.sha256(cbor2.dumps(v)).digest()
        
        vec.append(h_k + h_v)
    
    # Sort all key-value hash pairs and compute final hash
    s = b''.join(sorted(vec))
    return hashlib.sha256(s).digest()


def build_query_response_signable(
    status: str,
    request_id: bytes,
    timestamp: int,
    reply: Optional[Dict[str, Any]] = None,
    reject: Optional[Dict[str, Any]] = None,
) -> bytes:
    """
    Build the signable form of a query response.
    
    According to ICP spec, the signable data is:
    signable = b"\\x0Bic-response" + RequestId(QueryResponseSignable)
    
    QueryResponseSignable contains:
    - status (replied/rejected)
    - reply or reject information
    - request_id
    - timestamp
    
    The QueryResponseSignable is CBOR-serialized, then hashed to get RequestId.
    
    Args:
        status: Response status ("replied" or "rejected").
        request_id: The request ID bytes.
        timestamp: Timestamp in nanoseconds.
        reply: Reply data dict (for "replied" status).
        reject: Reject data dict (for "rejected" status).
    
    Returns:
        Signable bytes ready for signature verification.
    """
    if status == "replied":
        if reply is None:
            raise ValueError("reply is required for 'replied' status")
        reply_arg = reply.get("arg", reply.get(b"arg"))
        if reply_arg is None:
            raise ValueError("reply.arg is required")
        
        # Build QueryResponseSignable::Replied
        # Ensure request_id is bytes
        request_id_bytes = bytes(request_id) if not isinstance(request_id, bytes) else request_id
        signable_dict = {
            "status": "replied",
            "reply": {"arg": reply_arg},
            "request_id": request_id_bytes,
            "timestamp": timestamp,
        }
    elif status == "rejected":
        if reject is None:
            raise ValueError("reject is required for 'rejected' status")
        
        reject_code = reject.get("reject_code", reject.get(b"reject_code", 0))
        reject_message = reject.get("reject_message", reject.get(b"reject_message", ""))
        error_code = reject.get("error_code", reject.get(b"error_code"))
        
        # Build QueryResponseSignable::Rejected
        # Ensure request_id is bytes
        request_id_bytes = bytes(request_id) if not isinstance(request_id, bytes) else request_id
        signable_dict = {
            "status": "rejected",
            "reject_code": reject_code,
            "reject_message": reject_message,
            "request_id": request_id_bytes,
            "timestamp": timestamp,
        }
        if error_code is not None:
            signable_dict["error_code"] = error_code
    else:
        raise ValueError(f"Invalid status: {status}")
    
    # Compute RequestId using Representation Independent Hash
    # According to ICP spec and Rust implementation, to_request_id uses
    # a custom serde serializer that recursively hashes nested structures.
    # Our Python implementation matches this behavior.
    signable_request_id = to_request_id(signable_dict)
    
    # Build final signable: domain separator + request_id
    signable = IC_RESPONSE_DOMAIN_SEPARATOR + signable_request_id
    return signable


def verify_ed25519_signature(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """
    Verify an Ed25519 (EdDSA) signature using PyNaCl.

    Ed25519 is EdDSA, not ECDSA; this uses nacl.signing.VerifyKey for correct
    verification. The ecdsa library's VerifyingKey is for ECDSA curves and is
    not appropriate for query response signature verification.

    Args:
        signature: 64-byte Ed25519 signature.
        message: Message bytes that were signed.
        public_key: 32-byte Ed25519 public key.

    Returns:
        True if signature is valid, False otherwise.
    """
    if len(signature) != 64:
        return False
    if len(public_key) != 32:
        return False

    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError

        vk = VerifyKey(public_key)
        vk.verify(message, signature=signature)
        return True
    except BadSignatureError:
        return False
    except Exception:
        return False


def extract_ed25519_pubkey_from_der(der_key: bytes) -> bytes:
    """
    Extract Ed25519 public key from DER-encoded node public key.
    
    Node public keys are DER-encoded BLS keys (44 bytes):
    - 12-byte DER prefix: [48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0]
    - 32-byte Ed25519 public key
    
    Args:
        der_key: DER-encoded public key (44 bytes).
    
    Returns:
        32-byte Ed25519 public key.
    
    Raises:
        DerKeyLengthMismatch: If key length is not 44 bytes.
        DerPrefixMismatch: If DER prefix doesn't match.
        MalformedPublicKey: If key format is invalid.
    """
    if len(der_key) != 44:
        raise DerKeyLengthMismatch(expected=44, actual=len(der_key))
    
    if der_key[:12] != ED25519_DER_PREFIX:
        raise DerPrefixMismatch(expected=ED25519_DER_PREFIX, actual=der_key[:12])
    
    # Extract the 32-byte Ed25519 public key (last 32 bytes)
    return der_key[12:]


def encode_list(l: list) -> bytes:
    """
    Canonical list hashing fragment used inside to_request_id.
    
    This function converts a list into a canonical byte representation by:
    - Recursively encoding nested lists
    - Encoding integers as ULEB128
    - Using raw bytes for bytes/bytearray/memoryview
    - Encoding strings as UTF-8
    - Using CBOR encoding as a fallback for other types
    
    Each element is then hashed with SHA-256 and concatenated.
    
    Args:
        l: A list of elements to encode.
    
    Returns:
        Concatenated SHA-256 hashes of each element's canonical representation.
    
    Note:
        This is used internally by `to_request_id()` to ensure deterministic
        hashing of request data structures.
    """
    ret = b''
    for item in l:
        if isinstance(item, list):
            v = encode_list(item)
        elif isinstance(item, int):
            v = LEB128.encode_u(item)
        elif isinstance(item, (bytes, bytearray, memoryview)):
            v = bytes(item)
        elif isinstance(item, str):
            v = item.encode("utf-8")
        else:
            # fallback for unexpected types to maintain determinism
            v = cbor2.dumps(item)
        ret += hashlib.sha256(v).digest()
    return ret


# Default ingress expiry in seconds
DEFAULT_INGRESS_EXPIRY_SEC = 3 * 60


class NodeKeyCache:
    """
    Cache for node public keys to avoid repeated read_state calls.
    Key: (subnet_id, node_id) tuple
    Value: (public_key_bytes, valid_until_timestamp_ns)
    """
    def __init__(self, ttl_seconds: int = DEFAULT_NODE_KEY_CACHE_TTL_SEC):
        self.cache: dict = {}
        self.ttl_ns = ttl_seconds * NANOSECONDS

    def get(self, subnet_id: bytes, node_id: bytes) -> bytes | None:
        """Get cached public key if valid, None otherwise."""
        key = (bytes(subnet_id), bytes(node_id))
        if key not in self.cache:
            return None
        
        public_key, valid_until = self.cache[key]
        now_ns = time.time_ns()
        
        if now_ns >= valid_until:
            # Expired, remove from cache
            del self.cache[key]
            return None
        
        return public_key

    def set(self, subnet_id: bytes, node_id: bytes, public_key: bytes):
        """Cache a public key with TTL."""
        key = (bytes(subnet_id), bytes(node_id))
        valid_until = time.time_ns() + self.ttl_ns
        self.cache[key] = (bytes(public_key), valid_until)

    def clear(self) -> None:
        """
        Clear all cached entries.
        
        This method removes all entries from the cache, forcing fresh
        lookups on the next get() call.
        """
        self.cache.clear()


class Agent:
    """
    Internet Computer Agent for protocol interactions.
    
    The Agent class is the main interface for interacting with the Internet Computer
    protocol. It handles query and update operations, request signing, certificate
    verification, and replica-signed query verification.
    
    Key Features:
    - Query operations (read-only, fast)
    - Update operations (state-changing, requires consensus)
    - Automatic request signing with identity
    - Certificate verification with BLS signatures
    - Replica-signed query verification
    - Node key caching for performance
    - Polling with exponential backoff for update calls
    
    Attributes:
        identity: Identity object used for signing requests.
        client: HTTP client for communicating with IC boundary nodes.
        ingress_expiry: Ingress message expiry time in seconds (default: 3 minutes).
        root_key: Root public key for certificate verification (default: IC_ROOT_KEY).
        nonce_factory: Optional factory for generating nonces.
        verify_query_signatures: Whether to verify query response signatures (default: False).
                                 Note: Standard IC query responses do not include signatures. Only
                                 replica-signed queries include signatures. Enabling this will cause
                                 standard queries to fail unless signatures are present.
        node_key_cache: Cache for node public keys.
    
    Example:
        >>> from icp_core import Agent, Client, Identity
        >>> client = Client()
        >>> identity = Identity.from_hex("...")
        >>> agent = Agent(identity, client)
        >>> result = agent.query("canister-id", "method_name", None)
    """
    
    def __init__(
        self,
        identity: Any,
        client: Any,
        nonce_factory: Optional[Any] = None,
        ingress_expiry: float = DEFAULT_INGRESS_EXPIRY_SEC,
        root_key: bytes = IC_ROOT_KEY,
        verify_query_signatures: bool = False
    ) -> None:
        """
        Initialize the Agent.
        
        Args:
            identity: Identity object for signing requests (must have sign() and sender() methods).
            client: HTTP client instance (Client class).
            nonce_factory: Optional factory for generating nonces (for replay protection).
            ingress_expiry: Ingress message expiry time in seconds. Defaults to 3 minutes.
            root_key: Root public key for certificate verification. Defaults to IC_ROOT_KEY.
            verify_query_signatures: Whether to verify query response signatures. Defaults to False.
                                    Note: Standard IC query responses do not include signatures.
                                    Only replica-signed queries include signatures. Enabling this
                                    will cause standard queries to fail unless signatures are present.
        """
        self.identity = identity
        self.client = client
        self.ingress_expiry = ingress_expiry
        self.root_key = root_key
        self.nonce_factory = nonce_factory
        self.verify_query_signatures = verify_query_signatures
        self.node_key_cache = NodeKeyCache()

    def get_principal(self) -> Principal:
        """
        Get the principal ID of the agent's identity.
        
        Returns:
            Principal object representing the sender's identity.
        """
        return self.identity.sender()

    def get_expiry_date(self) -> int:
        """
        Calculate ingress expiry timestamp in nanoseconds.
        
        The expiry is calculated as current time + ingress_expiry seconds.
        This ensures requests are not accepted after they expire.
        
        Returns:
            Timestamp in nanoseconds since Unix epoch.
        """
        return time.time_ns() + int(self.ingress_expiry * 1e9)

    def _get_node_public_key(self, subnet_id: bytes, node_id: bytes) -> bytes:
        """
        Get node public key from state tree, using cache if available.
        """
        # Check cache first
        cached_key = self.node_key_cache.get(subnet_id, node_id)
        if cached_key is not None:
            return cached_key

        # Fetch from state tree
        try:
            subnet_id_str = Principal(subnet_id).to_str()
        except Exception as e:
            raise ValueError(f"Invalid subnet_id format: {subnet_id.hex()}") from e
        
        path = [b"subnet", subnet_id, b"node", node_id, b"public_key"]
        # Skip BLS verification when fetching node keys for query signature verification
        # The node key itself will be verified during signature verification
        certificate = self.read_state_subnet_raw(subnet_id_str, [path], verify_certificate=False)
        public_key = certificate.lookup(path)
        
        if public_key is None:
            raise NodeKeyNotFoundError(node_id, subnet_id)
        
        # Cache the key
        self.node_key_cache.set(subnet_id, node_id, public_key)
        return public_key

    async def _get_node_public_key_async(self, subnet_id: bytes, node_id: bytes) -> bytes:
        """
        Get node public key from state tree (async), using cache if available.
        """
        # Check cache first
        cached_key = self.node_key_cache.get(subnet_id, node_id)
        if cached_key is not None:
            return cached_key

        # Fetch from state tree
        try:
            subnet_id_str = Principal(subnet_id).to_str()
        except Exception as e:
            raise ValueError(f"Invalid subnet_id format: {subnet_id.hex()}") from e
        
        path = [b"subnet", subnet_id, b"node", node_id, b"public_key"]
        # Skip BLS verification when fetching node keys for query signature verification
        # The node key itself will be verified during signature verification
        certificate = await self.read_state_subnet_raw_async(subnet_id_str, [path], verify_certificate=False)
        public_key = certificate.lookup(path)
        
        if public_key is None:
            raise NodeKeyNotFoundError(node_id, subnet_id)
        
        # Cache the key
        self.node_key_cache.set(subnet_id, node_id, public_key)
        return public_key

    def _get_subnet_by_canister(self, canister_id: Union[str, Principal]) -> Tuple[bytes, Dict[bytes, bytes]]:
        """
        Get subnet ID for a canister.
        
        Returns:
            Tuple of (subnet_id, empty_dict). Node keys are fetched on-demand during signature verification.
        """
        # Read canister state to get certificate with delegation
        paths = [[b"time"]]  # Minimal path to get certificate
        cert = self.read_state_raw(canister_id, paths, verify_certificate=False)
        
        # Determine subnet_id from delegation
        subnet_id = None
        if cert.delegation is not None:
            subnet_id_raw = cert.delegation.get("subnet_id") or cert.delegation.get(b"subnet_id")
            if subnet_id_raw is not None:
                subnet_id = bytes(subnet_id_raw)
        
        if subnet_id is None:
            # If no delegation, this might be NNS canister (root subnet)
            # For root subnet, subnet_id is derived from root key
            subnet_id = Principal.self_authenticating(self.root_key).bytes
        
        # Return subnet_id and empty dict (node keys fetched on-demand)
        return subnet_id, {}

    async def _get_subnet_by_canister_async(self, canister_id: Union[str, Principal]) -> Tuple[bytes, Dict[bytes, bytes]]:
        """
        Get subnet ID for a canister (async).
        
        Returns:
            Tuple of (subnet_id, empty_dict). Node keys are fetched on-demand during signature verification.
        """
        # Read canister state to get certificate with delegation
        paths = [[b"time"]]  # Minimal path to get certificate
        cert = await self.read_state_raw_async(canister_id, paths, verify_certificate=False)
        
        # Determine subnet_id from delegation
        subnet_id = None
        if cert.delegation is not None:
            subnet_id_raw = cert.delegation.get("subnet_id") or cert.delegation.get(b"subnet_id")
            if subnet_id_raw is not None:
                subnet_id = bytes(subnet_id_raw)
        
        if subnet_id is None:
            # If no delegation, this might be NNS canister (root subnet)
            # For root subnet, subnet_id is derived from root key
            subnet_id = Principal.self_authenticating(self.root_key).bytes
        
        # Return subnet_id and empty dict (node keys fetched on-demand)
        return subnet_id, {}

    def _verify_query_response_signatures(
        self,
        result: Dict[str, Any],
        request_id: bytes,
        effective_canister_id: Union[str, Principal],
    ) -> None:
        """
        Verify query response signatures.
        
        Args:
            result: Query response dict from endpoint.
            request_id: The request ID bytes.
            effective_canister_id: Effective canister ID for subnet lookup.
        
        Raises:
            MissingSignature: If response has no signatures.
            TooManySignatures: If signature count exceeds node count.
            CertificateOutdated: If signature timestamp is outdated.
            CertificateNotAuthorized: If node is not authorized.
            QuerySignatureVerificationFailed: If signature verification fails.
        """
        signatures = result.get("signatures", [])
        if not isinstance(signatures, list) or len(signatures) == 0:
            raise MissingSignature()
        
        # Get subnet information
        subnet_id, _ = self._get_subnet_by_canister(effective_canister_id)
        
        # Check signature count
        # Note: We don't know the exact node count without fetching all nodes,
        # so we'll verify each signature individually and allow any valid signature
        if len(signatures) > 100:  # Reasonable upper limit
            raise TooManySignatures(had=len(signatures), needed=100)
        
        # Verify each signature
        verified = False
        for sig_obj in signatures:
            if not isinstance(sig_obj, dict):
                continue
            
            node_identity_raw = sig_obj.get("identity")
            sig_bytes_raw = sig_obj.get("signature")
            timestamp_ns_raw = sig_obj.get("timestamp")
            
            if not all([node_identity_raw, sig_bytes_raw, timestamp_ns_raw]):
                continue
            
            # Convert to bytes if needed
            if isinstance(node_identity_raw, str):
                node_identity = Principal.from_str(node_identity_raw).bytes
            elif isinstance(node_identity_raw, (bytes, bytearray, memoryview)):
                node_identity = bytes(node_identity_raw)
            else:
                continue
            
            if isinstance(sig_bytes_raw, str):
                sig_bytes = bytes.fromhex(sig_bytes_raw)
            elif isinstance(sig_bytes_raw, (bytes, bytearray, memoryview)):
                sig_bytes = bytes(sig_bytes_raw)
            else:
                continue
            
            if isinstance(timestamp_ns_raw, str):
                timestamp_ns = int(timestamp_ns_raw)
            elif isinstance(timestamp_ns_raw, int):
                timestamp_ns = timestamp_ns_raw
            else:
                continue
            
            # Check timestamp
            now_ns = time.time_ns()
            max_age_ns = int(self.ingress_expiry * NANOSECONDS)
            # Use absolute value to check both past and future timestamps
            if abs(now_ns - timestamp_ns) > max_age_ns:
                continue  # Skip outdated or future signature, try next one
            
            # Build signable data
            status = result.get("status", "")
            try:
                signable = build_query_response_signable(
                    status=status,
                    request_id=request_id,
                    timestamp=timestamp_ns,
                    reply=result.get("reply"),
                    reject=result.get("reject") if status == "rejected" else None,
                )
            except Exception:
                continue  # Skip if we can't build signable
            
            # Get node public key
            try:
                node_pubkey_der = self._get_node_public_key(subnet_id, node_identity)
            except NodeKeyNotFoundError:
                # Node not found, try next signature
                continue
            
            # Extract Ed25519 public key from DER
            try:
                ed25519_pubkey = extract_ed25519_pubkey_from_der(node_pubkey_der)
            except (DerKeyLengthMismatch, DerPrefixMismatch, MalformedPublicKey):
                continue
            
            # Verify signature
            try:
                if verify_ed25519_signature(sig_bytes, signable, ed25519_pubkey):
                    verified = True
                    break
            except Exception:
                continue  # Try next signature

        if not verified:
            sig_count = len(signatures)
            raise QuerySignatureVerificationFailed(
                f"Query signature verification failed for all {sig_count} signature(s). "
                "This may indicate: invalid signatures, outdated timestamps, or node key lookup failures."
            )

    async def _verify_query_response_signatures_async(
        self,
        result: Dict[str, Any],
        request_id: bytes,
        effective_canister_id: Union[str, Principal],
    ) -> None:
        """
        Verify query response signatures (async).
        
        Args:
            result: Query response dict from endpoint.
            request_id: The request ID bytes.
            effective_canister_id: Effective canister ID for subnet lookup.
        
        Raises:
            MissingSignature: If response has no signatures.
            TooManySignatures: If signature count exceeds node count.
            CertificateOutdated: If signature timestamp is outdated.
            CertificateNotAuthorized: If node is not authorized.
            QuerySignatureVerificationFailed: If signature verification fails.
        """
        signatures = result.get("signatures", [])
        if not isinstance(signatures, list) or len(signatures) == 0:
            raise MissingSignature()
        
        # Get subnet information
        subnet_id, _ = await self._get_subnet_by_canister_async(effective_canister_id)
        
        # Check signature count
        if len(signatures) > 100:  # Reasonable upper limit
            raise TooManySignatures(had=len(signatures), needed=100)
        
        # Verify each signature
        verified = False
        for sig_obj in signatures:
            if not isinstance(sig_obj, dict):
                continue
            
            node_identity_raw = sig_obj.get("identity")
            sig_bytes_raw = sig_obj.get("signature")
            timestamp_ns_raw = sig_obj.get("timestamp")
            
            if not all([node_identity_raw, sig_bytes_raw, timestamp_ns_raw]):
                continue
            
            # Convert to bytes if needed
            if isinstance(node_identity_raw, str):
                node_identity = Principal.from_str(node_identity_raw).bytes
            elif isinstance(node_identity_raw, (bytes, bytearray, memoryview)):
                node_identity = bytes(node_identity_raw)
            else:
                continue
            
            if isinstance(sig_bytes_raw, str):
                sig_bytes = bytes.fromhex(sig_bytes_raw)
            elif isinstance(sig_bytes_raw, (bytes, bytearray, memoryview)):
                sig_bytes = bytes(sig_bytes_raw)
            else:
                continue
            
            if isinstance(timestamp_ns_raw, str):
                timestamp_ns = int(timestamp_ns_raw)
            elif isinstance(timestamp_ns_raw, int):
                timestamp_ns = timestamp_ns_raw
            else:
                continue
            
            # Check timestamp
            now_ns = time.time_ns()
            max_age_ns = int(self.ingress_expiry * NANOSECONDS)
            # Use absolute value to check both past and future timestamps
            if abs(now_ns - timestamp_ns) > max_age_ns:
                continue  # Skip outdated or future signature, try next one
            
            # Build signable data
            status = result.get("status", "")
            try:
                signable = build_query_response_signable(
                    status=status,
                    request_id=request_id,
                    timestamp=timestamp_ns,
                    reply=result.get("reply"),
                    reject=result.get("reject") if status == "rejected" else None,
                )
            except Exception:
                continue  # Skip if we can't build signable
            
            # Get node public key
            try:
                node_pubkey_der = await self._get_node_public_key_async(subnet_id, node_identity)
            except NodeKeyNotFoundError:
                # Node not found, try next signature
                continue
            
            # Extract Ed25519 public key from DER
            try:
                ed25519_pubkey = extract_ed25519_pubkey_from_der(node_pubkey_der)
            except (DerKeyLengthMismatch, DerPrefixMismatch, MalformedPublicKey):
                continue
            
            # Verify signature
            try:
                if verify_ed25519_signature(sig_bytes, signable, ed25519_pubkey):
                    verified = True
                    break
            except Exception:
                continue  # Try next signature

        if not verified:
            sig_count = len(signatures)
            raise QuerySignatureVerificationFailed(
                f"Query signature verification failed for all {sig_count} signature(s). "
                "This may indicate: invalid signatures, outdated timestamps, or node key lookup failures."
            )

    # ----------- HTTP endpoints -----------

    def query_endpoint(self, canister_id, data, timeout: Optional[float] = None):
        """
        Send query request to endpoint with timeout handling.
        
        Args:
            canister_id: The canister ID to query.
            data: CBOR-encoded request data.
            timeout: Timeout in seconds. If None, uses DEFAULT_QUERY_TIMEOUT_SEC.
        
        Returns:
            Decoded CBOR response.
        
        Raises:
            TimeoutWaitingForResponse: If the request times out.
            TransportError: For other transport errors.
        """
        # Use default timeout if not provided
        timeout_sec = timeout if timeout is not None else DEFAULT_QUERY_TIMEOUT_SEC
        timeout_obj = Timeout(timeout_sec)
        
        try:
            raw_bytes = self.client.query(canister_id, data, timeout=timeout_obj)
            return cbor2.loads(raw_bytes)
        except TimeoutException as e:
            # Convert httpx timeout to unified TimeoutWaitingForResponse
            raise TimeoutWaitingForResponse(
                f"Query request timed out after {timeout_sec}s",
                timeout_seconds=timeout_sec,
                request_id=None,  # Query doesn't have request_id at this point
            ) from e

    async def query_endpoint_async(self, canister_id, data, timeout: Optional[float] = None):
        """
        Send query request to endpoint asynchronously with timeout handling.
        
        Args:
            canister_id: The canister ID to query.
            data: CBOR-encoded request data.
            timeout: Timeout in seconds. If None, uses DEFAULT_QUERY_TIMEOUT_SEC.
        
        Returns:
            Decoded CBOR response.
        
        Raises:
            TimeoutWaitingForResponse: If the request times out.
            TransportError: For other transport errors.
        """
        # Use default timeout if not provided
        timeout_sec = timeout if timeout is not None else DEFAULT_QUERY_TIMEOUT_SEC
        timeout_obj = Timeout(timeout_sec)
        
        try:
            raw_bytes = await self.client.query_async(canister_id, data, timeout=timeout_obj)
            return cbor2.loads(raw_bytes)
        except TimeoutException as e:
            # Convert httpx timeout to unified TimeoutWaitingForResponse
            raise TimeoutWaitingForResponse(
                f"Query request timed out after {timeout_sec}s",
                timeout_seconds=timeout_sec,
                request_id=None,  # Query doesn't have request_id at this point
            ) from e

    def call_endpoint(self, canister_id, data):
        return self.client.call(canister_id, data)

    async def call_endpoint_async(self, canister_id, request_id, data):
        await self.client.call_async(canister_id, request_id, data)
        return request_id

    def read_state_endpoint(self, canister_id, data):
        return self.client.read_state(canister_id, data)

    async def read_state_endpoint_async(self, canister_id, data):
        return await self.client.read_state_async(canister_id, data)

    def read_state_subnet_endpoint(self, subnet_id, data):
        return self.client.read_state_subnet(subnet_id, data)

    async def read_state_subnet_endpoint_async(self, subnet_id, data):
        return await self.client.read_state_subnet_async(subnet_id, data)

    def _encode_arg(self, arg) -> bytes:
        """
        Normalize argument to DIDL bytes:
          - If arg is None: encode([]) (empty Candid)
          - If arg is bytes-like: return bytes(arg) directly
          - Otherwise: assume it's acceptable by `icp_candid.candid.encode`
            (e.g., [{'type': Types.Text, 'value': 'hello'}]) and encode it.
        """
        if arg is None:
            return encode([])
        if isinstance(arg, (bytes, bytearray, memoryview)):
            return bytes(arg)
        # Let candid.encode decide (common case: list of typed values)
        return encode(arg)

    # ----------- High-level (ergonomic) APIs -----------

    def query(
        self,
        canister_id,
        method_name: str,
        arg=None,
        *,
        return_type=None,
        effective_canister_id=None,
        verify_query_signatures: Optional[bool] = None,
        timeout: Optional[float] = None,
    ):
        """
        High-level query (one-shot, no polling):
          - `arg` can be:
              * None -> encodes to empty DIDL (encode([]))
              * bytes/bytearray/memoryview -> used as-is
              * anything else acceptable by `icp_candid.candid.encode`
                (e.g. [{'type': Types.Nat, 'value': 42}])
          - If `return_type` is provided and reply is DIDL, it will be decoded.
          - `verify_query_signatures`: Whether to verify query response signatures.
                                     If None, uses Agent-level configuration (default: False).
                                     Note: Standard IC query responses do not include signatures.
          - `timeout`: Timeout in seconds. If None, uses DEFAULT_QUERY_TIMEOUT_SEC.
        """
        didl = self._encode_arg(arg)
        return self.query_raw(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
            verify_query_signatures=verify_query_signatures,
            timeout=timeout,
        )

    async def query_async(
        self,
        canister_id,
        method_name: str,
        arg=None,
        *,
        return_type=None,
        effective_canister_id=None,
        timeout: Optional[float] = None,
        verify_query_signatures: Optional[bool] = None,
    ):
        """
        High-level async query (one-shot, no polling).
        Same as query() but async; arg encoding and return_type handling are identical.
        
        Args:
            verify_query_signatures: Whether to verify query response signatures.
                                   If None, uses Agent-level configuration (default: False).
                                   Note: Standard IC query responses do not include signatures.
        """
        didl = self._encode_arg(arg)
        return await self.query_raw_async(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
            timeout=timeout,
            verify_query_signatures=verify_query_signatures,
        )

    def update(
            self,
            canister_id,
            method_name: str,
            arg=None,
            *,
            return_type=None,
            effective_canister_id=None,
            verify_certificate: bool = True,
            initial_delay: float = None,
            max_interval: float = None,
            multiplier: float = None,
            timeout: float = None,
    ):
        """
        High-level update: encode arg to DIDL and delegate to update_raw().
        Polling/backoff options are passed to update_raw() and then to poll().
        """
        didl = self._encode_arg(arg)
        # Use default timeout if not provided
        poll_timeout = timeout if timeout is not None else DEFAULT_POLL_TIMEOUT_SECS
        # Use default backoff parameters if not provided
        backoff_initial_delay = initial_delay if initial_delay is not None else DEFAULT_INITIAL_DELAY
        backoff_max_interval = max_interval if max_interval is not None else DEFAULT_MAX_INTERVAL
        backoff_multiplier = multiplier if multiplier is not None else DEFAULT_MULTIPLIER
        return self.update_raw(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
            verify_certificate=verify_certificate,
            timeout=poll_timeout,
            initial_delay=backoff_initial_delay,
            max_interval=backoff_max_interval,
            multiplier=backoff_multiplier,
        )

    async def update_async(
        self,
        canister_id,
        method_name: str,
        arg=None,
        *,
        return_type=None,
        effective_canister_id=None,
        verify_certificate: bool = True,
        initial_delay: float = None,
        max_interval: float = None,
        multiplier: float = None,
        timeout: float = None,
    ):
        """
        High-level async update: encode arg to DIDL and delegate to update_raw_async().
        Polling/backoff options are passed to poll_async() via update_raw_async(**kwargs).
        """
        didl = self._encode_arg(arg)
        poll_timeout = timeout if timeout is not None else DEFAULT_POLL_TIMEOUT_SECS
        kwargs = {}
        if initial_delay is not None:
            kwargs["initial_delay"] = initial_delay
        if max_interval is not None:
            kwargs["max_interval"] = max_interval
        if multiplier is not None:
            kwargs["multiplier"] = multiplier
        return await self.update_raw_async(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
            verify_certificate=verify_certificate,
            timeout=poll_timeout,
            **kwargs,
        )

    # ----------- Query (one-shot) -----------

    def query_raw(
        self,
        canister_id,
        method_name,
        arg,
        return_type=None,
        effective_canister_id=None,
        timeout: Optional[float] = None,
        verify_query_signatures: Optional[bool] = None,
    ):
        """
        Send query request with timeout handling.
        
        Args:
            canister_id: The canister ID to query.
            method_name: The method name to call.
            arg: The argument bytes (DIDL-encoded).
            return_type: Optional return type for decoding.
            effective_canister_id: Optional effective canister ID.
            timeout: Timeout in seconds. If None, uses DEFAULT_QUERY_TIMEOUT_SEC (30 seconds).
            verify_query_signatures: Whether to verify query response signatures.
                                   If None, uses Agent-level configuration (default: False).
                                   Note: Standard IC query responses do not include signatures.
        
        Returns:
            Decoded result if return_type is provided, otherwise raw bytes.
        
        Raises:
            TimeoutWaitingForResponse: If the request times out.
            ReplicaReject: If the query is rejected.
            QuerySignatureVerificationFailed: If signature verification fails.
        """
        req = {
            "request_type": "query",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        if self.nonce_factory is not None:
            req["nonce"] = self.nonce_factory()
        request_id, signed_cbor = sign_request(req, self.identity)
        target_canister = canister_id if effective_canister_id is None else effective_canister_id
        result = self.query_endpoint(target_canister, signed_cbor, timeout=timeout)

        if not isinstance(result, dict) or "status" not in result:
            raise RuntimeError("Malformed result: " + repr(result))

        # Determine if we should verify signatures
        should_verify = verify_query_signatures if verify_query_signatures is not None else self.verify_query_signatures
        
        # Verify query response signatures if enabled
        if should_verify:
            self._verify_query_response_signatures(result, request_id, target_canister)

        status = result["status"]
        if status == "replied":
            reply_arg = result["reply"]["arg"]
            
            if reply_arg[:4] == b"DIDL":
                return decode(reply_arg, return_type)
            return reply_arg
        elif status == "rejected":
            reject_code = result.get("reject_code", 0)
            reject_message = _safe_str(result.get("reject_message")) or "Unknown rejection"
            error_code = _safe_str(result.get("error_code"))
            raise ReplicaReject(reject_code, reject_message, error_code)
        else:
            raise RuntimeError("Unknown status: " + repr(status))

    async def query_raw_async(
        self,
        canister_id,
        method_name,
        arg,
        return_type=None,
        effective_canister_id=None,
        timeout: Optional[float] = None,
        verify_query_signatures: Optional[bool] = None,
    ):
        """
        Send query request asynchronously with timeout handling.
        
        Args:
            canister_id: The canister ID to query.
            method_name: The method name to call.
            arg: The argument bytes (DIDL-encoded).
            return_type: Optional return type for decoding.
            effective_canister_id: Optional effective canister ID.
            timeout: Timeout in seconds. If None, uses DEFAULT_QUERY_TIMEOUT_SEC (30 seconds).
            verify_query_signatures: Whether to verify query response signatures.
                                   If None, uses Agent-level configuration (default: False).
                                   Note: Standard IC query responses do not include signatures.
        
        Returns:
            Decoded result if return_type is provided, otherwise raw bytes.
        
        Raises:
            TimeoutWaitingForResponse: If the request times out.
            ReplicaReject: If the query is rejected.
            QuerySignatureVerificationFailed: If signature verification fails.
        """
        req = {
            "request_type": "query",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        if self.nonce_factory is not None:
            req["nonce"] = self.nonce_factory()
        request_id, signed_cbor = sign_request(req, self.identity)
        target_canister = canister_id if effective_canister_id is None else effective_canister_id
        result = await self.query_endpoint_async(target_canister, signed_cbor, timeout=timeout)

        if not isinstance(result, dict) or "status" not in result:
            raise RuntimeError("Malformed result: " + repr(result))

        # Determine if we should verify signatures
        should_verify = verify_query_signatures if verify_query_signatures is not None else self.verify_query_signatures
        
        # Verify query response signatures if enabled
        if should_verify:
            await self._verify_query_response_signatures_async(result, request_id, target_canister)

        status = result["status"]
        if status == "replied":
            reply_arg = result["reply"]["arg"]
            
            if reply_arg[:4] == b"DIDL":
                return decode(reply_arg, return_type)
            return reply_arg
        elif status == "rejected":
            reject_code = result.get("reject_code", 0)
            reject_message = _safe_str(result.get("reject_message")) or "Unknown rejection"
            error_code = _safe_str(result.get("error_code"))
            raise ReplicaReject(reject_code, reject_message, error_code)
        else:
            raise RuntimeError("Unknown status: " + repr(status))

    # ----------- Update (call + poll) -----------

    def update_raw(
        self,
        canister_id,
        method_name,
        arg,
        return_type=None,
        effective_canister_id=None,
        verify_certificate: bool = True,
        timeout: Optional[float] = None,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
    ):
        """
        Send update call and poll for result with timeout handling.
        
        Args:
            canister_id: The canister ID to call.
            method_name: The method name to call.
            arg: The argument bytes (DIDL-encoded).
            return_type: Optional return type for decoding.
            effective_canister_id: Optional effective canister ID.
            verify_certificate: Whether to verify certificate.
            timeout: Timeout in seconds for polling. If None, uses DEFAULT_POLL_TIMEOUT_SECS.
            initial_delay: Initial backoff interval in seconds (default 0.5s).
            max_interval: Maximum backoff interval in seconds (default 1s).
            multiplier: Backoff multiplier (default 1.4).
        
        Returns:
            Decoded result if return_type is provided, otherwise raw bytes.
        
        Raises:
            TimeoutWaitingForResponse: If polling times out.
            ReplicaReject: If the call is rejected.
        """
        # Use default timeout if not provided
        poll_timeout = timeout if timeout is not None else DEFAULT_POLL_TIMEOUT_SECS
        
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
            if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        if self.nonce_factory is not None:
            req["nonce"] = self.nonce_factory()
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        http_response: httpx.Response = self.call_endpoint(effective_id, signed_cbor)
        try:
            response_obj = cbor2.loads(http_response.content)
        except Exception:
            response_obj = None

        if not isinstance(response_obj, dict) or "status" not in response_obj:
            # The v4 /call endpoint may return a non-CBOR or incomplete response
            # when the canister takes too long for a synchronous reply.
            if http_response.status_code == 202:
                # Call was accepted but not yet complete; poll for result.
                return self.poll_and_wait(
                    effective_id,
                    request_id,
                    verify_certificate,
                    return_type=return_type,
                    timeout=poll_timeout,
                    initial_delay=initial_delay,
                    max_interval=max_interval,
                    multiplier=multiplier,
                )
            # Not 202 — the call was likely not accepted. Report the actual response.
            raise RuntimeError(
                f"v4 /call returned HTTP {http_response.status_code} "
                f"with non-CBOR body: {http_response.content[:200]!r}"
            )

        status = response_obj.get("status")

        if status == "replied":
            cbor_certificate = response_obj["certificate"]
            decoded_certificate = cbor2.loads(cbor_certificate)
            certificate = Certificate(decoded_certificate)

            if verify_certificate:
                certificate.assert_certificate_valid(effective_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            certified_status = certificate.lookup_request_status(request_id)
            if isinstance(certified_status, (bytes, bytearray, memoryview)):
                certified_status = bytes(certified_status).decode("utf-8", "replace")

            if certified_status == "replied":
                reply_data = certificate.lookup_reply(request_id)
                if reply_data is None:
                    raise RuntimeError(f"Certificate lookup failed: reply data not found for request {request_id.hex()}")
                return decode(reply_data, return_type)
            elif certified_status == "rejected":
                rejection = certificate.lookup_request_rejection(request_id)
                reject_code = rejection.get('reject_code')
                if isinstance(reject_code, bytes):
                    reject_code = int.from_bytes(reject_code, 'big')
                elif not isinstance(reject_code, int):
                    reject_code = 0
                reject_message = _safe_str(rejection.get('reject_message')) or "Unknown rejection"
                error_code = _safe_str(rejection.get('error_code'))
                raise ReplicaReject(reject_code, reject_message, error_code)
            else:
                # Not yet terminal in certification; continue polling
                return self.poll_and_wait(
                    effective_id,
                    request_id,
                    verify_certificate,
                    return_type=return_type,
                    timeout=poll_timeout,
                    initial_delay=initial_delay,
                    max_interval=max_interval,
                    multiplier=multiplier,
                )

        elif status == "accepted":
            # Not yet executed; start polling
            return self.poll_and_wait(
                effective_id,
                request_id,
                verify_certificate,
                return_type=return_type,
                timeout=poll_timeout,
                initial_delay=initial_delay,
                max_interval=max_interval,
                multiplier=multiplier,
            )

        elif status == "non_replicated_rejection":
            code = response_obj.get("reject_code", 0)
            if isinstance(code, bytes):
                code = int.from_bytes(code, 'big')
            elif not isinstance(code, int):
                code = 0
            message = _safe_str(response_obj.get("reject_message")) or "Unknown rejection"
            error = _safe_str(response_obj.get("error_code"))
            raise ReplicaReject(code, message, error)

        else:
            raise RuntimeError(f"Unknown status: {status}")

    async def update_raw_async(self, canister_id, method_name, arg, return_type=None,
                               effective_canister_id=None, verify_certificate: bool = True,
                               timeout: Optional[float] = None, **kwargs):
        """
        Send update call and poll for result asynchronously with timeout handling.
        
        Args:
            canister_id: The canister ID to call.
            method_name: The method name to call.
            arg: The argument bytes (DIDL-encoded).
            return_type: Optional return type for decoding.
            effective_canister_id: Optional effective canister ID.
            verify_certificate: Whether to verify certificate.
            timeout: Timeout in seconds for polling. If None, uses DEFAULT_POLL_TIMEOUT_SECS.
            **kwargs: Additional arguments passed to poll_async.
        
        Returns:
            Decoded result if return_type is provided, otherwise raw bytes.
        
        Raises:
            TimeoutWaitingForResponse: If polling times out.
            ReplicaReject: If the call is rejected.
        """
        # Use default timeout if not provided
        poll_timeout = timeout if timeout is not None else DEFAULT_POLL_TIMEOUT_SECS
        
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        if self.nonce_factory is not None:
            req["nonce"] = self.nonce_factory()
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        _ = await self.call_endpoint_async(effective_id, request_id, signed_cbor)

        # Merge timeout into kwargs if provided
        poll_kwargs = {**kwargs}
        if timeout is not None:
            poll_kwargs['timeout'] = poll_timeout
        
        status, result = await self.poll_async(
            effective_id, request_id, verify_certificate, **poll_kwargs
        )

        if status == "rejected":
            # result is a dict with rejection fields
            code = result.get("reject_code", 0)
            if isinstance(code, bytes):
                code = int.from_bytes(code, 'big')
            elif not isinstance(code, int):
                code = 0
            message = _safe_str(result.get("reject_message")) or "Unknown rejection"
            error = _safe_str(result.get("error_code"))
            raise ReplicaReject(code, message, error)

        elif status == "replied":
            # result is raw reply bytes
            if result[:4] == b"DIDL":
                return decode(result, return_type)
            return result

        else:
            raise RuntimeError("Timeout to poll result, current status: " + str(status))

    # ----------- Read state -----------

    def read_state_raw(self, canister_id, paths, effective_canister_id=None, verify_certificate: bool = True):
        # IC spec: read_state content map does NOT include canister_id.
        # The canister_id is only in the URL path for routing.
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        if self.nonce_factory is not None:
            req["nonce"] = self.nonce_factory()
        _, signed_cbor = sign_request(req, self.identity)
        
        # Determine effective ID for verification
        target = effective_canister_id if effective_canister_id else canister_id

        raw_bytes = self.read_state_endpoint(target, signed_cbor)

        if raw_bytes in (
            b"Invalid path requested.",
            b"Could not parse body as read request: invalid type: byte array, expected a sequence",
        ):
            raise ValueError(_safe_str(raw_bytes))

        try:
            decoded_obj = cbor2.loads(raw_bytes)
        except Exception:
            raise ValueError("Unable to decode cbor value: " + repr(raw_bytes))
        
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        certificate = Certificate(cert_dict)
        if verify_certificate:
            certificate.assert_certificate_valid(target)
            certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

        return certificate

    async def read_state_raw_async(self, canister_id, paths, effective_canister_id=None, verify_certificate: bool = True):
        # IC spec: read_state content map does NOT include canister_id.
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        if self.nonce_factory is not None:
            req["nonce"] = self.nonce_factory()
        _, signed_cbor = sign_request(req, self.identity)
        
        target = effective_canister_id if effective_canister_id else canister_id
        
        raw_bytes = await self.read_state_endpoint_async(target, signed_cbor)

        if raw_bytes in (
            b"Invalid path requested.",
            b"Could not parse body as read request: invalid type: byte array, expected a sequence",
        ):
            raise ValueError(_safe_str(raw_bytes))

        decoded_obj = cbor2.loads(raw_bytes)
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        certificate = Certificate(cert_dict)
        if verify_certificate:
            certificate.assert_certificate_valid(target)
            certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

        return certificate

    def read_state_subnet_raw(self, subnet_id, paths, verify_certificate: bool = True):
        """
        Read subnet state with certificate verification.
        This is for subnet-level queries and skips canister_ranges check.
        
        Args:
            subnet_id: Subnet ID string.
            paths: List of paths to read.
            verify_certificate: Whether to verify certificate (default: True).
                               Set to False to skip BLS verification (e.g., for query signature verification).
        """
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        
        raw_bytes = self.read_state_subnet_endpoint(subnet_id, signed_cbor)

        if raw_bytes in (
            b"Invalid path requested.",
            b"Could not parse body as read request: invalid type: byte array, expected a sequence",
        ):
            raise ValueError(_safe_str(raw_bytes))

        try:
            decoded_obj = cbor2.loads(raw_bytes)
        except Exception:
            raise ValueError("Unable to decode cbor value: " + repr(raw_bytes))
        
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        certificate = Certificate(cert_dict)
        
        if verify_certificate:
            # Skip canister_ranges check for subnet read_state
            certificate.assert_certificate_valid(subnet_id, skip_canister_range_check=True)
            certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

        return certificate

    async def read_state_subnet_raw_async(self, subnet_id, paths, verify_certificate: bool = True):
        """
        Read subnet state with certificate verification (async).
        This is for subnet-level queries and skips canister_ranges check.
        
        Args:
            subnet_id: Subnet ID string.
            paths: List of paths to read.
            verify_certificate: Whether to verify certificate (default: True).
                               Set to False to skip BLS verification (e.g., for query signature verification).
        """
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        
        raw_bytes = await self.read_state_subnet_endpoint_async(subnet_id, signed_cbor)

        if raw_bytes in (
            b"Invalid path requested.",
            b"Could not parse body as read request: invalid type: byte array, expected a sequence",
        ):
            raise ValueError(_safe_str(raw_bytes))

        decoded_obj = cbor2.loads(raw_bytes)
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        certificate = Certificate(cert_dict)
        
        if verify_certificate:
            # Skip canister_ranges check for subnet read_state
            certificate.assert_certificate_valid(subnet_id, skip_canister_range_check=True)
            certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)
        
        return certificate

    # ----------- Request status -----------

    def request_status_raw(self, canister_id, req_id, verify_certificate: bool = True):
        paths = [[b"request_status", req_id]]
        certificate = self.read_state_raw(canister_id, paths, verify_certificate=verify_certificate)
        
        status_bytes = certificate.lookup_request_status(req_id)
        if status_bytes is None:
            return status_bytes, certificate
        return status_bytes.decode(), certificate

    async def request_status_raw_async(self, canister_id, req_id, verify_certificate: bool = True):
        paths = [[b"request_status", req_id]]
        certificate = await self.read_state_raw_async(canister_id, paths, verify_certificate=verify_certificate)
        
        status_bytes = certificate.lookup_request_status(req_id)
        if status_bytes is None:
            return status_bytes, certificate
        return status_bytes.decode(), certificate

    # ----------- Polling helpers -----------

    def poll_and_wait(
        self,
        canister_id,
        req_id,
        verify_certificate,
        return_type=None,
        timeout: Optional[float] = None,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
    ):
        """
        Poll for update call result and decode if return_type is provided.
        
        Args:
            canister_id: The canister ID.
            req_id: The request ID.
            verify_certificate: Whether to verify certificate.
            return_type: Optional return type for decoding.
            timeout: Timeout in seconds. If None, uses DEFAULT_POLL_TIMEOUT_SECS.
            initial_delay: Initial backoff interval in seconds (default 0.5s).
            max_interval: Maximum backoff interval in seconds (default 1s).
            multiplier: Backoff multiplier (default 1.4).
        
        Returns:
            Decoded result if return_type is provided, otherwise raw bytes.
        
        Raises:
            TimeoutWaitingForResponse: If polling times out.
            ReplicaReject: If the call is rejected.
        """
        # Use default timeout if not provided
        poll_timeout = timeout if timeout is not None else DEFAULT_POLL_TIMEOUT_SECS
        status, result = self.poll(
            canister_id, req_id, verify_certificate,
            timeout=poll_timeout,
            initial_delay=initial_delay,
            max_interval=max_interval,
            multiplier=multiplier,
        )
        if status == "replied":
            return decode(result, return_type)
        elif status == "rejected":
            code = result.get("reject_code", 0)
            if isinstance(code, bytes):
                code = int.from_bytes(code, 'big')
            elif not isinstance(code, int):
                code = 0
            message = _safe_str(result.get("reject_message")) or "Unknown rejection"
            error = _safe_str(result.get("error_code"))
            raise ReplicaReject(code, message, error)
        else:
            raise RuntimeError(f"Unknown status: {status}")

    def poll(
        self,
        canister_id,
        req_id,
        verify_certificate,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
        timeout: float = DEFAULT_POLL_TIMEOUT_SECS,
    ):
        """
        Poll canister call status with exponential backoff (synchronous).

        Args:
            canister_id: target canister identifier (use effective canister id)
            req_id:      request ID bytes
            verify_certificate: whether to verify the certificate
            initial_delay: initial backoff interval in seconds (default 0.5s)
            max_interval:  maximum backoff interval in seconds (default 1s)
            multiplier:    backoff multiplier (default 1.4)
            timeout:       maximum total polling time in seconds

        Returns:
            Tuple(status_str, result_bytes_or_data)
        """
        start_monotonic = time.monotonic()
        backoff = initial_delay
        request_accepted = False

        while True:
            status_str, certificate = self.request_status_raw(canister_id, req_id, verify_certificate=verify_certificate)

            if status_str in ("replied", "done", "rejected"):
                break

            if status_str in ("received", "processing") and not request_accepted:
                backoff = initial_delay
                request_accepted = True

            if time.monotonic() - start_monotonic >= timeout:
                raise TimeoutWaitingForResponse(
                    f"Polling request {req_id.hex()} timed out after {timeout}s",
                    timeout_seconds=timeout,
                    request_id=req_id,
                )

            time.sleep(backoff)
            backoff = min(backoff * multiplier, max_interval)

        if status_str == "replied":
            reply_bytes = certificate.lookup_reply(req_id)
            if reply_bytes is None:
                raise RuntimeError(f"Certificate lookup failed: reply data not found for request {req_id.hex()}")
            return status_str, reply_bytes
        elif status_str == "rejected":
            rejection_obj = certificate.lookup_request_rejection(req_id)
            return status_str, rejection_obj
        elif status_str == "done":
            raise RuntimeError(f"Request {req_id.hex()} finished (Done) with no reply")
        else:
            raise RuntimeError(f"Unexpected final status in poll(): {status_str!r}")

    async def poll_async(
        self,
        canister_id,
        req_id,
        verify_certificate,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
        timeout: float = DEFAULT_POLL_TIMEOUT_SECS,
    ):
        """
        Poll canister call status with exponential backoff (asynchronous).
        Mirrors `poll` but uses async read_state.
        """
        start_monotonic = time.monotonic()
        backoff = initial_delay
        request_accepted = False

        while True:
            status_str, certificate = await self.request_status_raw_async(canister_id, req_id, verify_certificate=verify_certificate)

            if status_str in ("replied", "done", "rejected"):
                break

            if status_str in ("received", "processing") and not request_accepted:
                backoff = initial_delay
                request_accepted = True

            if time.monotonic() - start_monotonic >= timeout:
                raise TimeoutWaitingForResponse(
                    f"Polling request {req_id.hex()} timed out after {timeout}s",
                    timeout_seconds=timeout,
                    request_id=req_id,
                )

            await asyncio.sleep(backoff)
            backoff = min(backoff * multiplier, max_interval)

        if status_str == "replied":
            reply_bytes = certificate.lookup_reply(req_id)
            if reply_bytes is None:
                raise RuntimeError(f"Certificate lookup failed: reply data not found for request {req_id.hex()}")
            return status_str, reply_bytes
        elif status_str == "rejected":
            rejection_obj = certificate.lookup_request_rejection(req_id)
            return status_str, rejection_obj
        elif status_str == "done":
            raise RuntimeError(f"Request {req_id.hex()} finished (Done) with no reply")
        else:
            raise RuntimeError(f"Unexpected final status in poll_async(): {status_str!r}")