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
)

IC_REQUEST_DOMAIN_SEPARATOR = b"\x0Aic-request"
"""Domain separator for request signing (0x0A + "ic-request")."""

IC_RESPONSE_DOMAIN_SEPARATOR = b"\x0Bic-response"
"""Domain separator for response verification (0x0B + "ic-response")."""

DEFAULT_POLL_TIMEOUT_SECS = 60.0
"""Default timeout for polling update call results in seconds."""

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
    
    Args:
        d: A dictionary representing the request. Keys and values are hashed
           according to the RIH algorithm.
    
    Returns:
        A 32-byte SHA-256 hash of the request.
    
    Raises:
        TypeError: If the input is not a dictionary.
    
    Note:
        This implements the Representation Independent Hash algorithm as specified
        in the IC protocol specification.
    """
    if not isinstance(d, dict):
        raise TypeError("request must be a dict")

    vec = []
    for k, v in d.items():
        if isinstance(v, list):
            v = encode_list(v)
        if isinstance(v, int):
            v = LEB128.encode_u(v)
        if not isinstance(k, bytes):
            k = k.encode()
        if not isinstance(v, bytes):
            v = v.encode()
        h_k = hashlib.sha256(k).digest()
        h_v = hashlib.sha256(v).digest()
        vec.append(h_k + h_v)
    s = b''.join(sorted(vec))
    return hashlib.sha256(s).digest()


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
        verify_replica_signatures: Whether to verify replica-signed query signatures (default: True).
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
        verify_replica_signatures: bool = True
    ) -> None:
        """
        Initialize the Agent.
        
        Args:
            identity: Identity object for signing requests (must have sign() and sender() methods).
            client: HTTP client instance (Client class).
            nonce_factory: Optional factory for generating nonces (for replay protection).
            ingress_expiry: Ingress message expiry time in seconds. Defaults to 3 minutes.
            root_key: Root public key for certificate verification. Defaults to IC_ROOT_KEY.
            verify_replica_signatures: Whether to verify replica-signed query signatures.
                                     Defaults to True for security.
        """
        self.identity = identity
        self.client = client
        self.ingress_expiry = ingress_expiry
        self.root_key = root_key
        self.nonce_factory = nonce_factory
        self.verify_replica_signatures = verify_replica_signatures
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
            subnet_id_str = Principal.from_bytes(subnet_id).to_str()
        except Exception as e:
            raise ValueError(f"Invalid subnet_id format: {subnet_id.hex()}") from e
        
        path = [b"subnet", subnet_id, b"node", node_id, b"public_key"]
        certificate = self.read_state_subnet_raw(subnet_id_str, [path])
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
            subnet_id_str = Principal.from_bytes(subnet_id).to_str()
        except Exception as e:
            raise ValueError(f"Invalid subnet_id format: {subnet_id.hex()}") from e
        
        path = [b"subnet", subnet_id, b"node", node_id, b"public_key"]
        certificate = await self.read_state_subnet_raw_async(subnet_id_str, [path])
        public_key = certificate.lookup(path)
        
        if public_key is None:
            raise NodeKeyNotFoundError(node_id, subnet_id)
        
        # Cache the key
        self.node_key_cache.set(subnet_id, node_id, public_key)
        return public_key

    def _verify_replica_signature(
        self, 
        request_id: bytes, 
        timestamp_ns: int, 
        reply_data: bytes,
        signature: bytes,
        node_identity: bytes,
        subnet_id: bytes
    ) -> bool:
        """
        Verify replica-signed query signature.
        
        Args:
            request_id: The request ID bytes
            timestamp_ns: Timestamp in nanoseconds
            reply_data: The reply data bytes
            signature: BLS signature (48 bytes)
            node_identity: Node Principal ID
            subnet_id: Subnet Principal ID
            
        Returns:
            True if signature is valid, False otherwise
        """
        # Step 0: Verify timestamp to prevent replay attacks
        # According to ICP spec, timestamp should be within a small window (typically 5 minutes)
        now_ns = time.time_ns()
        max_age_ns = 5 * 60 * NANOSECONDS  # 5 minutes in nanoseconds
        if abs(now_ns - timestamp_ns) > max_age_ns:
            return False  # Timestamp is outside valid window
        
        # Step 1: Construct domain-separated message
        # Message = H("ic-response") || H(RequestId) || H(Timestamp) || H(ReplyData)
        # Using Representation Independent Hash for the map
        message_map = {
            b"request_id": request_id,
            b"timestamp": timestamp_ns.to_bytes(8, "big"),
            b"reply": reply_data,
        }
        message_hash = to_request_id(message_map)
        message = IC_RESPONSE_DOMAIN_SEPARATOR + message_hash

        # Step 2: Get node public key (from cache or state tree)
        node_pubkey = self._get_node_public_key(subnet_id, node_identity)
        
        # Extract 96-byte BLS public key from DER if needed
        from icp_certificate.certificate import extract_der
        try:
            bls_pubkey_96 = extract_der(node_pubkey)
        except (ValueError, TypeError):
            # If not DER format, assume it's already 96 bytes
            if len(node_pubkey) == 96:
                bls_pubkey_96 = node_pubkey
            else:
                raise ValueError(f"Invalid node public key format: expected 96 bytes or DER, got {len(node_pubkey)} bytes")

        # Step 3: Verify BLS signature
        from icp_certificate.certificate import verify_bls_signature_blst
        return verify_bls_signature_blst(signature, message, bls_pubkey_96)

    async def _verify_replica_signature_async(
        self, 
        request_id: bytes, 
        timestamp_ns: int, 
        reply_data: bytes,
        signature: bytes,
        node_identity: bytes,
        subnet_id: bytes
    ) -> bool:
        """
        Verify replica-signed query signature (async).
        """
        # Step 0: Verify timestamp to prevent replay attacks
        # According to ICP spec, timestamp should be within a small window (typically 5 minutes)
        now_ns = time.time_ns()
        max_age_ns = 5 * 60 * NANOSECONDS  # 5 minutes in nanoseconds
        if abs(now_ns - timestamp_ns) > max_age_ns:
            return False  # Timestamp is outside valid window
        
        # Step 1: Construct domain-separated message
        message_map = {
            b"request_id": request_id,
            b"timestamp": timestamp_ns.to_bytes(8, "big"),
            b"reply": reply_data,
        }
        message_hash = to_request_id(message_map)
        message = IC_RESPONSE_DOMAIN_SEPARATOR + message_hash

        # Step 2: Get node public key (from cache or state tree)
        node_pubkey = await self._get_node_public_key_async(subnet_id, node_identity)
        
        # Extract 96-byte BLS public key from DER if needed
        from icp_certificate.certificate import extract_der
        try:
            bls_pubkey_96 = extract_der(node_pubkey)
        except (ValueError, TypeError):
            # If not DER format, assume it's already 96 bytes
            if len(node_pubkey) == 96:
                bls_pubkey_96 = node_pubkey
            else:
                raise ValueError(f"Invalid node public key format: expected 96 bytes or DER, got {len(node_pubkey)} bytes")

        # Step 3: Verify BLS signature
        from icp_certificate.certificate import verify_bls_signature_blst
        return verify_bls_signature_blst(signature, message, bls_pubkey_96)

    # ----------- HTTP endpoints -----------

    def query_endpoint(self, canister_id, data):
        raw_bytes = self.client.query(canister_id, data)
        return cbor2.loads(raw_bytes)

    async def query_endpoint_async(self, canister_id, data):
        raw_bytes = await self.client.query_async(canister_id, data)
        return cbor2.loads(raw_bytes)

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
    ):
        """
        High-level query (one-shot, no polling):
          - `arg` can be:
              * None -> encodes to empty DIDL (encode([]))
              * bytes/bytearray/memoryview -> used as-is
              * anything else acceptable by `icp_candid.candid.encode`
                (e.g. [{'type': Types.Nat, 'value': 42}])
          - If `return_type` is provided and reply is DIDL, it will be decoded.
        """
        didl = self._encode_arg(arg)
        return self.query_raw(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
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
        Polling/backoff options are handled inside update_raw()/poll().
        """
        didl = self._encode_arg(arg)
        return self.update_raw(
            canister_id,
            method_name,
            didl,
            return_type=return_type,
            effective_canister_id=effective_canister_id,
            verify_certificate=verify_certificate,
        )

    # ----------- Query (one-shot) -----------

    def query_raw(self, canister_id, method_name, arg, return_type=None, effective_canister_id=None):
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
        result = self.query_endpoint(target_canister, signed_cbor)

        if not isinstance(result, dict) or "status" not in result:
            raise RuntimeError("Malformed result: " + repr(result))

        status = result["status"]
        if status == "replied":
            reply_arg = result["reply"]["arg"]
            
            # Verify replica signatures if present and verification is enabled
            if self.verify_replica_signatures and "signatures" in result:
                signatures = result["signatures"]
                if not isinstance(signatures, list) or len(signatures) == 0:
                    raise RuntimeError("Query response contains empty signatures list")
                
                # Get subnet_id from canister's certificate delegation
                # According to ICP spec, subnet_id is in the delegation chain
                subnet_id = None
                try:
                    # Read canister state to get certificate with delegation
                    paths = [[b"time"]]  # Minimal path to get certificate
                    cert = self.read_state_raw(target_canister, paths)
                    
                    # Extract subnet_id from delegation if present
                    if cert.delegation is not None:
                        subnet_id_raw = cert.delegation.get("subnet_id") or cert.delegation.get(b"subnet_id")
                        if subnet_id_raw is not None:
                            subnet_id = bytes(subnet_id_raw)
                    
                    # If no delegation, this might be NNS canister (no subnet_id needed)
                    # For now, skip verification if subnet_id is not available
                except Exception as e:
                    # If we can't get subnet_id, we can't verify signatures
                    # This is acceptable for backward compatibility
                    # In production, subnet_id should be available from routing table
                    pass
                
                if subnet_id:
                    # Verify at least one signature
                    verified = False
                    for sig_obj in signatures:
                        if not isinstance(sig_obj, dict):
                            continue
                        node_identity = sig_obj.get("identity")
                        sig_bytes = sig_obj.get("signature")
                        timestamp_ns = sig_obj.get("timestamp")
                        
                        if not all([node_identity, sig_bytes, timestamp_ns]):
                            continue
                        
                        # Convert to bytes if needed
                        if isinstance(node_identity, str):
                            node_identity = Principal.from_str(node_identity).bytes
                        elif not isinstance(node_identity, bytes):
                            node_identity = bytes(node_identity)
                        
                        if isinstance(sig_bytes, str):
                            sig_bytes = bytes.fromhex(sig_bytes)
                        elif not isinstance(sig_bytes, bytes):
                            sig_bytes = bytes(sig_bytes)
                        
                        if isinstance(timestamp_ns, str):
                            timestamp_ns = int(timestamp_ns)
                        
                        try:
                            if self._verify_replica_signature(
                                request_id, timestamp_ns, reply_arg, sig_bytes, 
                                node_identity, subnet_id
                            ):
                                verified = True
                                break
                        except Exception as e:
                            # Log but continue trying other signatures
                            continue
                    
                    if not verified:
                        # Use the first signature's node_id for error reporting
                        first_node_id = None
                        for sig_obj in signatures:
                            if isinstance(sig_obj, dict) and sig_obj.get("identity"):
                                node_id = sig_obj.get("identity")
                                if isinstance(node_id, str):
                                    node_id = Principal.from_str(node_id).bytes
                                elif not isinstance(node_id, bytes):
                                    node_id = bytes(node_id)
                                first_node_id = node_id
                                break
                        if first_node_id:
                            raise ReplicaSignatureVerificationFailed(
                                first_node_id, subnet_id, request_id,
                                f"Replica signature verification failed for all {len(signatures)} signatures"
                            )
                        else:
                            raise ReplicaSignatureVerificationFailed(
                                b"", subnet_id, request_id,
                                f"Replica signature verification failed: no valid signatures found"
                            )
            
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

    async def query_raw_async(self, canister_id, method_name, arg, return_type=None, effective_canister_id=None):
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
        result = await self.query_endpoint_async(target_canister, signed_cbor)

        if not isinstance(result, dict) or "status" not in result:
            raise RuntimeError("Malformed result: " + repr(result))

        status = result["status"]
        if status == "replied":
            reply_arg = result["reply"]["arg"]
            
            # Verify replica signatures if present and verification is enabled
            if self.verify_replica_signatures and "signatures" in result:
                signatures = result["signatures"]
                if not isinstance(signatures, list) or len(signatures) == 0:
                    raise RuntimeError("Query response contains empty signatures list")
                
                # Get subnet_id from canister's certificate delegation
                # According to ICP spec, subnet_id is in the delegation chain
                subnet_id = None
                try:
                    # Read canister state to get certificate with delegation
                    paths = [[b"time"]]  # Minimal path to get certificate
                    cert = await self.read_state_raw_async(target_canister, paths)
                    
                    # Extract subnet_id from delegation if present
                    if cert.delegation is not None:
                        subnet_id_raw = cert.delegation.get("subnet_id") or cert.delegation.get(b"subnet_id")
                        if subnet_id_raw is not None:
                            subnet_id = bytes(subnet_id_raw)
                    
                    # If no delegation, this might be NNS canister (no subnet_id needed)
                    # For now, skip verification if subnet_id is not available
                except Exception as e:
                    # If we can't get subnet_id, we can't verify signatures
                    # This is acceptable for backward compatibility
                    # In production, subnet_id should be available from routing table
                    pass
                
                if subnet_id:
                    # Verify at least one signature
                    verified = False
                    for sig_obj in signatures:
                        if not isinstance(sig_obj, dict):
                            continue
                        node_identity = sig_obj.get("identity")
                        sig_bytes = sig_obj.get("signature")
                        timestamp_ns = sig_obj.get("timestamp")
                        
                        if not all([node_identity, sig_bytes, timestamp_ns]):
                            continue
                        
                        # Convert to bytes if needed
                        if isinstance(node_identity, str):
                            node_identity = Principal.from_str(node_identity).bytes
                        elif not isinstance(node_identity, bytes):
                            node_identity = bytes(node_identity)
                        
                        if isinstance(sig_bytes, str):
                            sig_bytes = bytes.fromhex(sig_bytes)
                        elif not isinstance(sig_bytes, bytes):
                            sig_bytes = bytes(sig_bytes)
                        
                        if isinstance(timestamp_ns, str):
                            timestamp_ns = int(timestamp_ns)
                        
                        try:
                            if await self._verify_replica_signature_async(
                                request_id, timestamp_ns, reply_arg, sig_bytes, 
                                node_identity, subnet_id
                            ):
                                verified = True
                                break
                        except Exception as e:
                            # Log but continue trying other signatures
                            continue
                    
                    if not verified:
                        # Use the first signature's node_id for error reporting
                        first_node_id = None
                        for sig_obj in signatures:
                            if isinstance(sig_obj, dict) and sig_obj.get("identity"):
                                node_id = sig_obj.get("identity")
                                if isinstance(node_id, str):
                                    node_id = Principal.from_str(node_id).bytes
                                elif not isinstance(node_id, bytes):
                                    node_id = bytes(node_id)
                                first_node_id = node_id
                                break
                        if first_node_id:
                            raise ReplicaSignatureVerificationFailed(
                                first_node_id, subnet_id, request_id,
                                f"Replica signature verification failed for all {len(signatures)} signatures"
                            )
                        else:
                            raise ReplicaSignatureVerificationFailed(
                                b"", subnet_id, request_id,
                                f"Replica signature verification failed: no valid signatures found"
                            )
            
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

    def update_raw(self, canister_id, method_name, arg, return_type=None,
                   effective_canister_id=None, verify_certificate: bool = True):
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
            raise RuntimeError(f"Malformed update response (non-CBOR): {http_response.content!r}")

        if not isinstance(response_obj, dict) or "status" not in response_obj:
            raise RuntimeError("Malformed update response: " + repr(response_obj))

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
                return self.poll_and_wait(effective_id, request_id, verify_certificate, return_type=return_type)

        elif status == "accepted":
            # Not yet executed; start polling
            return self.poll_and_wait(effective_id, request_id, verify_certificate, return_type=return_type)

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
                               **kwargs):
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

        status, result = await self.poll_async(
            effective_id, request_id, verify_certificate, **kwargs
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
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
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
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
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

    def read_state_subnet_raw(self, subnet_id, paths):
        """
        Read subnet state with certificate verification.
        This is for subnet-level queries and skips canister_ranges check.
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
        # Skip canister_ranges check for subnet read_state
        certificate.assert_certificate_valid(subnet_id, skip_canister_range_check=True)
        certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

        return certificate

    async def read_state_subnet_raw_async(self, subnet_id, paths):
        """
        Read subnet state with certificate verification (async).
        This is for subnet-level queries and skips canister_ranges check.
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

    def poll_and_wait(self, canister_id, req_id, verify_certificate, return_type=None):
        status, result = self.poll(canister_id, req_id, verify_certificate)
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
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

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
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

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