# Copyright (c) 2021 Rocklabs
# Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
#
# Licensed under the MIT License
# See LICENSE file for details

"""
Error hierarchy for the ICP Agent.

This module defines a structured error hierarchy that strictly separates
transport, security, and protocol errors to prevent information leakage
and allow for granular error handling strategies.

The error hierarchy follows the design specified in the ICP Agent
Refactoring Plan Execution document.
"""

from __future__ import annotations

from typing import Optional


class ICError(Exception):
    """
    Base class for all Internet Computer Agent errors.
    
    Catching this exception ensures all agent-related failures are handled.
    All specific error types in this module inherit from ICError.
    """
    pass


class TransportError(ICError):
    """
    Raised when the HTTP transport layer fails.
    
    This includes connection timeouts, DNS failures, HTTP 4xx/5xx errors,
    and network connectivity issues. It wraps the original exception to
    preserve context for logging but sanitizes the message for the API consumer.
    
    Attributes:
        url: The URL that failed to connect.
        original_error: The original exception that caused the transport error.
    
    Example:
        >>> try:
        ...     client.query("canister-id", data)
        ... except TransportError as e:
        ...     print(f"Failed to connect to {e.url}: {e.original_error}")
    """
    
    def __init__(self, url: str, original_error: Exception):
        """
        Initialize TransportError.
        
        Args:
            url: The URL that failed to connect.
            original_error: The original exception (e.g., httpx.RequestError).
        """
        self.url = url
        self.original_error = original_error
        # Sanitize the string representation to avoid leaking complex internal stack traces
        error_msg = str(original_error)
        super().__init__(f"Transport error connecting to ICP Endpoint {url}: {error_msg}")
        # Set __cause__ for proper exception chaining
        self.__cause__ = original_error


class SecurityError(ICError):
    """
    Base class for cryptographic and verification failures.
    
    Any error of this type indicates a potential attack or a severe misconfiguration.
    Subclasses include signature verification failures, certificate validation errors,
    and path lookup failures.
    """
    pass


class SignatureVerificationFailed(SecurityError):
    """
    Raised when the BLS signature of a read_state certificate is invalid.
    
    This implies the boundary node returned data that does not match the
    subnet's signature, which could indicate:
    - A compromised boundary node
    - Network tampering
    - Invalid certificate data
    
    Example:
        >>> try:
        ...     certificate.verify_cert(canister_id)
        ... except SignatureVerificationFailed:
        ...     print("Certificate signature verification failed!")
    """
    
    def __init__(self, message: str = "BLS signature verification failed"):
        """
        Initialize SignatureVerificationFailed.
        
        Args:
            message: Optional detailed error message.
        """
        super().__init__(message)
        self.message = message


class LookupPathMissing(SecurityError):
    """
    Raised when the expected path (e.g., request status) is missing from
    the state tree despite a valid certificate.
    
    This defends against omission attacks where a node returns a valid
    certificate for a different part of the state tree to hide the actual result.
    
    Attributes:
        path: The path that was expected but not found.
        request_id: Optional request ID if this is related to a request status lookup.
    
    Example:
        >>> try:
        ...     status = certificate.lookup_request_status(request_id)
        ... except LookupPathMissing as e:
        ...     print(f"Path {e.path} not found in certificate")
    """
    
    def __init__(self, path: str, request_id: Optional[bytes] = None):
        """
        Initialize LookupPathMissing.
        
        Args:
            path: The path that was expected but not found.
            request_id: Optional request ID for context.
        """
        self.path = path
        self.request_id = request_id
        req_id_str = f" for request {request_id.hex()}" if request_id else ""
        super().__init__(f"Path '{path}' not found in certified tree{req_id_str}")


class PayloadEncodingError(ICError):
    """
    Raised when CBOR serialization/deserialization fails.
    
    This indicates malformed data from the network or invalid input arguments.
    It can occur during:
    - Request envelope encoding
    - Response certificate decoding
    - Candid data encoding/decoding
    
    Example:
        >>> try:
        ...     envelope = cbor2.dumps(request)
        ... except Exception as e:
        ...     raise PayloadEncodingError("Failed to encode request", e)
    """
    
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        """
        Initialize PayloadEncodingError.
        
        Args:
            message: Description of the encoding error.
            original_error: Optional original exception that caused the error.
        """
        self.original_error = original_error
        if original_error:
            super().__init__(f"{message}: {original_error}")
            # Set __cause__ for proper exception chaining
            self.__cause__ = original_error
        else:
            super().__init__(message)
        self.message = message


class ReplicaReject(ICError):
    """
    Raised when the Replica explicitly rejects a canister call.
    
    This is an application-layer error that maps strictly to the ICP
    Interface Spec reject codes. The rejection can occur for various
    reasons such as:
    - Insufficient cycles
    - Canister trap/panic
    - Invalid method arguments
    - Canister-specific business logic rejection
    
    Attributes:
        reject_code: The numeric reject code from the ICP spec.
        reject_message: Human-readable rejection message.
        error_code: Optional canister-specific error code.
    
    Example:
        >>> try:
        ...     result = agent.update("canister-id", "method", args)
        ... except ReplicaReject as e:
        ...     print(f"Rejected (code {e.reject_code}): {e.reject_message}")
    """
    
    def __init__(self, reject_code: int, reject_message: str, error_code: Optional[str] = None):
        """
        Initialize ReplicaReject.
        
        Args:
            reject_code: The numeric reject code (see ICP Interface Spec).
            reject_message: Human-readable rejection message.
            error_code: Optional canister-specific error code.
        """
        self.reject_code = reject_code
        self.reject_message = reject_message
        self.error_code = error_code
        # Format the error securely without exposing internal canister memory addresses
        error_code_str = f" [error_code={error_code}]" if error_code else ""
        super().__init__(f"Replica Reject (Code {reject_code}): {reject_message}{error_code_str}")


class IngressExpiryError(ICError):
    """
    Raised when the ingress expiry is invalid.
    
    This can occur when:
    - The ingress message has expired (time drift detected)
    - The ingress expiry timestamp is too far in the future
    - The local system clock is significantly skewed
    
    Attributes:
        ingress_expiry_ns: The ingress expiry timestamp in nanoseconds.
        current_time_ns: The current system time in nanoseconds.
        skew_ns: The time skew in nanoseconds.
    
    Example:
        >>> try:
        ...     agent.update("canister-id", "method", args)
        ... except IngressExpiryError as e:
        ...     print(f"Ingress expired: skew of {e.skew_ns / 1e9:.2f} seconds")
    """
    
    def __init__(
        self,
        message: str,
        ingress_expiry_ns: Optional[int] = None,
        current_time_ns: Optional[int] = None,
        skew_ns: Optional[int] = None
    ):
        """
        Initialize IngressExpiryError.
        
        Args:
            message: Error message describing the expiry issue.
            ingress_expiry_ns: Optional ingress expiry timestamp.
            current_time_ns: Optional current system time.
            skew_ns: Optional time skew in nanoseconds.
        """
        self.ingress_expiry_ns = ingress_expiry_ns
        self.current_time_ns = current_time_ns
        self.skew_ns = skew_ns
        super().__init__(message)


class CertificateVerificationError(SecurityError):
    """
    Raised when certificate verification fails.
    
    This is a more general error than SignatureVerificationFailed and can
    occur for various certificate-related issues:
    - Invalid certificate structure
    - Missing required fields
    - Certificate chain validation failure
    - Canister range authorization failure
    
    Attributes:
        reason: The specific reason for verification failure.
    
    Example:
        >>> try:
        ...     certificate.assert_certificate_valid(canister_id)
        ... except CertificateVerificationError as e:
        ...     print(f"Certificate verification failed: {e.reason}")
    """
    
    def __init__(self, reason: str):
        """
        Initialize CertificateVerificationError.
        
        Args:
            reason: The specific reason for verification failure.
        """
        self.reason = reason
        super().__init__(f"Certificate verification failed: {reason}")


class NodeKeyNotFoundError(SecurityError):
    """
    Raised when a node's public key cannot be found in the subnet state tree.
    
    This can occur when:
    - The node has been removed from the subnet
    - The subnet state is outdated
    - The node_id is invalid
    
    Attributes:
        node_id: The node ID that was not found.
        subnet_id: The subnet ID where the lookup was attempted.
    
    Example:
        >>> try:
        ...     pubkey = agent._get_node_public_key(subnet_id, node_id)
        ... except NodeKeyNotFoundError as e:
        ...     print(f"Node {e.node_id.hex()} not found in subnet {e.subnet_id.hex()}")
    """
    
    def __init__(self, node_id: bytes, subnet_id: bytes, message: Optional[str] = None):
        """
        Initialize NodeKeyNotFoundError.
        
        Args:
            node_id: The node ID that was not found.
            subnet_id: The subnet ID where the lookup was attempted.
            message: Optional custom error message.
        """
        self.node_id = node_id
        self.subnet_id = subnet_id
        if message:
            super().__init__(message)
        else:
            node_id_str = node_id.hex()[:16] + "..." if len(node_id) > 8 else node_id.hex()
            subnet_id_str = subnet_id.hex()[:16] + "..." if len(subnet_id) > 8 else subnet_id.hex()
            super().__init__(
                f"Node public key not found for node {node_id_str} in subnet {subnet_id_str}"
            )


class ReplicaSignatureVerificationFailed(SecurityError):
    """
    Raised when replica-signed query signature verification fails.
    
    This occurs when verifying the signature of a query response from
    a replica node. Failure can indicate:
    - The replica node is not authorized
    - The signature is invalid or tampered
    - The timestamp is outside the valid window
    
    Attributes:
        node_id: The node ID that signed the response.
        subnet_id: The subnet ID of the node.
        request_id: The request ID that was signed.
    
    Example:
        >>> try:
        ...     agent.query("canister-id", "method", args)
        ... except ReplicaSignatureVerificationFailed as e:
        ...     print(f"Replica signature verification failed for node {e.node_id.hex()}")
    """
    
    def __init__(
        self,
        node_id: bytes,
        subnet_id: bytes,
        request_id: bytes,
        message: Optional[str] = None
    ):
        """
        Initialize ReplicaSignatureVerificationFailed.
        
        Args:
            node_id: The node ID that signed the response.
            subnet_id: The subnet ID of the node.
            request_id: The request ID that was signed.
            message: Optional custom error message.
        """
        self.node_id = node_id
        self.subnet_id = subnet_id
        self.request_id = request_id
        if message:
            super().__init__(message)
        else:
            node_id_str = node_id.hex()[:16] + "..." if len(node_id) > 8 else node_id.hex()
            super().__init__(
                f"Replica signature verification failed for node {node_id_str} "
                f"on request {request_id.hex()[:16]}..."
            )
