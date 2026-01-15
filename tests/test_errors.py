"""
Test error handling hierarchy.

This module tests the structured error classes defined in icp_core.errors.
"""

import pytest
from unittest.mock import Mock, patch
import httpx

from icp_core.errors import (
    ICError,
    TransportError,
    SecurityError,
    SignatureVerificationFailed,
    CertificateVerificationError,
    LookupPathMissing,
    NodeKeyNotFoundError,
    ReplicaSignatureVerificationFailed,
    ReplicaReject,
    PayloadEncodingError,
    IngressExpiryError,
)
from icp_agent.client import Client


class TestErrorHierarchy:
    """Test that error classes form the correct hierarchy."""

    def test_ic_error_is_base(self):
        """Test that ICError is the base class."""
        assert issubclass(TransportError, ICError)
        assert issubclass(SecurityError, ICError)
        assert issubclass(ReplicaReject, ICError)
        assert issubclass(PayloadEncodingError, ICError)
        assert issubclass(IngressExpiryError, ICError)

    def test_security_error_hierarchy(self):
        """Test SecurityError subclasses."""
        assert issubclass(SignatureVerificationFailed, SecurityError)
        assert issubclass(CertificateVerificationError, SecurityError)
        assert issubclass(LookupPathMissing, SecurityError)
        assert issubclass(NodeKeyNotFoundError, SecurityError)
        assert issubclass(ReplicaSignatureVerificationFailed, SecurityError)

    def test_errors_are_exceptions(self):
        """Test that all errors inherit from Exception."""
        assert issubclass(ICError, Exception)
        assert issubclass(TransportError, Exception)
        assert issubclass(SecurityError, Exception)


class TestTransportError:
    """Test TransportError class."""

    def test_transport_error_creation(self):
        """Test creating a TransportError."""
        url = "https://ic0.app/api/v3/canister/test/query"
        original_error = httpx.RequestError("Connection failed")
        
        error = TransportError(url, original_error)
        
        assert error.url == url
        assert error.original_error == original_error
        assert str(error) is not None
        assert url in str(error)

    def test_transport_error_with_http_status_error(self):
        """Test TransportError with HTTPStatusError."""
        url = "https://ic0.app/api/v3/canister/test/query"
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        original_error = httpx.HTTPStatusError(
            "Server Error",
            request=Mock(),
            response=mock_response
        )
        
        error = TransportError(url, original_error)
        assert error.url == url
        assert error.original_error == original_error


class TestReplicaReject:
    """Test ReplicaReject class."""

    def test_replica_reject_creation(self):
        """Test creating a ReplicaReject."""
        reject_code = 3
        reject_message = "Canister trapped"
        error_code = "CANISTER_ERROR"
        
        error = ReplicaReject(reject_code, reject_message, error_code)
        
        assert error.reject_code == reject_code
        assert error.reject_message == reject_message
        assert error.error_code == error_code
        assert str(reject_code) in str(error)
        assert reject_message in str(error)

    def test_replica_reject_without_error_code(self):
        """Test ReplicaReject without error_code."""
        reject_code = 4
        reject_message = "Canister did not reply"
        
        error = ReplicaReject(reject_code, reject_message)
        
        assert error.reject_code == reject_code
        assert error.reject_message == reject_message
        assert error.error_code is None


class TestSecurityErrors:
    """Test security-related error classes."""

    def test_signature_verification_failed(self):
        """Test SignatureVerificationFailed."""
        error = SignatureVerificationFailed("BLS signature mismatch")
        assert isinstance(error, SecurityError)
        assert "BLS signature mismatch" in str(error)

    def test_certificate_verification_error(self):
        """Test CertificateVerificationError."""
        error = CertificateVerificationError("Invalid certificate structure")
        assert isinstance(error, SecurityError)
        assert error.reason == "Invalid certificate structure"
        assert "Invalid certificate structure" in str(error)

    def test_lookup_path_missing(self):
        """Test LookupPathMissing."""
        path = "/request_status/abc123/status"
        request_id = b"abc123"
        
        error = LookupPathMissing(path, request_id)
        
        assert isinstance(error, SecurityError)
        assert error.path == path
        assert error.request_id == request_id
        assert path in str(error)

    def test_lookup_path_missing_without_request_id(self):
        """Test LookupPathMissing without request_id."""
        path = "/time"
        error = LookupPathMissing(path)
        
        assert error.path == path
        assert error.request_id is None

    def test_node_key_not_found_error(self):
        """Test NodeKeyNotFoundError."""
        node_id = b"node123"
        subnet_id = b"subnet456"
        
        error = NodeKeyNotFoundError(node_id, subnet_id)
        
        assert isinstance(error, SecurityError)
        assert error.node_id == node_id
        assert error.subnet_id == subnet_id

    def test_replica_signature_verification_failed(self):
        """Test ReplicaSignatureVerificationFailed."""
        node_id = b"node123"
        subnet_id = b"subnet456"
        request_id = b"req789"
        
        error = ReplicaSignatureVerificationFailed(node_id, subnet_id, request_id)
        
        assert isinstance(error, SecurityError)
        assert error.node_id == node_id
        assert error.subnet_id == subnet_id
        assert error.request_id == request_id


class TestPayloadEncodingError:
    """Test PayloadEncodingError class."""

    def test_payload_encoding_error_with_message(self):
        """Test PayloadEncodingError with message only."""
        error = PayloadEncodingError("Failed to encode request")
        assert error.message == "Failed to encode request"
        assert error.original_error is None

    def test_payload_encoding_error_with_original_error(self):
        """Test PayloadEncodingError with original error."""
        original = ValueError("Invalid CBOR data")
        error = PayloadEncodingError("Encoding failed", original)
        
        assert error.message == "Encoding failed"
        assert error.original_error == original
        assert "Encoding failed" in str(error)
        assert "Invalid CBOR data" in str(error)


class TestIngressExpiryError:
    """Test IngressExpiryError class."""

    def test_ingress_expiry_error_creation(self):
        """Test creating IngressExpiryError."""
        message = "Ingress message expired"
        ingress_expiry_ns = 1000000000
        current_time_ns = 2000000000
        skew_ns = 1000000000
        
        error = IngressExpiryError(
            message,
            ingress_expiry_ns=ingress_expiry_ns,
            current_time_ns=current_time_ns,
            skew_ns=skew_ns
        )
        
        assert error.ingress_expiry_ns == ingress_expiry_ns
        assert error.current_time_ns == current_time_ns
        assert error.skew_ns == skew_ns
        assert message in str(error)


class TestClientErrorHandling:
    """Test that Client methods raise appropriate errors."""

    def test_client_query_raises_transport_error(self):
        """Test that client.query() raises TransportError on network failure."""
        client = Client()
        canister_id = "test-canister-id"
        data = b"test data"
        
        with patch('icp_agent.client.httpx.post') as mock_post:
            # Simulate network error
            mock_post.side_effect = httpx.RequestError("Connection failed")
            
            with pytest.raises(TransportError) as exc_info:
                client.query(canister_id, data)
            
            assert exc_info.value.url is not None
            assert exc_info.value.original_error is not None

    def test_client_call_raises_transport_error(self):
        """Test that client.call() raises TransportError on HTTP error."""
        client = Client()
        canister_id = "test-canister-id"
        data = b"test data"
        
        with patch('icp_agent.client.httpx.post') as mock_post:
            # Create a mock response that raises HTTPStatusError
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"
            http_error = httpx.HTTPStatusError(
                "Server Error",
                request=Mock(),
                response=mock_response
            )
            mock_response.raise_for_status = Mock(side_effect=http_error)
            
            mock_post.return_value = mock_response
            
            with pytest.raises(TransportError) as exc_info:
                client.call(canister_id, data)
            
            assert exc_info.value.url is not None
            assert exc_info.value.original_error == http_error

    @pytest.mark.skip(reason="Requires pytest-asyncio plugin for async test support")
    async def test_client_query_async_raises_transport_error(self):
        """Test that client.query_async() raises TransportError."""
        # This test requires pytest-asyncio plugin
        # Skipped for now as it's not critical for core functionality
        client = Client()
        canister_id = "test-canister-id"
        data = b"test data"
        
        with patch('icp_agent.client.httpx.AsyncClient') as mock_client_class:
            mock_client = Mock()
            mock_client.__aenter__ = Mock(return_value=mock_client)
            mock_client.__aexit__ = Mock(return_value=None)
            mock_client.post = Mock(side_effect=httpx.RequestError("Connection failed"))
            mock_client_class.return_value = mock_client
            
            with pytest.raises(TransportError):
                await client.query_async(canister_id, data)


class TestErrorChaining:
    """Test error chaining and exception context."""

    def test_transport_error_preserves_original(self):
        """Test that TransportError preserves original exception."""
        url = "https://ic0.app/test"
        original = httpx.RequestError("Network error")
        
        error = TransportError(url, original)
        
        # Check that original error is preserved
        assert error.original_error == original
        # Check that __cause__ is set (exception chaining)
        assert error.__cause__ == original

    def test_payload_encoding_error_chains(self):
        """Test that PayloadEncodingError chains original exception."""
        original = ValueError("Invalid data")
        error = PayloadEncodingError("Encoding failed", original)
        
        assert error.original_error == original
        assert error.__cause__ == original


class TestErrorMessages:
    """Test that error messages are informative but don't leak sensitive info."""

    def test_transport_error_message_sanitized(self):
        """Test that TransportError messages don't leak stack traces."""
        url = "https://ic0.app/test"
        original = httpx.RequestError("Connection failed")
        
        error = TransportError(url, original)
        message = str(error)
        
        # Should contain URL and error message, but not full stack trace
        assert url in message
        assert "Connection failed" in message
        # Should not contain Python traceback markers
        assert "Traceback" not in message
        assert "File" not in message

    def test_replica_reject_message_format(self):
        """Test that ReplicaReject messages are properly formatted."""
        error = ReplicaReject(3, "Canister trapped", "CANISTER_ERROR")
        message = str(error)
        
        assert "3" in message  # reject_code
        assert "Canister trapped" in message
        assert "CANISTER_ERROR" in message
        # Should not contain internal memory addresses
        assert "0x" not in message.lower() or "0x" in "error_code"  # Only in error_code field name
