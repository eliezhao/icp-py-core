"""
Unit tests for timeout feature.

- Agent query_endpoint / query_endpoint_async use DEFAULT_QUERY_TIMEOUT_SEC when timeout=None.
- Client timeout is passed through; TimeoutException is converted to TimeoutWaitingForResponse.
- TimeoutWaitingForResponse has timeout_seconds and optional request_id.
"""

import pytest
from unittest.mock import patch, MagicMock
import cbor2
import httpx
from httpx import TimeoutException

from icp_agent.agent import Agent, DEFAULT_QUERY_TIMEOUT_SEC, DEFAULT_POLL_TIMEOUT_SECS
from icp_agent.client import Client
from icp_core.errors import TimeoutWaitingForResponse
from icp_identity.identity import Identity

TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"


@pytest.fixture
def agent():
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


class TestTimeoutWaitingForResponse:
    """Test TimeoutWaitingForResponse error class."""

    def test_creation(self):
        """Test creating TimeoutWaitingForResponse with message, timeout_seconds, request_id."""
        err = TimeoutWaitingForResponse(
            "Query request timed out after 30s",
            timeout_seconds=30.0,
            request_id=None,
        )
        assert err.timeout_seconds == 30.0
        assert err.request_id is None
        assert "30" in str(err)

    def test_creation_with_request_id(self):
        """Test TimeoutWaitingForResponse with request_id."""
        req_id = b"\x01\x02\x03\x04"
        err = TimeoutWaitingForResponse(
            "Poll timed out",
            timeout_seconds=60.0,
            request_id=req_id,
        )
        assert err.timeout_seconds == 60.0
        assert err.request_id == req_id


class TestQueryEndpointTimeout:
    """Test that query_endpoint applies timeout and converts TimeoutException."""

    def test_query_endpoint_timeout_exception_raises_timeout_waiting(self, agent):
        """When client.query raises TimeoutException, query_endpoint raises TimeoutWaitingForResponse."""
        with patch.object(agent.client, "query") as mock_query:
            mock_query.side_effect = TimeoutException("timed out")
            with pytest.raises(TimeoutWaitingForResponse) as exc_info:
                agent.query_endpoint(CANISTER_ID, b"\x81\x00", timeout=5.0)
            err = exc_info.value
            assert err.timeout_seconds == 5.0
            assert err.request_id is None
            assert "5" in str(err)

    def test_query_endpoint_uses_default_timeout_when_none(self, agent):
        """When timeout=None, DEFAULT_QUERY_TIMEOUT_SEC is used and reflected in the raised error."""
        with patch.object(agent.client, "query") as mock_query:
            mock_query.side_effect = TimeoutException("timed out")
            with pytest.raises(TimeoutWaitingForResponse) as exc_info:
                agent.query_endpoint(CANISTER_ID, b"\x81\x00", timeout=None)
            err = exc_info.value
            assert err.timeout_seconds == DEFAULT_QUERY_TIMEOUT_SEC

    def test_query_endpoint_passes_timeout_to_client(self, agent):
        """query_endpoint passes the given timeout (or default) to client.query."""
        valid_cbor = cbor2.dumps({"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}})
        with patch.object(agent.client, "query") as mock_query:
            mock_query.return_value = valid_cbor
            agent.query_endpoint(CANISTER_ID, b"\x81\x00", timeout=10.0)
            call_kwargs = mock_query.call_args[1]
            assert call_kwargs["timeout"] is not None
            assert call_kwargs["timeout"].read == 10.0

    def test_query_endpoint_default_timeout_value_passed_to_client(self, agent):
        """When timeout=None, client.query receives Timeout(DEFAULT_QUERY_TIMEOUT_SEC)."""
        valid_cbor = cbor2.dumps({"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}})
        with patch.object(agent.client, "query") as mock_query:
            mock_query.return_value = valid_cbor
            agent.query_endpoint(CANISTER_ID, b"\x81\x00")
            call_kwargs = mock_query.call_args[1]
            assert call_kwargs["timeout"].read == DEFAULT_QUERY_TIMEOUT_SEC


class TestQueryEndpointAsyncTimeout:
    """Test that query_endpoint_async applies timeout and converts TimeoutException."""

    def test_query_endpoint_async_timeout_raises_timeout_waiting(self, agent):
        """When client.query_async raises TimeoutException, query_endpoint_async raises TimeoutWaitingForResponse."""
        import asyncio

        async def run():
            with patch.object(agent.client, "query_async") as mock_query:
                mock_query.side_effect = TimeoutException("timed out")
                with pytest.raises(TimeoutWaitingForResponse) as exc_info:
                    await agent.query_endpoint_async(CANISTER_ID, b"\x81\x00", timeout=2.0)
                err = exc_info.value
                assert err.timeout_seconds == 2.0

        asyncio.run(run())

    def test_query_endpoint_async_default_timeout_on_exception(self, agent):
        """When timeout=None and timeout occurs, error has DEFAULT_QUERY_TIMEOUT_SEC."""
        import asyncio

        async def run():
            with patch.object(agent.client, "query_async") as mock_query:
                mock_query.side_effect = TimeoutException("timed out")
                with pytest.raises(TimeoutWaitingForResponse) as exc_info:
                    await agent.query_endpoint_async(CANISTER_ID, b"\x81\x00")
                assert exc_info.value.timeout_seconds == DEFAULT_QUERY_TIMEOUT_SEC

        asyncio.run(run())


class TestDefaultTimeoutConstants:
    """Test that default timeout constants are defined and reasonable."""

    def test_default_query_timeout_defined(self):
        """DEFAULT_QUERY_TIMEOUT_SEC is 30 seconds."""
        assert DEFAULT_QUERY_TIMEOUT_SEC == 30.0

    def test_default_poll_timeout_defined(self):
        """DEFAULT_POLL_TIMEOUT_SECS is 60 seconds."""
        assert DEFAULT_POLL_TIMEOUT_SECS == 60.0
