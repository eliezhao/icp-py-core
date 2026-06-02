"""
Tests for cbor2 6.x compatibility (issue #14).

Background
----------
cbor2 5.x decodes tagged maps to plain ``dict``.  cbor2 6.0.0+ (Rust core
rewrite) decodes them to an immutable ``FrozenDict`` instead.  The IC
boundary node wraps every CBOR response with the self-describe tag 55799,
so once a user upgrades to cbor2 6.x, every response body coming back to
``update_raw``/``query_raw``/etc. is a ``FrozenDict``.

The previous code used ``isinstance(obj, dict)`` to gate response parsing.
``FrozenDict`` is a ``collections.abc.Mapping`` but **not** a ``dict``, so
the check would fail and ``update_raw`` would raise "Malformed result"
even though the CBOR decoded just fine.

The fix replaces these checks with ``isinstance(obj, Mapping)``.  cbor2's
own ``FrozenDict`` class (available in both 5.7+ and 6.x) is used to
simulate the cbor2 6.x decode behavior without needing the 6.x release.
"""

from collections.abc import Mapping
from unittest.mock import patch, MagicMock

import cbor2
import httpx
import pytest

from icp_agent.agent import Agent
from icp_agent.client import Client
from icp_identity.identity import Identity

# cbor2 exposes the immutable tagged-map class as ``FrozenDict`` (5.7–5.x)
# and renamed it to ``frozendict`` in the 6.x Rust core. Resolve whichever
# this install provides so these tests exercise the real decode type.
FrozenDict = getattr(cbor2, "FrozenDict", None) or getattr(cbor2, "frozendict")

# Ed25519 test vector (RFC 8032); used only for tests, not a real secret.
TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"


@pytest.fixture
def agent():
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


# ---------------------------------------------------------------------------
# Sanity: FrozenDict has the contract we rely on
# ---------------------------------------------------------------------------

class TestFrozenDictContract:
    """Confirm cbor2.FrozenDict is a Mapping but not a dict."""

    def test_frozendict_is_mapping_not_dict(self):
        fd = FrozenDict({"status": "replied"})
        assert isinstance(fd, Mapping)
        # This is the exact mismatch that caused issue #14:
        assert not isinstance(fd, dict)

    def test_frozendict_supports_get_and_in(self):
        fd = FrozenDict({"status": "replied", "certificate": b"x"})
        assert fd["status"] == "replied"
        assert fd.get("status") == "replied"
        assert "status" in fd
        assert "missing" not in fd


# ---------------------------------------------------------------------------
# update_raw: must accept FrozenDict response (cbor2 6.x)
# ---------------------------------------------------------------------------

class TestUpdateRawAcceptsFrozenDict:
    """
    With cbor2 6.x, ``cbor2.loads`` returns a ``FrozenDict`` for the v4 /call
    response.  ``update_raw`` must treat that as a valid response and not
    raise "Malformed result".
    """

    def _make_response(self, status_code, body_obj):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = status_code
        resp.content = b"<encoded>"  # actual bytes ignored; we patch cbor2.loads
        return resp

    def test_replied_status_with_frozendict(self, agent):
        """status=replied wrapped in FrozenDict must not raise Malformed."""
        # Build the response body as a FrozenDict (what cbor2 6.x produces)
        response_obj = FrozenDict({
            "status": "replied",
            "certificate": b"<cert-bytes>",
        })
        mock_http_resp = self._make_response(200, response_obj)

        with patch.object(agent, "call_endpoint", return_value=mock_http_resp), \
             patch("icp_agent.agent.cbor2.loads", return_value=response_obj), \
             patch.object(agent, "poll_and_wait") as mock_poll, \
             patch("icp_agent.agent.Certificate") as MockCert:
            cert_instance = MockCert.return_value
            cert_instance.lookup_request_status.return_value = "replied"
            # Empty DIDL payload (no args, no values)
            cert_instance.lookup_reply.return_value = b"DIDL\x00\x00"

            # Must not raise "Malformed result"
            agent.update_raw(
                CANISTER_ID, "some_method", b"",
                verify_certificate=False,
            )

        # We took the synchronous "replied" path, not the polling fallback
        mock_poll.assert_not_called()

    def test_non_replicated_rejection_with_frozendict(self, agent):
        """status=non_replicated_rejection wrapped in FrozenDict must surface as ReplicaReject."""
        from icp_core.errors import ReplicaReject

        response_obj = FrozenDict({
            "status": "non_replicated_rejection",
            "reject_code": 3,
            "reject_message": "method not found",
            "error_code": "IC0302",
        })
        mock_http_resp = self._make_response(200, response_obj)

        with patch.object(agent, "call_endpoint", return_value=mock_http_resp), \
             patch("icp_agent.agent.cbor2.loads", return_value=response_obj):
            with pytest.raises(ReplicaReject) as exc_info:
                agent.update_raw(
                    CANISTER_ID, "some_method", b"",
                    verify_certificate=False,
                )

        # Rejection details must have been extracted from the FrozenDict
        assert exc_info.value.reject_code == 3
        assert "method not found" in str(exc_info.value)

    def test_accepted_status_with_frozendict_polls(self, agent):
        """status=accepted wrapped in FrozenDict must trigger polling."""
        response_obj = FrozenDict({"status": "accepted"})
        mock_http_resp = self._make_response(202, response_obj)

        with patch.object(agent, "call_endpoint", return_value=mock_http_resp), \
             patch("icp_agent.agent.cbor2.loads", return_value=response_obj), \
             patch.object(agent, "poll_and_wait", return_value=b"polled") as mock_poll:
            result = agent.update_raw(
                CANISTER_ID, "some_method", b"",
                verify_certificate=False,
            )

        mock_poll.assert_called_once()
        assert result == b"polled"


# ---------------------------------------------------------------------------
# query_raw: must accept FrozenDict response (cbor2 6.x)
# ---------------------------------------------------------------------------

class TestQueryRawAcceptsFrozenDict:
    """
    ``query_endpoint`` returns the result of ``cbor2.loads``, which is a
    FrozenDict under cbor2 6.x.  Both sync and async query paths must accept
    it.
    """

    def test_query_raw_replied_with_frozendict(self, agent):
        # Inner reply is itself a FrozenDict (nested tagged map under 6.x)
        reply_arg = b"DIDL\x00\x00"
        result_obj = FrozenDict({
            "status": "replied",
            "reply": FrozenDict({"arg": reply_arg}),
        })

        with patch.object(agent, "query_endpoint", return_value=result_obj):
            out = agent.query_raw(
                CANISTER_ID, "greet", b"",
                verify_query_signatures=False,
            )

        # An empty DIDL was passed through decode → empty tuple/list of values
        assert out == [] or out == ()

    def test_query_raw_rejected_with_frozendict(self, agent):
        from icp_core.errors import ReplicaReject

        result_obj = FrozenDict({
            "status": "rejected",
            "reject_code": 5,
            "reject_message": "canister trapped",
            "error_code": "IC0503",
        })

        with patch.object(agent, "query_endpoint", return_value=result_obj):
            with pytest.raises(ReplicaReject) as exc_info:
                agent.query_raw(
                    CANISTER_ID, "greet", b"",
                    verify_query_signatures=False,
                )

        assert exc_info.value.reject_code == 5
        assert "canister trapped" in str(exc_info.value)

    def test_query_raw_async_replied_with_frozendict(self, agent):
        """Async variant must also accept FrozenDict."""
        import asyncio

        reply_arg = b"DIDL\x00\x00"
        result_obj = FrozenDict({
            "status": "replied",
            "reply": FrozenDict({"arg": reply_arg}),
        })

        async def _fake_query_async(*args, **kwargs):
            return result_obj

        async def _run():
            with patch.object(agent, "query_endpoint_async", side_effect=_fake_query_async):
                return await agent.query_raw_async(
                    CANISTER_ID, "greet", b"",
                    verify_query_signatures=False,
                )

        out = asyncio.run(_run())
        assert out == [] or out == ()


# ---------------------------------------------------------------------------
# Regression: a plain dict response (cbor2 5.x) still works
# ---------------------------------------------------------------------------

class TestPlainDictStillWorks:
    """The fix must not break cbor2 5.x users — plain dict still works."""

    def test_update_raw_plain_dict_replied(self, agent):
        """A plain dict response (cbor2 5.x) must still take the replied path."""
        fake_cert_cbor = cbor2.dumps({"tree": [0]})
        response_obj = {
            "status": "replied",
            "certificate": fake_cert_cbor,
        }
        mock_http_resp = MagicMock(spec=httpx.Response)
        mock_http_resp.status_code = 200
        mock_http_resp.content = cbor2.dumps(response_obj)

        with patch.object(agent, "call_endpoint", return_value=mock_http_resp), \
             patch.object(agent, "poll_and_wait") as mock_poll, \
             patch("icp_agent.agent.Certificate") as MockCert:
            cert_instance = MockCert.return_value
            cert_instance.lookup_request_status.return_value = "replied"
            cert_instance.lookup_reply.return_value = b"DIDL\x00\x00"

            agent.update_raw(
                CANISTER_ID, "some_method", b"",
                verify_certificate=False,
            )

        mock_poll.assert_not_called()

    def test_update_raw_malformed_response_still_raises(self, agent):
        """Truly malformed (non-Mapping) responses must still raise."""
        mock_http_resp = MagicMock(spec=httpx.Response)
        mock_http_resp.status_code = 500
        # Encode a CBOR list — not a Mapping at all
        mock_http_resp.content = cbor2.dumps([1, 2, 3])

        with patch.object(agent, "call_endpoint", return_value=mock_http_resp):
            with pytest.raises(RuntimeError, match="non-CBOR body"):
                agent.update_raw(
                    CANISTER_ID, "some_method", b"",
                    verify_certificate=False,
                )
