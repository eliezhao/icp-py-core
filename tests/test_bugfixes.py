"""
Unit tests for three bugfixes:

1. read_state_raw must NOT include canister_id in the signed content map.
   (IC spec: canister_id is only in the URL path for routing.)

2. update_raw must fall back to poll_and_wait when the v4 /call endpoint
   returns HTTP 202 with a non-CBOR body (canister took too long for
   synchronous reply).

3. Canister wrapper must pass through the `timeout` kwarg to Agent methods.
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
import cbor2
import httpx

from icp_agent.agent import Agent, sign_request
from icp_agent.client import Client
from icp_identity.identity import Identity

# Ed25519 test vector (RFC 8032); used only for tests, not a real secret.
TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"


@pytest.fixture
def agent():
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


# ---------------------------------------------------------------------------
# Fix 1: read_state_raw must NOT include canister_id in signed content
# ---------------------------------------------------------------------------

class TestReadStateNoCanisterId:
    """
    The IC spec says the read_state request content map contains:
        request_type, sender, paths, ingress_expiry
    It does NOT include canister_id.  Including it changes the
    representation-independent hash, causing signature verification
    failures on the boundary node (especially with secp256k1 identities).
    """

    def test_read_state_request_has_no_canister_id(self, agent):
        """Verify the request dict built by read_state_raw omits canister_id."""
        captured_req = {}

        original_sign = sign_request

        def spy_sign_request(req, iden):
            captured_req.update(req)
            return original_sign(req, iden)

        # Mock read_state_endpoint to avoid network call, and spy on sign_request
        with patch.object(agent, 'read_state_endpoint', return_value=b'') as mock_ep, \
             patch('icp_agent.agent.sign_request', side_effect=spy_sign_request):
            # read_state_raw will fail when trying to cbor2.loads(b''), but
            # we only care about the request dict passed to sign_request.
            try:
                agent.read_state_raw(CANISTER_ID, [[b"time"]])
            except Exception:
                pass  # Expected — we didn't return valid CBOR

        assert "canister_id" not in captured_req, \
            "read_state_raw must NOT include canister_id in the signed content map"
        assert captured_req["request_type"] == "read_state"
        assert "sender" in captured_req
        assert "paths" in captured_req
        assert "ingress_expiry" in captured_req


# ---------------------------------------------------------------------------
# Fix 2: update_raw falls back to poll_and_wait on non-CBOR 202
# ---------------------------------------------------------------------------

class TestUpdateRawV4Fallback:
    """
    The v4 /call endpoint returns a synchronous CBOR response if the canister
    replies within ~10s.  If the canister takes longer, the boundary node
    returns HTTP 202 with a non-CBOR body (e.g. plain text request_id).
    update_raw must detect this and fall back to poll_and_wait.
    """

    def test_non_cbor_202_triggers_polling(self, agent):
        """HTTP 202 with non-CBOR body must trigger poll_and_wait."""
        mock_http_resp = MagicMock(spec=httpx.Response)
        mock_http_resp.status_code = 202
        mock_http_resp.content = b"not-cbor-data"

        with patch.object(agent, 'call_endpoint', return_value=mock_http_resp), \
             patch.object(agent, 'poll_and_wait', return_value=b"poll_result") as mock_poll:
            result = agent.update_raw(
                CANISTER_ID, "some_method", b"",
                verify_certificate=False,
            )

        mock_poll.assert_called_once()
        assert result == b"poll_result"

    def test_non_cbor_non_202_raises(self, agent):
        """HTTP 500 with non-CBOR body must raise RuntimeError (not poll)."""
        mock_http_resp = MagicMock(spec=httpx.Response)
        mock_http_resp.status_code = 500
        mock_http_resp.content = b"Internal Server Error"

        with patch.object(agent, 'call_endpoint', return_value=mock_http_resp), \
             patch.object(agent, 'poll_and_wait') as mock_poll:
            with pytest.raises(RuntimeError, match="non-CBOR body"):
                agent.update_raw(
                    CANISTER_ID, "some_method", b"",
                    verify_certificate=False,
                )

        mock_poll.assert_not_called()

    def test_valid_cbor_replied_does_not_poll(self, agent):
        """Valid CBOR 'replied' response must be handled directly, not polled."""
        # Build a minimal CBOR response with status=replied and a certificate
        # We'll mock the Certificate to avoid needing real crypto
        fake_cert_cbor = cbor2.dumps({"tree": [0]})
        response_obj = {
            "status": "replied",
            "certificate": fake_cert_cbor,
        }
        mock_http_resp = MagicMock(spec=httpx.Response)
        mock_http_resp.status_code = 200
        mock_http_resp.content = cbor2.dumps(response_obj)

        with patch.object(agent, 'call_endpoint', return_value=mock_http_resp), \
             patch.object(agent, 'poll_and_wait') as mock_poll, \
             patch('icp_agent.agent.Certificate') as MockCert:
            # Set up the mock certificate
            cert_instance = MockCert.return_value
            cert_instance.lookup_request_status.return_value = "replied"
            cert_instance.lookup_reply.return_value = b"\x44\x49\x44\x4c\x00\x00"  # DIDL empty

            result = agent.update_raw(
                CANISTER_ID, "some_method", b"",
                verify_certificate=False,
            )

        mock_poll.assert_not_called()


# ---------------------------------------------------------------------------
# Fix 3: Canister wrapper passes timeout through to Agent methods
# ---------------------------------------------------------------------------

class TestCanisterTimeoutPassthrough:
    """
    The Canister wrapper's _create_method extracts `timeout` from kwargs
    and passes it to agent.query() or agent.update().  Previously, timeout
    was silently dropped.
    """

    def test_query_method_passes_timeout(self):
        """timeout kwarg must be forwarded to agent.query()."""
        from icp_canister.canister import Canister

        mock_agent = MagicMock()
        mock_agent.query.return_value = [42]

        # Create a minimal FuncClass-like object
        func = MagicMock()
        func.argTypes = []
        func.retTypes = []
        func.annotations = ["query"]

        canister = Canister.__new__(Canister)
        canister.agent = mock_agent
        canister.canister_id = CANISTER_ID
        canister.methods = {}
        canister.actor = None
        canister.init_args = []

        # Use the internal method to create a bound method
        method = canister._create_method("greet", func)
        method(timeout=120)

        # Verify timeout was passed through
        mock_agent.query.assert_called_once()
        call_kwargs = mock_agent.query.call_args[1]
        assert call_kwargs.get("timeout") == 120

    def test_update_method_passes_timeout(self):
        """timeout kwarg must be forwarded to agent.update()."""
        from icp_canister.canister import Canister

        mock_agent = MagicMock()
        mock_agent.update.return_value = [0]

        func = MagicMock()
        func.argTypes = []
        func.retTypes = []
        func.annotations = []  # no 'query' → update call

        canister = Canister.__new__(Canister)
        canister.agent = mock_agent
        canister.canister_id = CANISTER_ID
        canister.methods = {}
        canister.actor = None
        canister.init_args = []

        method = canister._create_method("do_something", func)
        method(timeout=300)

        mock_agent.update.assert_called_once()
        call_kwargs = mock_agent.update.call_args[1]
        assert call_kwargs.get("timeout") == 300

    def test_no_timeout_kwarg_omits_timeout(self):
        """When timeout is not passed, it must NOT appear in agent call kwargs."""
        from icp_canister.canister import Canister

        mock_agent = MagicMock()
        mock_agent.query.return_value = [42]

        func = MagicMock()
        func.argTypes = []
        func.retTypes = []
        func.annotations = ["query"]

        canister = Canister.__new__(Canister)
        canister.agent = mock_agent
        canister.canister_id = CANISTER_ID
        canister.methods = {}
        canister.actor = None
        canister.init_args = []

        method = canister._create_method("greet", func)
        method()

        mock_agent.query.assert_called_once()
        call_kwargs = mock_agent.query.call_args[1]
        assert "timeout" not in call_kwargs, \
            "timeout must be omitted when not explicitly provided"

    def test_verify_certificate_still_works(self):
        """verify_certificate kwarg must still be forwarded to agent.update()."""
        from icp_canister.canister import Canister

        mock_agent = MagicMock()
        mock_agent.update.return_value = [0]

        func = MagicMock()
        func.argTypes = []
        func.retTypes = []
        func.annotations = []

        canister = Canister.__new__(Canister)
        canister.agent = mock_agent
        canister.canister_id = CANISTER_ID
        canister.methods = {}
        canister.actor = None
        canister.init_args = []

        method = canister._create_method("do_something", func)
        method(verify_certificate=False, timeout=60)

        mock_agent.update.assert_called_once()
        call_kwargs = mock_agent.update.call_args[1]
        assert call_kwargs.get("verify_certificate") is False
        assert call_kwargs.get("timeout") == 60
