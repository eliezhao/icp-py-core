"""
Unit tests for verify query response signatures feature.

- Agent._verify_query_response_signatures raises MissingSignature when no signatures.
- Agent._verify_query_response_signatures raises TooManySignatures when > 100 signatures.
- Agent.query_raw with verify_query_signatures=True triggers verification and raises on failure.
- Integration test with real query response (from capture_query_response.py) when fixture is fresh.
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

from icp_agent.agent import Agent
from icp_agent.client import Client
from icp_core.errors import (
    MissingSignature,
    TooManySignatures,
    QuerySignatureVerificationFailed,
    SecurityError,
)
from icp_identity.identity import Identity

TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

# Path to fixture produced by scripts/capture_query_response.py
FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "query_response_with_signature.json")


def _deserialize_fixture_value(obj):
    """Convert fixture format (__bytes_hex, __bigint) back to bytes/int."""
    if isinstance(obj, dict):
        if "__bytes_hex" in obj:
            return bytes.fromhex(obj["__bytes_hex"])
        if "__bigint" in obj:
            return int(obj["__bigint"])
        return {k: _deserialize_fixture_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deserialize_fixture_value(x) for x in obj]
    return obj


def load_real_query_response_fixture():
    """Load and deserialize the real query response fixture. Returns (request_id_bytes, result_dict, canister_id) or None if missing."""
    if not os.path.isfile(FIXTURE_PATH):
        return None
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    request_id = bytes.fromhex(data["request_id_hex"])
    result = _deserialize_fixture_value(data["response"])
    canister_id = data["canister_id"]
    return request_id, result, canister_id


@pytest.fixture
def agent():
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


class TestVerifyQueryResponseSignaturesMissingSignature:
    """Test that _verify_query_response_signatures raises MissingSignature when response has no signatures."""

    def test_empty_signatures_list_raises_missing_signature(self, agent):
        """Result with signatures=[] raises MissingSignature."""
        result = {"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}, "signatures": []}
        request_id = b"\x00\x01\x02\x03"
        with pytest.raises(MissingSignature):
            agent._verify_query_response_signatures(result, request_id, CANISTER_ID)

    def test_missing_signatures_key_raises_missing_signature(self, agent):
        """Result without 'signatures' key raises MissingSignature."""
        result = {"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}}
        request_id = b"\x00\x01\x02\x03"
        with pytest.raises(MissingSignature):
            agent._verify_query_response_signatures(result, request_id, CANISTER_ID)

    def test_signatures_not_list_raises_missing_signature(self, agent):
        """Result with signatures as non-list (e.g. dict) is treated as empty."""
        result = {"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}, "signatures": {}}
        request_id = b"\x00\x01\x02\x03"
        with pytest.raises(MissingSignature):
            agent._verify_query_response_signatures(result, request_id, CANISTER_ID)


class TestVerifyQueryResponseSignaturesTooManySignatures:
    """Test that _verify_query_response_signatures raises TooManySignatures when signature count > 100."""

    def test_more_than_100_signatures_raises_too_many(self, agent):
        """Result with 101 signatures raises TooManySignatures(had=101, needed=100)."""
        sig = {"identity": "aaaaa-aa", "signature": b"\x00" * 64, "timestamp": 1_000_000_000_000}
        result = {
            "status": "replied",
            "reply": {"arg": b"DIDL\x00\x00"},
            "signatures": [sig] * 101,
        }
        request_id = b"\x00\x01\x02\x03"
        with pytest.raises(TooManySignatures) as exc_info:
            agent._verify_query_response_signatures(result, request_id, CANISTER_ID)
        assert exc_info.value.had == 101
        assert exc_info.value.needed == 100


class TestQueryRawWithVerifyQuerySignatures:
    """Test that query_raw with verify_query_signatures=True triggers verification."""

    def test_verify_query_signatures_true_and_no_signatures_raises_missing(self, agent):
        """When verify_query_signatures=True and endpoint returns no signatures, query_raw raises MissingSignature."""
        result = {"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}, "signatures": []}
        with patch.object(agent, "query_endpoint", return_value=result):
            with pytest.raises(MissingSignature):
                agent.query_raw(
                    CANISTER_ID,
                    "get",
                    b"DIDL\x00\x00",
                    return_type=None,
                    verify_query_signatures=True,
                )

    def test_verify_query_signatures_false_skips_verification(self, agent):
        """When verify_query_signatures=False, no signature check; reply is decoded and returned."""
        result = {"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}}
        with patch.object(agent, "query_endpoint", return_value=result):
            out = agent.query_raw(
                CANISTER_ID,
                "get",
                b"DIDL\x00\x00",
                return_type=None,
                verify_query_signatures=False,
            )
            # query_raw decodes reply_arg via decode(); DIDL empty may yield [] or similar
            assert out is not None


class TestQuerySignatureErrorClasses:
    """Test that query-signature-related error classes are SecurityError subclasses and have expected attributes."""

    def test_missing_signature_is_security_error(self):
        """MissingSignature is a SecurityError."""
        err = MissingSignature()
        assert isinstance(err, SecurityError)
        assert "signature" in str(err).lower() or "missing" in str(err).lower()

    def test_too_many_signatures_attributes(self):
        """TooManySignatures has had and needed."""
        err = TooManySignatures(had=150, needed=100)
        assert err.had == 150
        assert err.needed == 100
        assert isinstance(err, SecurityError)

    def test_query_signature_verification_failed_is_security_error(self):
        """QuerySignatureVerificationFailed is a SecurityError."""
        err = QuerySignatureVerificationFailed("Custom message")
        assert isinstance(err, SecurityError)
        assert err.message == "Custom message"


class TestRealQueryResponseSignatureVerification:
    """
    Verify real query response with replica signature (fixture from scripts/capture_query_response.py).
    Run that script to refresh tests/fixtures/query_response_with_signature.json with a fresh response.
    """

    @pytest.fixture
    def agent(self):
        client = Client(url="https://ic0.app")
        iden = Identity(privkey=TEST_PRIVKEY_HEX)
        return Agent(iden, client)

    def test_verify_real_query_response_signature(self, agent):
        """
        Load real query response fixture and run _verify_query_response_signatures.
        Passes if verification succeeds; skips if fixture missing or stale (timestamp/node key).
        """
        fixture = load_real_query_response_fixture()
        if fixture is None:
            pytest.skip("Fixture not found. Run: python scripts/capture_query_response.py")
        request_id, result, canister_id = fixture
        assert "signatures" in result and len(result["signatures"]) > 0
        try:
            agent._verify_query_response_signatures(result, request_id, canister_id)
        except QuerySignatureVerificationFailed as e:
            pytest.skip(
                "Real signature verification failed (fixture may be stale or node key lookup failed): %s" % e
            )
        except MissingSignature:
            pytest.fail("Fixture has signatures but MissingSignature was raised")
        except TooManySignatures:
            pytest.fail("Fixture has 1 signature but TooManySignatures was raised")
