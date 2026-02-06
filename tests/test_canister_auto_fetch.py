"""
Unit tests for automatically fetch .did file from canister feature.

- Canister(agent, canister_id, candid_str=...) does not call read_state_raw when candid_str is provided.
- Canister(agent, canister_id, candid_str=None, auto_fetch_candid=True) calls read_state_raw and uses fetched Candid when available.
- Canister(agent, canister_id, candid_str=None, auto_fetch_candid=True) raises ValueError when fetch fails.
"""

import pytest
from unittest.mock import patch, MagicMock

from icp_canister.canister import Canister
from icp_agent.agent import Agent
from icp_agent.client import Client
from icp_identity.identity import Identity

TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

# Minimal valid Candid that parses to a service (no methods required for some paths; DIDLoader may require at least one)
CANDID_SERVICE_EMPTY = "service : {}"
CANDID_SERVICE_GET = "service : { get : () -> (nat) query; set : (nat) -> () }"


@pytest.fixture
def agent():
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


class TestCanisterWithCandidStrNoFetch:
    """When candid_str is provided, no auto-fetch; read_state_raw is not called."""

    def test_candid_str_provided_does_not_call_read_state_raw(self, agent):
        """Canister(agent, cid, candid_str=CANDID_SERVICE_GET) never calls agent.read_state_raw."""
        with patch.object(agent, "read_state_raw") as mock_read:
            Canister(agent, CANISTER_ID, candid_str=CANDID_SERVICE_GET, auto_fetch_candid=True)
            mock_read.assert_not_called()

    def test_auto_fetch_candid_false_without_candid_does_not_call_read_state_raw(self, agent):
        """Canister(agent, cid, candid_str=None, auto_fetch_candid=False) does not call read_state_raw."""
        with patch.object(agent, "read_state_raw") as mock_read:
            Canister(agent, CANISTER_ID, candid_str=None, auto_fetch_candid=False)
            mock_read.assert_not_called()


class TestCanisterAutoFetchSuccess:
    """When auto_fetch_candid=True and no candid_str, fetch from IC; success path."""

    def test_public_metadata_candid_service_used(self, agent):
        """First try public path (candid:service); when lookup returns Candid string, it is used."""
        mock_cert = MagicMock()
        mock_cert.lookup.return_value = CANDID_SERVICE_GET.encode("utf-8")
        with patch.object(agent, "read_state_raw", return_value=mock_cert) as mock_read:
            c = Canister(agent, CANISTER_ID, candid_str=None, auto_fetch_candid=True)
            mock_read.assert_called_once()
            call_args = mock_read.call_args
            assert call_args[0][0] == CANISTER_ID
            paths = call_args[0][1]
            assert len(paths) == 1
            path = paths[0]
            assert b"candid:service" in path or path[-1] == b"candid:service"
            mock_cert.lookup.assert_called_once()
            assert "get" in c.methods or "set" in c.methods

    def test_private_metadata_fallback_when_public_fails(self, agent):
        """When public path fails (read_state_raw raises), try private path (candid)."""
        mock_cert = MagicMock()
        mock_cert.lookup.return_value = CANDID_SERVICE_GET.encode("utf-8")
        call_count = [0]

        def read_side_effect(cid, paths, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: public path
                raise RuntimeError("not found")
            return mock_cert

        with patch.object(agent, "read_state_raw", side_effect=read_side_effect) as mock_read:
            c = Canister(agent, CANISTER_ID, candid_str=None, auto_fetch_candid=True)
            assert mock_read.call_count == 2
            first_path = mock_read.call_args_list[0][0][1][0]
            second_path = mock_read.call_args_list[1][0][1][0]
            assert b"candid:service" in first_path or first_path[-1] == b"candid:service"
            assert second_path[-1] == b"candid"
            assert "get" in c.methods or "set" in c.methods


class TestCanisterAutoFetchFailure:
    """When both public and private fetch fail, ValueError is raised."""

    def test_both_fetches_fail_raises_value_error(self, agent):
        """When read_state_raw fails for both public and private paths, raise ValueError with helpful message."""
        with patch.object(agent, "read_state_raw", side_effect=RuntimeError("not found")):
            with pytest.raises(ValueError) as exc_info:
                Canister(agent, CANISTER_ID, candid_str=None, auto_fetch_candid=True)
            msg = str(exc_info.value)
            assert "Failed to fetch" in msg or "fetch" in msg.lower()
            assert CANISTER_ID in msg or "canister" in msg.lower()

    def test_public_returns_cert_but_lookup_returns_none_then_private_fails_raises(self, agent):
        """When public path returns cert but lookup returns None, try private; if that also fails, raise."""
        mock_cert = MagicMock()
        mock_cert.lookup.return_value = None  # no candid at this path
        with patch.object(agent, "read_state_raw", side_effect=[mock_cert, RuntimeError("private fail")]):
            with pytest.raises(ValueError):
                Canister(agent, CANISTER_ID, candid_str=None, auto_fetch_candid=True)
