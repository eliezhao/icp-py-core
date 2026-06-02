"""
Regression tests for the security/correctness audit fixes.

1. system_state.time() must return the already-decoded ULEB128 timestamp
   from Certificate.lookup_time() instead of decoding it a second time
   (the old code did LEB128.decode_u_bytes(bytes(int)), which allocates a
   multi-exabyte buffer and raises MemoryError).

2. Query-signature verification must fetch the subnet id and node public
   keys from BLS-verified certificates (verify_certificate=True). Reading
   them unverified would let a malicious boundary node supply forged node
   keys plus a matching forged signature, defeating the feature.
"""

from unittest.mock import patch, MagicMock

import pytest

from icp_agent import system_state
from icp_agent.agent import Agent
from icp_agent.client import Client
from icp_identity.identity import Identity, DelegateIdentity

# Ed25519 test vector (RFC 8032); used only for tests, not a real secret.
TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"
# A valid subnet principal (text form) for the node-key lookup test.
SUBNET_ID = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"


@pytest.fixture
def agent():
    client = Client(url="https://ic0.app")
    iden = Identity(privkey=TEST_PRIVKEY_HEX)
    return Agent(iden, client)


# ---------------------------------------------------------------------------
# Fix 1: system_state.time() must not double-decode the timestamp
# ---------------------------------------------------------------------------

class TestSystemStateTime:
    def test_time_returns_decoded_int_without_second_decode(self, agent):
        """time() returns lookup_time()'s int directly (no MemoryError)."""
        expected_ns = 1_700_000_000_123_456_789  # realistic ns timestamp
        fake_cert = MagicMock()
        fake_cert.lookup_time.return_value = expected_ns

        with patch.object(agent, "read_state_raw", return_value=fake_cert):
            result = system_state.time(agent, CANISTER_ID)

        assert result == expected_ns
        fake_cert.lookup_time.assert_called_once()

    def test_time_does_not_call_bytes_on_int(self, agent):
        """A large timestamp must not blow up (regression for MemoryError)."""
        fake_cert = MagicMock()
        fake_cert.lookup_time.return_value = 2**63  # huge; bytes(int) would OOM
        with patch.object(agent, "read_state_raw", return_value=fake_cert):
            # Must simply return the value, not attempt a giant allocation.
            assert system_state.time(agent, CANISTER_ID) == 2**63


# ---------------------------------------------------------------------------
# Fix 2: query-signature verification fetches keys from verified certificates
# ---------------------------------------------------------------------------

class TestQuerySignatureUsesVerifiedCertificates:
    def test_get_node_public_key_requires_verified_certificate(self, agent):
        """_get_node_public_key must read subnet state with verify_certificate=True."""
        captured = {}
        fake_cert = MagicMock()
        fake_cert.lookup.return_value = b"\x00" * 44  # any non-None key

        def fake_read_state_subnet_raw(subnet_id, paths, verify_certificate=True):
            captured["verify_certificate"] = verify_certificate
            return fake_cert

        subnet_id = Identity(privkey=TEST_PRIVKEY_HEX).sender().bytes
        node_id = b"\x11" * 28

        with patch.object(agent, "read_state_subnet_raw", side_effect=fake_read_state_subnet_raw):
            agent._get_node_public_key(subnet_id, node_id)

        assert captured["verify_certificate"] is True, \
            "node public key must come from a BLS-verified subnet certificate"

    def test_get_subnet_by_canister_requires_verified_certificate(self, agent):
        """_get_subnet_by_canister must read canister state with verify_certificate=True."""
        captured = {}
        fake_cert = MagicMock()
        fake_cert.delegation = None  # exercise the no-delegation branch

        def fake_read_state_raw(canister_id, paths, verify_certificate=True):
            captured["verify_certificate"] = verify_certificate
            return fake_cert

        with patch.object(agent, "read_state_raw", side_effect=fake_read_state_raw):
            subnet_id, node_keys = agent._get_subnet_by_canister(CANISTER_ID)

        assert captured["verify_certificate"] is True, \
            "subnet id must be derived from a BLS-verified canister certificate"
        assert isinstance(subnet_id, bytes)


# ---------------------------------------------------------------------------
# Fix 3: Identity repr/str must not leak the private key
# ---------------------------------------------------------------------------

class TestIdentityDoesNotLeakPrivateKey:
    PRIV = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"

    def test_repr_redacts_private_key(self):
        iden = Identity(privkey=self.PRIV, type="ed25519")
        assert self.PRIV not in repr(iden)
        assert iden.privkey not in repr(iden)
        # Public material is still useful for debugging.
        assert iden.pubkey in repr(iden)

    def test_str_redacts_private_key(self):
        iden = Identity(privkey=self.PRIV, type="ed25519")
        assert self.PRIV not in str(iden)
        assert iden.privkey not in str(iden)

    def test_privkey_property_still_works(self):
        """The redaction must not break the legitimate accessor."""
        iden = Identity(privkey=self.PRIV, type="ed25519")
        assert iden.privkey == self.PRIV

    def test_delegate_identity_repr_does_not_leak_inner_key(self):
        inner = Identity(privkey=self.PRIV, type="ed25519")
        delegation = {
            "publicKey": inner.der_pubkey.hex(),
            "delegations": [
                {
                    "delegation": {"expiration": "0x100", "pubkey": inner.der_pubkey.hex()},
                    "signature": "00" * 64,
                }
            ],
        }
        deleg = DelegateIdentity(inner, delegation)
        assert inner.privkey not in repr(deleg)
        assert inner.privkey not in str(deleg)
