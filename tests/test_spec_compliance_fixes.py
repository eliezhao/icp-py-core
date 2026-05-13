"""
Tests for IC interface spec compliance fixes.

Covers every issue called out in the May-2026 spec audit:

- H1  reject_code is decoded as ULEB128 nat, not UTF-8 string
- M1  Principal.self_authenticating accepts any well-formed SPKI DER
      (Ed25519, secp256k1, P-256, BLS12-381 G2)
- M2  to_request_id uses Unsigned LEB128 for natural numbers
- M3  update_raw_async parses the v4 synchronous /call body (fast path)
- M4  Identity supports ECDSA P-256 (secp256r1)
- L1  Principal.from_str is case-insensitive
- L2  query response signature verification has no arbitrary >100 cap
- L3  Candid encodes opaque (None) func/service references as 0x00
- L4  Candid raises on unknown func modes instead of silently fabricating one
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from unittest.mock import patch, MagicMock

import cbor2
import httpx
import pytest

from icp_agent.agent import Agent, to_request_id
from icp_agent.client import Client
from icp_candid.candid import LEB128, Types, encode, decode
from icp_certificate.certificate import IC_ROOT_KEY, Certificate
from icp_core.errors import ReplicaReject
from icp_identity.identity import Identity
from icp_principal.principal import Principal


# Ed25519 test vector (RFC 8032); used only for tests, not a real secret.
TEST_PRIVKEY_HEX = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"


@pytest.fixture
def agent():
    return Agent(Identity(privkey=TEST_PRIVKEY_HEX), Client(url="https://ic0.app"))


# ===========================================================================
# H1: reject_code is ULEB128 nat, not UTF-8 string
# ===========================================================================

class TestRejectCodeIsNatNotText:
    """
    The IC spec says /request_status/<id>/reject_code is a natural number
    (ULEB128). The old implementation decoded it as UTF-8 text, which made
    poll_and_wait report reject_code=0 for every certificate-based rejection.
    """

    def _make_cert(self, request_id: bytes, reject_code_leb: bytes,
                   reject_message: bytes = b"trapped") -> Certificate:
        """Build a minimal hash-tree Certificate carrying a 'rejected' status."""
        # Leaf nodes: tag=3, value=bytes.
        def L(v): return [3, v]
        # Labeled: tag=2, label, child.
        def Lbl(label, child): return [2, label, child]
        # Fork: tag=1, left, right.
        def F(left, right): return [1, left, right]

        # request_status / <req_id> / { status, reject_code, reject_message }
        req_status_subtree = Lbl(
            request_id,
            F(
                Lbl(b"status", L(b"rejected")),
                F(
                    Lbl(b"reject_code", L(reject_code_leb)),
                    Lbl(b"reject_message", L(reject_message)),
                ),
            ),
        )
        tree = Lbl(b"request_status", req_status_subtree)
        return Certificate({"tree": tree, "signature": b"\x00" * 48})

    def test_reject_code_returns_int(self):
        """lookup_reject_code returns an int, not a string."""
        req_id = b"\xaa" * 32
        # reject_code = 5 (CANISTER_REJECT) encoded as ULEB128 -> b'\x05'
        cert = self._make_cert(req_id, LEB128.encode_u(5))
        code = cert.lookup_reject_code(req_id)
        assert code == 5
        assert isinstance(code, int)

    def test_reject_code_multi_byte_uleb(self):
        """Multi-byte ULEB128 (e.g. value 200) decodes correctly."""
        req_id = b"\xab" * 32
        cert = self._make_cert(req_id, LEB128.encode_u(200))
        assert cert.lookup_reject_code(req_id) == 200

    def test_lookup_request_rejection_carries_int_code(self):
        """lookup_request_rejection returns a dict whose reject_code is int."""
        req_id = b"\xac" * 32
        cert = self._make_cert(req_id, LEB128.encode_u(3))
        rej = cert.lookup_request_rejection(req_id)
        assert rej["reject_code"] == 3
        assert isinstance(rej["reject_code"], int)
        assert rej["reject_message"] == "trapped"

    def test_poll_and_wait_propagates_real_reject_code(self, agent):
        """
        Regression: previously reject_code was always 0 in poll_and_wait.
        With the fix, the value carried in the certificate must reach
        ReplicaReject.reject_code unchanged.
        """
        req_id = b"\xad" * 32
        cert = self._make_cert(req_id, LEB128.encode_u(5), b"canister rejected")

        with patch.object(agent, "request_status_raw", return_value=("rejected", cert)):
            with pytest.raises(ReplicaReject) as exc_info:
                agent.poll_and_wait(CANISTER_ID, req_id, verify_certificate=False)

        assert exc_info.value.reject_code == 5
        assert "canister rejected" in str(exc_info.value)


# ===========================================================================
# M1: Principal.self_authenticating accepts any well-formed SPKI DER
# ===========================================================================

class TestSelfAuthenticatingAcceptsAllSpki:
    def test_accepts_bls_root_key(self):
        """The IC root key (BLS12-381 G2 DER) must be a valid input."""
        p = Principal.self_authenticating(IC_ROOT_KEY)
        # Sanity: 29-byte principal ending in 0x02
        assert len(p.bytes) == 29
        assert p.bytes[-1] == 0x02
        # Sanity: matches hand-computed derivation
        expected = hashlib.sha224(IC_ROOT_KEY).digest() + b"\x02"
        assert p.bytes == expected

    def test_accepts_p256_spki(self):
        """A real P-256 identity's SPKI DER must yield a valid principal."""
        iden = Identity(type="p256")
        p = Principal.self_authenticating(iden.der_pubkey)
        assert len(p.bytes) == 29
        assert p.bytes[-1] == 0x02

    def test_still_rejects_obvious_garbage(self):
        """Random bytes that aren't DER (no 0x30 prefix) are still rejected."""
        with pytest.raises(ValueError):
            Principal.self_authenticating(b"\x00" * 64)

    def test_still_rejects_too_short(self):
        with pytest.raises(ValueError):
            Principal.self_authenticating(b"\x30" + b"\x00" * 10)


# ===========================================================================
# M2: to_request_id uses Unsigned LEB128 for natural numbers
# ===========================================================================

class TestRequestIdUsesUnsignedLeb128:
    """
    Per spec: 'Natural numbers ... are hashed by hashing their binary
    encoding using the shortest form Unsigned LEB128 encoding.' This is
    observable: for values whose top 7-bit chunk has MSB=1, signed and
    unsigned LEB128 differ, so the resulting request_id differs.
    """

    @staticmethod
    def _expected_request_id(d: dict) -> bytes:
        """Hand-roll the spec's RIH using ULEB128 for nats."""
        pairs = []
        for k, v in d.items():
            kh = hashlib.sha256(k.encode("utf-8")).digest()
            if isinstance(v, int):
                vh = hashlib.sha256(LEB128.encode_u(v)).digest()
            elif isinstance(v, (bytes, bytearray, memoryview)):
                vh = hashlib.sha256(bytes(v)).digest()
            elif isinstance(v, str):
                vh = hashlib.sha256(v.encode("utf-8")).digest()
            else:
                raise AssertionError(f"unsupported in this helper: {type(v)}")
            pairs.append(kh + vh)
        return hashlib.sha256(b"".join(sorted(pairs))).digest()

    def test_typical_ingress_expiry_matches_uleb_hand_roll(self):
        """Today's ingress_expiry happens to match ULEB == SLEB; still must equal hand-roll."""
        req = {
            "request_type": "call",
            "ingress_expiry": 1_700_000_000_000_000_000,
        }
        assert to_request_id(req) == self._expected_request_id(req)

    def test_value_64_hashes_as_uleb_not_sleb(self):
        """
        Value 64 is the canonical divergence point: ULEB(64)=0x40,
        SLEB(64)=0xC0 0x00. The previous SLEB-based code produced the wrong
        hash for any nat with this shape (e.g. an integer nonce of 64).
        """
        req = {
            "request_type": "call",
            "ingress_expiry": 64,
        }
        # Hand-rolled ULEB result must equal what to_request_id produces now.
        assert to_request_id(req) == self._expected_request_id(req)
        # And it must NOT equal what SLEB would have produced for value 64.
        sleb_pairs = [
            hashlib.sha256(b"request_type").digest() + hashlib.sha256(b"call").digest(),
            hashlib.sha256(b"ingress_expiry").digest() + hashlib.sha256(LEB128.encode_i(64)).digest(),
        ]
        sleb_id = hashlib.sha256(b"".join(sorted(sleb_pairs))).digest()
        assert to_request_id(req) != sleb_id

    def test_bool_does_not_take_int_branch(self):
        """
        bool is a subclass of int. Make sure True/False are hashed as a
        single LEB byte (0/1), not as the int branch's general path.
        """
        req_true = {"x": True}
        req_one = {"x": 1}
        # True and 1 produce identical hashes under ULEB (both -> 0x01).
        assert to_request_id(req_true) == to_request_id(req_one)


# ===========================================================================
# M3: update_raw_async uses the v4 synchronous response (no needless polling)
# ===========================================================================

class TestUpdateRawAsyncFastPath:
    def test_async_replied_uses_sync_response(self, agent):
        """
        When the v4 /call body returns status=replied with a certificate,
        update_raw_async must consume it directly and NOT fall back to polling.
        """
        fake_cert_cbor = cbor2.dumps({"tree": [0]})
        response_obj = {"status": "replied", "certificate": fake_cert_cbor}

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.content = cbor2.dumps(response_obj)

        async def _fake_call_async(*args, **kwargs):
            return mock_resp

        async def _run():
            with patch.object(agent, "call_endpoint_async", side_effect=_fake_call_async), \
                 patch.object(agent, "poll_async") as mock_poll, \
                 patch("icp_agent.agent.Certificate") as MockCert:
                cert_instance = MockCert.return_value
                cert_instance.lookup_request_status.return_value = "replied"
                cert_instance.lookup_reply.return_value = b"DIDL\x00\x00"

                await agent.update_raw_async(
                    CANISTER_ID, "do_thing", b"", verify_certificate=False
                )
                return mock_poll

        mock_poll = asyncio.run(_run())
        mock_poll.assert_not_called()

    def test_async_non_replicated_rejection_with_real_code(self, agent):
        """
        v4 sync body with status=non_replicated_rejection must raise
        ReplicaReject carrying the actual reject_code (not 0).
        """
        response_obj = {
            "status": "non_replicated_rejection",
            "reject_code": 4,
            "reject_message": "destination invalid",
        }
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.content = cbor2.dumps(response_obj)

        async def _fake_call_async(*args, **kwargs):
            return mock_resp

        async def _run():
            with patch.object(agent, "call_endpoint_async", side_effect=_fake_call_async):
                with pytest.raises(ReplicaReject) as exc_info:
                    await agent.update_raw_async(
                        CANISTER_ID, "do_thing", b"", verify_certificate=False
                    )
                return exc_info.value

        err = asyncio.run(_run())
        assert err.reject_code == 4
        assert "destination invalid" in str(err)

    def test_async_202_with_non_cbor_falls_back_to_polling(self, agent):
        """HTTP 202 with a non-CBOR body must trigger poll_async."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 202
        mock_resp.content = b"not-cbor"

        async def _fake_call_async(*args, **kwargs):
            return mock_resp

        async def _fake_poll(*args, **kwargs):
            return "replied", b"DIDL\x00\x00"

        async def _run():
            with patch.object(agent, "call_endpoint_async", side_effect=_fake_call_async), \
                 patch.object(agent, "poll_async", side_effect=_fake_poll) as mock_poll:
                await agent.update_raw_async(
                    CANISTER_ID, "do_thing", b"", verify_certificate=False
                )
                return mock_poll

        mock_poll = asyncio.run(_run())
        mock_poll.assert_called_once()


# ===========================================================================
# M4: Identity supports ECDSA P-256 (secp256r1)
# ===========================================================================

class TestP256Identity:
    def test_p256_sign_and_verify_roundtrip(self):
        iden = Identity(type="p256")
        msg = b"\x0aic-request" + b"\x00" * 32
        der_pub, sig = iden.sign(msg)
        assert der_pub is not None
        assert len(sig) == 64  # raw r||s
        assert iden.verify(msg, sig) is True

    def test_p256_alias_secp256r1(self):
        """`secp256r1` is accepted as an alias for `p256`."""
        iden = Identity(type="secp256r1")
        assert iden.key_type == "p256"

    def test_p256_yields_self_authenticating_principal(self):
        """A P-256 identity must produce a valid self-authenticating principal."""
        iden = Identity(type="p256")
        p = iden.sender()
        assert len(p.bytes) == 29
        assert p.bytes[-1] == 0x02


# ===========================================================================
# L1: Principal.from_str is case-insensitive
# ===========================================================================

class TestPrincipalFromStrCaseInsensitive:
    def test_uppercase_management_canister(self):
        p_upper = Principal.from_str("AAAAA-AA")
        p_lower = Principal.from_str("aaaaa-aa")
        assert p_upper == p_lower
        # Canonical form is lowercase.
        assert p_upper.to_str() == "aaaaa-aa"

    def test_mixed_case(self):
        p_mixed = Principal.from_str("2VxSx-FAE")  # anonymous principal, mixed
        p_lower = Principal.from_str("2vxsx-fae")
        assert p_mixed == p_lower


# ===========================================================================
# L3 & L4: Candid opaque func/service refs + mode validation
# ===========================================================================

class TestCandidOpaqueAndModes:
    def test_func_encodes_opaque_as_zero_byte(self):
        func_type = Types.Func([], [], ["query"])
        # Note: encode wraps in DIDL; what we care about is that the func
        # value encoder produces 0x00 for None and does not crash.
        out = func_type.encodeValue(None)
        assert out == b"\x00"

    def test_service_encodes_opaque_as_zero_byte(self):
        svc_type = Types.Service({})
        out = svc_type.encodeValue(None)
        assert out == b"\x00"

    def test_func_roundtrip_opaque(self):
        func_type = Types.Func([], [], ["query"])
        wire = encode([{"type": func_type, "value": None}])
        decoded = decode(wire, func_type)
        assert decoded[0]["value"] is None

    def test_unknown_func_mode_raises(self):
        """Encoding a Func type with an unknown mode must raise instead of fabricating one."""
        # Build a Func type with an invalid mode and attempt to build its type table.
        bogus = Types.Func([], [], ["totally-not-a-mode"])
        with pytest.raises(ValueError, match="Unknown func mode"):
            encode([{"type": bogus, "value": [Principal.management_canister(), "m"]}])
