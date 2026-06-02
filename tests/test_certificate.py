# test_certificate.py
import copy
import builtins
import pytest
import cbor2

from icp_principal.principal import Principal
from icp_certificate.certificate import Certificate, extract_der, _to_effective_canister_bytes


# ---------------- blst availability helper (official binding only) ----------------
def blst_available() -> bool:
    try:
        import blst  # noqa: F401
        return all(hasattr(blst, n) for n in ("P1_Affine", "P2_Affine", "Pairing", "BLST_SUCCESS"))
    except ModuleNotFoundError:
        return False



# ---------------- Sample certificate ----------------
# Certificate from simple_counter_example.py update call (v4 API)
CERT_SAMPLE = {'tree': [1, [4, b'%DT\xbcr\xab\x96\xbb\xf9n\r\xdd\x94\x1c\xb8\x08\xdd7\x1foP\xb9\xf4\xadx\xe5T\xdbC\x10}\x15'], [1, [1, [2, b'request_status', [1, [1, [4, b'\xfa*\x9c2\xb2e^(\x0e=\xc9\xbe\x80\x82\xe9gW\xb7~\xf2\xa5p\xa4G\xe7m9\xdd\xdf\xda\x19\xda'], [1, [4, b'|\x91\n\xaf\x1f\x9d\xe3b\xa8\xc1<\x18\xf8\xc3\x83\x1bRt\xe0\x81\x0fh\xe3\xe3\xed\x1f\xc4\x14\xa2\x18W\xaf'], [1, [1, [4, b'\xfa\xa0E\xd9\xa3\x86\xbb\x90\xe5\x83\xfa\xc8\x9f?\xa4S\xa8\xe6j\xf6\x92#\x84\xd3\xfc*\xd8\xc3\xd3z\xf3\xa3'], [1, [4, b'q\x81\x18\x04\xccx:\xfc\x83L>\xf5\xbdDZ\xfe\x08\xeb\xed*`\xd8\xdb\x800\\/*\xff\x05\x9d\xa4'], [1, [4, b'\xc3xj\xfb\xea^\xf6X\x96\x89\xc1\xd1OJ\x18\xce\xc4P\x86\xb1\xf2\x12\x7f\xe9\xf4E\x00\x9a\x06\xf8\x84\xb7'], [2, b'\x9a\x87E\x1c!\xdc\xfdV\xdd\x18\x0fsr_8h\x7f\x1c\xa0\xe3A\xa17*>\xbc\xd6z\rWz\x8e', [1, [2, b'reply', [3, b'DIDL\x00\x01}{']], [2, b'status', [3, b'replied']]]]]]], [4, b'\xf9\x93\x0c\x07\xbc\x11\xda\xe5\x12\xf0R\x91\xec\xef\xfd\xdc\xabW\xc7\x10\xf9\x08\x1f\x81\xeb\xb2\xba;\xbb\x07\x85\x1d']]]], [4, b'{%\xe9\xb5\xd0\x9d9\xd5\xc4\x84z\xdc\xb8\xc6\xb0;\xead:*^<\xef\x06O6\xe9\x08~C\xac3']]], [4, b'\xc09}\xc8\x93\x84\x916+\xab\xe0\xaaH\xf8\xe4y\xee\xbfHJ\xb1o\xb8\x87P\xb0\x16\x80\xdd?\xb1g']], [1, [4, b'\xa5~\x11\xdc@\xe5Oy\xf3\xcf\xc3\xbd=\x81:\xb6c>\x93\xcb+\xa4\x1eN\x17\x9d\xebm\x90uw\xee'], [2, b'time', [3, b'\x8f\xda\x9d\x98\xe2\x91\xb2\xc6\x18']]]]], 'signature': b'\xb6hZ\x8b)#\xb9h\x0eN3^\xe1\xe2\x83_\xfa7`.\x84\x9btb/\xc7b\x90\x12\xf2\xaey\x18\xb9\xbb\xe2\xb4\x12\xadkF\xe6\xdbw\xfc\x16\x80q', 'delegation': {'subnet_id': b"\x1c\xc5\xadV?\x1b\xce\x93|0[\xe3\xd1+\xefb\x7fs\xb7'\x80\x86r\xdc$2\xae\xf9\x02", 'certificate': b'\xd9\xd9\xf7\xa2dtree\x83\x01\x83\x01\x82\x04X \xb3\xe1\xcf\xe6J\xdci\xf2,\xb1\xa0\x94\xa1\xc4\tE\x08!\x08hJ\xa9AC\xe1|B\xf8n\xf9e\x14\x83\x01\x83\x02Ocanister_ranges\x83\x01\x83\x01\x83\x01\x83\x01\x82\x04X \x94:.\x1dU\x0c8\xe7\x85~H\xc6\x85\xd9\x06\x9a\xed\x95\xaea\x7f\x01\xcew7\x8e\xd2\xbc9\x07\xfa\xa7\x83\x01\x82\x04X \xb5`8\x82b\x1f\xef\xf0\xdd\xe3y]IQi\x8d\xc4\x00\x1fE&\xed\xe62i\xaa\xe9S[6\xf9\xea\x83\x01\x83\x02X\x1d\x1c\xc5\xadV?\x1b\xce\x93|0[\xe3\xd1+\xefb\x7fs\xb7\'\x80\x86r\xdc$2\xae\xf9\x02\x83\x02J\x00\x00\x00\x00\x01\xf0\x00\x00\x01\x01\x82\x03X\x1b\xd9\xd9\xf7\x81\x82J\x00\x00\x00\x00\x01\xf0\x00\x00\x01\x01J\x00\x00\x00\x00\x01\xff\xff\xff\x01\x01\x82\x04X %\xca\xb2\xa7\xef\xbeQt\xed\xd9\xfd]a\xc0\x87\xca\xa3;\x8fz\xaf\x83\xd0\x03\xebk\xc0\xdf\x8eM\xf1\xe9\x82\x04X \xde\x03\x85\xb5"\x82\x0c\x8b~9\x1b<f\xa1H\xc7\x18\xa0\xa2:xg\x94}\x08Q\xe3\'\xaa\xe7G\xf8\x82\x04X $\x8c\r\x04yCH\x84f\xd0\x8b\xfaFH#\xe6\xba9\xfa\xa4;V\x079\xee\xe5S\x1b\x9f)\x1ax\x82\x04X \x8e\xa6\xbc\x17c\xae:\xf8!q\xb3\xd1%\x01y\xdc\xa8q\xa6a\xbe\xf0\xc1\xee\xbf \xdb*|3\xa6q\x82\x04X \xea{X\x0b-\x88\x8bM\xc5\xean\rx+r!\x95\x1c\xb8V/jP\x9c\x04\x02\xd3DV\x11\xdd\x80\x83\x01\x82\x04X \xf0\x15\x80v\xf7\xb5\xa6\xaar_)\xc8\xc1\xd1\xab/|\x9d\xde\xc6\x0b\xcb\x17}b(\x0c4\x1dRe7\x83\x01\x83\x02Fsubnet\x83\x01\x83\x01\x83\x01\x83\x01\x82\x04X yMP\xb5\xb9o\x1b\x0b\x1b:\xb1X\x14\xcf\xaa\xb3\xe1Q\xd6v`\xd4\xceI\xb5Lk@\x10\xc5?\x18\x83\x01\x82\x04X \x8c\xbaH-v.\x1e\xce\xd6\xd2\x03\n\x9aE/\x81\x84\xff"\xe5\x17\xd8\x90\xc5o>\x12-\xdfM&a\x83\x01\x83\x02X\x1d\x1c\xc5\xadV?\x1b\xce\x93|0[\xe3\xd1+\xefb\x7fs\xb7\'\x80\x86r\xdc$2\xae\xf9\x02\x83\x01\x82\x04X 6\x1f\xf9%\x93;\x02\xac\xa4H\xeadE\x11\xb3,\xb7\xf3\xf5vtsyx\xd8Y\x9ev\xf5\x12\x9bc\x83\x02Jpublic_key\x82\x03X\x850\x81\x820\x1d\x06\r+\x06\x01\x04\x01\x82\xdc|\x05\x03\x01\x02\x01\x06\x0c+\x06\x01\x04\x01\x82\xdc|\x05\x03\x02\x01\x03a\x00\x93\x90w\x10\xf0\xf8\x9a\xf4\xb5\xbd5\xa2\x8e\x01b\x17\x1e/A\x1d\x11\xe1R\x15.\x88\xe3\xdaL yy\x9eN\xacz:\x9f9#\xfbc\xb3;h\x92\x8a\xe9\x16R\xfa\xe5\xc2\xcc\xce\x87!sc&H\xefM\xd7\x9a\xe7\xe8\xc1[\x9e\x97\xf12\xea4\xa44\x95\x06\xd2\x81\xbdf\xbb\xd0\xc3\xaf\xddx\xcb\xe0&\x92z\x8c\x16\x82\x04X ~\r\xc1\xbb\x9d)N\xacW"\x80\xd6<\x80\xc2@\x16<\xb9\xad\x121\xe1"\x80.\x1fV\xca\x9a\r\xd1\x82\x04X \x83\x11\x15\xd9\xd0\x82\xf6\xbb\xc4\xe1\xe1\xe0-\x05\x1d\x14\x7f{I\xa6\xfb\xb7\x02xx\xec\x12\xae\x9bP\xb4\x89\x82\x04X \xaf\xaa\x882\x10\x1b\xce\xe2>\xb8q\xf6\xa3\xb3r\xb9\'\xeb:\xd5\xba\xcb\xbb\xf6z\xa4\xdf)k\xf8\xc4\x93\x82\x04X \x06:]D\xcdD\x15\xa2iz<\xc8\x86\x94\xbef\x9d\xb8\xc3\xde\x90wE\xa2\x90\xbb\xc8\x81\xdcl\xfc\x8d\x83\x02Dtime\x82\x03I\xac\x9f\x8e\xc4\xd6\x91\xb2\xc6\x18isignatureX0\x801\x98\xb0\xa6^QI\xfb\xc9?\xdf H\x994k\xfe$\x04h\xb3\x1f\xd7\x9a\x17\xce\xfe\x9dk\xbf\x86\xb0\xed\xc6\xba\xf1\x0f\x10\n)~vE\xc7)-Y'}}
CERT_CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

# ---------------- helpers ----------------
def _get_ranges_from_parent(cert_dict):
    """Return (lo, hi) from the first canister_ranges entry in the parent certificate."""
    cert = Certificate(cert_dict)
    d = cert.delegation
    assert d is not None, "sample must contain delegation"
    parent_cert_dict = cbor2.loads(d["certificate"])
    parent = Certificate(parent_cert_dict)
    subnet_id = bytes(d["subnet_id"])
    
    # v4 API uses sharded structure: [canister_ranges, subnet_id, shard_label]
    canister_range_shards_lookup = [b"canister_ranges", subnet_id]
    canister_range_shards = parent.lookup_tree(canister_range_shards_lookup)
    assert canister_range_shards is not None, "parent certificate must contain canister_ranges"
    
    # Get the first shard
    shard_paths = parent.list_paths(canister_range_shards)
    assert shard_paths and len(shard_paths) > 0, "canister_ranges must have at least one shard"
    
    # Get the first shard label
    first_shard_label = shard_paths[0][-1] if shard_paths[0] else None
    assert first_shard_label is not None, "shard label must exist"
    
    # Lookup the range data from the shard
    canister_range = parent._lookup_path([first_shard_label], canister_range_shards)
    assert canister_range is not None, "canister_range data must exist"
    
    ranges_raw = cbor2.loads(canister_range)
    # cbor2 6.x decodes the self-describe-tagged ranges as immutable tuples,
    # cbor2 5.x as lists; production code (check_delegation) tolerates both.
    assert isinstance(ranges_raw, (list, tuple)) and len(ranges_raw) >= 1
    lo, hi = ranges_raw[0]
    return bytes(lo), bytes(hi)

def _tamper_signature(cert_dict):
    """Flip the last bit of the signature to force a verification failure."""
    bad = copy.deepcopy(cert_dict)
    sig = bytearray(bad["signature"])
    sig[-1] ^= 0x01
    bad["signature"] = bytes(sig)
    return bad


# ========== Test 1: check_delegation authorized (use fixed canister id) ==========
def test_check_delegation_authorized():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)

    if blst_available():
        der_key = cert.check_delegation(cid_bytes, must_verify=True)
    else:
        # in environments without blst, allow materials-only (must_verify=False)
        der_key = cert.check_delegation(cid_bytes, must_verify=False)

    assert isinstance(der_key, (bytes, bytearray, memoryview)) and len(der_key) == 133
    pk96 = extract_der(der_key)
    assert isinstance(pk96, (bytes, bytearray, memoryview)) and len(pk96) == 96


# ========== Test 2: check_delegation unauthorized (construct an out-of-range id) ==========
def test_check_delegation_unauthorized_raises():
    _lo, hi = _get_ranges_from_parent(CERT_SAMPLE)
    cert = Certificate(CERT_SAMPLE)
    eff_outside = bytes(hi) + b"\x01"  # strictly greater than high bound

    with pytest.raises(ValueError, match="CertificateNotAuthorized"):
        cert.check_delegation(eff_outside, must_verify=blst_available())


# ========== Test 3: verify_cert returns materials (no real verification) ==========
def test_verify_return_materials_lengths():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)
    materials = cert.verify_cert(cid_bytes, backend="return_materials")

    assert set(materials.keys()) == {"signature", "message", "der_public_key", "bls_public_key"}
    assert isinstance(materials["signature"], (bytes, bytearray, memoryview)) and len(materials["signature"]) == 48
    # 1 + len("ic-state-root") + 32 = 46
    assert isinstance(materials["message"], (bytes, bytearray, memoryview)) and len(materials["message"]) == 46
    assert isinstance(materials["der_public_key"], (bytes, bytearray, memoryview)) and len(materials["der_public_key"]) == 133
    assert isinstance(materials["bls_public_key"], (bytes, bytearray, memoryview)) and len(materials["bls_public_key"]) == 96


# ========== Test 4: verify_cert success (requires blst) ==========
@pytest.mark.skipif(not blst_available(), reason="official 'blst' not installed")
def test_verify_with_blst_success():
    cid_bytes = _to_effective_canister_bytes(CERT_CANISTER_ID)
    cert = Certificate(CERT_SAMPLE)
    assert cert.verify_cert(cid_bytes, backend="blst") is True


# ========== Test 5: verify_cert fails when signature is tampered (requires blst) ==========
@pytest.mark.skipif(not blst_available(), reason="official 'blst' not installed")
def test_verify_with_blst_bad_signature_raises():
    from icp_core.errors import SignatureVerificationFailed
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    bad_cert = Certificate(_tamper_signature(CERT_SAMPLE))
    with pytest.raises(SignatureVerificationFailed, match="BLS signature verification failed"):
        bad_cert.verify_cert(cid_bytes, backend="blst")


# ========== Test 6: require blst for backend='blst' (simulate missing blst) ==========
def test_verify_requires_blst_when_backend_blst(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "blst":
            raise ModuleNotFoundError("No module named 'blst'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)

    with pytest.raises(RuntimeError, match="official 'blst' Python binding"):
        cert.verify_cert(cid_bytes, backend="blst")


# ========== Test 7: extract_der prefix mismatch ==========
def test_extract_der_prefix_mismatch():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)
    der_key = cert.check_delegation(cid_bytes, must_verify=False)
    bad = bytearray(der_key)
    bad[0] ^= 0x01
    with pytest.raises(ValueError, match="prefix mismatch"):
        extract_der(bytes(bad))


# ========== Test 8: missing canister_ranges should fail ==========
def test_check_delegation_missing_ranges_raises():
    mutated = copy.deepcopy(CERT_SAMPLE)
    # Change subnet_id so lookups won't find "canister_ranges"
    mutated["delegation"]["subnet_id"] = b"\x01" * len(mutated["delegation"]["subnet_id"])
    cert = Certificate(mutated)
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    with pytest.raises(ValueError, match="Missing canister_ranges"):
        cert.check_delegation(cid_bytes, must_verify=False)


# ========== Test 9: timestamp skew check ==========
def test_verify_cert_timestamp_skew_too_large():
    cert = Certificate(CERT_SAMPLE)
    with pytest.raises(ValueError, match="CertificateOutdated"):
        cert.verify_cert_timestamp(ingress_expiry_ns=1)