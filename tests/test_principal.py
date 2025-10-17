from icp_principal.principal import Principal

class TestPrincipal:

    def test_default(self):
        p = Principal()
        assert p.to_str() == 'aaaaa-aa'

    def test_anonymous(self):
        p = Principal.anonymous()
        assert p.to_str() == '2vxsx-fae'

    def test_self_authenticating_ed25519_der(self):
        # raw ed25519 pubkey (32 bytes) -> SPKI DER (RFC 8410)
        spki_der_hex = "302a300506032b6570032100298f91b3992137706d50547a6c9247168ed8faa0ec92710f397e97175eee7168"

        p = Principal.self_authenticating(spki_der_hex)
        # This is sha224(SPKI_DER) || 0x02, with CRC32 + base32 text
        assert p.to_str() == 'ytoqu-ey42w-sb2ul-m7xgn-oc7xo-i4btp-kuxjc-b6pt4-dwdzu-kfqs4-nae'

    def test_fromstr_roundtrip(self):
        s = '7aodp-4ebhh-pj5sa-5kdmg-fkkw3-wk6rv-yf4rr-pt2g7-ebx7j-7sjq4-4qe'
        p = Principal.from_str(s)
        assert p.to_str() == s

    def test_eq_and_hash(self):
        p0 = Principal.anonymous()
        p1 = Principal.management_canister()
        assert p0 != p1

        p2 = Principal.from_str("aaaaa-aa")
        assert p1 == p2

        m = {}
        m[p1] = 123
        assert m[p2] == 123
        m[p1] = 456
        assert m[p2] == 456
        assert len(m) == 1