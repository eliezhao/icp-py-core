from src.icp_identity.identity import Identity


class TestIdentity:

    def test_ed25519_privatekey(self):
        iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        assert iden.key_type == 'ed25519'
        assert iden.pubkey == 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf'

    def test_ed25519_frompem(self):
        pem = """
        -----BEGIN PRIVATE KEY-----
        MFMCAQEwBQYDK2VwBCIEIGQqNAZlORmn1k4QrYz1FvO4fOQowS3GXQMqRKDzmx9P
        oSMDIQCrO5iGM5hnLWrHavywoXekAoXPpYRuB0Dr6DjZF6FZkg==
        -----END PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        assert iden.key_type == 'ed25519'
        assert iden.privkey == '642a3406653919a7d64e10ad8cf516f3b87ce428c12dc65d032a44a0f39b1f4f'
        assert iden.pubkey == 'ab3b98863398672d6ac76afcb0a177a40285cfa5846e0740ebe838d917a15992'

    def test_ed25519_from_seed_slip10(self):
        # SLIP-0010 with ICP path m/44'/223'/0'/0'/0'
        mnemonic = 'fence dragon soft spoon embrace bronze regular hawk more remind detect slam'
        iden = Identity.from_seed(mnemonic)
        assert iden.key_type == 'ed25519'
        # Verified with Rust slip10/bip39 reference output
        assert iden.privkey == 'd0de9643a6869d6690590434e15248cf43694966ff0d95a28f7587e9a0afca40'