from gamekernel import crypto_utils


def test_sign_and_verify_with_user_trusted_key():
    priv_pem, pub_pem = crypto_utils.generate_keypair(password=b"pw")
    priv = crypto_utils.load_private_key(priv_pem, b"pw")
    (crypto_utils.user_trusted_keys_dir() / "test.pub").write_bytes(pub_pem)
    sig = crypto_utils.sign(priv, b"manifest")
    kid = crypto_utils.verify(b"manifest", sig)
    assert kid == crypto_utils.key_id(crypto_utils.load_public_key(pub_pem))
    assert crypto_utils.verify(b"tampered", sig) is None
