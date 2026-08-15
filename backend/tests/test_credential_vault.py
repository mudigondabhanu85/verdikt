from app.vault.credential_vault import decrypt_credential, encrypt_credential, mask_reference


def test_encrypt_decrypt_roundtrip():
    ciphertext = encrypt_credential("user_a", "sup3r-secret-pw")
    username, secret = decrypt_credential(ciphertext)
    assert username == "user_a"
    assert secret == "sup3r-secret-pw"


def test_ciphertext_never_contains_plaintext_secret():
    ciphertext = encrypt_credential("user_a", "sup3r-secret-pw")
    assert b"sup3r-secret-pw" not in ciphertext
    assert b"user_a" not in ciphertext


def test_mask_reference_does_not_leak_secret():
    masked = mask_reference("user_a", "sup3r-secret-pw")
    assert "sup3r-secret-pw" not in masked
    assert "user_a" in masked
    assert masked.endswith("pw)")


def test_different_secrets_produce_different_ciphertext():
    a = encrypt_credential("user_a", "secret-one")
    b = encrypt_credential("user_a", "secret-two")
    assert a != b
