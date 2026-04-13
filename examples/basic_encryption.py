import qboost


def main():
    for k, v in qboost.info().items():
        print(f"  {k}: {v}")
    print()

    keys = qboost.generate_keypair()
    print(f"keypair {keys.key_id}")

    message = b"This is a secret message protected by QBoost!"
    ciphertext = qboost.encrypt(message, keys.public_key)
    print(f"encrypted: {len(ciphertext)} bytes")

    plaintext = qboost.decrypt(ciphertext, keys)
    print(f"decrypted: {plaintext.decode()}")
    assert plaintext == message

    password = "my-strong-passphrase"
    secret = b"Another secret, this time password-protected."
    encrypted = qboost.encrypt_symmetric(secret, password)
    decrypted = qboost.decrypt_symmetric(encrypted, password)
    print(f"symmetric ok: {decrypted == secret}")


if __name__ == "__main__":
    main()
