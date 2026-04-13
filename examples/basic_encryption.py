"""Basic encryption and decryption with QBoost."""

import qboost


def main():
    # Check quantum readiness
    print("QBoost Info:")
    for key, value in qboost.info().items():
        print(f"  {key}: {value}")
    print(f"  quantum_ready: {qboost.is_quantum_ready()}")
    print()

    # --- Asymmetric (keypair) encryption ---
    print("=== Asymmetric Encryption ===")
    keys = qboost.generate_keypair()
    print(f"Generated keypair (key_id: {keys.key_id})")

    message = b"This is a secret message protected by QBoost!"
    ciphertext = qboost.encrypt(message, keys.public_key)
    print(f"Encrypted: {len(ciphertext)} bytes")

    plaintext = qboost.decrypt(ciphertext, keys)
    print(f"Decrypted: {plaintext.decode()}")
    assert plaintext == message
    print()

    # --- Symmetric (password) encryption ---
    print("=== Symmetric Encryption ===")
    password = "my-strong-passphrase"
    secret = b"Another secret, this time password-protected."

    encrypted = qboost.encrypt_symmetric(secret, password)
    print(f"Encrypted: {len(encrypted)} bytes")

    decrypted = qboost.decrypt_symmetric(encrypted, password)
    print(f"Decrypted: {decrypted.decode()}")
    assert decrypted == secret
    print()

    print("All operations completed successfully.")


if __name__ == "__main__":
    main()
