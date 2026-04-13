"""Demonstrate key exchange and signing between two parties."""

import qboost
from qboost import HybridSigner, QBoostPublicKey


def key_exchange_demo():
    """Alice and Bob exchange encrypted messages using exported keys."""
    print("=== Key Exchange ===")

    # Alice generates a keypair and exports her public key
    alice_keys = qboost.generate_keypair()
    alice_pub_export = alice_keys.export_public_key()
    print(f"Alice generated keypair (id: {alice_keys.key_id})")
    print(f"Alice's exported public key: {len(alice_pub_export)} bytes")

    # Bob receives Alice's exported public key and imports it
    alice_pub = QBoostPublicKey.from_export(alice_pub_export)

    # Bob encrypts a message for Alice
    bob_message = b"Hey Alice, let's meet at the quantum cafe."
    ciphertext = qboost.encrypt(bob_message, alice_pub)
    print(f"Bob encrypted a message: {len(ciphertext)} bytes")

    # Alice decrypts with her private key
    plaintext = qboost.decrypt(ciphertext, alice_keys)
    print(f"Alice decrypted: {plaintext.decode()}")
    assert plaintext == bob_message

    # Alice replies to Bob
    bob_keys = qboost.generate_keypair()
    bob_pub_export = bob_keys.export_public_key()
    print(f"\nBob generated keypair (id: {bob_keys.key_id})")

    bob_pub = QBoostPublicKey.from_export(bob_pub_export)
    alice_reply = b"See you there, Bob!"
    reply_ct = qboost.encrypt(alice_reply, bob_pub)
    reply_pt = qboost.decrypt(reply_ct, bob_keys)
    print(f"Bob decrypted Alice's reply: {reply_pt.decode()}")
    assert reply_pt == alice_reply
    print()


def signing_demo():
    """Alice signs a document, Bob verifies it."""
    print("=== Digital Signatures ===")

    # Alice generates signing keys
    alice_signing = HybridSigner.generate_keypair()
    print("Alice generated signing keypair")

    # Alice signs a document
    document = b"I, Alice, authorize the transfer of 100 qubits to Bob."
    signature = HybridSigner.sign(document, alice_signing.private_key)
    print(f"Alice signed the document ({len(signature)} byte signature)")

    # Bob verifies using Alice's public key
    valid = HybridSigner.verify(document, signature, alice_signing.public_key)
    print(f"Bob verified Alice's signature: {valid}")
    assert valid

    # Tampered document fails verification
    tampered = b"I, Alice, authorize the transfer of 999 qubits to Bob."
    tampered_valid = HybridSigner.verify(tampered, signature, alice_signing.public_key)
    print(f"Tampered document verification: {tampered_valid}")
    assert not tampered_valid
    print()


def main():
    print(f"QBoost v{qboost.__version__}")
    print(f"Quantum ready: {qboost.is_quantum_ready()}\n")

    key_exchange_demo()
    signing_demo()

    print("All demos completed successfully.")


if __name__ == "__main__":
    main()
