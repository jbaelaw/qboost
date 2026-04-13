import qboost
from qboost import HybridSigner, QBoostPublicKey


def key_exchange_demo():
    alice = qboost.generate_keypair()
    alice_pub_export = alice.export_public_key()
    print(f"alice keypair id={alice.key_id}")

    alice_pub = QBoostPublicKey.from_export(alice_pub_export)
    ct = qboost.encrypt(b"rendezvous at 0900", alice_pub)
    pt = qboost.decrypt(ct, alice)
    print(f"bob->alice: {pt.decode()}")

    bob = qboost.generate_keypair()
    bob_pub = QBoostPublicKey.from_export(bob.export_public_key())
    reply_ct = qboost.encrypt(b"ack", bob_pub)
    reply_pt = qboost.decrypt(reply_ct, bob)
    print(f"alice->bob: {reply_pt.decode()}")


def signing_demo():
    kp = HybridSigner.generate_keypair()
    doc = b"transfer 500 to acct 8812"
    sig = HybridSigner.sign(doc, kp.private_key)
    print(f"signature: {len(sig)} bytes")

    assert HybridSigner.verify(doc, sig, kp.public_key)
    print(f"valid: True")

    tampered = b"transfer 500000 to acct 8812"
    assert not HybridSigner.verify(tampered, sig, kp.public_key)
    print(f"tampered: rejected")


def main():
    print(f"qboost v{qboost.__version__} (pq={qboost.is_quantum_ready()})\n")
    key_exchange_demo()
    print()
    signing_demo()


if __name__ == "__main__":
    main()
