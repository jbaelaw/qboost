import argparse
import sys
from pathlib import Path

import qboost


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    plaintext = input_path.read_bytes()
    print(f"Read {len(plaintext)} bytes from {input_path}")

    ciphertext = qboost.encrypt_symmetric(plaintext, password)
    output_path.write_bytes(ciphertext)
    print(f"Encrypted and wrote {len(ciphertext)} bytes to {output_path}")


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    ciphertext = input_path.read_bytes()
    print(f"Read {len(ciphertext)} bytes from {input_path}")

    try:
        plaintext = qboost.decrypt_symmetric(ciphertext, password)
    except qboost.DecryptionError:
        print("Error: Decryption failed. Wrong password or corrupted file.", file=sys.stderr)
        sys.exit(1)

    output_path.write_bytes(plaintext)
    print(f"Decrypted and wrote {len(plaintext)} bytes to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files with QBoost")
    parser.add_argument("action", choices=["encrypt", "decrypt"])
    parser.add_argument("input", type=Path, help="Input file path")
    parser.add_argument("output", type=Path, help="Output file path")
    parser.add_argument("--password", required=True, help="Encryption password")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Error: {args.input} not found.", file=sys.stderr)
        sys.exit(1)

    if args.action == "encrypt":
        encrypt_file(args.input, args.output, args.password)
    else:
        decrypt_file(args.input, args.output, args.password)


if __name__ == "__main__":
    main()
