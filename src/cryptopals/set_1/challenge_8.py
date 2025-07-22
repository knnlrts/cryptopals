#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "cryptography",
# ]
# ///

# Challenge 8: Detect AES in ECB mode
#
# In this file are a bunch of hex-encoded ciphertexts.
# One of them has been encrypted with ECB.
# Detect it.
# Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

from challenge_7 import decrypt_aes_128_ecb
from pathlib import Path


def main() -> None:
    key = b"YELLOW SUBMARINE"

    # The file path is relative to this script
    file_path = Path(__file__).parent / "challenge_8.txt"

    with open(file_path, "r") as f:
        for i, line in enumerate(f.readlines()):
            line = line.strip()
            print(f"Line {i}")
            print(f"Hex ciphertext: {line}")
            ciphertext = bytes.fromhex(line)
            print(f"Bytes ciphertext: {ciphertext}")
            plaintext = decrypt_aes_128_ecb(ciphertext, key)
            print(f"Decrypted plaintext: {plaintext}\n")


if __name__ == "__main__":
    main()
