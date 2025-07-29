#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "cryptography",
# ]
# ///

# Challenge 7: AES in ECB mode
#
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
# Decrypt it. You know the key, after all.
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
# Do this with code.
# You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason.
# You'll need it a lot later on, and not just for attacking ECB.

# >>> b"YELLOW SUBMARINE".hex()
# openssl enc -d -aes-128-ecb -in src/cryptopals/set_1/challenge_7.txt -K 59454C4C4F57205355424D4152494E45 -a

import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_aes_128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts AES-128-ECB encrypted ciphertext."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main() -> None:
    """Main function to decrypt the file."""
    key = b"YELLOW SUBMARINE"

    # The file path is relative to this script
    file_path = Path(__file__).parent / "challenge_07.txt"

    with open(file_path, "rb") as f:
        base64_content = f.read()

    ciphertext = base64.b64decode(base64_content)

    plaintext_bytes = decrypt_aes_128_ecb(ciphertext, key)

    print(plaintext_bytes.decode("utf-8"))


if __name__ == "__main__":
    main()
