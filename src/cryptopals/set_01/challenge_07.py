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
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
# But do this with code.
#
# You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason.
# You'll need it a lot later on, and not just for attacking ECB.

# >>> b"YELLOW SUBMARINE".hex()
# openssl enc -d -aes-128-ecb -in src/cryptopals/set_1/challenge_7.txt -K 59454C4C4F57205355424D4152494E45 -a

import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_aes_128_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts AES-128-ECB encrypted ciphertext using the cryptography library."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# AES-128 in ECB (Electronic Codebook) mode is one of the simplest block cipher modes of operation.
# AES (Advanced Encryption Standard) is a symmetric encryption algorithm, established in 2001 as a replacement for DES (Data Encryption Standard).
# AES-128 always uses a 128-bit (16 byte) key/128-bit (16 byte) block size and 10 rounds of encryption/decryption.
# Each block is encrypted independently. The same plaintext block always produces same ciphertext block (with same key). No initialization vector (IV) required
#
# Encryption Process
# 1. Padding: If the plaintext isn't a multiple of 16 bytes, pad it (commonly using PKCS#7 padding)
# 2. Block Division: Split the padded plaintext into 16-byte blocks
# 3. Individual Block Encryption: For each 16-byte block:
# Ciphertext_block[i] = AES_Encrypt(Plaintext_block[i], Key)
# 4. Concatenation: Join all ciphertext blocks together
#
# Decryption Process
# 1. Block Division: Split ciphertext into 16-byte blocks
# 2. Individual Block Decryption: For each block:
# Plaintext_block[i] = AES_Decrypt(Ciphertext_block[i], Key)
# 3. Concatenation: Join all plaintext blocks
# 4. Remove Padding: Strip the padding from the final block
#
# ECB mode has significant weaknesses:
# - Pattern Preservation: identical plaintext blocks produce identical ciphertext blocks, revealing patterns
# - Block Rearrangement: blocks can be rearranged without detection; there is no integrity protection to ensure the ciphertext hasn't been tampered with
# - No Diffusion: changes in one block don't affect other blocks
# Therefore, ECB is generally not recommended for encrypting data longer than one block.
# The classic demonstration of ECB's weakness is encrypting an image - patterns in the original image remain visible in the encrypted version
# because identical pixel blocks encrypt to identical ciphertext blocks.


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
