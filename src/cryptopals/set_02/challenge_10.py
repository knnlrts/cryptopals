#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 10: Implement CBC mode
#
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.
# In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
# The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.
#
# Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
# (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.
#
# The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
#
# Don't cheat!
# Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?

import base64
from pathlib import Path
from ..set_01.challenge_07 import (
    aes_128_encrypt_cryptography,
    aes_128_encrypt_pycryptodome,
    aes_128_decrypt_cryptography,
    aes_128_decrypt_pycryptodome,
)

iv = bytes([0] * 16)
key = b"YELLOW SUBMARINE"

file_path = Path(__file__).parent / "challenge_10.txt"
with open(file_path, "rb") as f:
    b64content = f.read()

content = base64.b64decode(b64content)

print(content)
print(len(content) % 16)

# decrypted = aes_128_decrypt_pycryptodome(content, key, iv, "CBC")

encrypted_blocks = [content[i : i + len(key)] for i in range(0, len(content), len(key))]

plaintext_blocks = []
previous = iv
for encrypted_block in encrypted_blocks:
    decrypted_block = aes_128_decrypt_cryptography(encrypted_block, key, None, "ECB")
    plaintext_block = bytes([a ^ b for a, b in zip(decrypted_block, previous)])
    plaintext_blocks.append(plaintext_block)
    previous = encrypted_block

print(plaintext_blocks)
