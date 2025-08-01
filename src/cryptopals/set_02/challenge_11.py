#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 11: An ECB/CBC detection oracle
#
# Now that you have ECB and CBC working:
# Write a function to generate a random AES key; that's just 16 random bytes.
# Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
#
# The function should look like:
# encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER]
#
# Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC).
# Use rand(2) to decide which to use.
#
# Detect the block cipher mode the function is using each time. You should end up with a piece of code that,
# pointed at a black box that might be encrypting ECB or CBC, tells you which one is happening.

import os
import random

from src.cryptopals.set_01.challenge_07 import aes_128_encrypt_pycryptodome


def random_aes_128_key() -> bytes:
    return os.urandom(16)


def encryption_oracle(plaintext: bytes, key: bytes) -> tuple[bytes, str]:
    prefix = os.urandom(random.randint(5, 10))
    postfix = os.urandom(random.randint(5, 10))
    appended_plaintext = prefix + plaintext + postfix
    if random.choice([True, False]):
        ciphertext, _ = aes_128_encrypt_pycryptodome(
            appended_plaintext, key, None, "ECB"
        )
        answer = "ECB"
    else:
        iv = os.urandom(16)
        ciphertext, _ = aes_128_encrypt_pycryptodome(appended_plaintext, key, iv, "CBC")
        answer = "CBC"
    return ciphertext, answer


def detect_cipher_mode(ciphertext: bytes) -> str:
    blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
    unique_blocks = len(set(blocks))
    return "ECB" if unique_blocks != len(blocks) else "CBC"


if __name__ == "__main__":
    key = random_aes_128_key()
    _input = bytes([0] * 60)
    print(f"Input bytes: {_input}")
    ciphertext, answer = encryption_oracle(_input, key)
    print(f"Ciphertext: {ciphertext}")
    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Generated: {answer} cipher mode")
    detected = detect_cipher_mode(ciphertext)
    print(f"Detected:  {detected} cipher mode")
    assert answer == detected, "Cipher mode detection failed!"
