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
# pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

import os
import random

from src.cryptopals.set_01.challenge_07 import aes_128_encrypt_pycryptodome


def random_aes_128_key() -> bytes:
    return os.urandom(16)


def encryption_oracle(plaintext: bytes, key: bytes) -> bytes:
    prefix = os.urandom(random.randint(5, 10))
    postfix = os.urandom(random.randint(5, 10))
    appended_plaintext = prefix + plaintext + postfix
    if random.choice([True, False]):
        ciphertext, _ = aes_128_encrypt_pycryptodome(
            appended_plaintext, key, None, "ECB"
        )
    else:
        ciphertext, _ = aes_128_encrypt_pycryptodome(
            appended_plaintext, key, os.urandom(16), "CBC"
        )
    return ciphertext


if __name__ == "__main__":
    key = random_aes_128_key()
    plaintext = b"""CALL me Ishmael. Some years ago never mind how 
long precisely having little or no money in my purse, 
and nothing particular to interest me on shore, I thought 
I would sail about a little and see the watery part of the 
world. It is a way I have of driving off the spleen, and 
regulating the circulation. Whenever I find myself 
growing grim about the mouth ; whenever it is a damp, 
drizzly November in my soul ; whenever I find myself 
involuntarily pausing before coffin warehouses, and bring- 
ing up the rear of every funeral I meet ; and especially 
whenever my hypos get such an upper hand of me, that 
it requires a strong moral principle to prevent me from 
deliberately stepping into the street, and methodically 
knocking people's hats off then, I account it high time 
to get to sea as soon as I can. This is my substitute for 
pistol and ball. With a philosophical flourish Cato throws 
himself upon his sword ; I quietly take to the ship. 
There is nothing surprising in this. If they but knew 
it, almost all men in their degree, some time or other, 
cherish very nearly the same feelings toward the ocean 
with me."""

    print(encryption_oracle(plaintext, key))
