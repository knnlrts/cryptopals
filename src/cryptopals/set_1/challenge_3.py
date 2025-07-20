#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# challenge 3: Single-byte XOR cipher
# The hex encoded string:
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.
# You can do this by hand. But don't: write code to do it for you.
# How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
# Achievement Unlocked:
# You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.

from typing import List, Tuple
import string


def plaintext_frequency(str_in: str) -> List[Tuple]:
    freq = [
        (char, str_in.lower().count(char))
        for char in set(str_in.lower())
        if char.isalpha()
    ]
    sorted_freq = sorted(freq, key=lambda x: x[1], reverse=True)
    return sorted_freq


if __name__ == "__main__":
    hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    plaintext = "The quick brown fox jumps over the lazy dog."

    print(plaintext_frequency(plaintext))

    print(bytes.fromhex(hex_str))
    print([format(b, "08b") for b in bytes.fromhex(hex_str)])

    for cipher in range(256):
        # print(cipher)
        xored_bytes = bytes([byte ^ cipher for byte in bytes.fromhex(hex_str)])
        print(xored_bytes)
