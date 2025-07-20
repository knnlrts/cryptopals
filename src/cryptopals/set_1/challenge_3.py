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

# https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
weights = {
    " ": 13.0,
    "e": 12.02,
    "t": 9.10,
    "a": 8.12,
    "o": 7.68,
    "i": 7.31,
    "n": 6.95,
    "s": 6.28,
    "r": 6.02,
    "h": 5.92,
    "d": 4.32,
    "l": 3.98,
    "u": 2.88,
    "c": 2.71,
    "m": 2.61,
    "f": 2.30,
    "y": 2.11,
    "w": 2.09,
    "g": 2.03,
    "p": 1.82,
    "b": 1.49,
    "v": 1.11,
    "k": 0.69,
    "x": 0.17,
    "q": 0.11,
    "j": 0.10,
    "z": 0.07,
}


def plaintext_frequency(str_in: str) -> List[Tuple]:
    freq = [
        (char, str_in.lower().count(char))
        for char in set(str_in.lower())
        if char.isalpha()
    ]
    sorted_freq = sorted(freq, key=lambda x: x[1], reverse=True)
    return sorted_freq


def decrypt_single_byte_XOR_cipher(hex_string: str) -> Tuple:
    data = bytes.fromhex(hex_string)
    printable_chars = set(string.printable.encode("ascii"))
    best_score = float("-inf")
    best_cipher = None
    best_text = None

    # brute force each byte (0-255)
    for cipher in range(256):
        xored_bytes = bytes([byte ^ cipher for byte in data])
        if all(byte in printable_chars for byte in xored_bytes):
            # print(f"Candidate cipher: {cipher} = {chr(cipher)}")
            # print(f"Candidate XOR'ed bytes: {xored_bytes}")

            candidate_text = xored_bytes.decode("ascii")
            score = 0

            for char in candidate_text:
                char_lower = char.lower()
                if char_lower in weights:
                    score += weights[char_lower]

            # print(f"Frequency score: {score}")

            if score > best_score:
                best_score = score
                best_cipher = cipher
                best_text = candidate_text

    return best_cipher, best_text


if __name__ == "__main__":
    hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    plaintext = "Cooking MC's like a pound of bacon"

    print(plaintext_frequency(plaintext))

    assert decrypt_single_byte_XOR_cipher(hex_str)[1] == plaintext

    cipher, decrypted_text = decrypt_single_byte_XOR_cipher(hex_str)
    print(f"Hex string: {hex_str}")
    print(f"Cipher: {cipher} (as char: {chr(cipher)})")
    print(f"Decrypted plaintext: {decrypted_text}")
