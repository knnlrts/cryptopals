#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 3: Single-byte XOR cipher
#
# The hex encoded string:
#   1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
# How? Devise some method for "scoring" a piece of English plaintext.
# Character frequency is a good metric.
# Evaluate each output and choose the one with the best score.
#
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


def score_text(text: str) -> float:
    """Score text based on character frequency analysis."""
    # Expected frequency of characters in English text
    # https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
    english_freq = {
        " ": 0.15,
        "e": 0.1202,
        "t": 0.0910,
        "a": 0.0812,
        "o": 0.0768,
        "i": 0.0731,
        "n": 0.0695,
        "s": 0.0628,
        "r": 0.0602,
        "h": 0.0592,
        "d": 0.0432,
        "l": 0.0398,
        "u": 0.0288,
        "c": 0.0271,
        "m": 0.0261,
        "f": 0.0230,
        "y": 0.0211,
        "w": 0.0209,
        "g": 0.0203,
        "p": 0.0182,
        "b": 0.0149,
        "v": 0.0111,
        "k": 0.0069,
        "x": 0.0017,
        "q": 0.0011,
        "j": 0.0010,
        "z": 0.0007,
    }

    score = 0
    text_lower = text.lower()

    # Score based on character frequency
    for char in text_lower:
        if char in english_freq:
            score += english_freq[char]
        elif char in string.printable:
            score += 0.001  # Small bonus for printable characters
        else:
            score -= 0.01  # Penalty for non-printable characters

    return score


def single_byte_xor_decrypt(ciphertext: bytes) -> Tuple[int | None, str | None, float]:
    """Find the best single-byte XOR key for the given ciphertext."""
    best_score = -float("inf")
    best_key = None
    best_plaintext = None

    for key in range(256):
        # Try XOR with this key
        plaintext = bytes([byte ^ key for byte in ciphertext])

        try:
            # Try to decode as ASCII/UTF-8
            text = plaintext.decode("ascii")
            score = score_text(text)

            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = text
        except UnicodeDecodeError:
            # If decoding fails, skip this key
            continue

    return best_key, best_plaintext, best_score


if __name__ == "__main__":
    hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    plaintext = "Cooking MC's like a pound of bacon"

    print(plaintext_frequency(plaintext))

    assert single_byte_xor_decrypt(bytes.fromhex(hex_str))[1] == plaintext

    cipher, decrypted_text, score = single_byte_xor_decrypt(bytes.fromhex(hex_str))
    print(f"Ciphertext hex string: {hex_str}")
    print(f"Ciphertext bytes: {bytes.fromhex(hex_str)}")
    print(
        f"Single byte cipher: {cipher} (as char: {chr(cipher) if cipher is not None else cipher}), frequency score: {score}"
    )
    print(f"Decrypted ciphertext: {decrypted_text}")
