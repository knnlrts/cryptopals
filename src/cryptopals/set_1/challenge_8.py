#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 8: Detect AES in ECB mode
#
# In this file are a bunch of hex-encoded ciphertexts.
# One of them has been encrypted with ECB.
# Detect it.
# Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

from typing import Dict, List
from pathlib import Path


def score_repeated_blocks(ciphertext: bytes, blocksize: int) -> int:
    blocks = [
        ciphertext[i : i + blocksize]
        for i in range(0, len(ciphertext), blocksize)
        if len(ciphertext[i : i + blocksize]) == blocksize
    ]
    return len(blocks) - len(set(blocks))


def detect_ecb_encryption(lines: List, keysize: int = 16) -> Dict:
    best = {"line": b"", "score": -1, "index": -1}
    for line_index, line in enumerate(lines):
        ciphertext_bytes = bytes.fromhex(line.strip())
        score = score_repeated_blocks(ciphertext_bytes, keysize)
        if score > best["score"]:
            best["line"] = line
            best["score"] = score
            best["index"] = line_index
    return best


def main() -> None:
    key = b"YELLOW SUBMARINE"
    keysize = len(key)
    # keysize = 2

    # The file path is relative to this script
    file_path = Path(__file__).parent / "challenge_8.txt"

    with open(file_path, "r") as f:
        result = detect_ecb_encryption(f.readlines(), keysize)
        if result["score"] > 0:
            print(
                f"ECB encryption detected: the same {keysize}-byte block was repeated {result["score"]} times"
            )
            print(f"Line number: {result["index"]}")
            print(f"Hex-encoded ciphertext: {result["line"]}")


if __name__ == "__main__":
    main()
