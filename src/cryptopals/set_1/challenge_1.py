#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# challenge 1: Convert hex to base64
# The string:
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# Should produce:
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
# So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
# Cryptopals Rule:
# Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.


import base64

test_hex_string = "49276D206B696C6C696E6720796F757220627261696E206C696B65206120706F69736F6E6F7573206D757368726F6F6D"
test_base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# print(f"{int(hex_string, 16):b}")
# print(f"{int(hex_string, 16):o}")
# print(f"{int(hex_string, 16):x}")


def hex_to_base64(hex_str: str) -> str:
    assert len(hex_str) % 2 == 0
    raw_bytes = bytes.fromhex(hex_str)
    print(raw_bytes)
    print([format(byte, "08b") for byte in raw_bytes])
    encoded_base64 = base64.b64encode(raw_bytes).decode()
    print(encoded_base64)
    return encoded_base64


def base64_to_hex(base64_str: str) -> str:
    raw_bytes = base64.b64decode(base64_str)
    print(raw_bytes)
    print([bin(byte)[2:].zfill(8) for byte in raw_bytes])
    hex_str = raw_bytes.hex()
    print(hex_str)
    return hex_str


assert hex_to_base64(test_hex_string) == test_base64_string
assert base64_to_hex(test_base64_string) == test_hex_string.lower()
