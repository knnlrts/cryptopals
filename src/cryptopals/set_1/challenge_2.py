#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# challenge 2: fixed XOR
# Write a function that takes two equal-length buffers and produces their XOR combination.
# If your function works properly, then when you feed it the string:
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
# 686974207468652062756c6c277320657965
# ... should produce:
# 746865206b696420646f6e277420706c6179


def fixed_xor(hex_1: str, hex_2: str) -> str:
    assert len(hex_1) == len(hex_2)

    raw_bytes_1 = bytes.fromhex(hex_1)
    print(hex_1)
    print(raw_bytes_1)
    print([format(byte, "08b") for byte in raw_bytes_1])

    raw_bytes_2 = bytes.fromhex(hex_2)
    print(hex_2)
    print(raw_bytes_2)
    print([format(byte, "08b") for byte in raw_bytes_2])

    xored_bytes = bytes([a ^ b for (a, b) in zip(raw_bytes_1, raw_bytes_2)])
    print(xored_bytes)
    print([format(byte, "08b") for byte in xored_bytes])

    xored_hex_str = xored_bytes.hex()
    print(xored_hex_str)

    return xored_hex_str


if __name__ == "__main__":
    hex_str1 = "1c0111001f010100061a024b53535009181c"
    hex_str2 = "686974207468652062756c6c277320657965"
    hex_out = "746865206b696420646f6e277420706c6179"

    assert fixed_xor(hex_str1, hex_str2) == hex_out
