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

hex_str1 = "1c0111001f010100061a024b53535009181c"
hex_str2 = "686974207468652062756c6c277320657965"


def hex_xor(hex_1: str, hex_2: str) -> str:
    assert len(hex_1) == len(hex_2)
    raw_1 = int(hex_1, 16)
    raw_2 = int(hex_2, 16)
    xor = raw_1 ^ raw_2
    return f"{xor:x}"


hex_out = "746865206b696420646f6e277420706c6179"
print(hex_xor(hex_str1, hex_str2))

assert hex_xor(hex_str1, hex_str2) == hex_out
print("OK!")
