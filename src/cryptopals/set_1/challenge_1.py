#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# challenge 1: convert hex to base64

import base64

hex_string = "49276D206B696C6C696E6720796F757220627261696E206C696B65206120706F69736F6E6F7573206D757368726F6F6D"
EXPECTED_BASE64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

raw_bytes = bytes.fromhex(hex_string)
print(raw_bytes)
print(type(raw_bytes))
print(f"{int(hex_string, 16):b}")
print(f"{int(hex_string, 16):o}")
print(f"{int(hex_string, 16):x}")

assert f"{int(hex_string, 16):x}".upper() == hex_string

encoded_base64 = base64.b64encode(raw_bytes).decode("ascii")
print(encoded_base64)
print(type(encoded_base64))

assert encoded_base64 == EXPECTED_BASE64
print("OK!")
