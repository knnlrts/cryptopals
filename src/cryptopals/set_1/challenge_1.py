#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# challenge 1: convert hex to base64

import base64

input = "49276D206B696C6C696E6720796F757220627261696E206C696B65206120706F69736F6E6F7573206D757368726F6F6D"
output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

b = bytes.fromhex(input)
print(b)
print(type(b))

b64 = base64.b64encode(b).decode("ascii")
print(b64)

assert b64 == output
