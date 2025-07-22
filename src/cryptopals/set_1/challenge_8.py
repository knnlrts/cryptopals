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
