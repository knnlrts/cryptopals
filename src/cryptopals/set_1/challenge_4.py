#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# challenge 4: Detect single-character XOR
# One of the 60-character strings in this file has been encrypted by single-character XOR.
# Find it.
# (Your code from #3 should help.)


from challenge_3 import decrypt_single_byte_XOR_cipher

with open("src/cryptopals/set_1/challenge_4.txt", "r") as file:
    for line in file:
        cipher, decrypted_text = decrypt_single_byte_XOR_cipher(line)
        if cipher is not None:
            print(f"Hex string: {line.strip('\n')}")
            print(f"Cipher: {cipher} (as char: {chr(cipher) if cipher else 'None'})")
            print(f"Decrypted plaintext: {decrypted_text.encode('ascii')}")
