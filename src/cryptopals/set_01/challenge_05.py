#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 5: Implement repeating-key XOR
#
# Here is the opening stanza of an important work of the English language:
#   Burning 'em, if you ain't quick and nimble
#   I go crazy when I hear a cymbal
# Encrypt it, under the key "ICE", using repeating-key XOR.
#
# In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be
# XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
#
# It should come out to:
#   0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a31243
#   33a653e2b2027630c692b20283165286326302e27282f
#
# Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file.
# Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.


def encrypt_repeating_key_XOR_cipher(plaintext: str, cipher: str) -> str:
    plaintext_bytes = plaintext.encode()
    print(f"Plaintext: {plaintext_bytes}")
    cipher_bytes = cipher.encode()
    print(f"Cipher: {cipher_bytes}")
    plaintext_len = len(plaintext_bytes)
    # print(plaintext_len)
    cipher_len = len(cipher_bytes)
    # print(cipher_len)
    cipher_key = (
        cipher_bytes * int(plaintext_len / cipher_len)
        + cipher_bytes[: int(plaintext_len % cipher_len)]
    )
    print(f"Cipher key: {cipher_key}")

    xored_bytes = bytes([a ^ b for (a, b) in zip(plaintext_bytes, cipher_key)])
    print(f"Ciphertext bytes (repeating XOR cipher): {xored_bytes}")
    xored_hex_str = xored_bytes.hex()
    print(f"Ciphertext hex (repeating XOR cipher): {xored_hex_str}")

    return xored_hex_str


if __name__ == "__main__":
    plaintext_1 = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    cipher = "ICE"
    hex_str_1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    assert encrypt_repeating_key_XOR_cipher(plaintext_1, cipher) == hex_str_1

    encrypt_repeating_key_XOR_cipher(
        "This is my super-secret message\r\nwith new lines...", "LOL"
    )
