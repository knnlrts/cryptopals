#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "pycryptodome",
# ]
# ///

# Challenge 10: Implement CBC mode
#
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.
# In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
# The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.
#
# Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt
# (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.
#
# The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
#
# Don't cheat!
# Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?

import base64
from pathlib import Path
from Crypto.Cipher import AES


class CBC:
    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.key_size = len(key)
        self.iv = iv
        self.cipher = AES.new(key, AES.MODE_ECB)

    def _get_blocks(self, _bytes: bytes) -> list[bytes]:
        return [
            _bytes[i : i + self.key_size] for i in range(0, len(_bytes), self.key_size)
        ]

    def _xor_bytes(self, left: bytes, right: bytes) -> bytes:
        xored_bytes = b""
        for left_byte, right_byte in zip(left, right):
            xored_byte = bytes([left_byte ^ right_byte])
            xored_bytes += xored_byte
        return xored_bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        blocks = self._get_blocks(plaintext)
        previous = self.iv
        ciphertext = b""
        for block in blocks:
            xor_result = self._xor_bytes(previous, block)
            encrypted_block = self.cipher.encrypt(xor_result)
            ciphertext += encrypted_block
            previous = encrypted_block
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        blocks = self._get_blocks(ciphertext)
        previous = self.iv
        plaintext = b""
        for block in blocks:
            decrypted_block = self.cipher.decrypt(block)
            xor_result = self._xor_bytes(previous, decrypted_block)
            plaintext += xor_result
            previous = block
        return plaintext


if __name__ == "__main__":
    iv = bytes([0] * 16)
    key = b"YELLOW SUBMARINE"
    cipher = CBC(key, iv)

    file_path = Path(__file__).parent / "challenge_10.txt"
    with open(file_path, "rb") as f:
        b64content = f.read()

    content = base64.b64decode(
        b64content, validate=False
    )  # non-base64 alphabet characters such as newlines b'\n' are stripped

    plaintext = cipher.decrypt(content)
    print(plaintext)

    ciphertext = cipher.encrypt(plaintext)
    print(ciphertext)

    assert content == ciphertext, "CBC cipher implementation failed!!!"
