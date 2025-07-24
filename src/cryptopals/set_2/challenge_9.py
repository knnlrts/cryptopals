#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 9: Implement PKCS#7 padding
#
# A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext.
# But we almost never want to transform a single block; we encrypt irregularly-sized messages.
#
# One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize.
# The most popular padding scheme is called PKCS#7.
# So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,
# "YELLOW SUBMARINE"
# ... padded to 20 bytes would be:
# "YELLOW SUBMARINE\x04\x04\x04\x04"


def pad_cipher_to_blocksize(cipher: bytes, blocksize: int, fill_byte: int = 4) -> bytes:
    assert (
        len(cipher) < blocksize
    ), "Cipher length should be smaller than blocksize for padding"
    assert fill_byte < 256 and fill_byte >= 0, "fill_byte needs to be a valid byte"
    return cipher.ljust(blocksize, bytes([fill_byte]))


if __name__ == "__main__":
    cipher = "YELLOW SUBMARINE"
    block_size = 20

    padded_cipher = pad_cipher_to_blocksize(cipher.encode(), block_size)
    assert (
        padded_cipher == b"YELLOW SUBMARINE\x04\x04\x04\x04"
    ), f"Expected {padded_cipher} to be equal to b'YELLOW SUBMARINE\x04\x04\x04\x04'"
    print(padded_cipher)

    # bunchaBytes = bytes([4, 5, 10, 15, 20, 65])
    # print(bunchaBytes)
