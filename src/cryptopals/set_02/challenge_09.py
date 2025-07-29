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


def pad_text_to_block_cipher_size(text: bytes, block_cipher_size: int) -> bytes:
    assert (
        0 < block_cipher_size <= 255
    ), "PKCS#7 only supports block sizes up to 255 bytes"

    # If the message is already a multiple of the block size, you must add a full block of padding
    padding_needed = block_cipher_size - (len(text) % block_cipher_size)
    # print(padding_needed)

    # Each padding byte contains the number of padding bytes added
    padding_byte = (
        padding_needed  # % 256  # Wrap around for large values (non-standard!)
    )
    # print(padding_byte)

    padding = bytes([padding_byte]) * padding_needed
    padded_text = text + padding
    # print(len(padded_text))

    return padded_text


if __name__ == "__main__":
    text = "YELLOW SUBMARINE"
    block_size = 20

    padded_text = pad_text_to_block_cipher_size(text.encode(), block_size)
    assert (
        padded_text == b"YELLOW SUBMARINE\x04\x04\x04\x04"
    ), f"Expected {padded_text} to be equal to b'YELLOW SUBMARINE\x04\x04\x04\x04'"
    print(padded_text)

    # buncha_bytes = bytes(
    #     [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 65]
    # )
    # print(buncha_bytes)
