#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# Challenge 6: Break repeating-key XOR
#
# It is officially on, now:
# This challenge isn't conceptually hard, but it involves actual error-prone coding.
# The other challenges in this set are there to bring you up to speed.
# This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.
#
# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
# Decrypt it.
#
# Here's how:
# 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
# 2. Write a function to compute the edit distance/Hamming distance between two strings.
#    The Hamming distance is just the number of differing bits. The distance between:
#      this is a test
#    and
#      wokka wokka!!!
#    is 37. Make sure your code agrees before you proceed.
# 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
#    and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
# 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps
#    with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
# 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
# 6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the
#    second byte of every block, and so on.
# 7. Solve each block as if it was single-character XOR. You already have code to do this.
# 8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key
#    XOR key byte for that block. Put them together and you have the key.
#
# This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere")
# statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break
# it than can actually break it, and a similar technique breaks something much more important.
#
# No, that's not a mistake:
# We get more tech support questions for this challenge than any of the other ones. We promise,
# there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

from challenge_1 import base64_to_hex, hex_to_base64
from challenge_3 import decrypt_single_byte_XOR_cipher


# calculate the hamming disctance
def calculate_hamming_distance(bytes_1: bytes, bytes_2: bytes) -> int:
    # str_1_bytes = str_1.encode()
    # print(str_1_bytes)
    # print([format(byte, "08b") for byte in str_1_bytes])
    # str_2_bytes = str_2.encode()
    # print(str_2_bytes)
    # print([format(byte, "08b") for byte in str_2_bytes])
    if len(bytes_1) != len(bytes_2):
        raise ValueError("Byte arrays must be of equal length.")
    xor_bytes = bytes([a ^ b for (a, b) in zip(bytes_1, bytes_2)])
    # print(xor_bytes)
    # print([format(byte, "08b") for byte in xor_bytes])
    hamming_distance = sum([byte.bit_count() for byte in xor_bytes])
    # print(hamming_distance)
    return hamming_distance


def decrypt_repeating_key_XOR(base64_str: str, max_keysize: int, blocks: int):
    # print(base64_str)
    hex_str_in = base64_to_hex(base64_str)
    # print(hex_str_in)
    bytes_in = bytes.fromhex(hex_str_in)
    # print(bytes_in)
    # test keysizes between 2 bytes and 40 bytes (1 byte = 2 hex digits)
    KEYSIZES = list(range(2, max_keysize))
    # KEYSIZES = list(range(4, 81, 2))
    # print(KEYSIZES)

    keysize_hamming = dict()

    for keysize in KEYSIZES:
        # get the first KEYSIZE blocks
        # print(f"Keysize: {int(keysize / 2)} bytes")
        # hex_strings = [
        #     hex_str_in[keysize * i : keysize * (i + 1)] for i in range(blocks)
        # ]
        byte_blocks = [bytes_in[keysize * i : keysize * (i + 1)] for i in range(blocks)]
        # print(byte_blocks)
        # for byte_block in byte_blocks:
        #     print(len(byte_block))

        # print(f"{blocks} first {int(keysize / 2)} byte hex strings: {hex_strings}")
        # print(f"{blocks} first {int(keysize)}-byte blocks: {byte_blocks}")

        # get pairwise hamming distances
        # hamming_distances = [
        #     calculate_hamming_distance(bytes.fromhex(i), bytes.fromhex(j))
        #     for i, j in zip(hex_strings, hex_strings[1:])
        # ]
        hamming_distances = [
            calculate_hamming_distance(i, j)
            for i, j in zip(byte_blocks, byte_blocks[1:])
        ]
        # print(f"Pairwise hamming distances: {hamming_distances}")

        # get normalized hamming distance
        normalized_hamming = (
            (sum(hamming_distances) / keysize)
            if blocks == 2
            else (sum(hamming_distances) / (len(hamming_distances) * keysize))
        )
        # print(f"Normalized hamming distance: {normalized_hamming}\n")
        # normalized_hamming = (
        #     (sum(hamming_distances) / keysize)
        #     if blocks == 2
        #     else (sum(hamming_distances) / len(hamming_distances))
        # )
        # print(f"Normalized hamming distance: {normalized_hamming}\n")

        keysize_hamming[keysize] = normalized_hamming

    # sort the keysizes by lowest normalized hamming distance
    sorted_keysize_hamming = sorted(keysize_hamming.items(), key=lambda x: x[1])
    print(
        f"Keysizes sorted by lowest normalized hamming distance: {sorted_keysize_hamming}\n"
    )

    # continue with the 3 lowest hamming distance keysizes
    for keysize, _ in sorted_keysize_hamming:
        print(f"Byte keysize: {keysize}")
        # break the ciphertext into blocks of keysize length
        byte_blocks = [
            bytes_in[i : i + keysize] for i in range(0, len(bytes_in), keysize)
        ]
        # ensure all byte blocks are equal length
        byte_blocks = [
            byte_block for byte_block in byte_blocks if len(byte_block) == keysize
        ]
        # print(byte_blocks)
        # hex_chunks = [
        #     hex_str_in[i : i + keysize] for i in range(0, len(hex_str_in), keysize)
        # ]
        # print(hex_chunks)

        # Split each hex string into 2-character chunks (bytes)
        # hex_bytes_per_chunk = [
        #     [s[i : i + 2] for i in range(0, len(s), 2)] for s in hex_chunks
        # ]
        # print(hex_bytes_per_chunk)

        # Transpose the list of lists (matrix)
        transposed = list(zip(*byte_blocks))
        # print(transposed)
        # transposed = list(zip(*hex_bytes_per_chunk))

        # Join each group of bytes to form new hex strings
        transposed_byte_blocks = [bytes(group) for group in transposed]
        # print(transposed_byte_blocks)
        # transposed_hex_strings = ["".join(group) for group in transposed]
        # print(transposed_hex_strings)

        # break single-byte XOR
        for bb in transposed_byte_blocks:
            # print(bb)
            cipher, text = decrypt_single_byte_XOR_cipher(bb.hex())
            print(
                f"(cipher: {chr(cipher) if cipher is not None else 'no cipher found'}, decrypted text: {text.encode() if text is not None else 'no text'})"
            )
        # for hex_str in transposed_hex_strings:
        #     # print(hex_str)
        #     cipher, text = decrypt_single_byte_XOR_cipher(hex_str)
        #     print(
        #         f"{hex_str} : (cipher: {chr(cipher) if cipher is not None else 'no cipher found'}, decrypted text: {text if text is not None else 'no text'})"
        #     )


if __name__ == "__main__":
    str_1 = "this is a test"
    str_2 = "wokka wokka!!!"

    assert calculate_hamming_distance(str_1.encode(), str_2.encode()) == 37

    hex_str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    base64_str = hex_to_base64(hex_str)
    decrypt_repeating_key_XOR(base64_str, 11, 4)

    base64_str = """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"""

    decrypt_repeating_key_XOR(base64_str, 41, 2)
