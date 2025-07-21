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

from challenge_1 import base64_to_hex
from challenge_3 import decrypt_single_byte_XOR_cipher


# calculate the hamming disctance
def calculate_hamming_distance(str_1: str, str_2: str) -> int:
    str_1_bytes = str_1.encode()
    # print(str_1_bytes)
    # print([format(byte, "08b") for byte in str_1_bytes])
    str_2_bytes = str_2.encode()
    # print(str_2_bytes)
    # print([format(byte, "08b") for byte in str_2_bytes])
    xor_bytes = bytes([a ^ b for (a, b) in zip(str_1_bytes, str_2_bytes)])
    # print(xor_bytes)
    # print([format(byte, "08b") for byte in xor_bytes])
    hamming_distance = sum([byte.bit_count() for byte in xor_bytes])
    # print(hamming_distance)
    return hamming_distance


def decrypt_repeating_key_XOR(base64_str: str, blocks: int):
    hex_str = base64_to_hex(base64_str)
    # test keysizes between 2 bytes and 40 bytes (1 byte = 2 hex digits)
    KEYSIZES = list(range(4, 81, 2))
    print(KEYSIZES)

    keysize_hamming = dict()

    for keysize in KEYSIZES:
        # get the first KEYSIZE blocks
        print(f"Keysize: {int(keysize / 2)} bytes")
        hex_strings = [hex_str[keysize * i : keysize * (i + 1)] for i in range(blocks)]
        print(f"{blocks} first {int(keysize / 2)} byte hex strings: {hex_strings}")
        # get pairwise hamming distances
        hamming_distances = [
            calculate_hamming_distance(i, j)
            for i, j in zip(hex_strings, hex_strings[1:])
        ]
        print(f"Pairwise hamming distances: {hamming_distances}")
        normalized_hamming = (
            (sum(hamming_distances) / keysize)
            if blocks == 2
            else (sum(hamming_distances) / len(hamming_distances))
        )
        # get normalized hamming distance
        print(f"Normalized hamming distance: {normalized_hamming}\n")
        keysize_hamming[keysize] = normalized_hamming

    # sort the keysizes by lowest hamming distance
    sorted_keysize_hamming = sorted(keysize_hamming.items(), key=lambda x: x[1])
    print(
        f"Keysizes sorted by lowest normalized hamming distance: {sorted_keysize_hamming}\n"
    )

    # continue with the 3 lowest hamming distance keysizes
    for keysize, _ in sorted_keysize_hamming[:3]:
        # break the ciphertext into blocks of keysize length
        chunks = [
            # bytes.fromhex(hex_str[i : i + keysize])
            hex_str[i : i + keysize]
            for i in range(0, len(hex_str), keysize)
        ]
        print(chunks)

        # transpose the blocks
        # Split each hex string into 2-character chunks (bytes)
        split_bytes = [[s[i : i + 2] for i in range(0, len(s), 2)] for s in chunks]
        # Transpose the list of lists (matrix)
        transposed = list(zip(*split_bytes))
        # Join each group of bytes to form new hex strings
        transposed_hex_strings = ["".join(group) for group in transposed]
        print(transposed_hex_strings)

        # break single-byte XOR
        for hex_str in transposed_hex_strings:
            cipher, decrypted_text = decrypt_single_byte_XOR_cipher(hex_str)
            print(cipher)
            print(decrypted_text)


if __name__ == "__main__":
    str_1 = "this is a test"
    str_2 = "wokka wokka!!!"

    base64_str = """HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS
BgBHVBwNRU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYG
DBoXQR0BUlQwXwAgEwoFR08SSAhFTmU+Fgk4RQYFCBpGB08fWXh+amI2DB0P
QQ1IBlUaGwAdQnQEHgFJGgkRAlJ6f0kASDoAGhNJGk9FSA8dDVMEOgFSGQEL
QRMGAEwxX1NiFQYHCQdUCxdBFBZJeTM1CxsBBQ9GB08dTnhOSCdSBAcMRVhI
CEEATyBUCHQLHRlJAgAOFlwAUjBpZR9JAgJUAAELB04CEFMBJhAVTQIHAh9P
G054MGk2UgoBCVQGBwlTTgIQUwg7EAYFSQ8PEE87ADpfRyscSWQzT1QCEFMa
TwUWEXQMBk0PAg4DQ1JMPU4ALwtJDQhOFw0VVB1PDhxFXigLTRkBEgcKVVN4
Tk9iBgELR1MdDAAAFwoFHww6Ql5NLgFBIg4cSTRWQWI1Bk9HKn47CE8BGwFT
QjcEBx4MThUcDgYHKxpUKhdJGQZZVCFFVwcDBVMHMUV4LAcKQR0JUlk3TwAm"""

    assert calculate_hamming_distance(str_1, str_2) == 37

    decrypt_repeating_key_XOR(base64_str, 2)
