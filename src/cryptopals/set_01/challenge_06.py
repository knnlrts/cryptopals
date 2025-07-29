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

from challenge_01 import base64_to_hex
from challenge_03 import single_byte_xor_decrypt
from typing import List, Tuple


def hamming_distance(s1: bytes, s2: bytes) -> int:
    """Calculate the Hamming distance between two byte strings."""
    if len(s1) != len(s2):
        raise ValueError("Byte arrays must be of equal length")

    distance = 0
    for b1, b2 in zip(s1, s2):
        # XOR the bytes and count the number of 1s in the result
        xor_result = b1 ^ b2
        distance += bin(xor_result).count("1")

    return distance


def find_keysize(
    ciphertext: bytes,
    min_keysize: int = 2,
    max_keysize: int = 40,
) -> List[Tuple[int, int]]:
    """Find the most likely key size using Hamming distance."""
    normalized_averaged_distances = []

    for keysize in range(min_keysize, max_keysize + 1):
        # Take multiple pairs of blocks for better accuracy
        distances = []

        # Use up to 4 pairs of blocks
        num_blocks = min(4, len(ciphertext) // (keysize * 2))

        for i in range(num_blocks):
            start1 = i * keysize * 2
            start2 = start1 + keysize

            block1 = ciphertext[start1 : start1 + keysize]
            block2 = ciphertext[start2 : start2 + keysize]

            if len(block1) == keysize and len(block2) == keysize:
                distance = hamming_distance(block1, block2)
                # normalize the found distance by dividing by the keysize
                distances.append(distance / keysize)

        if distances:
            # take the average of the normalized distances
            avg_distance = sum(distances) / len(distances)
            normalized_averaged_distances.append((keysize, avg_distance))

    # Sort by normalized distance and return top candidates
    normalized_averaged_distances.sort(key=lambda x: x[1])
    # print(f"Sorted averaged normalized distances: {normalized_averaged_distances}")
    return normalized_averaged_distances  # Return sorted averaged normalized hamming distances


def break_repeating_key_xor(
    ciphertext: bytes, top_keysize_candidates: int = 3
):  # -> Tuple[bytes, bytes]:
    """Break repeating-key XOR encryption."""
    results = []
    # Find the most likely key sizes
    keysize_candidates = find_keysize(ciphertext)[:top_keysize_candidates]

    print(f"Top {top_keysize_candidates} most likely keysizes:")
    for keysize, distance in keysize_candidates:
        print(f"Keysize: {keysize}, normalized averaged distance: {distance:.2f}")

        # Break ciphertext into blocks of keysize length, and ensure all blocks are the equal length of keysize
        blocks = [
            ciphertext[i : i + keysize]
            for i in range(0, len(ciphertext), keysize)
            if len(ciphertext[i : i + keysize]) == keysize
        ]

        # Transpose the blocks
        transposed = list(zip(*blocks))
        transposed_blocks = [bytes(group) for group in transposed]

        # Solve each transposed block as single-character XOR
        key = []
        for i, block in enumerate(transposed_blocks):
            key_byte, _, _ = single_byte_xor_decrypt(block)
            if key_byte is not None:
                key.append(key_byte)
                print(
                    f"  Position {str(i+1):0>2}: key byte = {str(key_byte):0>3} ('{chr(key_byte) if 32 <= key_byte < 127 else '?'}')"
                )

        # Convert key to bytes
        key_bytes = bytes(key)
        print(f"Found key: {key_bytes} (hexadecimal: {key_bytes.hex()})")

        # Decrypt the entire message
        plaintext = bytes(
            [ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))]
        )
        print(f"Decrypted ciphertext: {plaintext}\n")

        results.append((key_bytes, plaintext))

    return results


if __name__ == "__main__":

    def test_hamming_distance():
        """Test the Hamming distance function with the provided example."""
        s1 = b"this is a test"
        s2 = b"wokka wokka!!!"
        distance = hamming_distance(s1, s2)
        print(f"Hamming distance test: {distance} (should be 37)")
        assert distance == 37, f"Expected 37, got {distance}"
        print("Hamming distance test passed!\n")

    test_hamming_distance()

    hex_str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    plaintext = (
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )
    assert (
        break_repeating_key_xor(bytes.fromhex(hex_str))[2][1] == plaintext
    ), f"Decryption failed: {hex_str}"

    challenge_6_decrypted = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"

    try:
        with open(
            "src/cryptopals/set_01/challenge_06.txt", "rb"
        ) as f:  # "rb" returns file content as bytes
            # Read and decode base64
            base64_data = f.read()
            ciphertext = bytes.fromhex(
                base64_to_hex(base64_data.decode())
            )  # decode (bytes -> string) -> transform to hex -> transform to bytes ciphertext
            print(f"Loaded {len(ciphertext)} bytes of ciphertext\n")

        assert (
            break_repeating_key_xor(ciphertext)[2][1] == challenge_6_decrypted
        ), f"Decryption failed: {ciphertext}"

    except FileNotFoundError:
        print("Error: File 'challenge_06.txt' not found")
    except Exception as e:
        print(f"Error: {e}")

    # # Read the encrypted file
    # filename = input("Enter the filename of the base64-encoded encrypted file: ")
    #
    # try:
    #     with open(filename, 'rb') as f:
    #         # Read and decode base64
    #         base64_data = f.read()
    #         ciphertext = bytes.fromhex(base64_to_hex(base64_data.decode()))
    #         print(f"Loaded {len(ciphertext)} bytes of ciphertext\n")
    #
    #     # Break the encryption
    #     results = break_repeating_key_xor(ciphertext)
    #
    #     # Display results
    #     for key, plaintext in results:
    #         print(f"\nDetected cipher: {key}")
    #         print("="*50)
    #         print("DECRYPTED MESSAGE:")
    #         print("="*50)
    #         print(plaintext.decode('ascii', errors='replace'))
    #
    #     # Save to file
    #     output_filename = filename + '.decrypted'
    #     with open(output_filename, 'wb') as f:
    #         f.write(plaintext)
    #     print(f"\nDecrypted message saved to: {output_filename}")
    #
    # except FileNotFoundError:
    #     print(f"Error: File '{filename}' not found")
    # except Exception as e:
    #     print(f"Error: {e}")
