#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "cryptography",
#   "pycryptodome",
# ]
# ///


# Challenge 7: AES in ECB mode
#
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
# But do this with code.
#
# You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason.
# You'll need it a lot later on, and not just for attacking ECB.


# ================================== COMMENTS ==================================
#
# >>> b"YELLOW SUBMARINE".hex()
# openssl enc -d -aes-128-ecb -in src/cryptopals/set_1/challenge_7.txt -K 59454C4C4F57205355424D4152494E45 -a
#
# AES-128 in ECB (Electronic Codebook) mode is one of the simplest block cipher modes of operation.
# AES (Advanced Encryption Standard) is a symmetric encryption algorithm, established in 2001 as a replacement for DES (Data Encryption Standard).
# AES-128 always uses a 128-bit (16 byte) key/128-bit (16 byte) block size and 10 rounds of encryption/decryption.
# Each block is encrypted independently. The same plaintext block always produces same ciphertext block (with same key).
# No initialization vector (IV) required
#
# Encryption Process
# 1. Padding: If the plaintext isn't a multiple of 16 bytes, pad it (commonly using PKCS#7 padding)
# 2. Block Division: Split the padded plaintext into 16-byte blocks
# 3. Individual Block Encryption for each 16-byte block
# 4. Concatenation: Join all ciphertext blocks together
#
# Decryption Process
# 1. Block Division: Split ciphertext into 16-byte blocks
# 2. Individual Block Decryption for each block
# 3. Concatenation: Join all plaintext blocks
# 4. Remove Padding: Strip the padding from the final block
#
# ECB mode has significant weaknesses:
# - Pattern Preservation: identical plaintext blocks produce identical ciphertext blocks, revealing patterns
# - Block Rearrangement: blocks can be rearranged without detection; there is no integrity protection to ensure the ciphertext hasn't been tampered with
# - No Diffusion: changes in one block don't affect other blocks
# Therefore, ECB is generally not recommended for encrypting data longer than one block.
# The classic demonstration of ECB's weakness is encrypting an image - patterns in the original image remain visible in the encrypted version
# because identical pixel blocks encrypt to identical ciphertext blocks.
#
# Other AES-128 cipher modes:
# 1. CBC (Cipher Block Chaining)
#    - Each plaintext block is XORed with the previous ciphertext block before encryption.
#    - First block uses an IV (random nonce) for uniqueness.
#    - Secure for large data, but errors propagate (one corrupted block affects subsequent blocks).
#    - Requires padding for partial blocks.
# 2. CTR (Counter)
#    - Converts AES into a stream cipher. Encrypts a counter value (e.g., nonce + increment) and XORs it with plaintext.
#    - No padding needed (works byte-wise).
#    - Parallelizable and efficient. Allows random access to ciphertext.
#    - IV (nonce) must be unique per encryption.
# 3. GCM (Galois/Counter Mode)
#    - Combines CTR mode (for encryption) with Galois authentication (for integrity).
#    - Provides authenticated encryption (confidentiality + integrity).
#    - No padding, parallelizable, and highly efficient (hardware-accelerated).
#    - Widely used in modern protocols (TLS, IPsec).


import base64
import os
from pathlib import Path

# cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# pycryptodome imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ===================================================================
# 1. Using 'cryptography' library (recommended, modern approach)
# ===================================================================


def aes_128_decrypt_cryptography(
    encrypted_data: bytes, key: bytes, iv: bytes | None = None, mode: str = "CBC"
) -> bytes:
    """
    Decrypt data using AES-128 with the 'cryptography' library

    Args:
        encrypted_data (bytes): The encrypted data to decrypt
        key (bytes): 16-byte encryption key for AES-128
        iv (bytes): Initialization vector (required for CBC and CTR modes)
        mode (str): Encryption cipher mode ('CBC', 'ECB', 'CTR', 'GCM')

    Returns:
        bytes: Decrypted plaintext
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")

    # Select the appropriate mode
    if mode == "CBC":
        if not iv or len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CBC mode")
        cipher_mode = modes.CBC(iv)
        needs_padding = True
    elif mode == "ECB":
        cipher_mode = modes.ECB()
        needs_padding = True
    elif mode == "CTR":
        if not iv or len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CTR mode")
        cipher_mode = modes.CTR(iv)
        needs_padding = False
    elif mode == "GCM":
        if not iv:
            raise ValueError("IV is required for GCM mode")
        # For GCM, we need the tag (last 16 bytes typically)
        tag = encrypted_data[-16:]
        encrypted_data = encrypted_data[:-16]
        cipher_mode = modes.GCM(iv, tag)
        needs_padding = False
    else:
        raise ValueError(f"Unsupported cipher mode: {mode}")

    # Create cipher
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding if needed
    if needs_padding:
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted) + unpadder.finalize()

    return decrypted


def aes_128_encrypt_cryptography(
    plaintext: bytes, key: bytes, iv: bytes | None = None, mode: str = "CBC"
) -> tuple[bytes, bytes | None]:
    """
    Encrypt data using AES-128 with the 'cryptography' library

    Args:
        plaintext (bytes): The data to encrypt
        key (bytes): 16-byte encryption key for AES-128
        iv (bytes): Initialization vector (auto-generated if None for most modes)
        mode (str): Encryption mode ('CBC', 'ECB', 'CTR', 'GCM')

    Returns:
        tuple: (encrypted_data, iv_used) or (encrypted_data_with_tag, iv_used) for GCM
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")

    # Generate IV if not provided
    if mode in ["CBC", "CTR", "GCM"] and iv is None:
        iv = os.urandom(16)

    # Select the appropriate mode
    if mode == "CBC":
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CBC mode")
        cipher_mode = modes.CBC(iv)
        needs_padding = True
    elif mode == "ECB":
        cipher_mode = modes.ECB()
        needs_padding = True
    elif mode == "CTR":
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CTR mode")
        cipher_mode = modes.CTR(iv)
        needs_padding = False
    elif mode == "GCM":
        cipher_mode = modes.GCM(iv)
        needs_padding = False
    else:
        raise ValueError(f"Unsupported cipher mode: {mode}")

    # Apply padding if needed
    if needs_padding:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
    else:
        padded_data = plaintext

    # Create cipher and encrypt
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Handle GCM tag
    if mode == "GCM":
        tag = encryptor.tag
        encrypted_with_tag = encrypted + tag
        return encrypted_with_tag, iv

    return encrypted, iv


# ===================================================================
# 2. Using 'pycryptodome' library (popular alternative)
# ===================================================================


def aes_128_decrypt_pycryptodome(
    encrypted_data: bytes, key: bytes, iv: bytes | None = None, mode: str = "CBC"
) -> bytes:
    """
    Decrypt data using AES-128 with the 'pycryptodome' library

    Args:
        encrypted_data (bytes): The encrypted data to decrypt
        key (bytes): 16-byte encryption key for AES-128
        iv (bytes): Initialization vector (required for CBC, CTR modes)
        mode (str): Encryption mode ('CBC', 'ECB', 'CTR', 'GCM')

    Returns:
        bytes: Decrypted plaintext
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")

    if mode == "CBC":
        if not iv or len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        # Remove PKCS7 padding
        decrypted = unpad(decrypted, AES.block_size)

    elif mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted_data)
        # Remove PKCS7 padding
        decrypted = unpad(decrypted, AES.block_size)

    elif mode == "CTR":
        if not iv or len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
        decrypted = cipher.decrypt(encrypted_data)

    elif mode == "GCM":
        if not iv:
            raise ValueError("IV is required for GCM mode")
        # For GCM, we need the tag (last 16 bytes typically)
        tag = encrypted_data[-16:]
        encrypted_data = encrypted_data[:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(encrypted_data, tag)

    else:
        raise ValueError(f"Unsupported cipher mode: {mode}")

    return decrypted


def aes_128_encrypt_pycryptodome(
    plaintext: bytes, key: bytes, iv: bytes | None = None, mode: str = "CBC"
) -> tuple[bytes, bytes | None]:
    """
    Encrypt data using AES-128 with the 'pycryptodome' library

    Args:
        plaintext (bytes): The data to encrypt
        key (bytes): 16-byte encryption key for AES-128
        iv (bytes): Initialization vector (auto-generated if None for most modes)
        mode (str): Encryption mode ('CBC', 'ECB', 'CTR', 'GCM')

    Returns:
        tuple: (encrypted_data, iv_used) or (encrypted_data_with_tag, iv_used) for GCM
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")

    # Generate IV if not provided
    if mode in ["CBC", "CTR", "GCM"] and iv is None:
        iv = os.urandom(16)

    if mode == "CBC":
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CBC mode")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Apply PKCS7 padding
        padded_data = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded_data)

    elif mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        # Apply PKCS7 padding
        padded_data = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded_data)

    elif mode == "CTR":
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes for CTR mode")
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
        encrypted = cipher.encrypt(plaintext)

    elif mode == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        encrypted, tag = cipher.encrypt_and_digest(plaintext)
        encrypted_with_tag = encrypted + tag
        return encrypted_with_tag, iv

    else:
        raise ValueError(f"Unsupported mode: {mode}")

    return encrypted, iv


# ===================================================================
# 3. Utility functions for key derivation and handling
# ===================================================================


def derive_key_from_password(
    password: bytes, salt: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    Derive a 16-byte AES-128 key from a password using PBKDF2
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,  # 16 bytes for AES-128
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )

    key = kdf.derive(password)
    return key, salt


def encrypt_file_aes128(input_file_path, encrypted_file_path, key, prepend_iv=True):
    """
    Encrypt a file using AES-128 CBC mode
    """
    with open(input_file_path, "rb") as f:
        plaintext_data = f.read()

    # Encrypt the file data
    encrypted_data, iv = aes_128_encrypt_cryptography(plaintext_data, key, mode="CBC")

    with open(encrypted_file_path, "wb") as f:
        if prepend_iv:
            # Prepend IV to the encrypted file for easy decryption
            f.write(iv + encrypted_data)
        else:
            f.write(encrypted_data)

    print(f"File encrypted successfully: {encrypted_file_path}")
    return iv if not prepend_iv else None


def decrypt_file_aes128(encrypted_file_path, output_file_path, key, iv=None):
    """
    Decrypt a file using AES-128 CBC mode
    """
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    if iv is None:
        # Assume IV is prepended to the file (first 16 bytes)
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

    decrypted_data = aes_128_decrypt_cryptography(encrypted_data, key, iv, "CBC")

    with open(output_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"File decrypted successfully: {output_file_path}")


# ===================================================================
# 4. Examples
# ===================================================================


def example_usage() -> None:
    """Demonstrate the AES-128 encryption and decryption functions"""

    # Example key and data (in real use, these would come from secure sources)
    key = b"Sixteen byte key"  # 16 bytes for AES-128
    plaintext = (
        b"Hello, this is a secret message that needs to be encrypted and decrypted!"
    )

    print("=== AES-128 Encryption/Decryption Examples ===\n")
    print(f"Original message: {plaintext}")
    print(f"Key: {key}")
    print(f"Message length: {len(plaintext)} bytes\n")

    # Test different modes with both libraries
    modes_to_test = ["CBC", "ECB", "CTR", "GCM"]

    for mode in modes_to_test:
        print(f"--- Testing {mode} cipher mode ---")

        # Test with 'cryptography' library
        try:
            # Encrypt
            encrypted, iv = aes_128_encrypt_cryptography(plaintext, key, mode=mode)
            print(f"✓ Cryptography - Encrypted ({len(encrypted)} bytes): \n{encrypted}")
            print(f"  IV: {iv.hex() if iv else 'N/A'}")

            # Decrypt
            decrypted = aes_128_decrypt_cryptography(encrypted, key, iv, mode)
            print(f"✓ Cryptography - Decrypted: \n{decrypted}")

            # Verify round-trip
            if decrypted == plaintext:
                print("✓ Cryptography - Round-trip successful!")
            else:
                print("✗ Cryptography - Round-trip failed!")

        except Exception as e:
            print(f"✗ Cryptography library error: {e}")

        # Test with 'pycryptodome' library
        try:
            # Encrypt
            encrypted, iv = aes_128_encrypt_pycryptodome(plaintext, key, mode=mode)
            print(f"✓ PyCryptodome - Encrypted ({len(encrypted)} bytes): \n{encrypted}")
            print(f"  IV: {iv.hex() if iv else 'N/A'}")

            # Decrypt
            decrypted = aes_128_decrypt_pycryptodome(encrypted, key, iv, mode)
            print(f"✓ PyCryptodome - Decrypted: \n{decrypted}")

            # Verify round-trip
            if decrypted == plaintext:
                print("✓ PyCryptodome - Round-trip successful!")
            else:
                print("✗ PyCryptodome - Round-trip failed!")

        except Exception as e:
            print(f"✗ PyCryptodome library error: {e}")

        print()  # Empty line between modes


def demonstrate_different_key_sizes() -> None:
    """Show examples with different AES key sizes (though functions are for AES-128)"""
    print("=== AES Key Size Examples ===\n")

    # AES-128 (16 bytes)
    key_128 = os.urandom(16)
    print("AES-128 key:")
    print(f"  {key_128} ({len(key_128)} bytes)")
    print(f"  {key_128.hex()} (hex)")

    # AES-192 would be 24 bytes (not implemented in our functions)
    key_192 = os.urandom(24)
    print("AES-192 key:")
    print(f"  {key_192} ({len(key_192)} bytes)")
    print(f"  {key_192.hex()} (hex)")

    # AES-256 would be 32 bytes (not implemented in our functions)
    key_256 = os.urandom(32)
    print("AES-256 key:")
    print(f"  {key_256} ({len(key_256)} bytes)")
    print(f"  {key_256.hex()} (hex)")
    print()


def main() -> None:
    """Main function to decrypt the challenge_07.txt file."""
    key = b"YELLOW SUBMARINE"
    # The file path is relative to this script
    file_path = Path(__file__).parent / "challenge_07.txt"

    print(f"\n=== AES-128 ECB Mode Decryption ({file_path})  ===\n")

    with open(file_path, "rb") as f:
        base64_content = f.read()

    print(f"Base64-encoded message: \n{base64_content}\n")

    encrypted = base64.b64decode(base64_content)

    print(f"Encrypted message: \n{encrypted}\n")
    print(f"Encrypted message length: {len(encrypted)} bytes\n")
    print(f"Key: {key}\n")

    decrypted = aes_128_decrypt_cryptography(encrypted, key, None, "ECB")
    print(f"✓ Cryptography - Decrypted: \n{decrypted}\n")

    decrypted = aes_128_decrypt_pycryptodome(encrypted, key, None, "ECB")
    print(f"✓ PyCryptodome - Decrypted: \n{decrypted}\n")


if __name__ == "__main__":
    main()

    example_usage()

    demonstrate_different_key_sizes()

    # Example of key derivation
    print("=== Key Derivation Example ===\n")
    password = "my_secure_password"
    print(f"Plaintext password: {password}")
    key, salt = derive_key_from_password(password.encode())
    print(f"Derived 16-byte key from password '{password}':")
    print(f"  {key} (16 bytes)")
    print(f"  {key.hex()} (hex)")
    print("Salt used:")
    print(f"  {salt} (16 bytes)")
    print(f"  {salt.hex()} (hex)")

    # Test the derived key
    test_message = b"Testing derived key encryption"
    encrypted, iv = aes_128_encrypt_cryptography(test_message, key, mode="CBC")
    decrypted = aes_128_decrypt_cryptography(encrypted, key, iv, "CBC")
    print(f"Test with derived key - Original:  {test_message}")
    print(f"Test with derived key - Encrypted: {encrypted}")
    print(f"Test with derived key - Decrypted: {decrypted}")
    print(
        f"Derived key test: {'✓ PASSED' if test_message == decrypted else '✗ FAILED'}"
    )
