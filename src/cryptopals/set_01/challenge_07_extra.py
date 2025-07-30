#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "cryptography",
#   "pycryptodome",
#   "matplotlib",
#   "pillow",
#   "kitcat",
# ]
# ///


# Challenge 7 extra: AES in ECB mode on pattern data (images)
#
# 1. Encrypt image data using AES-128 ECB mode
# 2. Display a side-by-side comparison of the original vs encrypted image
#    - Left side: Original image with clear patterns
#    - Right side: ECB-encrypted image where patterns are still visible!
# 3. Shows the ECB security flaw visually
#    - Colors are scrambled (encryption working)
#    - Shapes are still visible (ECB weakness!)
#    - Patterns are recognizable (security failure!)
#
# This clearly demonstrates why ECB mode should never be used for images or any data with patterns - the visual structure remains visible even after encryption!


import os
from pathlib import Path
from PIL import Image, ImageDraw
import matplotlib
import matplotlib.pyplot as plt

from challenge_07 import (
    aes_128_encrypt_cryptography,
    aes_128_encrypt_pycryptodome,
)


matplotlib.use("kitcat")


def create_test_image(width=256, height=256):
    """Create a test image with visible patterns"""
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)

    # Draw colorful rectangles
    draw.rectangle([20, 20, 120, 120], fill="red")
    draw.rectangle([140, 20, 240, 120], fill="blue")
    draw.rectangle([20, 140, 120, 240], fill="green")
    draw.rectangle([140, 140, 240, 240], fill="yellow")

    # Draw some stripes
    for i in range(0, width, 30):
        draw.rectangle([i, 60, i + 15, 180], fill="purple")

    # Draw circles
    draw.ellipse([80, 80, 180, 180], fill="orange")

    return img


def encrypt_image(image, key):
    """Encrypt image data and return as new image"""
    # Convert image to raw bytes
    image_data = image.tobytes()
    original_size = image.size
    original_mode = image.mode

    print(f"Original image: {original_size}, Mode: {original_mode}")
    print(f"Image data size: {len(image_data)} bytes")

    # Encrypt the image data
    encrypted_data, _ = aes_128_encrypt_cryptography(image_data, key, None, "ECB")
    print(f"Encrypted data size: {len(encrypted_data)} bytes")

    # Truncate encrypted data to original image size (remove padding effect)
    encrypted_image_data = encrypted_data[: len(image_data)]

    # Create new image from encrypted bytes
    encrypted_image = Image.frombytes(
        original_mode, original_size, encrypted_image_data
    )

    return encrypted_image


def display_images(original, encrypted):
    """Display original and encrypted images side by side"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
    fig.patch.set_facecolor("#f8f9fa")

    # Add professional frame
    rect1 = plt.Rectangle(
        (0, 0),
        1,
        1,
        transform=ax1.transAxes,
        fill=False,
        edgecolor="#bdc3c7",
        linewidth=1.5,
    )
    ax1.add_patch(rect1)

    # Original image
    ax1.imshow(original, aspect="equal")
    ax1.set_title(
        "Original Image",
        fontsize=10,
        pad=10,
    )
    ax1.axis("off")

    # Add professional frame
    rect2 = plt.Rectangle(
        (0, 0),
        1,
        1,
        transform=ax2.transAxes,
        fill=False,
        edgecolor="#bdc3c7",
        linewidth=1.5,
    )
    ax2.add_patch(rect2)

    # Encrypted image
    ax2.imshow(encrypted, aspect="equal")
    ax2.set_title(
        "AES-128 ECB Encrypted",
        fontsize=10,
        pad=10,
    )
    ax2.axis("off")

    # Ensure proper layout
    plt.tight_layout(pad=4)

    plt.suptitle(
        "AES-128 ECB Encryption of Images",
        fontsize=11,
        fontweight="bold",
    )

    # # Save the result
    # file_path = Path(__file__).parent / "ecb_encryption_comparison.png"
    # plt.savefig(file_path, dpi=300, bbox_inches="tight")
    # print(f"Comparison saved to {file_path}")

    plt.show()


def load_image_file(filename):
    """Load an image file if it exists"""
    try:
        img = Image.open(filename)
        # Convert to RGB if necessary
        if img.mode != "RGB":
            img = img.convert("RGB")
        return img
    except FileNotFoundError:
        print(f"Image file '{filename}' not found. Using generated test image instead.")
        return None
    except Exception as e:
        print(f"Error loading image: {e}. Using generated test image instead.")
        return None


def main():
    """Main function to demonstrate ECB encryption on images"""
    print("=== AES-128 ECB Image Encryption Demo ===\n")

    # Generate random encryption key
    key = os.urandom(16)
    print(f"Generated AES-128 key (os.urandom): {key.hex()}\n")

    # Try to load an existing image file, or create a test image
    image_filename = Path(__file__).parent / "test_image.png"
    original_image = load_image_file(image_filename)
    # original_image = None

    if original_image is None:
        print("Creating test image with patterns...")
        original_image = create_test_image(256, 256)
        # Save the test image
        file_path = Path(__file__).parent / "generated_test_image.png"
        original_image.save(file_path)
        print(f"Test image saved to {file_path}\n")

    # Encrypt the image
    print("Encrypting image with AES-128 ECB...")
    encrypted_image = encrypt_image(original_image, key)
    print("Encryption complete!\n")

    # Save the results
    display_images(original_image, encrypted_image)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
