#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "rich",
# ]
# ///

# Challenge 2: fixed XOR
#
# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
#   1c0111001f010100061a024b53535009181c
#
# ... after hex decoding, and when XOR'd against:
#   686974207468652062756c6c277320657965
#
# ... should produce:
#   746865206b696420646f6e277420706c6179

from rich import print, box
from rich.table import Table
import os


def fixed_xor(hex_1: str, hex_2: str) -> str:
    assert len(hex_1) == len(hex_2)

    raw_bytes_1 = bytes.fromhex(hex_1)
    # print(hex_1)
    # print(raw_bytes_1)
    # print([format(byte, "08b") for byte in raw_bytes_1])

    raw_bytes_2 = bytes.fromhex(hex_2)
    # print(hex_2)
    # print(raw_bytes_2)
    # print([format(byte, "08b") for byte in raw_bytes_2])

    xored_bytes = bytes([a ^ b for (a, b) in zip(raw_bytes_1, raw_bytes_2)])
    # print(xored_bytes)
    # print([format(byte, "08b") for byte in xored_bytes])

    xored_hex_str = xored_bytes.hex()
    # print(xored_hex_str)

    return xored_hex_str


def build_table(left, right, xor):
    table = Table(
        title="",
        caption="XOR operation visualizer",
        show_footer=False,
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_white",
        row_styles=["white"],
        highlight=True,
    )
    table.add_column("Binary")
    table.add_column("Decimal", justify="right")
    table.add_column("Bytes")
    table.add_column("Hexadecimal", justify="right")

    table.add_row(f"{left:08b}", f"{left:03}", f"{bytes([left])}", f"{left:02x}")
    table.add_row(f"{right:08b}", f"{right:03}", f"{bytes([right])}", f"{right:02x}")
    table.add_row(
        "=" * 8,
        "=" * max(len(f"{left}"), len(f"{right}"), len(f"{xor}"), len("Decimal")),
        "="
        * max(
            len(f"{bytes([left])}"),
            len(f"{bytes([right])}"),
            len(f"{bytes([xor])}"),
            len("Bytes"),
        ),
        "=" * len("Hexadecimal"),
    )
    table.add_row(
        f"{xor:08b}", f"{xor:03}", f"{bytes([xor])}", f"{xor:02x}", style="bold"
    )

    return table


def xor_print(bytes_left: bytes, bytes_right: bytes) -> None:
    print(f"[bold]Left bytes ({len(bytes_left)}): [/bold]\t{bytes_left}")
    print(f"[bold]Right bytes ({len(bytes_right)}):[/bold]\t{bytes_right}")
    xored_bytes = b""
    for i, (byte_left, byte_right) in enumerate(zip(bytes_left, bytes_right)):
        xored_byte = byte_left ^ byte_right
        print(f"[bold magenta]Byte {i:02}: [/bold magenta] ")
        print(build_table(byte_left, byte_right, xored_byte))
        xored_bytes += bytes([xored_byte])
    print(f"XORed bytes ({len(xored_bytes)}):\t{xored_bytes}")


if __name__ == "__main__":
    hex_str1 = "1c0111001f010100061a024b53535009181c"
    hex_str2 = "686974207468652062756c6c277320657965"
    hex_out = "746865206b696420646f6e277420706c6179"

    assert fixed_xor(hex_str1, hex_str2) == hex_out

    a = os.urandom(8)
    b = os.urandom(8)
    xor_print(a, b)
