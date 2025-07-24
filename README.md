# Cryptopals Challenges Solutions

🔐 Python implementations of the [Cryptopals Crypto Challenges](https://cryptopals.com/)

## Features

- Set 1: Basic crypto challenges
  - Hex/base64 conversions
  - Fixed XOR cipher
  - Single-bycyber XBREAK cipher breaking
  - Detect AES-ECB encryption
  - And more...
- Clean type-annotated Python code
- Comprehensive test coverage
- Practical crypto examples

## Installation

```bash
python -m pip install -e .
```

## Usage

Run challenges directly or use in your code:

```python
from cryptopals.set_1 import (
    hex_to_base64,
    fixed_xor,
    single_byte_xor_decrypt
)

# Example usage:
ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
key, plaintext, score = single_byte_xor_decrypt(bytes.fromhex(ct))
```

## Challenges Progress

✅ Completed Set 1 (Challenges 1-8)

## Documentation

Full challenge descriptions and code documentation available at:  
[cryptopals.com](https://cryptopals.com/)

## License

MIT License - see [LICENSE](LICENSE) for details
