try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise ImportError(
        "3DES requires the 'cryptography' package; install it with: pip install cryptography"
    ) from exc

import os

# Read plaintext
plaintext = input("Enter plaintext: ").encode()

# Generate a valid 3DES key (24 bytes)
key = os.urandom(24)

# Generate an IV (8 bytes for 3DES/CBC)
iv = os.urandom(8)

# Create 3DES cipher in CBC mode
cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

# Pad plaintext
padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
padded_text = padder.update(plaintext) + padder.finalize()

# Encrypt
ciphertext = encryptor.update(padded_text) + encryptor.finalize()

print("Key (hex):", key.hex())
print("IV (hex):", iv.hex())
print("Ciphertext (hex):", ciphertext.hex())