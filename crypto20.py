from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Input plaintext
plaintext = input("Enter plaintext (at least 32 characters): ").encode()

# Apply PKCS7 padding for AES block size (16 bytes)
padder = padding.PKCS7(128).padder()
padded_plaintext = padder.update(plaintext) + padder.finalize()

key = os.urandom(16)
iv = os.urandom(16)

# ECB encryption
ecb_cipher = Cipher(algorithms.AES(key), modes.ECB())
ecb_encryptor = ecb_cipher.encryptor()
ecb_ciphertext = ecb_encryptor.update(padded_plaintext) + ecb_encryptor.finalize()

# CBC encryption
cbc_cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
cbc_encryptor = cbc_cipher.encryptor()
cbc_ciphertext = cbc_encryptor.update(padded_plaintext) + cbc_encryptor.finalize()

# Introduce a bit error in the first ciphertext block
ecb_error = bytearray(ecb_ciphertext)
ecb_error[0] ^= 1

cbc_error = bytearray(cbc_ciphertext)
cbc_error[0] ^= 1

# Decrypt modified ciphertexts
ecb_decipher = Cipher(algorithms.AES(key), modes.ECB())
ecb_decryptor = ecb_decipher.decryptor()
ecb_plaintext = ecb_decryptor.update(bytes(ecb_error)) + ecb_decryptor.finalize()

cbc_decipher = Cipher(algorithms.AES(key), modes.CBC(iv))
cbc_decryptor = cbc_decipher.decryptor()
cbc_plaintext = cbc_decryptor.update(bytes(cbc_error)) + cbc_decryptor.finalize()

# Remove PKCS7 padding
unpadder = padding.PKCS7(128).unpadder()
ecb_plaintext_unpadded = unpadder.update(ecb_plaintext) + unpadder.finalize()
cbc_plaintext_unpadded = unpadder.update(cbc_plaintext) + unpadder.finalize()

print("\nOriginal plaintext:", plaintext)
print("ECB decrypted after error:", ecb_plaintext_unpadded)
print("CBC decrypted after error:", cbc_plaintext_unpadded)

print("\nECB ciphertext:", ecb_ciphertext.hex())
print("CBC ciphertext:", cbc_ciphertext.hex())