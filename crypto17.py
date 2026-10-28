try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise ImportError(
        "DES requires the 'cryptography' package; install it with: pip install cryptography"
    ) from exc


def decrypt_des_ecb(key_hex: str, cipher_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(cipher_hex)

    if len(key) != 8 or len(ciphertext) != 8:
        raise ValueError("Key and ciphertext must each be 8 bytes.")

    cipher = Cipher(algorithms.DES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


key_hex = input("Enter 16-digit hexadecimal key: ").strip()
cipher_hex = input("Enter 16-digit hexadecimal ciphertext: ").strip()

try:
    plaintext = decrypt_des_ecb(key_hex, cipher_hex)
    print("Plaintext (hex):", plaintext.hex().upper())

    try:
        print("Plaintext (text):", plaintext.decode("utf-8"))
    except UnicodeDecodeError:
        print("Plaintext is not valid UTF-8 text.")
except ValueError as e:
    print("Error:", e)