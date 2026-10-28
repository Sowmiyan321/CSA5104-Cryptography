import string

msg = "meet me at the usual place at ten rather than eight oclock"

plain = ""
cipher = ""
decrypted = ""

# Key matrix and inverse matrix
K = [[9, 4],
     [5, 7]]

Inv = [[5, 12],
       [15, 25]]

# Remove spaces and convert to uppercase
for ch in msg:
    if ch.isalpha():
        plain += ch.upper()

# Add X if length is odd
if len(plain) % 2 != 0:
    plain += "X"

# Encryption
for i in range(0, len(plain), 2):
    x = ord(plain[i]) - ord('A')
    y = ord(plain[i + 1]) - ord('A')

    c1 = (K[0][0] * x + K[0][1] * y) % 26
    c2 = (K[1][0] * x + K[1][1] * y) % 26

    cipher += chr(c1 + ord('A'))
    cipher += chr(c2 + ord('A'))

print("Plaintext:", plain)
print("Ciphertext:", cipher)

# Decryption
for i in range(0, len(cipher), 2):
    x = ord(cipher[i]) - ord('A')
    y = ord(cipher[i + 1]) - ord('A')

    c1 = (Inv[0][0] * x + Inv[0][1] * y) % 26
    c2 = (Inv[1][0] * x + Inv[1][1] * y) % 26

    decrypted += chr(c1 + ord('A'))
    decrypted += chr(c2 + ord('A'))

print("Decrypted text:", decrypted)