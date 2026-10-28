
plaintext = "SENDMOREMONEY"
key = [9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9]

# Encryption
cipher = ""
for i in range(len(plaintext)):
    p = ord(plaintext[i]) - ord('A')
    cipher += chr((p + key[i]) % 26 + ord('A'))

print("Ciphertext:", cipher)

# Find a key for the chosen plaintext
new_plaintext = "CASHNOTNEEDED"
new_key = []

for i in range(len(cipher)):
    c = ord(cipher[i]) - ord('A')
    p = ord(new_plaintext[i]) - ord('A')
    new_key.append((c - p) % 26)

print("New key stream:", new_key)
