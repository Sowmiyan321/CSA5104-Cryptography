plaintext = input("Enter plaintext: ").upper()
key = input("Enter key: ").upper()

ciphertext = ""
j = 0

for ch in plaintext:
    if ch.isalpha():
        p = ord(ch) - ord('A')
        k = ord(key[j % len(key)]) - ord('A')
        ciphertext += chr((p + k) % 26 + ord('A'))
        j += 1
    else:
        ciphertext += ch

print("Ciphertext:", ciphertext)