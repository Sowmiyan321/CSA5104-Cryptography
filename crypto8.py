plain = input("Enter plaintext: ")
key = "CIPHER"
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

cipher = ""

# Add keyword letters without duplicates
for char in key:
    if char not in cipher:
        cipher += char

# Add remaining alphabet letters
for char in alphabet:
    if char not in cipher:
        cipher += char

print(f"Cipher alphabet: {cipher}")
print("Encrypted text: ", end="")

# Encrypt and print the text
for char in plain:
    ch = char.upper()
    
    if 'A' <= ch <= 'Z':
        index = ord(ch) - ord('A')
        print(cipher[index], end="")
    else:
        print(char, end="")

print()