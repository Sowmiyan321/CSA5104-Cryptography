text = input("Enter the message: ")     #Monoalphabetic Substitution Cipher

key = "QWERTYUIOPASDFGHJKLZXCVBNM"

encrypted = ""

for char in text:
    if 'A' <= char <= 'Z':
        pos = ord(char) - ord('A')
        encrypted += key[pos]

    elif 'a' <= char <= 'z':
        pos = ord(char) - ord('a')
        encrypted += key[pos].lower()

    else:
        encrypted += char

print("Encrypted message:", encrypted)
