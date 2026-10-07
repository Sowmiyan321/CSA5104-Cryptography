text = input("Enter the message: ")
k = int(input("Enter key (1-25): "))    #caesar cipher

encrypted = ""

for char in text:
    if 'A' <= char <= 'Z':
        encrypted += chr((ord(char) - ord('A') + k) % 26 + ord('A'))

    elif 'a' <= char <= 'z':
        encrypted += chr((ord(char) - ord('a') + k) % 26 + ord('a'))

    else:
        encrypted += char

print("Encrypted message:", encrypted)
