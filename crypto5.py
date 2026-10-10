from math import gcd

text = input("Enter plaintext: ").upper()
a = int(input("Enter key a: "))
b = int(input("Enter key b: "))

if gcd(a, 26) != 1:
    print("Invalid key a")
else:
    result = ""

    for ch in text:
        if ch.isalpha():
            p = ord(ch) - ord('A')
            c = (a * p + b) % 26
            result += chr(c + ord('A'))
        else:
            result += ch

    print("Ciphertext:", result)