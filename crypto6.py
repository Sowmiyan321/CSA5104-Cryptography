from math import gcd

ciphertext = input("Enter ciphertext: ").upper()

# Assume B -> E and U -> T
# A=0, B=1, ..., Z=25
c1, p1 = 1, 4
c2, p2 = 20, 19

solutions = []

for a in range(26):
    if gcd(a, 26) == 1:
        b = (c1 - a * p1) % 26
        if (a * p2 + b) % 26 == c2:
            solutions.append((a, b))

if not solutions:
    print("No valid key under these assumptions.")
else:
    for a, b in solutions:
        inverse = pow(a, -1, 26)
        plaintext = ""

        for ch in ciphertext:
            if ch.isalpha():
                c = ord(ch) - ord('A')
                p = (inverse * (c - b)) % 26
                plaintext += chr(p + ord('A'))
            else:
                plaintext += ch

        print("Key:", a, b)
        print("Possible plaintext:", plaintext)