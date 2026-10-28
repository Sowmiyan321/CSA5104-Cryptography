from collections import Counter

# Common English letter frequencies
frequency = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

def decrypt(ciphertext, shift):
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            plaintext += chr((ord(ch) - base - shift) % 26 + base)
        else:
            plaintext += ch
    return plaintext

def score(text):
    letters = [ch.upper() for ch in text if ch.isalpha()]
    counts = Counter(letters)
    return sum(counts[ch] * (26 - frequency.index(ch))
               for ch in counts if ch in frequency)

ciphertext = input("Enter ciphertext: ")
top_n = int(input("Enter number of possible plaintexts: "))

results = []

for shift in range(26):
    plaintext = decrypt(ciphertext, shift)
    results.append((score(plaintext), shift, plaintext))

results.sort(reverse=True)

print("\nPossible plaintexts:")
for rank, (value, shift, plaintext) in enumerate(results[:top_n], 1):
    print(f"{rank}. Shift {shift}: {plaintext}")
