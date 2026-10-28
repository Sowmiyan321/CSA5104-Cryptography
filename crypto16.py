from collections import Counter
import string

# English letter frequencies from most to least common
english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
alphabet = string.ascii_uppercase

ciphertext = input("Enter ciphertext: ").upper()
top_n = int(input("Enter number of possible plaintexts: "))

# Count ciphertext letter frequencies
counts = Counter(ch for ch in ciphertext if ch in alphabet)

# Rank ciphertext letters by frequency
cipher_order = sorted(alphabet, key=lambda ch: -counts[ch])

results = []

# Generate candidate plaintexts using frequency rankings
for shift in range(26):
    mapping = {}

    for i, ch in enumerate(cipher_order):
        mapping[ch] = english_order[(i + shift) % 26]

    plaintext = "".join(
        mapping.get(ch, ch) for ch in ciphertext
    )

    # Score candidates using common English letters
    score = sum(
        counts[ch] * (26 - english_order.index(mapping[ch]))
        for ch in counts
    )

    results.append((score, plaintext, shift))

# Sort and display candidates
results.sort(reverse=True)
seen = set()
rank = 0

print("\nPossible plaintexts:")

for score, plaintext, shift in results:
    if plaintext not in seen:
        seen.add(plaintext)
        rank += 1
        print(f"{rank}. {plaintext}")

    if rank >= top_n:
        break
