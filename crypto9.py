
key = "ROYAL NEW ZEALAND NAVY"

ciphertext = """
KXJEY UREBE ZWEHE WRYTU HEYFS
KREHE GOYFI WTTTU OLKSY CAJPO
BOTEI ZONTX BYBNT GONEY CUZWR
GDSON SXBOU YWRHE BAAHY USEDQ
"""

alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

# Create Playfair matrix
letters = ""

for ch in (key + alphabet):
    ch = ch.upper()
    if ch.isalpha():
        if ch == 'J':
            ch = 'I'
        if ch not in letters:
            letters += ch

matrix = [letters[i:i+5] for i in range(0, 25, 5)]

print("Playfair Matrix:")
for row in matrix:
    print(" ".join(row))

# Store letter positions
pos = {}
for r in range(5):
    for c in range(5):
        pos[matrix[r][c]] = (r, c)

pos['J'] = pos['I']

text = ''.join(ch for ch in ciphertext if ch.isalpha())
plaintext = ""

for i in range(0, len(text), 2):
    a, b = text[i], text[i+1]
    r1, c1 = pos[a]
    r2, c2 = pos[b]

    if r1 == r2:
        plaintext += matrix[r1][(c1-1) % 5]
        plaintext += matrix[r2][(c2-1) % 5]
    elif c1 == c2:
        plaintext += matrix[(r1-1) % 5][c1]
        plaintext += matrix[(r2-1) % 5][c2]
    else:
        plaintext += matrix[r1][c2]
        plaintext += matrix[r2][c1]

print("Decrypted text:", plaintext)
