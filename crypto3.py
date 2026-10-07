def create_matrix(key):
    key = key.upper().replace("J", "I")             #playfair cipher
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    letters = ""
    for ch in key + alphabet:
        if ch.isalpha() and ch not in letters:
            letters += ch

    matrix = [letters[i:i+5] for i in range(0, 25, 5)]
    return matrix


def find_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col


def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = "".join(ch for ch in text if ch.isalpha())

    result = ""
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 == len(text):
            result += a + "X"
            i += 1
        elif text[i] == text[i + 1]:
            result += a + "X"
            i += 1
        else:
            result += a + text[i + 1]
            i += 2

    return result


def playfair_encrypt(plaintext, key):
    matrix = create_matrix(key)
    plaintext = prepare_text(plaintext)

    ciphertext = ""

    for i in range(0, len(plaintext), 2):
        a = plaintext[i]
        b = plaintext[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        # Same row
        if r1 == r2:
            ciphertext += matrix[r1][(c1 + 1) % 5]
            ciphertext += matrix[r2][(c2 + 1) % 5]

        # Same column
        elif c1 == c2:
            ciphertext += matrix[(r1 + 1) % 5][c1]
            ciphertext += matrix[(r2 + 1) % 5][c2]

        # Rectangle rule
        else:
            ciphertext += matrix[r1][c2]
            ciphertext += matrix[r2][c1]

    return matrix, ciphertext


# Main program
key = input("Enter the key: ")
plaintext = input("Enter the plaintext: ")

matrix, ciphertext = playfair_encrypt(plaintext, key)

print("\nPlayfair Matrix:")
for row in matrix:
    print(" ".join(row))

print("\nPlaintext :", plaintext)
print("Ciphertext:", ciphertext)