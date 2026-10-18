mat = [
    ['M', 'F', 'H', 'I', 'K'],
    ['U', 'N', 'O', 'P', 'Q'],
    ['Z', 'V', 'W', 'X', 'Y'],
    ['E', 'L', 'A', 'R', 'G'],
    ['D', 'S', 'T', 'B', 'C']
]

def encrypt(a, b):
    if a == 'J': a = 'I'
    if b == 'J': b = 'I'
    
    r1 = c1 = r2 = c2 = 0
    
    # Find positions of a and b in the matrix
    for i in range(5):
        for j in range(5):
            if mat[i][j] == a:
                r1, c1 = i, j
            if mat[i][j] == b:
                r2, c2 = i, j

    # Apply Playfair cipher rules
    if r1 == r2:
        print(f"{mat[r1][(c1 + 1) % 5]}{mat[r2][(c2 + 1) % 5]}", end="")
    elif c1 == c2:
        print(f"{mat[(r1 + 1) % 5][c1]}{mat[(r2 + 1) % 5][c2]}", end="")
    else:
        print(f"{mat[r1][c2]}{mat[r2][c1]}", end="")

def main():
    msg = "Must see you over Cadogan West. Coming at once."
    text = ""

    # Extract alphabetic characters, convert to uppercase, and replace 'J' with 'I'
    for char in msg:
        if char.isalpha():
            ch = char.upper()
            if ch == 'J': 
                ch = 'I'
            text += ch

    print(f"Plaintext: {msg}")
    print("Ciphertext: ", end="")

    i = 0
    n = len(text)
    
    # Process text in pairs
    while i < n:
        a = text[i]
        
        if i + 1 >= n:
            # Odd length padding
            b = 'X'
            encrypt(a, b)
            i += 1
        elif a == text[i + 1]:
            # Handle duplicate consecutive characters
            b = 'X'
            encrypt(a, b)
            i += 1  # Advance by 1 so the duplicate character is processed in the next pair
        else:
            # Standard pair
            b = text[i + 1]
            encrypt(a, b)
            i += 2  # Advance by 2 for the next pair

    print()

if __name__ == "__main__":
    main()