# DES round key generation

PC1 = [
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

def left_shift(bits, n):
    return bits[n:] + bits[:n]

key = input("Enter 16-digit hexadecimal key: ")

if len(key) != 16:
    print("Error: Key must contain 16 hexadecimal digits.")
else:
    try:
        bits = bin(int(key, 16))[2:].zfill(64)

        key56 = permute(bits, PC1)
        C, D = key56[:28], key56[28:]

        print("\nDES Round Keys:")

        for round_no, shift in enumerate(SHIFTS, 1):
            C = left_shift(C, shift)
            D = left_shift(D, shift)

            subkey = permute(C + D, PC2)
            print(f"K{round_no:02}: {hex(int(subkey, 2))[2:].upper().zfill(12)}")

    except ValueError:
        print("Error: Enter a valid hexadecimal key.")
