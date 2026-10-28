
import numpy as np
from math import gcd

plaintext = "HELP"
ciphertext = "HIAT"

# Convert letters to numbers
P = np.array([[ord(plaintext[i]) - 65 for i in range(0, len(plaintext), 2)],
              [ord(plaintext[i+1]) - 65 for i in range(0, len(plaintext), 2)]])

C = np.array([[ord(ciphertext[i]) - 65 for i in range(0, len(ciphertext), 2)],
              [ord(ciphertext[i+1]) - 65 for i in range(0, len(ciphertext), 2)]])

det = int(round(np.linalg.det(P))) % 26

if gcd(det, 26) != 1:
    print("Cannot recover key: plaintext matrix is not invertible")
else:
    inv_det = pow(det, -1, 26)

    P_inv = (inv_det * np.array([
        [P[1, 1], -P[0, 1]],
        [-P[1, 0], P[0, 0]]
    ])) % 26

    K = (C @ P_inv) % 26

    print("Recovered Key Matrix:")
    print(K)
