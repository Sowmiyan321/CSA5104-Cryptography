import math


def text_to_matrix_2x2(text: str) -> list[list[int]]:
  """Converts a 4-letter string into a 2x2 column-major matrix mod 26."""
  letters = [ord(ch.upper()) - ord('A') for ch in text if ch.isalpha()]
  if len(letters) != 4:
    raise ValueError('Exactly 4 alphabetic characters are required.')
  return [[letters[0], letters[2]], [letters[1], letters[3]]]


def matrix_mult_2x2(
    A: list[list[int]], B: list[list[int]], mod: int = 26
) -> list[list[int]]:
  """Multiplies two 2x2 matrices modulo 26."""
  return [
      [
          (A[0][0] * B[0][0] + A[0][1] * B[1][0]) % mod,
          (A[0][0] * B[0][1] + A[0][1] * B[1][1]) % mod,
      ],
      [
          (A[1][0] * B[0][0] + A[1][1] * B[1][0]) % mod,
          (A[1][0] * B[0][1] + A[1][1] * B[1][1]) % mod,
      ],
  ]


def matrix_inv_2x2(M: list[list[int]], mod: int = 26) -> list[list[int]]:
  """Computes the modular inverse of a 2x2 matrix modulo 26."""
  det = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % mod
  if math.gcd(det, mod) != 1:
    raise ValueError(
        f'Matrix determinant {det} is not coprime to {mod}; not invertible.'
    )
  det_inv = pow(det, -1, mod)
  return [
      [(M[1][1] * det_inv) % mod, (-M[0][1] * det_inv) % mod],
      [(-M[1][0] * det_inv) % mod, (M[0][0] * det_inv) % mod],
  ]


def hill_encrypt(plaintext: str, key: list[list[int]]) -> str:
  """Encrypts a 4-letter plaintext using a 2x2 Hill cipher key."""
  P = text_to_matrix_2x2(plaintext)
  C = matrix_mult_2x2(key, P, 26)
  return ''.join(
      chr(val + ord('A')) for val in [C[0][0], C[1][0], C[0][1], C[1][1]]
  )


def known_plaintext_attack_hill_2x2(
    known_pt: str, known_ct: str
) -> list[list[int]]:
  """
    Recovers the 2x2 Hill cipher key matrix K from two known plaintext-ciphertext
    digraph pairs (4 letters total):
        C = K * P (mod 26)  ==>  K = C * P^(-1) (mod 26)
    """
  P = text_to_matrix_2x2(known_pt)
  C = text_to_matrix_2x2(known_ct)
  P_inv = matrix_inv_2x2(P, 26)
  return matrix_mult_2x2(C, P_inv, 26)


def chosen_plaintext_attack_hill_2x2(encrypt_oracle) -> list[list[int]]:
  """
    Recovers the 2x2 Hill cipher key matrix K directly via a Chosen Plaintext Attack.
    By querying the identity matrix columns P = [[1, 0], [0, 1]] (i.e., "BAAB"):
        - Encrypting "BA" ([1, 0]^T) yields the first column of K.
        - Encrypting "AB" ([0, 1]^T) yields the second column of K.
    No matrix inversion is required!
    """
  chosen_pt = 'BAAB'  # Column 1 = [1, 0]^T ("BA"), Column 2 = [0, 1]^T ("AB")
  chosen_ct = encrypt_oracle(chosen_pt)
  return text_to_matrix_2x2(chosen_ct)


# --- Driver Code ---
if __name__ == '__main__':
  # Secret 2x2 Hill cipher key matrix (det = 9*7 - 4*5 = 43 ≡ 17 mod 26, coprime to 26)
  secret_key = [[9, 4], [5, 7]]
  print(f'Actual Secret Key Matrix K : {secret_key}\n')

  # 1. Known-Plaintext Attack (KPA)
  # Suppose attacker intercepts "HELP" -> encrypted as "LEZE"
  known_pt = 'HELP'
  known_ct = hill_encrypt(known_pt, secret_key)
  recovered_k_kpa = known_plaintext_attack_hill_2x2(known_pt, known_ct)

  print('--- 1. Known-Plaintext Attack (KPA) ---')
  print(f"Known Pair : '{known_pt}' -> '{known_ct}'")
  print(f'Recovered Key K = C * P^(-1) mod 26 : {recovered_k_kpa}\n')

  # 2. Chosen-Plaintext Attack (CPA)
  # Attacker chooses plaintext "BAAB" (corresponding to the 2x2 Identity Matrix)
  oracle = lambda pt: hill_encrypt(pt, secret_key)
  recovered_k_cpa = chosen_plaintext_attack_hill_2x2(oracle)

  print('--- 2. Chosen-Plaintext Attack (CPA) ---')
  print(f"Chosen Plaintext ('BAAB' = Identity Matrix) -> '{oracle('BAAB')}'")
  print(f'Recovered Key K directly (no inversion)    : {recovered_k_cpa}')