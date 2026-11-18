import string


def encrypt_char_by_char(plaintext: str, e: int, n: int) -> list[int]:
  """
    Encrypts a message character-by-character (A=0 ... Z=25) using Bob's public key (e, n).
    """
  ciphertext = []
  for char in plaintext.upper():
    if char in string.ascii_uppercase:
      m = ord(char) - ord('A')
      c = pow(m, e, n)
      ciphertext.append(c)
  return ciphertext


def break_rsa_chosen_plaintext_dictionary(
    ciphertext: list[int], e: int, n: int
) -> str:
  """
    Breaks character-by-character RSA without knowing the private key d or factoring n.
    Precomputes C = M^e mod n for all 26 possible letters (0..25) to build a lookup table.
    """
  # Step 1: Precompute ciphertext for all 26 uppercase letters (26 modular exponentiations)
  lookup_table = {}
  for m in range(26):
    c = pow(m, e, n)
    lookup_table[c] = chr(m + ord('A'))

  # Step 2: Map each intercepted ciphertext block back to its plaintext letter
  recovered_chars = [lookup_table[c] for c in ciphertext]
  return ''.join(recovered_chars)


# --- Driver Code ---
if __name__ == '__main__':
  # Very large RSA modulus n and large public exponent e (cannot be factored easily)
  p = 10000000000000000039323
  q = 10000000000000000067539
  n = p * q
  e = 65537

  secret_message = 'ATTACKATDAWN'

  # Alice encrypts each character (0..25) separately
  intercepted_ciphertext = encrypt_char_by_char(secret_message, e, n)

  print(f'Public Key (e, n)       : ({e}, {n})')
  print(f'Intercepted Ciphertext  : {intercepted_ciphertext[:4]} ... (12 blocks)')

  # Attacker recovers the entire plaintext instantly without factoring n
  cracked_message = break_rsa_chosen_plaintext_dictionary(
      intercepted_ciphertext, e, n
  )
  print(f'Cracked Plaintext       : {cracked_message}')