import math


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
  """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
  if a == 0:
    return b, 0, 1
  gcd, x1, y1 = extended_gcd(b % a, a)
  x = y1 - (b // a) * x1
  y = x1
  return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
  """
    Computes the modular multiplicative inverse d of e modulo phi.
    """
  gcd, x, _ = extended_gcd(e, phi)
  if gcd != 1:
    raise ValueError("Modular inverse does not exist.")
  return x % phi


def break_rsa_via_common_factor(
    ciphertexts: list[int], e: int, n: int
) -> tuple[int, int, int, list[int]]:
  """
    Breaks RSA when at least one plaintext block shares a non-trivial factor with n.
    Uses gcd(C_i, n) to factor n, computes the private key d, and decrypts all blocks.
    """
  p = None
  for c in ciphertexts:
    common_factor = math.gcd(c, n)
    # If 1 < gcd(C, n) < n, we have found one of the prime factors of n
    if 1 < common_factor < n:
      p = common_factor
      break

  if p is None:
    raise ValueError(
        "None of the ciphertext blocks shared a non-trivial factor with n."
    )

  q = n // p
  phi_n = (p - 1) * (q - 1)
  d = mod_inverse(e, phi_n)

  # Decrypt all ciphertext blocks using the recovered private key d
  recovered_plaintexts = [pow(c, d, n) for c in ciphertexts]
  return p, q, d, recovered_plaintexts


# --- Driver Code ---
if __name__ == "__main__":
  # Public key parameters (n = p * q)
  p_secret, q_secret = 59, 61
  n = p_secret * q_secret  # 3599
  e = 31

  # Plaintext blocks (Note: 118 = 2 * 59, so it shares the prime factor 59 with n)
  original_plaintexts = [42, 118, 250]

  # Encrypt each block using public key (e, n)
  ciphertexts = [pow(m, e, n) for m in original_plaintexts]

  print(f"Public Key (e, n)   : ({e}, {n})")
  print(f"Intercepted Blocks  : {ciphertexts}\n")

  # Attacker breaks the system without knowing p, q, or d beforehand
  p, q, d, decrypted = break_rsa_via_common_factor(ciphertexts, e, n)

  print(f"Recovered Factors   : p = {p}, q = {q}")
  print(f"Recovered Private d : {d}")
  print(f"Decrypted Blocks    : {decrypted}")