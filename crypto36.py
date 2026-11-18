import math


def is_valid_affine_key(a: int, m: int = 26) -> bool:
  """
    Checks if the affine multiplier 'a' produces a one-to-one mapping modulo m.
    This holds if and only if gcd(a, m) == 1.
    """
  return math.gcd(a, m) == 1


def mod_inverse(a: int, m: int = 26) -> int:
  """Computes the modular multiplicative inverse of 'a' modulo m."""
  if not is_valid_affine_key(a, m):
    raise ValueError(
        f"Invalid key a={a}: gcd({a}, {m}) = {math.gcd(a, m)} != 1. Cipher is not"
        " one-to-one."
    )
  return pow(a, -1, m)


def affine_encrypt(plaintext: str, a: int, b: int) -> str:
  """
    Encrypts plaintext using C = (a * p + b) mod 26.
    """
  if not is_valid_affine_key(a, 26):
    raise ValueError(
        f"Key a={a} is not allowed because gcd({a}, 26) != 1 (not one-to-one)."
    )

  ciphertext = []
  for ch in plaintext.upper():
    if ch.isalpha():
      p = ord(ch) - ord("A")
      c = (a * p + b) % 26
      ciphertext.append(chr(c + ord("A")))
    else:
      ciphertext.append(ch)
  return "".join(ciphertext)


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
  """
    Decrypts ciphertext using p = a^(-1) * (C - b) mod 26.
    """
  a_inv = mod_inverse(a, 26)
  plaintext = []
  for ch in ciphertext.upper():
    if ch.isalpha():
      c = ord(ch) - ord("A")
      p = (a_inv * (c - b)) % 26
      plaintext.append(chr(p + ord("A")))
    else:
      plaintext.append(ch)
  return "".join(plaintext)


def demonstrate_collision(a: int, b: int):
  """
    Demonstrates why an invalid 'a' (like a=2, b=3) fails the one-to-one requirement
    by showing two distinct plaintext values mapping to the exact same ciphertext.
    """
  seen = {}
  collisions = []
  for p in range(26):
    c = (a * p + b) % 26
    if c in seen:
      collisions.append((seen[c], p, c))
    else:
      seen[c] = p
  return collisions


# --- Driver Code ---
if __name__ == "__main__":
  allowed_a = [a for a in range(26) if is_valid_affine_key(a, 26)]
  disallowed_a = [a for a in range(26) if not is_valid_affine_key(a, 26)]

  print(f"Allowed values of a (coprime to 26)     : {allowed_a}")
  print(f"Disallowed values of a (not one-to-one) : {disallowed_a}\n")

  # Demonstrate the exact non-one-to-one example from Question 36 (a = 2, b = 3)
  collisions = demonstrate_collision(a=2, b=3)
  p1, p2, c_val = collisions[0]
  print(f"Collision test for a=2, b=3:")
  print(
      f"  E([2, 3], {p1}) = {c_val} and E([2, 3], {p2}) = {c_val} -> Ambiguous"
      " decryption!\n"
  )

  # Valid encryption and decryption example (a = 5, b = 8)
  msg = "AFFINE CIPHER"
  a_valid, b_valid = 5, 8
  enc = affine_encrypt(msg, a_valid, b_valid)
  dec = affine_decrypt(enc, a_valid, b_valid)

  print(f"Valid Key [a={a_valid}, b={b_valid}]")
  print(f"  Plaintext  : {msg}")
  print(f"  Ciphertext : {enc}")
  print(f"  Decrypted  : {dec}")