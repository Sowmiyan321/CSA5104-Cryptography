import math


def find_prime_factors(n: int) -> tuple[int, int]:
  """
    Uses trial-and-error to find the two prime factors p and q of modulus n.
    """
  for p in range(2, math.isqrt(n) + 1):
    if n % p == 0:
      q = n // p
      return p, q
  raise ValueError("n could not be factored into two primes.")


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
    raise ValueError(f"Modular inverse does not exist since gcd({e}, {phi}) != 1")
  return x % phi


# --- Driver Code (Values from Question 24) ---
if __name__ == "__main__":
  e = 31
  n = 3599

  # Step 1: Find p and q via trial-and-error
  p, q = find_prime_factors(n)

  # Step 2: Compute Euler's totient function f(n) = (p - 1)(q - 1)
  phi_n = (p - 1) * (q - 1)

  # Step 3: Find private key d using Extended Euclidean Algorithm
  d = mod_inverse(e, phi_n)

  print(f"Public Key (e, n) : ({e}, {n})")
  print(f"Prime factors     : p = {p}, q = {q}")
  print(f"Totient f(n)      : {phi_n}")
  print(f"Private Key (d)   : {d}")
  print(f"Verification      : ({e} * {d}) mod {phi_n} = {(e * d) % phi_n}")