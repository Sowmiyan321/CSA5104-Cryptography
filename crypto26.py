import math
import random


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
  """Extended Euclidean Algorithm returning (gcd, x, y) such that a*x + b*y = gcd."""
  if a == 0:
    return b, 0, 1
  gcd, x1, y1 = extended_gcd(b % a, a)
  x = y1 - (b // a) * x1
  y = x1
  return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
  """Computes the modular multiplicative inverse d of e modulo phi."""
  gcd, x, _ = extended_gcd(e, phi)
  if gcd != 1:
    raise ValueError("Modular inverse does not exist.")
  return x % phi


def factor_n_using_leaked_key(
    n: int, e_old: int, d_old: int
) -> tuple[int, int]:
  """
    Uses a leaked (e, d) pair to factor the modulus n into p and q.
    Since e*d - 1 is a multiple of phi(n), we write e*d - 1 = (2^s) * r (with r odd)
    and find a non-trivial square root of 1 modulo n.
    """
  k = e_old * d_old - 1
  s = 0
  r = k
  while r % 2 == 0:
    s += 1
    r //= 2

  while True:
    a = random.randint(2, n - 2)
    x = pow(a, r, n)

    if x == 1 or x == n - 1:
      continue

    for _ in range(s - 1):
      x_prev = x
      x = pow(x, 2, n)
      if x == 1:
        p = math.gcd(x_prev - 1, n)
        q = n // p
        return p, q
      if x == n - 1:
        break


def compromise_new_keypair(
    n: int, e_old: int, d_old: int, e_new: int
) -> tuple[int, int, int]:
  """
    Demonstrates how an attacker uses Bob's leaked keypair (e_old, d_old)
    to derive Bob's newly generated private key d_new on the same modulus n.
    """
  p, q = factor_n_using_leaked_key(n, e_old, d_old)
  phi_n = (p - 1) * (q - 1)
  d_new = mod_inverse(e_new, phi_n)
  return p, q, d_new


# --- Driver Code ---
if __name__ == "__main__":
  # Bob's original setup
  p_secret, q_secret = 59, 61
  n = p_secret * q_secret  # 3599
  phi_n = (p_secret - 1) * (q_secret - 1)  # 3480

  e_old = 31
  d_old = mod_inverse(e_old, phi_n)  # 3031 (Leaked!)

  # Bob keeps n = 3599 and generates a new keypair (e_new, d_new)
  e_new = 37
  d_new_actual = mod_inverse(e_new, phi_n)  # 283

  print(f"Shared Modulus (n)      : {n}")
  print(f"Leaked Old Keypair      : (e={e_old}, d={d_old})")
  print(f"Bob's New Public Key    : e_new = {e_new}\n")

  # Attacker recovers p, q, and d_new using only public info + leaked keypair
  p_found, q_found, d_new_cracked = compromise_new_keypair(
      n, e_old, d_old, e_new
  )

  print(f"Attacker Factored n     : p = {p_found}, q = {q_found}")
  print(f"Cracked New Private Key : d_new = {d_new_cracked}")
  print(f"Matches Bob's New d?    : {d_new_cracked == d_new_actual}")