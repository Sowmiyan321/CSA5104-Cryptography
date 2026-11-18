import hashlib
import random


def int_hash(message: bytes, q: int) -> int:
  """Computes H(M) mod q using SHA-256."""
  digest = hashlib.sha256(message).hexdigest()
  return int(digest, 16) % q


def dsa_keygen_and_sign(message: bytes, p: int, q: int, g: int, x: int):
  """
    Demonstrates DSA signing twice on the exact same message using fresh random nonces k.
    Each signature (r, s) is completely different, yet both verify validly.
    """
  y = pow(g, x, p)  # Public key

  def sign(msg: bytes):
    k = random.randint(1, q - 1)  # Fresh per-signature random nonce k
    r = pow(g, k, p) % q
    k_inv = pow(k, -1, q)
    h = int_hash(msg, q)
    s = (k_inv * (h + x * r)) % q
    return r, s

  def verify(msg: bytes, sig: tuple[int, int]) -> bool:
    r, s = sig
    if not (0 < r < q and 0 < s < q):
      return False
    w = pow(s, -1, q)
    h = int_hash(msg, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

  sig1 = sign(message)
  sig2 = sign(message)
  return sig1, sig2, verify(message, sig1), verify(message, sig2)


def rsa_deterministic_sign(message: bytes, n: int, e: int, d: int):
  """
    Demonstrates deterministic textbook RSA signing twice on the same message.
    Both signatures are identical.
    """
  h = int_hash(message, n)
  sig1 = pow(h, d, n)
  sig2 = pow(h, d, n)
  verified = pow(sig1, e, n) == h
  return sig1, sig2, verified


# --- Driver Code ---
if __name__ == "__main__":
  msg = b"Transfer Rs. 50,000 to Account 12345"

  # 1. DSA Parameters (small primes for clear demonstration)
  p, q, g = 283, 47, 60  # q divides (p - 1); g^q mod p == 1
  x_dsa = 24  # Private key

  dsa_sig1, dsa_sig2, valid1, valid2 = dsa_keygen_and_sign(msg, p, q, g, x_dsa)
  print("=== DSA Signatures (Randomized per-message nonce k) ===")
  print(f"Signature 1 : (r={dsa_sig1[0]}, s={dsa_sig1[1]}) -> Valid: {valid1}")
  print(f"Signature 2 : (r={dsa_sig2[0]}, s={dsa_sig2[1]}) -> Valid: {valid2}")
  print(f"Signatures identical? : {dsa_sig1 == dsa_sig2}\n")

  # 2. Textbook RSA Parameters
  n_rsa, e_rsa, d_rsa = 3599, 31, 3031
  rsa_sig1, rsa_sig2, rsa_valid = rsa_deterministic_sign(
      msg, n_rsa, e_rsa, d_rsa
  )
  print("=== Textbook RSA Signatures (Deterministic) ===")
  print(f"Signature 1 : {rsa_sig1} -> Valid: {rsa_valid}")
  print(f"Signature 2 : {rsa_sig2} -> Valid: {rsa_valid}")
  print(f"Signatures identical? : {rsa_sig1 == rsa_sig2}")