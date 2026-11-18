def standard_diffie_hellman(q: int, a: int, x_alice: int, x_bob: int):
  """Standard Diffie-Hellman key exchange using modular exponentiation (a^x mod q)."""
  A = pow(a, x_alice, q)  # Alice sends a^x_alice mod q
  B = pow(a, x_bob, q)  # Bob sends a^x_bob mod q

  key_alice = pow(B, x_alice, q)
  key_bob = pow(A, x_bob, q)
  assert key_alice == key_bob
  return A, B, key_alice


def multiplicative_dh_variant(q: int, a: int, x_alice: int, x_bob: int):
  """
    Variant where participants send (x * a) mod q instead of a^x mod q,
    and demonstrates how Eve breaks it completely using modular division.
    """
  # 1. Key Exchange (Multiplication instead of exponentiation)
  A = (x_alice * a) % q  # Alice sends x_alice * a mod q
  B = (x_bob * a) % q  # Bob sends x_bob * a mod q

  # Method to agree on a shared key:
  # Alice computes (x_alice * B) mod q = x_alice * x_bob * a mod q
  # Bob computes   (x_bob * A) mod q   = x_bob * x_alice * a mod q
  key_alice = (x_alice * B) % q
  key_bob = (x_bob * A) % q
  assert key_alice == key_bob

  # 2. Eve's Attack (Breaking the system completely)
  # Since a and q are public, Eve computes the modular inverse of a mod q: a^(-1) mod q
  a_inv = pow(a, -1, q)

  # Eve directly recovers both secret numbers x_alice and x_bob
  eve_found_x_alice = (A * a_inv) % q
  eve_found_x_bob = (B * a_inv) % q

  # Eve computes the shared secret key
  eve_found_key = (eve_found_x_alice * eve_found_x_bob * a) % q

  return {
      "A_sent": A,
      "B_sent": B,
      "shared_key": key_alice,
      "eve_x_alice": eve_found_x_alice,
      "eve_x_bob": eve_found_x_bob,
      "eve_key": eve_found_key,
  }


# --- Driver Code ---
if __name__ == "__main__":
  q = 353  # Public prime modulus
  a = 3  # Public base/multiplier
  x_alice = 97  # Alice's secret number
  x_bob = 233  # Bob's secret number

  _, _, std_key = standard_diffie_hellman(q, a, x_alice, x_bob)
  print(f"Standard DH Shared Key      : {std_key}\n")

  res = multiplicative_dh_variant(q, a, x_alice, x_bob)
  print("--- Multiplicative Variant (x * a mod q) ---")
  print(f"Public Values Intercepted   : A = {res['A_sent']}, B = {res['B_sent']}")
  print(f"Alice & Bob's Shared Key    : {res['shared_key']}")
  print(
      f"Eve Recovered Secrets       : x_alice = {res['eve_x_alice']}, x_bob ="
      f" {res['eve_x_bob']}"
  )
  print(f"Eve Recovered Shared Key    : {res['eve_key']}")