import secrets


def generate_otp_keystream(length: int) -> list[int]:
  """
    Generates a truly random key stream of integers in the range [0, 25]
    (representing shifts of 0 through 25 letters modulo 26).
    """
  return [secrets.randbelow(26) for _ in range(length)]


def otp_vigenere_encrypt(plaintext: str, key_stream: list[int]) -> str:
  """
    Encrypts alphabetic characters using a one-time pad Vigenère shift stream.
    """
  letters = [ch.lower() for ch in plaintext if ch.isalpha()]
  if len(key_stream) < len(letters):
    raise ValueError(
        "Key stream must be at least as long as the number of letters in"
        " plaintext."
    )

  ciphertext = []
  for ch, shift in zip(letters, key_stream):
    p_val = ord(ch) - ord("a")
    c_val = (p_val + shift) % 26
    ciphertext.append(chr(c_val + ord("a")))

  return "".join(ciphertext)


def otp_vigenere_decrypt(ciphertext: str, key_stream: list[int]) -> str:
  """
    Decrypts ciphertext back to plaintext using the same one-time pad shift stream.
    """
  letters = [ch.lower() for ch in ciphertext if ch.isalpha()]
  if len(key_stream) < len(letters):
    raise ValueError(
        "Key stream must be at least as long as the ciphertext length."
    )

  plaintext = []
  for ch, shift in zip(letters, key_stream):
    c_val = ord(ch) - ord("a")
    p_val = (c_val - shift) % 26
    plaintext.append(chr(p_val + ord("a")))

  return "".join(plaintext)


# --- Driver Code ---
if __name__ == "__main__":
  # Example using the shift sequence shown in Question 35
  plaintext = "send more money"
  example_key = [3, 19, 5, 12, 8, 21, 0, 14, 7, 25, 4, 11, 2]

  encrypted = otp_vigenere_encrypt(plaintext, example_key)
  decrypted = otp_vigenere_decrypt(encrypted, example_key)

  print(f"Plaintext  : {plaintext}")
  print(f"Key Stream : {example_key}")
  print(f"Ciphertext : {encrypted}")
  print(f"Decrypted  : {decrypted}\n")

  # Random One-Time Pad generation example
  letter_count = sum(1 for c in plaintext if c.isalpha())
  random_key = generate_otp_keystream(letter_count)
  rand_ct = otp_vigenere_encrypt(plaintext, random_key)
  rand_pt = otp_vigenere_decrypt(rand_ct, random_key)

  print(f"Random Key : {random_key}")
  print(f"Ciphertext : {rand_ct}")
  print(f"Decrypted  : {rand_pt}")