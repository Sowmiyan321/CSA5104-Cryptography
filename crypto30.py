def xor_bytes(a: bytes, b: bytes) -> bytes:
  """XORs two equal-length byte strings."""
  return bytes(x ^ y for x, y in zip(a, b))


def toy_block_cipher(block: bytes, key: bytes) -> bytes:
  """
    A simple deterministic block cipher E(K, block) for demonstration.
    (Any real block cipher like AES works identically here.)
    """
  # Simple round mixing: XOR with key and rotate left by 1 byte
  xored = xor_bytes(block, key)
  return xored[1:] + xored[:1]


def cbc_mac(blocks: list[bytes], key: bytes) -> bytes:
  """
    Computes the CBC-MAC of a sequence of fixed-size blocks using IV = 0^n.
    T = E(K, ... E(K, E(K, X_1) ^ X_2) ... ^ X_m)
    """
  block_size = len(key)
  state = bytes(block_size)  # Initial Vector IV = 00...0

  for block in blocks:
    if len(block) != block_size:
      raise ValueError(f"Each block must be {block_size} bytes.")
    state = toy_block_cipher(xor_bytes(state, block), key)

  return state


# --- Driver Code (Demonstration of Problem 30 Forgery Attack) ---
if __name__ == "__main__":
  key = b"SECRET_8"  # 8-byte (64-bit) key
  X = b"PAY_100$"  # 1-block message X (8 bytes)

  # Step 1: Legitimate sender computes T = MAC(K, X) for the 1-block message X
  T = cbc_mac([X], key)

  # Step 2: Adversary intercepts (X, T) without knowing K, and constructs
  # the forged 2-block message: X || (X ^ T)
  forged_second_block = xor_bytes(X, T)
  forged_message_blocks = [X, forged_second_block]

  # Step 3: Verify the CBC-MAC of the forged 2-block message X || (X ^ T)
  forged_mac = cbc_mac(forged_message_blocks, key)

  print(f"Original 1-block message X      : {X}")
  print(f"Valid tag T = MAC(K, X)         : {T.hex()}")
  print(f"Forged 2nd block (X ^ T)        : {forged_second_block.hex()}")
  print(f"Tag for 2-block X || (X ^ T)    : {forged_mac.hex()}")
  print(f"Tags match (Forgery succeeds)?  : {T == forged_mac}")