def pad_bits(bitstring: str, block_size: int) -> str:
  """
    Pads a binary string by ALWAYS appending a '1' bit followed by 
    as few '0' bits as needed to reach a multiple of block_size.
    """
  # Always append '1' first, even if already aligned to block_size
  padded = bitstring + "1"

  # Append '0's until the length is a multiple of block_size
  while len(padded) % block_size != 0:
    padded += "0"

  return padded


def unpad_bits(padded_bitstring: str) -> str:
  """
    Removes padding by stripping trailing '0' bits and the final '1' delimiter bit.
    """
  # Find the last occurrence of '1'
  last_one_index = padded_bitstring.rfind("1")
  if last_one_index == -1:
    raise ValueError("Invalid padding: No '1' delimiter bit found.")

  return padded_bitstring[:last_one_index]


def xor_bits(a: str, b: str) -> str:
  """XORs two binary strings of equal length."""
  return "".join("1" if x != y else "0" for x, y in zip(a, b))


def simple_block_cipher(block: str, key: str, encrypt: bool = True) -> str:
  """
    A toy reversible block cipher (XOR + bit rotation) for demonstration.
    """
  if encrypt:
    xored = xor_bits(block, key)
    return xored[1:] + xored[0]  # Left circular shift by 1
  else:
    unshifted = block[-1] + block[:-1]  # Right circular shift by 1
    return xor_bits(unshifted, key)


def encrypt_modes(plaintext_bits: str, key: str, iv: str, mode: str) -> str:
  block_size = len(key)
  # Always pad the message, even if len(plaintext_bits) % block_size == 0
  padded_pt = pad_bits(plaintext_bits, block_size)
  blocks = [
      padded_pt[i : i + block_size]
      for i in range(0, len(padded_pt), block_size)
  ]

  ciphertext_blocks = []
  prev_block = iv

  for block in blocks:
    if mode == "ECB":
      c_block = simple_block_cipher(block, key, encrypt=True)
    elif mode == "CBC":
      xored = xor_bits(block, prev_block)
      c_block = simple_block_cipher(xored, key, encrypt=True)
      prev_block = c_block
    elif mode == "CFB":
      keystream = simple_block_cipher(prev_block, key, encrypt=True)
      c_block = xor_bits(block, keystream)
      prev_block = c_block
    else:
      raise ValueError("Unsupported mode. Choose ECB, CBC, or CFB.")

    ciphertext_blocks.append(c_block)

  return "".join(ciphertext_blocks)


def decrypt_modes(ciphertext_bits: str, key: str, iv: str, mode: str) -> str:
  block_size = len(key)
  blocks = [
      ciphertext_bits[i : i + block_size]
      for i in range(0, len(ciphertext_bits), block_size)
  ]

  plaintext_blocks = []
  prev_block = iv

  for c_block in blocks:
    if mode == "ECB":
      p_block = simple_block_cipher(c_block, key, encrypt=False)
    elif mode == "CBC":
      decrypted = simple_block_cipher(c_block, key, encrypt=False)
      p_block = xor_bits(decrypted, prev_block)
      prev_block = c_block
    elif mode == "CFB":
      keystream = simple_block_cipher(prev_block, key, encrypt=True)
      p_block = xor_bits(c_block, keystream)
      prev_block = c_block
    else:
      raise ValueError("Unsupported mode.")

    plaintext_blocks.append(p_block)

  padded_pt = "".join(plaintext_blocks)
  return unpad_bits(padded_pt)


# --- Driver Code ---
if __name__ == "__main__":
  key = "10110010"  # 8-bit key (block size = 8 bits)
  iv = "01010101"  # 8-bit Initialization Vector

  # Case 1: Message length is already an exact multiple of block size (8 bits)
  msg_exact = "11001000"

  print(f"Original Message (8 bits): {msg_exact}")
  print(f"Padded Message (16 bits) : {pad_bits(msg_exact, len(key))}\n")

  for mode in ["ECB", "CBC", "CFB"]:
    ct = encrypt_modes(msg_exact, key, iv, mode)
    pt = decrypt_modes(ct, key, iv, mode)
    print(f"[{mode}] Ciphertext: {ct} -> Decrypted & Unpadded: {pt}")