def left_shift_one_bit(data: bytes) -> bytes:
  """Performs a 1-bit left shift across an entire byte array."""
  shifted = bytearray(len(data))
  carry = 0
  for i in reversed(range(len(data))):
    next_carry = (data[i] >> 7) & 1
    shifted[i] = ((data[i] << 1) | carry) & 0xFF
    carry = next_carry
  return bytes(shifted)


def xor_bytes(a: bytes, b: bytes) -> bytes:
  """XORs two equal-length byte arrays."""
  return bytes(x ^ y for x, y in zip(a, b))


def derive_next_subkey(prev_key: bytes, rb_constant: bytes) -> bytes:
  """
    Derives the next CMAC subkey:
    1. Left-shift prev_key by 1 bit.
    2. If the Most Significant Bit (MSB) of prev_key was 1, XOR with R_b.
    """
  msb_is_one = (prev_key[0] & 0x80) != 0
  shifted = left_shift_one_bit(prev_key)
  if msb_is_one:
    return xor_bytes(shifted, rb_constant)
  return shifted


def generate_cmac_subkeys(
    block_cipher_encrypt_zero, block_size_bits: int
) -> tuple[bytes, bytes, bytes]:
  """
    Generates CMAC subkeys K1 and K2 for 64-bit or 128-bit block ciphers.
    """
  if block_size_bits == 64:
    # R_64 = 0x000000000000001B (from irreducible polynomial x^64 + x^4 + x^3 + x + 1)
    rb = bytes.fromhex("000000000000001B")
  elif block_size_bits == 128:
    # R_128 = 0x00000000000000000000000000000087 (from x^128 + x^7 + x^2 + x + 1)
    rb = bytes.fromhex("00000000000000000000000000000087")
  else:
    raise ValueError("Block size must be 64 or 128 bits.")

  # Step 1: Apply the block cipher to an all-zero block L = E(K, 0^b)
  L = block_cipher_encrypt_zero(block_size_bits // 8)

  # Step 2: Derive K1 from L, and K2 from K1
  K1 = derive_next_subkey(L, rb)
  K2 = derive_next_subkey(K1, rb)

  return L, K1, K2


# --- Driver Code ---
if __name__ == "__main__":
  # Example simulated output L = E(K, 0^b) with MSB = 1 to trigger conditional XOR
  def mock_cipher_zero_block(num_bytes: int) -> bytes:
    if num_bytes == 8:  # 64-bit block (e.g., 3DES)
      return bytes.fromhex("8011223344556677")
    elif num_bytes == 16:  # 128-bit block (e.g., AES)
      return bytes.fromhex("80112233445566778899AABBCCDDEEFF")
    raise ValueError("Unsupported block size")

  for bits in (64, 128):
    L, k1, k2 = generate_cmac_subkeys(mock_cipher_zero_block, bits)
    print(f"=== {bits}-bit Block Size ===")
    print(f"L  = E(K, 0^{bits}) : {L.hex().upper()}")
    print(f"Subkey K1         : {k1.hex().upper()}")
    print(f"Subkey K2         : {k2.hex().upper()}\n")