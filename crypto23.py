# Standard S-DES Permutation Tables and S-Boxes
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def permute(bits: str, table: tuple) -> str:
  return "".join(bits[i - 1] for i in table)


def left_shift(bits: str, n: int) -> str:
  return bits[n:] + bits[:n]


def xor(a: str, b: str) -> str:
  return "".join("1" if x != y else "0" for x, y in zip(a, b))


def generate_subkeys(key_10bit: str) -> tuple[str, str]:
  p10 = permute(key_10bit, P10)
  left, right = p10[:5], p10[5:]

  # Subkey K1 (Left Shift 1)
  left_1, right_1 = left_shift(left, 1), left_shift(right, 1)
  k1 = permute(left_1 + right_1, P8)

  # Subkey K2 (Left Shift 2 from previous state)
  left_2, right_2 = left_shift(left_1, 2), left_shift(right_1, 2)
  k2 = permute(left_2 + right_2, P8)

  return k1, k2


def sbox_lookup(bits_4: str, sbox: list[list[int]]) -> str:
  row = int(bits_4[0] + bits_4[3], 2)
  col = int(bits_4[1] + bits_4[2], 2)
  return f"{sbox[row][col]:02b}"


def fk(bits_8: str, subkey: str) -> str:
  left, right = bits_8[:4], bits_8[4:]
  expanded = permute(right, EP)
  xored = xor(expanded, subkey)
  s_out = sbox_lookup(xored[:4], S0) + sbox_lookup(xored[4:], S1)
  p4_out = permute(s_out, P4)
  return xor(left, p4_out) + right


def sdes_encrypt_block(block_8bit: str, k1: str, k2: str) -> str:
  ip = permute(block_8bit, IP)
  round1 = fk(ip, k1)
  swapped = round1[4:] + round1[:4]
  round2 = fk(swapped, k2)
  return permute(round2, IP_INV)


def ctr_crypt(data_bits: str, key_10bit: str, initial_counter_8bit: str) -> str:
  """
    Encrypts or decrypts data using S-DES in Counter (CTR) mode.
    (CTR encryption and decryption use the exact same operation.)
    """
  k1, k2 = generate_subkeys(key_10bit)
  blocks = [data_bits[i : i + 8] for i in range(0, len(data_bits), 8)]

  counter = int(initial_counter_8bit, 2)
  output_blocks = []

  for block in blocks:
    counter_bits = f"{counter:08b}"
    keystream = sdes_encrypt_block(counter_bits, k1, k2)
    output_blocks.append(xor(block, keystream))
    counter = (counter + 1) % 256  # Increment 8-bit counter modulo 256

  return "".join(output_blocks)


def format_nibbles(bitstring: str) -> str:
  return " ".join(bitstring[i : i + 4] for i in range(0, len(bitstring), 4))


# --- Driver Code (Test Data from Question 23) ---
if __name__ == "__main__":
  counter_start = "00000000"
  key = "0111111101"
  plaintext = "000000010000001000000100"

  ciphertext = ctr_crypt(plaintext, key, counter_start)
  decrypted = ctr_crypt(ciphertext, key, counter_start)

  print(f"Plaintext  : {format_nibbles(plaintext)}")
  print(f"Ciphertext : {format_nibbles(ciphertext)}")
  print(f"Decrypted  : {format_nibbles(decrypted)}")