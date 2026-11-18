def simulate_sha3_capacity_diffusion():
  """
    Simulates SHA-3 (Keccak-f[1600]) state diffusion for a 1024-bit block size (rate r = 1024).
    State size b = 1600 bits (5x5 matrix of 64-bit lanes = 25 lanes total).
    - Rate r = 1024 bits -> 16 lanes (indices 0..15)
    - Capacity c = 576 bits -> 9 lanes (indices 16..24), initially all 0s.
    """
  total_lanes = 25
  lane_size = 64
  rate_bits = 1024
  rate_lanes = rate_bits // lane_size  # 16 lanes
  capacity_lanes = total_lanes - rate_lanes  # 9 lanes

  # Represent each lane by whether it contains at least one nonzero bit (True/False)
  # Initially, all 25 lanes are all zeros (False)
  state = [False] * total_lanes

  # Step 1: Absorb first message block P0 (1024 bits = 16 nonzero lanes) into rate portion
  for i in range(rate_lanes):
    state[i] = True

  zero_capacity_lanes = sum(
      1 for i in range(rate_lanes, total_lanes) if not state[i]
  )
  print(f"Initial state after absorbing P0 (before permutation):")
  print(
      f"  Rate lanes nonzero     : {sum(state[:rate_lanes])} / {rate_lanes}"
  )
  print(
      f"  Capacity lanes still 0 : {zero_capacity_lanes} / {capacity_lanes}\n"
  )

  # Step 2: Apply Keccak-f round transformations (theta, rho, pi, chi, iota)
  # Tracking diffusion across rounds (ignoring permutation positions as instructed)
  rounds = 0
  while any(not lane for lane in state):
    rounds += 1
    # In Keccak-f, the theta (θ) step XORs every bit with the parity of two columns:
    # C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
    # D[x] = C[(x-1)%5] ^ ROT(C[(x+1)%5], 1)
    # A'[x,y] = A[x,y] ^ D[x]
    # Because the first 16 lanes (rows y=0,1,2 and lane [0,3]) are all nonzero,
    # every column x in 0..4 already contains at least 3 nonzero lanes.
    # Thus, after just 1 round's theta step, nonzero bits diffuse into ALL 25 lanes!
    new_state = list(state)
    for x in range(5):
      # Check if column (x-1) or (x+1) has nonzero bits
      col_prev_nonzero = any(state[(x - 1) % 5 + 5 * y] for y in range(5))
      col_next_nonzero = any(state[(x + 1) % 5 + 5 * y] for y in range(5))
      if col_prev_nonzero or col_next_nonzero:
        for y in range(5):
          new_state[x + 5 * y] = True
    state = new_state

    remaining_zeros = sum(1 for lane in state if not lane)
    print(f"After Round {rounds}:")
    print(f"  Total nonzero lanes    : {sum(state)} / {total_lanes}")
    print(f"  Capacity lanes still 0 : {remaining_zeros} / {capacity_lanes}")

  return rounds


# --- Driver Code ---
if __name__ == "__main__":
  rounds_needed = simulate_sha3_capacity_diffusion()
  print(
      f"\nResult: All capacity lanes contain at least one nonzero bit after"
      f" {rounds_needed} round(s)."
  )