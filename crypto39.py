from collections import Counter

# Standard English letter frequency percentages (A-Z)
ENGLISH_FREQ = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
    'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
    'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
    'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
    'Y': 1.97, 'Z': 0.07,
}


def decrypt_additive(ciphertext: str, key: int) -> str:
  """Decrypts an additive (Caesar) cipher with shift key k (0..25)."""
  result = []
  for ch in ciphertext:
    if ch.isalpha():
      base = ord('A') if ch.isupper() else ord('a')
      shifted = (ord(ch) - base - key) % 26
      result.append(chr(base + shifted))
    else:
      result.append(ch)
  return ''.join(result)


def chi_squared_score(text: str) -> float:
  """
    Computes the Chi-Squared statistic comparing candidate text's letter
    distribution against standard English frequencies. Lower score = better match.
    """
  letters = [ch.upper() for ch in text if ch.isalpha()]
  total = len(letters)
  if total == 0:
    return float('inf')

  counts = Counter(letters)
  chi_sq = 0.0
  for letter, expected_pct in ENGLISH_FREQ.items():
    observed = counts.get(letter, 0)
    expected = total * (expected_pct / 100.0)
    chi_sq += ((observed - expected) ** 2) / expected

  return chi_sq


def frequency_attack_additive(
    ciphertext: str, top_n: int = 10
) -> list[tuple[float, int, str]]:
  """
    Performs an automated letter-frequency attack across all 26 additive keys
    and returns the top_n candidate plaintexts ordered from most to least likely.
    """
  candidates = []
  for key in range(26):
    candidate_pt = decrypt_additive(ciphertext, key)
    score = chi_squared_score(candidate_pt)
    candidates.append((score, key, candidate_pt))

  # Sort ascending by Chi-Squared score (lowest deviation from English = highest likelihood)
  candidates.sort(key=lambda item: item[0])
  return candidates[:top_n]


# --- Driver Code ---
if __name__ == '__main__':
  # Example ciphertext encrypted with an unknown additive shift
  sample_ciphertext = (
      'WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ DQG LQIRUPDWLRQ VHFXULWB '
      'GHSHQGV RQ NHHS LQJ WKH NHB VHFUHW IURP DQBDGYHUVDUB'
  )

  print(f'Intercepted Ciphertext:\n{sample_ciphertext}\n')
  user_input = input(
      'Enter number of top possible plaintexts to display (e.g., 10): '
  ).strip()
  top_k = int(user_input) if user_input else 10
  top_k = max(1, min(26, top_k))

  results = frequency_attack_additive(sample_ciphertext, top_n=top_k)

  print(
      f'\nTop {len(results)} Most Likely Plaintexts (Ordered by Likelihood):\n'
      + '-' * 65
  )
  for rank, (score, key, pt) in enumerate(results, start=1):
    print(f'#{rank:2d} [Key={key:2d} | Chi-Sq={score:7.2f}] -> {pt}')