from collections import Counter
import math
import random

# Standard English letter frequencies (%) from most common to least common
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# Log-probabilities of common English bigrams for scoring candidate plaintexts
COMMON_BIGRAMS = {
    "TH": 3.56,
    "HE": 3.07,
    "IN": 2.43,
    "ER": 2.05,
    "AN": 1.99,
    "RE": 1.85,
    "ON": 1.76,
    "AT": 1.49,
    "EN": 1.45,
    "ND": 1.35,
    "TI": 1.34,
    "ES": 1.34,
    "OR": 1.28,
    "TE": 1.20,
    "OF": 1.17,
    "ED": 1.17,
    "IS": 1.13,
    "IT": 1.12,
    "AL": 1.09,
    "AR": 1.07,
    "ST": 1.05,
    "TO": 1.04,
    "NT": 1.04,
    "NG": 0.95,
    "SE": 0.93,
    "HA": 0.93,
    "AS": 0.87,
    "OU": 0.87,
    "IO": 0.83,
    "LE": 0.83,
    "VE": 0.83,
    "CO": 0.79,
    "ME": 0.79,
    "DE": 0.76,
    "HI": 0.76,
    "RI": 0.73,
    "RO": 0.73,
    "IC": 0.70,
    "NE": 0.69,
    "EA": 0.69,
    "RA": 0.69,
    "CE": 0.65,
}


def decrypt_with_key(ciphertext: str, key_map: dict[str, str]) -> str:
  """Applies a cipher-to-plain character mapping while preserving non-letters."""
  return "".join(
      key_map.get(ch.upper(), ch) if ch.isalpha() else ch for ch in ciphertext
  )


def score_english_text(text: str) -> float:
  """
    Scores how closely candidate plaintext resembles English using bigram log-likelihood.
    """
  letters = [ch for ch in text.upper() if ch.isalpha()]
  if len(letters) < 2:
    return 0.0

  score = 0.0
  for i in range(len(letters) - 1):
    bigram = letters[i] + letters[i + 1]
    freq = COMMON_BIGRAMS.get(bigram, 0.01)
    score += math.log(freq)
  return score


def initial_frequency_key(ciphertext: str) -> dict[str, str]:
  """
    Creates an initial substitution mapping by aligning the ciphertext's
    most frequent letters with ETAOINSHRDLCUMWFGYPBVKJXQZ.
    """
  letters = [ch.upper() for ch in ciphertext if ch.isalpha()]
  counts = Counter(letters)

  # Order ciphertext letters by descending frequency, then append unseen letters
  sorted_cipher_chars = [char for char, _ in counts.most_common()]
  for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    if ch not in sorted_cipher_chars:
      sorted_cipher_chars.append(ch)

  return {
      c_char: p_char
      for c_char, p_char in zip(sorted_cipher_chars, ENGLISH_FREQ_ORDER)
  }


def frequency_attack_monoalphabetic(
    ciphertext: str, top_n: int = 10, iterations: int = 2500
) -> list[tuple[float, str]]:
  """
    Performs an automated letter-frequency and hill-climbing bigram attack on a
    monoalphabetic substitution cipher without human intervention.
    Returns the top_n candidate plaintexts ordered by likelihood.
    """
  base_key = initial_frequency_key(ciphertext)
  candidates: dict[str, float] = {}

  # Record the pure unigram frequency-matching baseline first
  base_pt = decrypt_with_key(ciphertext, base_key)
  candidates[base_pt] = score_english_text(base_pt)

  # Refine the frequency mapping using hill-climbing swaps to maximize English bigram likelihood
  cipher_alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

  for restart in range(5):
    current_key = dict(base_key)
    if restart > 0:
      # Small perturbation around the frequency-aligned key for diverse candidates
      for _ in range(3):
        a, b = random.sample(cipher_alphabet, 2)
        current_key[a], current_key[b] = current_key[b], current_key[a]

    current_pt = decrypt_with_key(ciphertext, current_key)
    current_score = score_english_text(current_pt)
    candidates[current_pt] = current_score

    for _ in range(iterations):
      a, b = random.sample(cipher_alphabet, 2)
      # Swap two plaintext assignments
      current_key[a], current_key[b] = current_key[b], current_key[a]

      new_pt = decrypt_with_key(ciphertext, current_key)
      new_score = score_english_text(new_pt)

      if new_score > current_score:
        current_score = new_score
        candidates[new_pt] = new_score
      else:
        # Revert swap if it did not improve likelihood
        current_key[a], current_key[b] = current_key[b], current_key[a]

  # Sort unique candidate plaintexts in descending order of likelihood score
  ranked = sorted(
      ((score, pt) for pt, score in candidates.items()), reverse=True
  )
  return ranked[:top_n]


# --- Driver Code ---
if __name__ == "__main__":
  random.seed(42)

  # Sample ciphertext encrypted with a secret monoalphabetic substitution key
  sample_plaintext = (
      "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND INFORMATION SECURITY "
      "DEPENDS ON KEEPING THE SUBSTITUTION KEY SECRET FROM ANY ADVERSARY "
      "ANALYZING LETTER FREQUENCIES IN THE INTERCEPTED CIPHERTEXT"
  )
  secret_sub_map = str.maketrans(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "QWERTYUIOPASDFGHJKLZXCVBNM"
  )
  ciphertext = sample_plaintext.translate(secret_sub_map)

  top_k = int(
      input("Enter number of top possible plaintexts to display (e.g., 10): ")
      or 10
  )

  results = frequency_attack_monoalphabetic(ciphertext, top_n=top_k)

  print(f"\nTop {len(results)} Most Likely Plaintexts:\n" + "-" * 50)
  for rank, (score, pt) in enumerate(results, start=1):
    print(f"#{rank:2d} [Score: {score:7.2f}] -> {pt}")