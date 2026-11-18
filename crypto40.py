from collections import Counter
import math
import random

# Standard English single-letter frequency order (most frequent to least frequent)
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# Common English bigrams (%) used to score candidate plaintexts without human intervention
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


def apply_substitution(ciphertext: str, key_map: dict[str, str]) -> str:
  """Decrypts ciphertext using a cipher-letter -> plaintext-letter mapping."""
  return "".join(
      key_map.get(ch.upper(), ch) if ch.isalpha() else ch for ch in ciphertext
  )


def score_english(text: str) -> float:
  """Scores candidate plaintext using English bigram log-likelihood."""
  letters = [ch for ch in text.upper() if ch.isalpha()]
  if len(letters) < 2:
    return 0.0

  score = 0.0
  for i in range(len(letters) - 1):
    bigram = letters[i] + letters[i + 1]
    score += math.log(COMMON_BIGRAMS.get(bigram, 0.01))
  return score


def get_initial_frequency_map(ciphertext: str) -> dict[str, str]:
  """
    Maps ciphertext letters directly to English letters ordered by single-letter frequency.
    """
  counts = Counter(ch.upper() for ch in ciphertext if ch.isalpha())
  ordered_cipher = [ch for ch, _ in counts.most_common()]

  for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    if ch not in ordered_cipher:
      ordered_cipher.append(ch)

  return dict(zip(ordered_cipher, ENGLISH_FREQ_ORDER))


def monoalphabetic_frequency_attack(
    ciphertext: str, top_n: int = 10, steps: int = 2500
) -> list[tuple[float, str]]:
  """
    Performs an automated letter-frequency attack on any monoalphabetic substitution
    cipher without human intervention and returns the top_n candidate plaintexts
    ordered from most to least likely.
    """
  base_map = get_initial_frequency_map(ciphertext)
  candidates: dict[str, float] = {}

  # Include pure unigram frequency-aligned plaintext first
  base_pt = apply_substitution(ciphertext, base_map)
  candidates[base_pt] = score_english(base_pt)

  alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

  for restart in range(5):
    current_map = dict(base_map)
    if restart > 0:
      for _ in range(3):
        a, b = random.sample(alphabet, 2)
        current_map[a], current_map[b] = current_map[b], current_map[a]

    current_pt = apply_substitution(ciphertext, current_map)
    current_score = score_english(current_pt)
    candidates[current_pt] = current_score

    for _ in range(steps):
      a, b = random.sample(alphabet, 2)
      current_map[a], current_map[b] = current_map[b], current_map[a]

      trial_pt = apply_substitution(ciphertext, current_map)
      trial_score = score_english(trial_pt)

      if trial_score > current_score:
        current_score = trial_score
        candidates[trial_pt] = trial_score
      else:
        current_map[a], current_map[b] = current_map[b], current_map[a]

  ranked = sorted(
      ((score, pt) for pt, score in candidates.items()), reverse=True
  )
  return ranked[:top_n]


# --- Driver Code ---
if __name__ == "__main__":
  random.seed(42)

  # Sample monoalphabetic ciphertext
  sample_plain = (
      "CRYPTOGRAPHY AND NETWORK SECURITY PROTECT DATA CONFIDENTIALITY "
      "INTEGRITY AND AUTHENTICATION ACROSS INSECURE COMMUNICATION CHANNELS"
  )
  cipher_table = str.maketrans(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ZEBRASCDFGHIJKLMNOPQTUVWXY"
  )
  ciphertext = sample_plain.translate(cipher_table)

  print(f"Intercepted Ciphertext:\n{ciphertext}\n")
  user_choice = input(
      "Enter number of top possible plaintexts to display (e.g., 10): "
  ).strip()
  top_k = int(user_choice) if user_choice else 10

  top_candidates = monoalphabetic_frequency_attack(ciphertext, top_n=top_k)

  print(
      f"\nTop {len(top_candidates)} Most Likely Plaintexts (Rough Order of"
      " Likelihood):\n"
      + "-" * 70
  )
  for rank, (score, plaintext) in enumerate(top_candidates, start=1):
    print(f"#{rank:2d} [Score: {score:7.2f}] -> {plaintext}")