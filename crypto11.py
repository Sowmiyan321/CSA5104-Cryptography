import math

# Total possible keys
total_keys = math.factorial(25)
total_power = math.log2(total_keys)

# Effectively unique keys
unique_keys = total_keys // (25 * 24)
unique_power = math.log2(unique_keys)

print("Total possible keys:", total_keys)
print("Total keys approximately: 2^", round(total_power, 2))

print("Effectively unique keys:", unique_keys)
print("Unique keys approximately: 2^", round(unique_power, 2))