import matplotlib.pyplot as plt
import os
import random
from dynamic_aes_enc_code import generate_dynamic_sbox, generate_dynamic_xor_table, key_expansion, aes_encrypt_block

# 1. Setup from your code
key = b'0123456789abcdef'
sbox = generate_dynamic_sbox(key)
xor_table = generate_dynamic_xor_table(key)
round_keys = key_expansion(key, sbox)

bit_change_percentages = []

print("Running 1,000 trials for Avalanche Effect...")
for _ in range(1000):
    # Generate random 16-byte plaintext
    pt = os.urandom(16)
    
    # Encrypt original
    ct1 = aes_encrypt_block(pt, round_keys, sbox, xor_table)
    
    # Flip one random bit (0 to 127)
    bit_to_flip = random.randint(0, 127)
    pt_mutated = bytearray(pt)
    pt_mutated[bit_to_flip // 8] ^= (1 << (bit_to_flip % 8))
    
    # Encrypt mutated
    ct2 = aes_encrypt_block(bytes(pt_mutated), round_keys, sbox, xor_table)
    
    # Count changed bits in ciphertext
    diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1, ct2))
    percentage = (diff_bits / 128) * 100
    bit_change_percentages.append(percentage)

# 2. Draw the Diagram
plt.figure(figsize=(10, 6))
plt.hist(bit_change_percentages, bins=20, color='skyblue', edgecolor='black', alpha=0.8)

# Add the ideal 50% line
plt.axvline(x=50, color='red', linestyle='dashed', linewidth=2, label='Ideal 50%')

plt.title('Avalanche Effect Distribution (1,000 Trials)', fontsize=14, fontweight='bold')
plt.xlabel('Percentage of Ciphertext Bits Changed (%)', fontsize=12)
plt.ylabel('Frequency (Number of Trials)', fontsize=12)
plt.legend()
plt.grid(axis='y', alpha=0.5)

# Save the image
plt.savefig('avalanche_histogram.png', dpi=300, bbox_inches='tight')
print("Diagram saved as 'avalanche_histogram.png'!")
plt.show()