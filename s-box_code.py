# ============================================
# DYNAMIC S-BOX GENERATOR
# Method: RC4 KSA + Logistic Chaos Map
# ============================================

# ---------- STEP 1: RC4 Key Scheduling Algorithm ----------
def rc4_ksa(key):
    """Generate a 256-byte permutation using RC4 KSA."""
    S = list(range(256))   # S = [0, 1, 2, ..., 255]
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]   # swap
    
    return S


# ---------- STEP 2: Logistic Chaotic Map ----------
def logistic_chaos(seed, r=3.9, n=256):
    """Generate n chaotic values from a seed (0 < seed < 1)."""
    x = seed
    values = []
    
    for _ in range(n):
        x = r * x * (1 - x)
        values.append(x)
    
    return values


# ---------- STEP 3: Generate Dynamic S-Box ----------
def generate_dynamic_sbox(key):
    """
    Input  : key (bytes)
    Output : dynamic S-Box (list of 256 integers, 0-255)
    """
    # Step 1: RC4 KSA gives us a base permutation
    base = rc4_ksa(key)
    
    # Step 2: Create a chaotic seed from the key
    # Convert first 8 bytes of key to a float between 0 and 1
    seed = int.from_bytes(key[:8], 'big') / (2**64 - 1)
    
    # Step 3: Generate 256 chaotic values
    chaos = logistic_chaos(seed, r=3.9, n=256)
    
    # Step 4: Sort indices by chaotic values → gives a permutation
    order = sorted(range(256), key=lambda i: chaos[i])
    
    # Step 5: Reorder the RC4 permutation using the chaotic order
    dynamic_sbox = [base[i] for i in order]
    
    return dynamic_sbox


# ---------- STEP 6: Print S-Box as 16x16 Grid ----------
def print_sbox(sbox):
    """Print S-Box in 16x16 hexadecimal grid."""
    print("\nDynamic S-Box (16x16):\n")
    for row in range(16):
        line = ""
        for col in range(16):
            line += f"{sbox[row * 16 + col]:02X} "
        print(line)


# ---------- MAIN ----------
if __name__ == "__main__":
    # Input key (16 bytes = AES-128 key)
    key = b'0123456789abcdef'
    
    # Generate S-Box
    sbox = generate_dynamic_sbox(key)
    
    # Print result
    print("Key:", key.hex())
    print_sbox(sbox)