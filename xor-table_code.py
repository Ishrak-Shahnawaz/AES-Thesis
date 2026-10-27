# ============================================
# DYNAMIC XOR TABLE GENERATOR
# Method: PRNG + Fisher-Yates Shuffle
# ============================================

# ---------- STEP 1: Simple PRNG (LCG) ----------
def lcg(seed):
    """Linear Congruential Generator - returns a stream of pseudo-random numbers."""
    a = 1103515245
    c = 12345
    m = 2**31
    while True:
        seed = (a * seed + c) % m
        yield seed


# ---------- STEP 2: Fisher-Yates Shuffle ----------
def fisher_yates(seed, size=16):
    """Shuffle array [0..size-1] using Fisher-Yates with PRNG."""
    prng = lcg(seed)
    arr = list(range(size))
    
    for i in range(size - 1, 0, -1):
        j = next(prng) % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]   # swap
    
    return arr


# ---------- STEP 3: Generate Dynamic XOR Table ----------
def generate_dynamic_xor_table(key):
    """
    Input  : key (bytes)
    Output : dynamic XOR Table (16x16 integers, 0-15)
    """
    # Step 1: Create two different seeds from the key
    seed1 = int.from_bytes(key[:8], 'big') % (2**31 - 1)
    seed2 = int.from_bytes(key[8:16], 'big') % (2**31 - 1)
    
    # Step 2: Generate two independent permutations of 0-15
    P1 = fisher_yates(seed1, 16)
    P2 = fisher_yates(seed2, 16)
    
    # Step 3: Build the XOR table
    # T[r][c] = P1[r] XOR P2[c]
    table = [[P1[r] ^ P2[c] for c in range(16)] for r in range(16)]
    
    return table


# ---------- STEP 4: Print XOR Table ----------
def print_xor_table(table):
    """Print XOR table in 16x16 hexadecimal grid."""
    print("\nDynamic XOR Table (16x16):\n")
    for row in range(16):
        line = ""
        for col in range(16):
            line += f"{table[row][col]:X} "
        print(line)


# ---------- MAIN ----------
if __name__ == "__main__":
    # Input key (16 bytes = AES-128 key)
    key = b'0123456789abcdef'
    
    # Generate XOR table
    xor_table = generate_dynamic_xor_table(key)
    
    # Print result
    print("Key:", key.hex())
    print_xor_table(xor_table)