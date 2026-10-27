# ============================================
# DYNAMIC AES-128 DECRYPTION (CBC MODE)
# Uses: Inverse Dynamic S-Box + Inverse Dynamic XOR Table
# Input  : Key + IV + Ciphertext
# Output : Plaintext
# ============================================

from Crypto.Util.Padding import unpad

# ---------- STEP 1: RC4 KEY SCHEDULING ALGORITHM ----------
def rc4_ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

# ---------- STEP 2: LOGISTIC CHAOTIC MAP ----------
def logistic_chaos(seed, r=3.9, n=256):
    x = seed
    values = []
    for _ in range(n):
        x = r * x * (1 - x)
        values.append(x)
    return values

# ---------- STEP 3: GENERATE DYNAMIC S-BOX ----------
def generate_dynamic_sbox(key):
    base = rc4_ksa(key)
    seed = int.from_bytes(key[:8], 'big') / (2**64 - 1)
    chaos = logistic_chaos(seed, r=3.9, n=256)
    order = sorted(range(256), key=lambda i: chaos[i])
    dynamic_sbox = [base[i] for i in order]
    return dynamic_sbox

# ---------- STEP 4: GENERATE INVERSE S-BOX ----------
def inverse_sbox(sbox):
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

# ---------- STEP 5: SIMPLE PRNG (LCG) ----------
def lcg(seed):
    a = 1103515245
    c = 12345
    m = 2**31
    while True:
        seed = (a * seed + c) % m
        yield seed

# ---------- STEP 6: FISHER-YATES SHUFFLE ----------
def fisher_yates(seed, size=16):
    prng = lcg(seed)
    arr = list(range(size))
    for i in range(size - 1, 0, -1):
        j = next(prng) % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return arr

# ---------- STEP 7: GENERATE DYNAMIC XOR TABLE + INVERSE ----------
def generate_dynamic_xor_table(key):
    seed1 = int.from_bytes(key[:8], 'big') % (2**31 - 1)
    seed2 = int.from_bytes(key[8:16], 'big') % (2**31 - 1)
    P1 = fisher_yates(seed1, 16)
    P2 = fisher_yates(seed2, 16)
    
    # Forward table
    table = [[P1[r] ^ P2[c] for c in range(16)] for r in range(16)]
    
    # Inverse of P1 (needed for inverse table)
    invP1 = [0] * 16
    for i, v in enumerate(P1):
        invP1[v] = i
    
    # Inverse table: inv_table[o][k] = invP1[o ^ P2[k]]
    inv_table = [[invP1[o ^ P2[k]] for k in range(16)] for o in range(16)]
    
    return table, inv_table

# ---------- STEP 8: STANDARD AES KEY SCHEDULE ----------
def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word, sbox):
    return [sbox[b] for b in word]

def rcon(i):
    return [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36][i-1] if 1 <= i <= 10 else 0

def key_expansion(key, sbox):
    Nk, Nr = 4, 10
    w = []
    for i in range(Nk):
        w.append(list(key[4*i:4*i+4]))
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1][:]
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp, sbox)
            temp[0] ^= rcon(i//Nk)
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(Nr+1):
        key_mat = [[0]*4 for _ in range(4)]
        for col in range(4):
            word = w[4*r + col]
            for row in range(4):
                key_mat[row][col] = word[row]
        round_keys.append(key_mat)
    return round_keys

# ---------- STEP 9: INVERSE AES TRANSFORMATIONS ----------
def inv_sub_bytes(state, inv_sbox):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def xtime(a):
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return (a << 1) & 0xff

def inv_mix_column(col):
    def mul9(a):  return xtime(xtime(xtime(a))) ^ a
    def mul11(a): return xtime(xtime(xtime(a))) ^ xtime(a) ^ a
    def mul13(a): return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ a
    def mul14(a): return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ xtime(a)
    u0, u1, u2, u3 = col[0], col[1], col[2], col[3]
    col[0] = mul14(u0) ^ mul11(u1) ^ mul13(u2) ^ mul9(u3)
    col[1] = mul9(u0)  ^ mul14(u1) ^ mul11(u2) ^ mul13(u3)
    col[2] = mul13(u0) ^ mul9(u1)  ^ mul14(u2) ^ mul11(u3)
    col[3] = mul11(u0) ^ mul13(u1) ^ mul9(u2)  ^ mul14(u3)

def inv_mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        inv_mix_column(col)
        for j in range(4):
            state[j][i] = col[j]

# ---------- STEP 10: INVERSE DYNAMIC ADD ROUND KEY ----------
def inv_add_round_key(state, round_key, inv_table):
    for i in range(4):
        for j in range(4):
            val = state[i][j]
            key_byte = round_key[i][j]
            hi = (val >> 4) & 0x0F
            lo = val & 0x0F
            khi = (key_byte >> 4) & 0x0F
            klo = key_byte & 0x0F
            old_hi = inv_table[hi][khi]
            old_lo = inv_table[lo][klo]
            state[i][j] = (old_hi << 4) | old_lo

# ---------- STEP 11: DECRYPT ONE BLOCK ----------
def aes_decrypt_block(ciphertext_block, round_keys, inv_sbox, inv_table):
    state = [[ciphertext_block[j*4 + i] for j in range(4)] for i in range(4)]
    
    inv_add_round_key(state, round_keys[10], inv_table)
    inv_shift_rows(state)
    inv_sub_bytes(state, inv_sbox)
    
    for rnd in range(9, 0, -1):
        inv_add_round_key(state, round_keys[rnd], inv_table)
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state, inv_sbox)
    
    inv_add_round_key(state, round_keys[0], inv_table)
    
    return bytes([state[j][i] for i in range(4) for j in range(4)])

# ---------- STEP 12: CBC DECRYPTION ----------
def decrypt_cbc(iv, ciphertext, key):
    sbox = generate_dynamic_sbox(key)
    inv_sbox = inverse_sbox(sbox)
    _, inv_table = generate_dynamic_xor_table(key)
    round_keys = key_expansion(key, sbox)
    
    plaintext = b''
    prev_block = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec_block = aes_decrypt_block(block, round_keys, inv_sbox, inv_table)
        plaintext_block = bytes([dec_block[j] ^ prev_block[j] for j in range(16)])
        plaintext += plaintext_block
        prev_block = block
    
    return unpad(plaintext, 16)

# ---------- MAIN ----------
if __name__ == "__main__":
    
    # ---------- INPUTS (paste from encryption output) ----------
    key = b'0123456789abcdef'
    
    iv_hex = "eef77b1bc69dffefa91fd6a68f5be17d"
    ciphertext_hex = "0aa490bbb5a8c2dfe2207902453fd442ba7bfe1a9786b5a6bccb4e59d2ff289dd0ce831ed5d2ed4da72026c7430e55af"
    
    # ---------- CONVERT HEX TO BYTES ----------
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    # ---------- DECRYPT ----------
    plaintext = decrypt_cbc(iv, ciphertext, key)
    
    # ---------- OUTPUT ----------
    print("Plaintext:", plaintext.decode('utf-8'))